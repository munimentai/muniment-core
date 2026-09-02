//! macOS attach listener admission.

use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use super::{
    decode_frame, encode_frame, negotiate_first, verify_macos_attach_peer,
    verify_macos_attach_peer_with_reader, welcome, FirstMessage, MacosAttachPeerReader,
    MacosAttachSessionError, VersionRange, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachAcceptError {
    Accept,
    PeerRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachListenerError {
    Accept(MacosAttachAcceptError),
    Session(MacosAttachSessionError),
}

/// The result of waiting for an attach connection or a stop signal.
#[derive(Debug)]
pub enum MacosAttachWaitOutcome {
    Connected(UnixStream),
    Stopped,
}

/// A signal that wakes a blocked macOS attach accept.
#[derive(Debug)]
pub struct MacosAttachStopEvent {
    reader: UnixStream,
    writer: UnixStream,
}

impl MacosAttachStopEvent {
    pub fn new() -> io::Result<Self> {
        let (reader, writer) = UnixStream::pair()?;
        writer.set_nonblocking(true)?;
        Ok(Self { reader, writer })
    }

    pub fn signal(&self) -> io::Result<()> {
        let byte = [1_u8];
        loop {
            // SAFETY: the descriptor and one-byte buffer remain valid for this call.
            let written =
                unsafe { libc::write(self.writer.as_raw_fd(), byte.as_ptr().cast(), byte.len()) };
            if written >= 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(error),
            }
        }
    }
}

/// An owned macOS attach endpoint.
#[derive(Debug)]
pub struct MacosAttachListener {
    listener: UnixListener,
    path: PathBuf,
    _parent_directory: fs::File,
    device: u64,
    inode: u64,
}

impl MacosAttachListener {
    /// Removes a closed endpoint and binds its path.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "attach socket has no parent")
        })?;
        let parent_directory = prepare_attach_directory(parent)?;
        verify_attach_directory(parent, &parent_directory)?;
        match UnixStream::connect(path) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AddrInUse)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                let metadata = fs::symlink_metadata(path)?;
                if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() }
                {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                verify_attach_directory(parent, &parent_directory)?;
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error),
        }
        verify_attach_directory(parent, &parent_directory)?;
        let listener = UnixListener::bind(path)?;
        let bound_metadata = fs::symlink_metadata(path)?;
        let bound_identity = (bound_metadata.dev(), bound_metadata.ino());
        let metadata = match secure_bound_socket(path, parent, &parent_directory, bound_metadata) {
            Ok(metadata) => metadata,
            Err(error) => {
                remove_matching_socket(path, bound_identity);
                return Err(error);
            }
        };
        Ok(Self {
            listener,
            path: path.to_owned(),
            _parent_directory: parent_directory,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Waits without a timer until a connection or stop signal arrives.
    pub fn accept_until(
        &self,
        stop: &MacosAttachStopEvent,
    ) -> Result<MacosAttachWaitOutcome, MacosAttachAcceptError> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: both poll descriptors remain valid for this blocking call.
            let result =
                unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(MacosAttachAcceptError::Accept);
            }
            if descriptors[1].revents != 0 {
                return Ok(MacosAttachWaitOutcome::Stopped);
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                return accept_macos_attach(&self.listener).map(MacosAttachWaitOutcome::Connected);
            }
            return Err(MacosAttachAcceptError::Accept);
        }
    }
}

fn prepare_attach_directory(path: &Path) -> io::Result<fs::File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(error) => return Err(error),
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    verify_attach_directory(path, &directory)?;
    Ok(directory)
}

fn verify_attach_directory(path: &Path, directory: &fs::File) -> io::Result<()> {
    let descriptor_metadata = directory.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || path_metadata.uid() != unsafe { libc::geteuid() }
        || path_metadata.mode() & 0o777 != 0o700
        || (path_metadata.dev(), path_metadata.ino())
            != (descriptor_metadata.dev(), descriptor_metadata.ino())
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn secure_bound_socket(
    path: &Path,
    parent: &Path,
    parent_directory: &fs::File,
    bound_metadata: fs::Metadata,
) -> io::Result<fs::Metadata> {
    if !bound_metadata.file_type().is_socket() || bound_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let bound_identity = (bound_metadata.dev(), bound_metadata.ino());
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(path)?;
    verify_attach_directory(parent, parent_directory)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || (metadata.dev(), metadata.ino()) != bound_identity
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(metadata)
}

fn remove_matching_socket(path: &Path, identity: (u64, u64)) {
    if fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && (metadata.dev(), metadata.ino()) == identity
    }) {
        let _ = fs::remove_file(path);
    }
}

impl Drop for MacosAttachListener {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Writes one Welcome frame after peer admission, then closes the stream.
/// Authorization arrives in a later slice.
fn serve_macos_companion_session(
    mut stream: UnixStream,
    desktop_version: &str,
) -> Result<(), MacosAttachSessionError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| MacosAttachSessionError::Read)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(MacosAttachSessionError::MalformedFrame);
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| MacosAttachSessionError::Read)?;
    let message = decode_frame::<FirstMessage>(&frame)
        .map_err(|_| MacosAttachSessionError::MalformedFrame)?
        .ok_or(MacosAttachSessionError::MalformedFrame)?
        .0;
    let selected = negotiate_first(message, VersionRange { min: 1, max: 1 })
        .map_err(|_| MacosAttachSessionError::MalformedFrame)?;
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| MacosAttachSessionError::Randomness)?;
    let server_nonce: String = random[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let approval_challenge: String = random[16..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let response = welcome(selected, desktop_version, server_nonce, approval_challenge);
    stream
        .write_all(&encode_frame(&response).map_err(|_| MacosAttachSessionError::MalformedFrame)?)
        .map_err(|_| MacosAttachSessionError::Write)
}

/// Accepts, verifies, and serves one attach stream.
pub fn serve_next_macos_attach(
    listener: &UnixListener,
    desktop_version: &str,
) -> Result<(), MacosAttachListenerError> {
    let stream = accept_macos_attach(listener).map_err(MacosAttachListenerError::Accept)?;
    spawn_macos_attach_session(stream, desktop_version);
    Ok(())
}

/// Testable listener path through an injected peer identity boundary.
#[doc(hidden)]
pub fn serve_next_macos_attach_with_reader(
    listener: &UnixListener,
    reader: &impl MacosAttachPeerReader,
    desktop_version: &str,
) -> Result<(), MacosAttachListenerError> {
    let stream = accept_macos_attach_with_reader(listener, reader)
        .map_err(MacosAttachListenerError::Accept)?;
    spawn_macos_attach_session(stream, desktop_version);
    Ok(())
}

fn spawn_macos_attach_session(stream: UnixStream, desktop_version: &str) {
    let desktop_version = desktop_version.to_owned();
    std::thread::spawn(move || {
        let _ = serve_macos_companion_session(stream, &desktop_version);
    });
}

/// Accepts a stream and verifies its owner before any frame read.
pub fn accept_macos_attach(listener: &UnixListener) -> Result<UnixStream, MacosAttachAcceptError> {
    let (stream, _) = listener
        .accept()
        .map_err(|_| MacosAttachAcceptError::Accept)?;
    verify_macos_attach_peer(&stream).map_err(|_| MacosAttachAcceptError::PeerRejected)?;
    Ok(stream)
}

/// Accepts a stream through an injected peer identity boundary.
#[doc(hidden)]
pub fn accept_macos_attach_with_reader(
    listener: &UnixListener,
    reader: &impl MacosAttachPeerReader,
) -> Result<UnixStream, MacosAttachAcceptError> {
    let (stream, _) = listener
        .accept()
        .map_err(|_| MacosAttachAcceptError::Accept)?;
    verify_macos_attach_peer_with_reader(&stream, reader)
        .map_err(|_| MacosAttachAcceptError::PeerRejected)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "muniment-macos-listener-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn secures_the_attach_directory_and_socket() {
        let root = temporary_directory("permissions");
        fs::create_dir(&root).unwrap();
        let socket = root.join("muniment/attach-v1.sock");
        let listener = MacosAttachListener::bind(&socket).unwrap();

        assert_eq!(
            fs::symlink_metadata(socket.parent().unwrap())
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(fs::symlink_metadata(&socket).unwrap().mode() & 0o777, 0o600);

        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_a_symlink_at_the_attach_directory() {
        let root = temporary_directory("symlink");
        let target = temporary_directory("symlink-target");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&target).unwrap();
        symlink(&target, root.join("muniment")).unwrap();

        let result = MacosAttachListener::bind(root.join("muniment/attach-v1.sock"));

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(!target.join("attach-v1.sock").exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}
