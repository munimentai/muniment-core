//! macOS attach listener admission.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use super::{
    decode_frame, encode_frame, negotiate_first, verify_macos_attach_peer,
    verify_macos_attach_peer_with_reader, welcome, FirstMessage, MacosAttachPeerReader,
    VersionRange, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachAcceptError {
    Accept,
    PeerRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachSessionError {
    Read,
    MalformedFrame,
    Randomness,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachListenerError {
    Accept(MacosAttachAcceptError),
    Session(MacosAttachSessionError),
}

/// An owned macOS attach endpoint.
#[derive(Debug)]
pub struct MacosAttachListener {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl MacosAttachListener {
    /// Removes a closed endpoint and binds its path.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        match UnixStream::connect(path) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AddrInUse)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                let metadata = fs::symlink_metadata(path)?;
                if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() }
                {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            listener,
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub fn listener(&self) -> &UnixListener {
        &self.listener
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
pub fn serve_macos_attach_session(
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
        let _ = serve_macos_attach_session(stream, &desktop_version);
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
