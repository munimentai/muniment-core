//! Linux filesystem boundary for the companion attach endpoint.

use std::env;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

const ATTACH_DIRECTORY: &[u8] = b"muniment\0";
const ENDPOINT_NAME: &str = "attach-v1.sock";
const PRIVATE_MODE: libc::mode_t = 0o700;
const SOCKET_MODE: libc::mode_t = 0o600;

/// A verified, pinned filesystem boundary for the Linux attach endpoint.
#[derive(Debug)]
pub struct AttachFilesystem {
    runtime_directory: OwnedFd,
    attach_directory: OwnedFd,
    endpoint_path: PathBuf,
}

impl AttachFilesystem {
    /// Validates `XDG_RUNTIME_DIR` and prepares its private attach directory.
    pub fn from_environment() -> Result<Self, AttachFilesystemError> {
        let runtime =
            env::var_os("XDG_RUNTIME_DIR").ok_or(AttachFilesystemError::RuntimeDirectoryMissing)?;
        Self::from_runtime_directory(runtime)
    }

    /// Validates an explicit runtime directory. This is also useful to contract tests.
    pub fn from_runtime_directory(
        runtime: impl AsRef<OsStr>,
    ) -> Result<Self, AttachFilesystemError> {
        Self::from_runtime_directory_with_hook(runtime, || {})
    }

    /// Prepares the boundary, invoking `after_create` after a successful `mkdirat`
    /// and before opening the new entry. The hook makes replacement-race contract
    /// tests deterministic; production callers should use `from_environment`.
    #[doc(hidden)]
    pub fn from_runtime_directory_with_hook(
        runtime: impl AsRef<OsStr>,
        after_create: impl FnOnce(),
    ) -> Result<Self, AttachFilesystemError> {
        let runtime = Path::new(runtime.as_ref());
        if !runtime.is_absolute() {
            return Err(AttachFilesystemError::RuntimeDirectoryNotAbsolute);
        }
        if runtime.as_os_str().as_bytes().ends_with(b"/") {
            return Err(AttachFilesystemError::RuntimeDirectoryInvalid);
        }

        let runtime_c = CString::new(runtime.as_os_str().as_bytes())
            .map_err(|_| AttachFilesystemError::RuntimeDirectoryInvalid)?;
        let runtime_directory = open_directory(
            libc::AT_FDCWD,
            runtime_c.as_ptr(),
            AttachFilesystemError::RuntimeDirectoryOpen,
        )?;
        validate_directory(
            &runtime_directory,
            false,
            AttachFilesystemError::RuntimeDirectoryMetadata,
            AttachFilesystemError::RuntimeDirectoryWrongOwner,
            AttachFilesystemError::RuntimeDirectoryInsecure,
        )?;

        let name = ATTACH_DIRECTORY.as_ptr().cast();
        let created =
            unsafe { libc::mkdirat(runtime_directory.as_raw_fd(), name, PRIVATE_MODE) } == 0;
        if !created {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(AttachFilesystemError::AttachDirectoryCreate);
            }
        } else {
            after_create();
        }

        let attach_directory = open_directory(
            runtime_directory.as_raw_fd(),
            name,
            AttachFilesystemError::AttachDirectoryOpen,
        )?;

        if created && unsafe { libc::fchmod(attach_directory.as_raw_fd(), PRIVATE_MODE) } != 0 {
            return Err(AttachFilesystemError::AttachDirectoryPermissions);
        }
        validate_directory(
            &attach_directory,
            true,
            AttachFilesystemError::AttachDirectoryMetadata,
            AttachFilesystemError::AttachDirectoryWrongOwner,
            AttachFilesystemError::AttachDirectoryInsecure,
        )?;

        Ok(Self {
            runtime_directory,
            attach_directory,
            endpoint_path: runtime.join("muniment").join(ENDPOINT_NAME),
        })
    }

    pub fn endpoint_path(&self) -> &Path {
        &self.endpoint_path
    }

    pub fn runtime_directory(&self) -> BorrowedFd<'_> {
        self.runtime_directory.as_fd()
    }

    pub fn attach_directory(&self) -> BorrowedFd<'_> {
        self.attach_directory.as_fd()
    }
}

/// A pathname Unix listener published inside a verified [`AttachFilesystem`].
#[derive(Debug)]
pub struct AttachTransport<'a> {
    filesystem: &'a AttachFilesystem,
    listener: Option<UnixListener>,
    identity: EndpointIdentity,
}

impl<'a> AttachTransport<'a> {
    /// Publishes a blocking stream listener. No accept thread is started.
    pub fn bind(filesystem: &'a AttachFilesystem) -> Result<Self, AttachTransportError> {
        Self::bind_with_quarantine_candidate_hook(filesystem, || {}, || {}, || {}, |_| {})
    }

    /// Binds while invoking deterministic race hooks used by contract tests.
    #[doc(hidden)]
    pub fn bind_with_hooks(
        filesystem: &'a AttachFilesystem,
        after_bind: impl FnOnce(),
        before_stale_remove: impl FnOnce(),
    ) -> Result<Self, AttachTransportError> {
        Self::bind_with_quarantine_candidate_hook(
            filesystem,
            after_bind,
            before_stale_remove,
            || {},
            |_| {},
        )
    }

    /// Binds with an additional hook after a stale entry has been quarantined.
    #[doc(hidden)]
    pub fn bind_with_race_hooks(
        filesystem: &'a AttachFilesystem,
        after_bind: impl FnOnce(),
        before_stale_remove: impl FnOnce(),
        after_stale_quarantine: impl FnOnce(),
    ) -> Result<Self, AttachTransportError> {
        Self::bind_with_quarantine_candidate_hook(
            filesystem,
            after_bind,
            before_stale_remove,
            after_stale_quarantine,
            |_| {},
        )
    }

    /// Binds with a hook before each quarantine move attempt.
    #[doc(hidden)]
    pub fn bind_with_quarantine_candidate_hook(
        filesystem: &'a AttachFilesystem,
        after_bind: impl FnOnce(),
        before_stale_remove: impl FnOnce(),
        after_stale_quarantine: impl FnOnce(),
        quarantine_candidate: impl FnMut(&str),
    ) -> Result<Self, AttachTransportError> {
        let uid = unsafe { libc::geteuid() };
        recover_stale_endpoint(
            filesystem,
            uid,
            before_stale_remove,
            after_stale_quarantine,
            quarantine_candidate,
        )?;

        let bind_path = pinned_endpoint_path(filesystem);
        let listener = UnixListener::bind(&bind_path).map_err(|_| AttachTransportError::Bind)?;
        let created_identity = match endpoint_identity(filesystem) {
            Ok(identity) => identity,
            Err(_) => {
                drop(listener);
                return Err(AttachTransportError::EndpointMetadata);
            }
        };
        after_bind();
        if apply_socket_permissions(filesystem, created_identity).is_err() {
            drop(listener);
            remove_if_identity(filesystem, created_identity);
            return Err(AttachTransportError::Permissions);
        }

        let identity = match verified_endpoint(filesystem, uid) {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                remove_if_identity(filesystem, created_identity);
                return Err(error);
            }
        };
        if identity != created_identity {
            drop(listener);
            remove_if_identity(filesystem, created_identity);
            return Err(AttachTransportError::EndpointMetadata);
        }
        Ok(Self {
            filesystem,
            listener: Some(listener),
            identity,
        })
    }

    /// Accepts and authenticates one connection using Linux `SO_PEERCRED`.
    pub fn accept(&self) -> Result<(UnixStream, PeerCredentials), AttachAcceptError> {
        let (stream, _) = self
            .listener
            .as_ref()
            .ok_or(AttachAcceptError::Closed)?
            .accept()
            .map_err(|_| AttachAcceptError::Accept)?;
        let credentials = peer_credentials(&stream)?;
        if credentials.uid != unsafe { libc::geteuid() } {
            return Err(AttachAcceptError::WrongUid(credentials));
        }
        Ok((stream, credentials))
    }

    pub fn local_path(&self) -> &Path {
        self.filesystem.endpoint_path()
    }

    /// Closes acceptance and safely withdraws this listener's pathname.
    pub fn shutdown(mut self) {
        self.close_and_remove();
    }

    /// Shuts down while invoking a deterministic check/remove race hook.
    #[doc(hidden)]
    pub fn shutdown_with_hook(mut self, before_remove: impl FnOnce()) {
        self.listener.take();
        let _ = remove_exact_endpoint_with_hook(self.filesystem, self.identity, before_remove);
    }

    fn close_and_remove(&mut self) {
        self.listener.take();
        remove_if_identity(self.filesystem, self.identity);
    }
}

impl Drop for AttachTransport<'_> {
    fn drop(&mut self) {
        self.close_and_remove();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachAcceptError {
    Closed,
    Accept,
    PeerCredentials,
    WrongUid(PeerCredentials),
}

impl fmt::Display for AttachAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "attach listener is closed",
            Self::Accept => "attach connection could not be accepted",
            Self::PeerCredentials => "attach peer credentials could not be verified",
            Self::WrongUid(_) => "attach peer has the wrong owner",
        })
    }
}

impl std::error::Error for AttachAcceptError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachTransportError {
    ExistingEndpointUnsafe,
    ExistingListener,
    ExistingEndpointProbe,
    ExistingEndpointRemove,
    Bind,
    Permissions,
    EndpointMetadata,
    EndpointWrongOwner,
    EndpointWrongType,
    EndpointInsecure,
}

impl fmt::Display for AttachTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExistingEndpointUnsafe => "existing attach endpoint is unsafe",
            Self::ExistingListener => "attach endpoint is already in use",
            Self::ExistingEndpointProbe => "existing attach endpoint could not be probed",
            Self::ExistingEndpointRemove => "stale attach endpoint could not be removed safely",
            Self::Bind => "attach endpoint could not be bound",
            Self::Permissions => "attach endpoint permissions could not be applied",
            Self::EndpointMetadata => "attach endpoint could not be verified",
            Self::EndpointWrongOwner => "attach endpoint has the wrong owner",
            Self::EndpointWrongType => "attach endpoint has the wrong type",
            Self::EndpointInsecure => "attach endpoint permissions are insecure",
        })
    }
}

impl std::error::Error for AttachTransportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointIdentity {
    device: u64,
    inode: u64,
}

fn pinned_endpoint_path(filesystem: &AttachFilesystem) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        filesystem.attach_directory.as_raw_fd(),
        ENDPOINT_NAME
    ))
}

fn endpoint_metadata(filesystem: &AttachFilesystem) -> io::Result<std::fs::Metadata> {
    std::fs::symlink_metadata(pinned_endpoint_path(filesystem))
}

fn endpoint_identity(filesystem: &AttachFilesystem) -> io::Result<EndpointIdentity> {
    let metadata = endpoint_metadata(filesystem)?;
    Ok(EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn verified_endpoint(
    filesystem: &AttachFilesystem,
    uid: libc::uid_t,
) -> Result<EndpointIdentity, AttachTransportError> {
    let metadata =
        endpoint_metadata(filesystem).map_err(|_| AttachTransportError::EndpointMetadata)?;
    if metadata.file_type().is_symlink() || metadata.mode() & libc::S_IFMT != libc::S_IFSOCK {
        return Err(AttachTransportError::EndpointWrongType);
    }
    if metadata.uid() != uid {
        return Err(AttachTransportError::EndpointWrongOwner);
    }
    if metadata.mode() & 0o777 != SOCKET_MODE {
        return Err(AttachTransportError::EndpointInsecure);
    }
    Ok(EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn recover_stale_endpoint(
    filesystem: &AttachFilesystem,
    uid: libc::uid_t,
    before_remove: impl FnOnce(),
    after_quarantine: impl FnOnce(),
    quarantine_candidate: impl FnMut(&str),
) -> Result<(), AttachTransportError> {
    let pinned = match open_endpoint(filesystem) {
        Ok(endpoint) => endpoint,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(AttachTransportError::ExistingEndpointUnsafe),
    };
    let metadata = File::from(
        pinned
            .try_clone()
            .map_err(|_| AttachTransportError::ExistingEndpointUnsafe)?,
    )
    .metadata()
    .map_err(|_| AttachTransportError::ExistingEndpointUnsafe)?;
    if metadata.mode() & libc::S_IFMT != libc::S_IFSOCK || metadata.uid() != uid {
        return Err(AttachTransportError::ExistingEndpointUnsafe);
    }
    let identity = EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    match UnixStream::connect(pinned_endpoint_path(filesystem)) {
        Ok(_) => return Err(AttachTransportError::ExistingListener),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(AttachTransportError::ExistingEndpointProbe),
    }
    remove_pinned_endpoint_with_hooks(
        filesystem,
        identity,
        pinned,
        before_remove,
        after_quarantine,
        quarantine_candidate,
    )
    .map_err(|_| AttachTransportError::ExistingEndpointRemove)
}

fn open_endpoint(filesystem: &AttachFilesystem) -> io::Result<OwnedFd> {
    let name = CString::new(ENDPOINT_NAME).unwrap();
    let fd = unsafe {
        libc::openat(
            filesystem.attach_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn apply_socket_permissions(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
) -> io::Result<()> {
    let name = CString::new(ENDPOINT_NAME).unwrap();
    let fd = unsafe {
        libc::openat(
            filesystem.attach_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let endpoint = unsafe { OwnedFd::from_raw_fd(fd) };
    let metadata = File::from(endpoint.try_clone()?).metadata()?;
    if (EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }) != identity
    {
        return Err(io::Error::other("endpoint identity changed"));
    }
    std::fs::set_permissions(
        PathBuf::from(format!("/proc/self/fd/{}", endpoint.as_raw_fd())),
        std::fs::Permissions::from_mode(SOCKET_MODE),
    )
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, AttachAcceptError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(AttachAcceptError::PeerCredentials);
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn remove_if_identity(filesystem: &AttachFilesystem, identity: EndpointIdentity) {
    let _ = remove_exact_endpoint(filesystem, identity);
}

fn remove_exact_endpoint(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
) -> io::Result<()> {
    remove_exact_endpoint_with_hook(filesystem, identity, || {})
}

fn remove_exact_endpoint_with_hook(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
    before_remove: impl FnOnce(),
) -> io::Result<()> {
    remove_exact_endpoint_with_hooks(filesystem, identity, before_remove, || {})
}

fn remove_exact_endpoint_with_hooks(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
    before_remove: impl FnOnce(),
    after_quarantine: impl FnOnce(),
) -> io::Result<()> {
    let pinned = open_endpoint(filesystem)?;
    remove_pinned_endpoint_with_hooks(
        filesystem,
        identity,
        pinned,
        before_remove,
        after_quarantine,
        |_| {},
    )
}

fn remove_pinned_endpoint_with_hooks(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
    pinned: OwnedFd,
    before_remove: impl FnOnce(),
    after_quarantine: impl FnOnce(),
    mut quarantine_candidate: impl FnMut(&str),
) -> io::Result<()> {
    let directory = filesystem.attach_directory.as_raw_fd();
    let from = CString::new(ENDPOINT_NAME).unwrap();
    let pinned_metadata = File::from(pinned.try_clone()?).metadata()?;
    if (EndpointIdentity {
        device: pinned_metadata.dev(),
        inode: pinned_metadata.ino(),
    }) != identity
        || pinned_metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
        || pinned_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::other("endpoint identity changed"));
    }

    before_remove();
    let (quarantine, to) = loop {
        let quarantine = quarantine_name()?;
        quarantine_candidate(&quarantine);
        let to = CString::new(quarantine.clone()).unwrap();
        if unsafe {
            libc::renameat2(
                directory,
                from.as_ptr(),
                directory,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            break (quarantine, to);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
    };
    after_quarantine();
    let metadata = std::fs::symlink_metadata(PathBuf::from(format!(
        "/proc/self/fd/{directory}/{quarantine}"
    )))?;
    let moved = EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if moved == identity
        && metadata.mode() & libc::S_IFMT == libc::S_IFSOCK
        && metadata.uid() == unsafe { libc::geteuid() }
    {
        if unsafe { libc::unlinkat(directory, to.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
    restore_quarantined_entry(directory, &to, &from)?;
    Err(io::Error::other("endpoint identity changed"))
}

fn quarantine_name() -> io::Result<String> {
    let mut random = [0_u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        let result = unsafe {
            libc::getrandom(
                random[filled..].as_mut_ptr().cast(),
                random.len() - filled,
                0,
            )
        };
        if result > 0 {
            filled += result as usize;
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    let token = u128::from_ne_bytes(random);
    Ok(format!(".attach-v1.sock.{token:032x}"))
}

fn restore_quarantined_entry(
    directory: libc::c_int,
    quarantine: &CString,
    endpoint: &CString,
) -> io::Result<()> {
    if unsafe {
        libc::renameat2(
            directory,
            quarantine.as_ptr(),
            directory,
            endpoint.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == 0
    {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EEXIST) {
        return Err(error);
    }
    if unsafe {
        libc::renameat2(
            directory,
            quarantine.as_ptr(),
            directory,
            endpoint.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_directory(
    parent: libc::c_int,
    path: *const libc::c_char,
    error: AttachFilesystemError,
) -> Result<OwnedFd, AttachFilesystemError> {
    let fd = unsafe {
        libc::openat(
            parent,
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(error)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn validate_directory(
    directory: &OwnedFd,
    exact_private_mode: bool,
    metadata_error: AttachFilesystemError,
    owner_error: AttachFilesystemError,
    mode_error: AttachFilesystemError,
) -> Result<(), AttachFilesystemError> {
    let metadata = File::from(directory.try_clone().map_err(|_| metadata_error)?)
        .metadata()
        .map_err(|_| metadata_error)?;
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(owner_error);
    }
    let mode = metadata.mode() & 0o777;
    if (exact_private_mode && mode != PRIVATE_MODE) || (!exact_private_mode && mode & 0o077 != 0) {
        return Err(mode_error);
    }
    Ok(())
}

/// Fail-closed reasons for rejecting the Linux attach filesystem boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachFilesystemError {
    RuntimeDirectoryMissing,
    RuntimeDirectoryNotAbsolute,
    RuntimeDirectoryInvalid,
    RuntimeDirectoryOpen,
    RuntimeDirectoryMetadata,
    RuntimeDirectoryWrongOwner,
    RuntimeDirectoryInsecure,
    AttachDirectoryCreate,
    AttachDirectoryOpen,
    AttachDirectoryMetadata,
    AttachDirectoryWrongOwner,
    AttachDirectoryInsecure,
    AttachDirectoryPermissions,
}

impl fmt::Display for AttachFilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RuntimeDirectoryMissing => "runtime directory is not configured",
            Self::RuntimeDirectoryNotAbsolute => "runtime directory is not absolute",
            Self::RuntimeDirectoryInvalid => "runtime directory value is invalid",
            Self::RuntimeDirectoryOpen => "runtime directory could not be opened safely",
            Self::RuntimeDirectoryMetadata => "runtime directory could not be verified",
            Self::RuntimeDirectoryWrongOwner => "runtime directory has the wrong owner",
            Self::RuntimeDirectoryInsecure => "runtime directory permissions are insecure",
            Self::AttachDirectoryCreate => "attach directory could not be created",
            Self::AttachDirectoryOpen => "attach directory could not be opened safely",
            Self::AttachDirectoryMetadata => "attach directory could not be verified",
            Self::AttachDirectoryWrongOwner => "attach directory has the wrong owner",
            Self::AttachDirectoryInsecure => "attach directory permissions are insecure",
            Self::AttachDirectoryPermissions => "attach directory permissions could not be applied",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AttachFilesystemError {}
