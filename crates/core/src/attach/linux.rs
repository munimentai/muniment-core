//! Linux filesystem boundary for the companion attach endpoint.

use std::env;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const ATTACH_DIRECTORY: &[u8] = b"muniment\0";
const ENDPOINT_NAME: &str = "attach-v1.sock";
const PRIVATE_MODE: libc::mode_t = 0o700;

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
