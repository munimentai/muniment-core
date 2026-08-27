//! Per-profile instance lock for the Windows attach listener.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use fs2::FileExt;

const ATTACH_DIRECTORY_NAME: &str = "attach";
const INSTANCE_LOCK_NAME: &str = "instance.lock";
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Returns the instance lock path below an injected state directory.
pub fn windows_attach_instance_lock_path(state_directory: impl AsRef<Path>) -> PathBuf {
    state_directory
        .as_ref()
        .join(ATTACH_DIRECTORY_NAME)
        .join(INSTANCE_LOCK_NAME)
}

/// An owned instance lock that releases when dropped.
#[derive(Debug)]
pub struct WindowsAttachInstanceLock {
    _file: File,
}

/// Reasons the Windows attach instance lock cannot be acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachInstanceLockError {
    Unavailable,
    Contended,
}

impl std::fmt::Display for WindowsAttachInstanceLockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "the Windows attach instance lock is unavailable",
            Self::Contended => "the Windows attach instance lock is already held",
        })
    }
}

impl std::error::Error for WindowsAttachInstanceLockError {}

/// Acquires the per-profile Windows attach instance lock within `bounded_wait`.
pub fn acquire_windows_attach_instance_lock(
    state_directory: impl AsRef<Path>,
    bounded_wait: Duration,
) -> Result<WindowsAttachInstanceLock, WindowsAttachInstanceLockError> {
    let lock_path = windows_attach_instance_lock_path(state_directory);
    let attach_directory = lock_path
        .parent()
        .ok_or(WindowsAttachInstanceLockError::Unavailable)?;
    fs::create_dir_all(attach_directory)
        .map_err(|_| WindowsAttachInstanceLockError::Unavailable)?;

    let started = Instant::now();
    let mut first_attempt = true;
    loop {
        let elapsed = started.elapsed();
        if !first_attempt && elapsed >= bounded_wait {
            return Err(WindowsAttachInstanceLockError::Contended);
        }
        first_attempt = false;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| WindowsAttachInstanceLockError::Unavailable)?;
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(WindowsAttachInstanceLock { _file: file }),
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {}
            Err(_) => return Err(WindowsAttachInstanceLockError::Unavailable),
        }

        let remaining = bounded_wait.saturating_sub(elapsed);
        if remaining.is_zero() {
            return Err(WindowsAttachInstanceLockError::Contended);
        }
        thread::sleep(RETRY_INTERVAL.min(remaining));
    }
}
