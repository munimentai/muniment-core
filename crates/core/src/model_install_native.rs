//! Standard-library native adapters for coordinated model installation.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::asr::acquisition::{AsrAcquisitionClock, AsrCancellation, AsrRetryWait};
use crate::asr::{AsrLifecycleBoundary, AsrPersistenceError};
use crate::llama::acquisition::{
    ResidentModelAcquisitionClock, ResidentModelCancellation, ResidentModelRetryWait,
};
use crate::llama::lifecycle::{ResidentModelLifecycleBoundary, ResidentModelPersistenceError};
use crate::model_install::{
    AvailableSpace, AvailableSpaceError, InstallCancellation, InstallLock, InstallLockError,
    InstallLockState,
};
use fs2::FileExt;

const CANCELLATION_POLL: Duration = Duration::from_millis(10);

/// Cloneable cancellation handle suitable for command and worker threads.
#[derive(Debug, Clone, Default)]
pub struct NativeInstallCancellation(Arc<AtomicBool>);

impl NativeInstallCancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
impl InstallCancellation for NativeInstallCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}
impl ResidentModelCancellation for NativeInstallCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}
impl AsrCancellation for NativeInstallCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// An advisory OS lock retained by an open file guard. Advisory locking is
/// used instead of lockfile creation so a crashed process cannot leave stale
/// state; the operating system releases the lock when the guard is dropped.
#[derive(Debug)]
pub struct NativeInstallLock {
    path: PathBuf,
    retry_interval: Duration,
}

impl NativeInstallLock {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_retry_interval(path, Duration::from_millis(50))
    }
    pub fn with_retry_interval(path: impl Into<PathBuf>, retry_interval: Duration) -> Self {
        Self {
            path: path.into(),
            retry_interval,
        }
    }
}
impl InstallLock for NativeInstallLock {
    type Guard = File;
    fn try_lock_exclusive(&mut self) -> Result<InstallLockState<Self::Guard>, InstallLockError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|_| InstallLockError::Failed)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(InstallLockState::Acquired(file)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                Ok(InstallLockState::Contended)
            }
            Err(_) => Err(InstallLockError::Failed),
        }
    }
    fn wait_for_retry(&mut self, cancellation: &dyn InstallCancellation) -> bool {
        cancellable_sleep(self.retry_interval, || cancellation.is_cancelled())
    }
}

/// Free-space adapter for the filesystem volume containing `path`.
#[derive(Debug)]
pub struct NativeAvailableSpace {
    path: PathBuf,
}
impl NativeAvailableSpace {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}
impl AvailableSpace for NativeAvailableSpace {
    fn available_bytes(&mut self) -> Result<Option<u64>, AvailableSpaceError> {
        fs2::available_space(&self.path)
            .map(Some)
            .map_err(|_| AvailableSpaceError::Failed)
    }
}

/// Monotonic clock anchored when constructed.
#[derive(Debug)]
pub struct NativeAcquisitionClock(Instant);
impl NativeAcquisitionClock {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}
impl Default for NativeAcquisitionClock {
    fn default() -> Self {
        Self::new()
    }
}
impl ResidentModelAcquisitionClock for NativeAcquisitionClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}
impl AsrAcquisitionClock for NativeAcquisitionClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// Bounded jittered retry sleep which polls cancellation every 10ms.
#[derive(Debug, Default)]
pub struct NativeRetryWait;
impl ResidentModelRetryWait for NativeRetryWait {
    fn wait(
        &mut self,
        maximum_delay: Duration,
        cancellation: &dyn ResidentModelCancellation,
    ) -> bool {
        cancellable_sleep(jittered_delay(maximum_delay), || {
            cancellation.is_cancelled()
        })
    }
}
impl AsrRetryWait for NativeRetryWait {
    fn wait(&mut self, maximum_delay: Duration, cancellation: &dyn AsrCancellation) -> bool {
        cancellable_sleep(jittered_delay(maximum_delay), || {
            cancellation.is_cancelled()
        })
    }
}
fn jittered_delay(maximum: Duration) -> Duration {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    if maximum.is_zero() {
        return maximum;
    }
    let ceiling = maximum.as_nanos();
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        ^ u128::from(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    Duration::from_nanos((seed % (ceiling + 1)).min(u128::from(u64::MAX)) as u64)
}
fn cancellable_sleep(duration: Duration, cancelled: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        if cancelled() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return true;
        }
        thread::sleep(remaining.min(CANCELLATION_POLL));
    }
}

/// Native durable filesystem operations for ResidentModel publication.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeResidentModelLifecycleBoundary;
impl ResidentModelLifecycleBoundary for NativeResidentModelLifecycleBoundary {
    type LockGuard = File;
    fn lock_exclusive(
        &self,
        path: &Path,
    ) -> Result<Self::LockGuard, ResidentModelPersistenceError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|_| ResidentModelPersistenceError::Failed)?;
        file.lock_exclusive()
            .map_err(|_| ResidentModelPersistenceError::Failed)?;
        Ok(file)
    }
    fn sync_file(&self, path: &Path) -> Result<(), ResidentModelPersistenceError> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| ResidentModelPersistenceError::Failed)
    }
    fn sync_directory(&self, path: &Path) -> Result<(), ResidentModelPersistenceError> {
        #[cfg(unix)]
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| ResidentModelPersistenceError::Failed)?;
        let _ = path;
        Ok(())
    }
    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), ResidentModelPersistenceError> {
        atomic_replace_directory(staged, destination)
    }
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), ResidentModelPersistenceError> {
        fs::rename(temporary, destination).map_err(|_| ResidentModelPersistenceError::Failed)
    }
}

/// Native durable filesystem operations for Parakeet publication.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeAsrLifecycleBoundary;
impl AsrLifecycleBoundary for NativeAsrLifecycleBoundary {
    fn sync_file(&self, path: &Path) -> Result<(), AsrPersistenceError> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| AsrPersistenceError::Failed)
    }

    fn sync_directory(&self, path: &Path) -> Result<(), AsrPersistenceError> {
        #[cfg(unix)]
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| AsrPersistenceError::Failed)?;
        let _ = path;
        Ok(())
    }

    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), AsrPersistenceError> {
        fs::rename(temporary, destination).map_err(|_| AsrPersistenceError::Failed)
    }
}

fn atomic_replace_directory(
    staged: &Path,
    destination: &Path,
) -> Result<(), ResidentModelPersistenceError> {
    if !destination.exists() {
        return fs::rename(staged, destination).map_err(|_| ResidentModelPersistenceError::Failed);
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        const AT_FDCWD: i32 = -100;
        const RENAME_EXCHANGE: u32 = 2;
        unsafe extern "C" {
            fn renameat2(
                olddirfd: i32,
                oldpath: *const i8,
                newdirfd: i32,
                newpath: *const i8,
                flags: u32,
            ) -> i32;
        }
        let old = CString::new(staged.as_os_str().as_bytes())
            .map_err(|_| ResidentModelPersistenceError::Failed)?;
        let new = CString::new(destination.as_os_str().as_bytes())
            .map_err(|_| ResidentModelPersistenceError::Failed)?;
        if unsafe {
            renameat2(
                AT_FDCWD,
                old.as_ptr(),
                AT_FDCWD,
                new.as_ptr(),
                RENAME_EXCHANGE,
            )
        } != 0
        {
            return Err(ResidentModelPersistenceError::Failed);
        }
        fs::remove_dir_all(staged).map_err(|_| ResidentModelPersistenceError::Failed)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Match the native Pi lifecycle: quarantine the old complete revision
        // before publishing the new complete revision. This can leave neither
        // directory published after interruption, which the lifecycle contract
        // permits, but never exposes a partially staged revision.
        let quarantine = destination.with_extension("replaced");
        if quarantine.exists() {
            fs::remove_dir_all(&quarantine).map_err(|_| ResidentModelPersistenceError::Failed)?;
        }
        fs::rename(destination, &quarantine).map_err(|_| ResidentModelPersistenceError::Failed)?;
        fs::rename(staged, destination).map_err(|_| ResidentModelPersistenceError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "muniment-{label}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn lock_is_exclusive_and_releases_on_drop() {
        let root = temp_dir("lock");
        let path = root.join("install.lock");
        let mut first = NativeInstallLock::new(&path);
        let mut second = NativeInstallLock::new(&path);
        let guard = match first.try_lock_exclusive().unwrap() {
            InstallLockState::Acquired(g) => g,
            _ => panic!(),
        };
        assert!(matches!(
            second.try_lock_exclusive().unwrap(),
            InstallLockState::Contended
        ));
        drop(guard);
        assert!(matches!(
            second.try_lock_exclusive().unwrap(),
            InstallLockState::Acquired(_)
        ));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn available_space_reports_the_temp_volume() {
        let root = temp_dir("space");
        assert!(
            NativeAvailableSpace::new(&root)
                .available_bytes()
                .unwrap()
                .unwrap()
                > 0
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn replacement_keeps_a_destination_and_removes_the_stage() {
        let root = temp_dir("replace");
        let staged = root.join("staged");
        let destination = root.join("revision");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("value"), b"new").unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("value"), b"old").unwrap();
        NativeResidentModelLifecycleBoundary
            .replace_revision(&staged, &destination)
            .unwrap();
        assert_eq!(fs::read(destination.join("value")).unwrap(), b"new");
        assert!(!staged.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn retry_wait_stops_promptly_when_cancelled_at_start() {
        let cancellation = NativeInstallCancellation::new();
        cancellation.cancel();
        let started = Instant::now();
        let result = ResidentModelRetryWait::wait(
            &mut NativeRetryWait,
            Duration::from_secs(1),
            &cancellation,
        );
        assert!(!result);
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn native_resident_model_install_composition_is_compile_checked_without_network() {
        use crate::llama::acquisition::{
            ResidentModelAcquisitionLimits, ResidentModelAcquisitionRuntime,
        };
        use crate::llama::install::install_resident_model_revision;
        use crate::llama::lifecycle::{
            ResidentModelRevisionLifecycle, PINNED_RESIDENT_MODEL_REVISION,
            RESIDENT_MODEL_REVISIONS,
        };
        use crate::model_acquisition_transport::NativeModelAcquisitionTransport;

        let root = temp_dir("composition");
        let missing_staging = root.join("missing-staging");
        let lifecycle = ResidentModelRevisionLifecycle::new(
            root.join("models"),
            &RESIDENT_MODEL_REVISIONS,
            &PINNED_RESIDENT_MODEL_REVISION,
        )
        .unwrap();
        let mut transport = NativeModelAcquisitionTransport::new();
        let clock = NativeAcquisitionClock::new();
        let mut wait = NativeRetryWait;
        let cancellation = NativeInstallCancellation::new();
        let mut lock = NativeInstallLock::new(root.join("install.lock"));
        let mut space = NativeAvailableSpace::new(&root);
        let result = install_resident_model_revision(
            &missing_staging,
            "native-composition",
            &PINNED_RESIDENT_MODEL_REVISION,
            ResidentModelAcquisitionLimits::default(),
            &mut transport,
            ResidentModelAcquisitionRuntime {
                clock: &clock,
                retry_wait: &mut wait,
            },
            &cancellation,
            &mut lock,
            &mut space,
            &lifecycle,
            &NativeResidentModelLifecycleBoundary,
        );
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
