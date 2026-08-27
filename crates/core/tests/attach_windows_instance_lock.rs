use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use muniment_core::attach::{
    acquire_windows_attach_instance_lock, windows_attach_instance_lock_path,
    WindowsAttachInstanceLockError,
};
use uuid::Uuid;

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "muniment-attach-windows-instance-lock-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&path).expect("create temporary state directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lock_path_is_below_the_state_directory() {
    let state_directory = Path::new("profile-state");

    assert_eq!(
        windows_attach_instance_lock_path(state_directory),
        state_directory.join("attach").join("instance.lock")
    );
}

#[test]
fn lock_creates_the_attach_directory_and_releases_on_drop() {
    let state_directory = TempDirectory::new();
    let lock_path = windows_attach_instance_lock_path(state_directory.path());

    let guard = acquire_windows_attach_instance_lock(state_directory.path(), Duration::ZERO)
        .expect("acquire first instance lock");
    assert!(lock_path.is_file());

    drop(guard);
    acquire_windows_attach_instance_lock(state_directory.path(), Duration::ZERO)
        .expect("reacquire instance lock after guard drops");
}

#[test]
fn invalid_state_directory_reports_unavailable() {
    let state_directory = TempDirectory::new();
    let file_path = state_directory.path().join("not-a-directory");
    fs::write(&file_path, b"occupied").expect("create state directory collision");

    let error = acquire_windows_attach_instance_lock(&file_path, Duration::ZERO)
        .expect_err("reject a file as the state directory");

    assert_eq!(error, WindowsAttachInstanceLockError::Unavailable);
}

#[test]
fn held_lock_reports_contention_after_the_bounded_wait() {
    let state_directory = TempDirectory::new();
    let _guard = acquire_windows_attach_instance_lock(state_directory.path(), Duration::ZERO)
        .expect("acquire first instance lock");
    let bounded_wait = Duration::from_millis(75);
    let started = Instant::now();

    let error = acquire_windows_attach_instance_lock(state_directory.path(), bounded_wait)
        .expect_err("reject a second instance lock");

    assert_eq!(error, WindowsAttachInstanceLockError::Contended);
    assert!(started.elapsed() >= bounded_wait);
}
