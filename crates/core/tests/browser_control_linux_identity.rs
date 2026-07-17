#![cfg(target_os = "linux")]

use muniment_core::browser_control::{
    verify_browser_process, verify_browser_process_with_reader, BrowserProcessIdentity,
    LinuxProcReader, ProcReadError, ProcReader, VerificationError,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-browser-identity-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeProcReader {
    starts: RefCell<VecDeque<Result<u64, ProcReadError>>>,
    executable: Result<PathBuf, ProcReadError>,
}

impl FakeProcReader {
    fn new(
        starts: impl IntoIterator<Item = Result<u64, ProcReadError>>,
        executable: PathBuf,
    ) -> Self {
        Self {
            starts: RefCell::new(starts.into_iter().collect()),
            executable: Ok(executable),
        }
    }
}

impl LinuxProcReader for FakeProcReader {
    fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
        self.starts.borrow_mut().pop_front().unwrap()
    }

    fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
        self.executable.clone()
    }
}

fn observed(start_identity: u64) -> BrowserProcessIdentity {
    BrowserProcessIdentity {
        pid: std::process::id(),
        start_identity,
    }
}

#[test]
fn authorizes_current_process_through_temporary_symlinks() {
    let directory = TestDirectory::new();
    let current_executable = fs::read_link("/proc/self/exe").unwrap();
    let first = directory.0.join("browser");
    let second = directory.0.join("selected-browser");
    symlink(&current_executable, &first).unwrap();
    symlink(&first, &second).unwrap();
    let start_identity = ProcReader.start_identity(std::process::id()).unwrap();

    assert!(verify_browser_process(observed(start_identity), &second).is_ok());
}

#[test]
fn rejects_observed_mismatch_and_pid_reuse_during_resolution() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();

    let stale = FakeProcReader::new([Ok(8)], executable.clone());
    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &stale),
        Err(VerificationError::ProcessIdentityChanged)
    );

    let reused = FakeProcReader::new([Ok(7), Ok(8)], executable.clone());
    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &reused),
        Err(VerificationError::ProcessIdentityChanged)
    );
}

#[test]
fn rejects_process_disappearance_before_or_after_resolution() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    for starts in [vec![Err(ProcReadError)], vec![Ok(7), Err(ProcReadError)]] {
        let reader = FakeProcReader::new(starts, executable.clone());
        assert_eq!(
            verify_browser_process_with_reader(observed(7), &executable, &reader),
            Err(VerificationError::ProcessUnavailable)
        );
    }

    let during_resolution = FakeProcReader {
        starts: RefCell::new([Ok(7)].into_iter().collect()),
        executable: Err(ProcReadError),
    };
    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &during_resolution),
        Err(VerificationError::ProcessExecutableInvalid)
    );
}

#[test]
fn rejects_invalid_expected_and_proc_executable_paths() {
    let directory = TestDirectory::new();
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let missing = directory.0.join("missing");
    let loop_a = directory.0.join("loop-a");
    let loop_b = directory.0.join("loop-b");
    symlink(&loop_b, &loop_a).unwrap();
    symlink(&loop_a, &loop_b).unwrap();

    for expected in [Path::new("relative"), &missing, &loop_a] {
        let reader = FakeProcReader::new([Ok(7), Ok(7)], executable.clone());
        assert_eq!(
            verify_browser_process_with_reader(observed(7), expected, &reader),
            Err(VerificationError::ExpectedExecutableInvalid)
        );
    }

    for actual in [
        PathBuf::from("relative"),
        missing,
        loop_a,
        PathBuf::from("/secret/browser (deleted)"),
    ] {
        let reader = FakeProcReader::new([Ok(7), Ok(7)], actual);
        assert_eq!(
            verify_browser_process_with_reader(observed(7), &executable, &reader),
            Err(VerificationError::ProcessExecutableInvalid)
        );
    }
}

#[test]
fn rejects_a_different_canonical_executable() {
    let directory = TestDirectory::new();
    let other = directory.0.join("other");
    fs::write(&other, b"not the browser").unwrap();
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader::new([Ok(7), Ok(7)], other);

    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &reader),
        Err(VerificationError::ExecutableMismatch)
    );
}

#[test]
fn errors_are_bounded_and_redacted() {
    let secrets = [
        "424242",
        "987654321",
        "/secret/expected",
        "/secret/actual",
        "permission denied",
    ];
    for error in [
        VerificationError::ProcessUnavailable,
        VerificationError::ProcessIdentityChanged,
        VerificationError::ExpectedExecutableInvalid,
        VerificationError::ProcessExecutableInvalid,
        VerificationError::ExecutableMismatch,
    ] {
        let rendered = format!("{error:?}: {error}");
        assert!(rendered.len() < 100);
        for secret in secrets {
            assert!(!rendered.contains(secret));
        }
    }
}
