#![cfg(target_os = "linux")]

use muniment_core::attach::{verify_migration_control_peer_with_reader, MigrationAuthorityError};
use muniment_core::browser_control::{LinuxProcReader, ProcReadError};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

struct FakeProcReader {
    starts: RefCell<VecDeque<Result<u64, ProcReadError>>>,
    executable: Result<PathBuf, ProcReadError>,
}

impl FakeProcReader {
    fn new(
        starts: impl IntoIterator<Item = Result<u64, ProcReadError>>,
        executable: Result<PathBuf, ProcReadError>,
    ) -> Self {
        Self {
            starts: RefCell::new(starts.into_iter().collect()),
            executable,
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

fn verify(
    expected: &Path,
    starts: impl IntoIterator<Item = Result<u64, ProcReadError>>,
    executable: Result<PathBuf, ProcReadError>,
) -> Result<muniment_core::attach::AuthorizedMigrationControlPeer, MigrationAuthorityError> {
    verify_migration_control_peer_with_reader(
        424242,
        expected,
        &FakeProcReader::new(starts, executable),
    )
}

#[test]
fn accepts_the_installed_runtime_executable() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();

    assert!(verify(&executable, [Ok(7), Ok(7)], Ok(executable.clone())).is_ok());
}

#[test]
fn rejects_relative_and_unresolvable_expected_paths() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();

    assert_eq!(
        verify(Path::new("relative"), [], Ok(executable.clone())),
        Err(MigrationAuthorityError::ExpectedExecutableInvalid)
    );
    assert_eq!(
        verify(
            Path::new("/path/that/does/not/exist/muniment-runtime"),
            [Ok(7)],
            Ok(executable)
        ),
        Err(MigrationAuthorityError::ExpectedExecutableInvalid)
    );
}

#[test]
fn rejects_unresolvable_and_deleted_peer_executables() {
    let expected = fs::canonicalize("/proc/self/exe").unwrap();

    for executable in [
        Err(ProcReadError),
        Ok(PathBuf::from("relative")),
        Ok(PathBuf::from("/path/that/does/not/exist/muniment-runtime")),
        Ok(PathBuf::from("/secret/muniment-runtime (deleted)")),
    ] {
        assert_eq!(
            verify(&expected, [Ok(7), Ok(7)], executable),
            Err(MigrationAuthorityError::PeerExecutableInvalid)
        );
    }
}

#[test]
fn rejects_process_disappearance_and_identity_change() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader::new([], Ok(executable.clone()));

    assert_eq!(
        verify_migration_control_peer_with_reader(0, &executable, &reader),
        Err(MigrationAuthorityError::PeerUnavailable)
    );

    for starts in [vec![Err(ProcReadError)], vec![Ok(7), Err(ProcReadError)]] {
        assert_eq!(
            verify(&executable, starts, Ok(executable.clone())),
            Err(MigrationAuthorityError::PeerUnavailable)
        );
    }
    assert_eq!(
        verify(&executable, [Ok(7), Ok(8)], Ok(executable.clone())),
        Err(MigrationAuthorityError::PeerIdentityChanged)
    );
}

#[test]
fn rejects_another_executable() {
    let expected = fs::canonicalize("/proc/self/exe").unwrap();
    let other = fs::canonicalize("/proc/self/status").unwrap();

    assert_eq!(
        verify(&expected, [Ok(7), Ok(7)], Ok(other)),
        Err(MigrationAuthorityError::ExecutableMismatch)
    );
}

#[test]
fn errors_are_bounded_and_redacted() {
    for error in [
        MigrationAuthorityError::ExpectedExecutableInvalid,
        MigrationAuthorityError::PeerUnavailable,
        MigrationAuthorityError::PeerIdentityChanged,
        MigrationAuthorityError::PeerExecutableInvalid,
        MigrationAuthorityError::ExecutableMismatch,
    ] {
        let rendered = format!("{error:?}: {error}");
        assert!(rendered.len() < 100);
        for secret in ["424242", "/secret/expected", "/secret/actual"] {
            assert!(!rendered.contains(secret));
        }
    }
}
