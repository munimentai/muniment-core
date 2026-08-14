//! Linux attach peer verification.

use crate::browser_control::{LinuxProcReader, ProcReader};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Proof that an attach peer is the installed runtime executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedMigrationControlPeer(());

/// Proof that an attach peer is the installed approval presenter executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedApprovalPresenter(());

/// Proof that an attach peer is the installed desktop client executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedDesktopClientPeer(());

/// A bounded failure reason. Variants carry no peer values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAuthorityError {
    ExpectedExecutableInvalid,
    PeerUnavailable,
    PeerIdentityChanged,
    PeerExecutableInvalid,
    ExecutableMismatch,
}

impl fmt::Display for PeerAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpectedExecutableInvalid => "expected executable is invalid",
            Self::PeerUnavailable => "attach peer is unavailable",
            Self::PeerIdentityChanged => "attach peer identity changed",
            Self::PeerExecutableInvalid => "attach peer executable is invalid",
            Self::ExecutableMismatch => "attach peer executable does not match",
        })
    }
}

impl std::error::Error for PeerAuthorityError {}

/// Verifies an attach peer against the installed runtime executable.
pub fn verify_migration_control_peer(
    peer_pid: u32,
    expected_executable: &Path,
) -> Result<AuthorizedMigrationControlPeer, PeerAuthorityError> {
    verify_migration_control_peer_with_reader(peer_pid, expected_executable, &ProcReader)
}

/// Verifies an attach peer using an injected procfs boundary.
#[doc(hidden)]
pub fn verify_migration_control_peer_with_reader(
    peer_pid: u32,
    expected_executable: &Path,
    reader: &(impl LinuxProcReader + ?Sized),
) -> Result<AuthorizedMigrationControlPeer, PeerAuthorityError> {
    verify_peer_executable(peer_pid, expected_executable, reader)?;
    Ok(AuthorizedMigrationControlPeer(()))
}

/// Verifies an attach peer against the installed approval presenter executable.
pub fn verify_approval_presenter_peer(
    peer_pid: u32,
    expected_executable: &Path,
) -> Result<AuthorizedApprovalPresenter, PeerAuthorityError> {
    verify_approval_presenter_peer_with_reader(peer_pid, expected_executable, &ProcReader)
}

/// Verifies an approval presenter peer using an injected procfs boundary.
#[doc(hidden)]
pub fn verify_approval_presenter_peer_with_reader(
    peer_pid: u32,
    expected_executable: &Path,
    reader: &(impl LinuxProcReader + ?Sized),
) -> Result<AuthorizedApprovalPresenter, PeerAuthorityError> {
    verify_peer_executable(peer_pid, expected_executable, reader)?;
    Ok(AuthorizedApprovalPresenter(()))
}

/// Verifies an attach peer against the installed desktop client executable.
pub fn verify_desktop_client_peer(
    peer_pid: u32,
    expected_executable: &Path,
) -> Result<AuthorizedDesktopClientPeer, PeerAuthorityError> {
    verify_desktop_client_peer_with_reader(peer_pid, expected_executable, &ProcReader)
}

/// Verifies a desktop client peer using an injected procfs boundary.
#[doc(hidden)]
pub fn verify_desktop_client_peer_with_reader(
    peer_pid: u32,
    expected_executable: &Path,
    reader: &(impl LinuxProcReader + ?Sized),
) -> Result<AuthorizedDesktopClientPeer, PeerAuthorityError> {
    verify_peer_executable(peer_pid, expected_executable, reader)?;
    Ok(AuthorizedDesktopClientPeer(()))
}

fn verify_peer_executable(
    peer_pid: u32,
    expected_executable: &Path,
    reader: &(impl LinuxProcReader + ?Sized),
) -> Result<(), PeerAuthorityError> {
    if !expected_executable.is_absolute() {
        return Err(PeerAuthorityError::ExpectedExecutableInvalid);
    }
    if peer_pid == 0 {
        return Err(PeerAuthorityError::PeerUnavailable);
    }

    let before = reader
        .start_identity(peer_pid)
        .map_err(|_| PeerAuthorityError::PeerUnavailable)?;
    let actual = reader
        .executable(peer_pid)
        .map_err(|_| PeerAuthorityError::PeerExecutableInvalid)?;
    if !actual.is_absolute() || actual.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(PeerAuthorityError::PeerExecutableInvalid);
    }

    let expected = std::fs::canonicalize(expected_executable)
        .map_err(|_| PeerAuthorityError::ExpectedExecutableInvalid)?;
    let actual =
        std::fs::canonicalize(actual).map_err(|_| PeerAuthorityError::PeerExecutableInvalid)?;

    let after = reader
        .start_identity(peer_pid)
        .map_err(|_| PeerAuthorityError::PeerUnavailable)?;
    if before != after {
        return Err(PeerAuthorityError::PeerIdentityChanged);
    }
    if actual.as_os_str().as_bytes() != expected.as_os_str().as_bytes() {
        return Err(PeerAuthorityError::ExecutableMismatch);
    }

    Ok(())
}
