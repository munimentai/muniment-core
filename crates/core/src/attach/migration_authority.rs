//! Linux migration control peer verification.

use crate::browser_control::{LinuxProcReader, ProcReader};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Proof that an attach peer is the installed runtime executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedMigrationControlPeer(());

/// A bounded failure reason. Variants carry no peer values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationAuthorityError {
    ExpectedExecutableInvalid,
    PeerUnavailable,
    PeerIdentityChanged,
    PeerExecutableInvalid,
    ExecutableMismatch,
}

impl fmt::Display for MigrationAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpectedExecutableInvalid => "expected runtime executable is invalid",
            Self::PeerUnavailable => "migration control peer is unavailable",
            Self::PeerIdentityChanged => "migration control peer identity changed",
            Self::PeerExecutableInvalid => "migration control peer executable is invalid",
            Self::ExecutableMismatch => "migration control peer executable does not match",
        })
    }
}

impl std::error::Error for MigrationAuthorityError {}

/// Verifies an attach peer against the installed runtime executable.
pub fn verify_migration_control_peer(
    peer_pid: u32,
    expected_executable: &Path,
) -> Result<AuthorizedMigrationControlPeer, MigrationAuthorityError> {
    verify_migration_control_peer_with_reader(peer_pid, expected_executable, &ProcReader)
}

/// Verifies an attach peer using an injected procfs boundary.
#[doc(hidden)]
pub fn verify_migration_control_peer_with_reader(
    peer_pid: u32,
    expected_executable: &Path,
    reader: &(impl LinuxProcReader + ?Sized),
) -> Result<AuthorizedMigrationControlPeer, MigrationAuthorityError> {
    if !expected_executable.is_absolute() {
        return Err(MigrationAuthorityError::ExpectedExecutableInvalid);
    }
    if peer_pid == 0 {
        return Err(MigrationAuthorityError::PeerUnavailable);
    }

    let before = reader
        .start_identity(peer_pid)
        .map_err(|_| MigrationAuthorityError::PeerUnavailable)?;
    let actual = reader
        .executable(peer_pid)
        .map_err(|_| MigrationAuthorityError::PeerExecutableInvalid)?;
    if !actual.is_absolute() || actual.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(MigrationAuthorityError::PeerExecutableInvalid);
    }

    let expected = std::fs::canonicalize(expected_executable)
        .map_err(|_| MigrationAuthorityError::ExpectedExecutableInvalid)?;
    let actual = std::fs::canonicalize(actual)
        .map_err(|_| MigrationAuthorityError::PeerExecutableInvalid)?;

    let after = reader
        .start_identity(peer_pid)
        .map_err(|_| MigrationAuthorityError::PeerUnavailable)?;
    if before != after {
        return Err(MigrationAuthorityError::PeerIdentityChanged);
    }
    if actual.as_os_str().as_bytes() != expected.as_os_str().as_bytes() {
        return Err(MigrationAuthorityError::ExecutableMismatch);
    }

    Ok(AuthorizedMigrationControlPeer(()))
}
