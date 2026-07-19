//! macOS browser executable identity verification.

use std::fmt;
use std::fs::File;
use std::mem;
use std::net::SocketAddr;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserProcessIdentity {
    pub pid: u32,
    /// Process start time, represented as `(seconds, microseconds)` since the epoch.
    pub start_identity: (u64, u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedBrowserProcess(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    InvalidEndpoint,
    InspectionUnavailable,
    SocketNotFound,
    AmbiguousOwner,
    ProcessIdentityChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    ProcessUnavailable,
    ProcessIdentityChanged,
    ExpectedExecutableInvalid,
    ProcessExecutableInvalid,
    ExecutableMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    OwnerResolutionFailed,
    ExecutableVerificationFailed,
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "connection endpoints are invalid",
            Self::InspectionUnavailable => "process inspection is unavailable",
            Self::SocketNotFound => "connection socket was not found",
            Self::AmbiguousOwner => "connection socket owner is ambiguous",
            Self::ProcessIdentityChanged => "socket owner identity changed",
        })
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProcessUnavailable => "browser process is unavailable",
            Self::ProcessIdentityChanged => "browser process identity changed",
            Self::ExpectedExecutableInvalid => "expected browser executable is invalid",
            Self::ProcessExecutableInvalid => "browser process executable is invalid",
            Self::ExecutableMismatch => "browser executable does not match",
        })
    }
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OwnerResolutionFailed => "browser connection owner could not be resolved",
            Self::ExecutableVerificationFailed => "browser connection owner was not authorized",
        })
    }
}

impl std::error::Error for ResolutionError {}
impl std::error::Error for VerificationError {}
impl std::error::Error for AuthorizationError {}

/// Opaque error from the native process-inspection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessReadError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessSocket {
    pub local: SocketAddr,
    pub peer: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableIdentity {
    device: u64,
    inode: u64,
}

/// Injected boundary around macOS libproc process and descriptor inspection.
pub trait NativeProcessReader {
    fn process_ids(&self) -> Result<Vec<u32>, ProcessReadError>;
    fn start_identity(&self, pid: u32) -> Result<(u64, u64), ProcessReadError>;
    fn executable_identity(&self, pid: u32) -> Result<ExecutableIdentity, ProcessReadError>;
    fn tcp_sockets(&self, pid: u32) -> Result<Vec<ProcessSocket>, ProcessReadError>;
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsProcessReader;

#[cfg(target_os = "macos")]
pub fn authorize_browser_process(
    local: SocketAddr,
    peer: SocketAddr,
    expected_executable: &Path,
) -> Result<AuthorizedBrowserProcess, AuthorizationError> {
    authorize_browser_process_with_reader(local, peer, expected_executable, &MacOsProcessReader)
}

#[doc(hidden)]
pub fn authorize_browser_process_with_reader(
    local: SocketAddr,
    peer: SocketAddr,
    expected_executable: &Path,
    reader: &impl NativeProcessReader,
) -> Result<AuthorizedBrowserProcess, AuthorizationError> {
    let observed = resolve_browser_process_with_reader(local, peer, reader)
        .map_err(|_| AuthorizationError::OwnerResolutionFailed)?;
    verify_browser_process_with_reader(observed, expected_executable, reader)
        .map_err(|_| AuthorizationError::ExecutableVerificationFailed)
}

#[cfg(target_os = "macos")]
pub fn resolve_browser_process(
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<BrowserProcessIdentity, ResolutionError> {
    resolve_browser_process_with_reader(local, peer, &MacOsProcessReader)
}

#[doc(hidden)]
pub fn resolve_browser_process_with_reader(
    local: SocketAddr,
    peer: SocketAddr,
    reader: &impl NativeProcessReader,
) -> Result<BrowserProcessIdentity, ResolutionError> {
    validate_endpoints(local, peer)?;
    let matches = matching_processes(local, peer, reader)?;
    let owner = match matches.as_slice() {
        [] => return Err(ResolutionError::SocketNotFound),
        [owner] => *owner,
        _ => return Err(ResolutionError::AmbiguousOwner),
    };
    let confirmed = matching_processes(local, peer, reader)?;
    if confirmed.as_slice() != [owner] {
        return Err(if confirmed.len() > 1 {
            ResolutionError::AmbiguousOwner
        } else {
            ResolutionError::ProcessIdentityChanged
        });
    }
    Ok(owner)
}

fn matching_processes(
    local: SocketAddr,
    peer: SocketAddr,
    reader: &impl NativeProcessReader,
) -> Result<Vec<BrowserProcessIdentity>, ResolutionError> {
    let mut matches = Vec::new();
    for pid in reader
        .process_ids()
        .map_err(|_| ResolutionError::InspectionUnavailable)?
    {
        let before = reader
            .start_identity(pid)
            .map_err(|_| ResolutionError::InspectionUnavailable)?;
        let sockets = reader
            .tcp_sockets(pid)
            .map_err(|_| ResolutionError::InspectionUnavailable)?;
        let after = reader
            .start_identity(pid)
            .map_err(|_| ResolutionError::InspectionUnavailable)?;
        if before != after {
            return Err(ResolutionError::ProcessIdentityChanged);
        }
        if sockets
            .iter()
            .filter(|socket| socket.local == peer && socket.peer == local)
            .count()
            > 0
        {
            matches.push(BrowserProcessIdentity {
                pid,
                start_identity: before,
            });
        }
    }
    Ok(matches)
}

fn validate_endpoints(local: SocketAddr, peer: SocketAddr) -> Result<(), ResolutionError> {
    if local.port() == 0
        || peer.port() == 0
        || !local.ip().is_loopback()
        || !peer.ip().is_loopback()
        || mem::discriminant(&local.ip()) != mem::discriminant(&peer.ip())
        || local == peer
    {
        return Err(ResolutionError::InvalidEndpoint);
    }
    Ok(())
}

fn verify_browser_process_with_reader(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
    reader: &impl NativeProcessReader,
) -> Result<AuthorizedBrowserProcess, VerificationError> {
    if !expected_executable.is_absolute() {
        return Err(VerificationError::ExpectedExecutableInvalid);
    }
    let before = reader
        .start_identity(observed.pid)
        .map_err(|_| VerificationError::ProcessUnavailable)?;
    if before != observed.start_identity {
        return Err(VerificationError::ProcessIdentityChanged);
    }
    let actual = reader
        .executable_identity(observed.pid)
        .map_err(|_| VerificationError::ProcessExecutableInvalid)?;
    let expected = expected_executable
        .canonicalize()
        .map_err(|_| VerificationError::ExpectedExecutableInvalid)?;
    let expected = File::open(expected)
        .and_then(|file| file.metadata())
        .map(|metadata| ExecutableIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
        .map_err(|_| VerificationError::ExpectedExecutableInvalid)?;
    let after = reader
        .start_identity(observed.pid)
        .map_err(|_| VerificationError::ProcessUnavailable)?;
    if after != observed.start_identity || after != before {
        return Err(VerificationError::ProcessIdentityChanged);
    }
    if actual != expected {
        return Err(VerificationError::ExecutableMismatch);
    }
    Ok(AuthorizedBrowserProcess(()))
}

#[cfg(target_os = "macos")]
mod native;

#[cfg(test)]
mod tests;
