//! Linux browser executable identity verification.

use std::fmt;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The process identity observed while determining the loopback connection owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserProcessIdentity {
    pub pid: u32,
    /// Linux `/proc/<pid>/stat` starttime, in clock ticks since boot.
    pub start_identity: u64,
}

/// Proof that a live process is the desktop-selected browser executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedBrowserProcess(());

/// A bounded failure reason. Variants deliberately carry no sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    ProcessUnavailable,
    ProcessIdentityChanged,
    ExpectedExecutableInvalid,
    ProcessExecutableInvalid,
    ExecutableMismatch,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ProcessUnavailable => "browser process is unavailable",
            Self::ProcessIdentityChanged => "browser process identity changed",
            Self::ExpectedExecutableInvalid => "expected browser executable is invalid",
            Self::ProcessExecutableInvalid => "browser process executable is invalid",
            Self::ExecutableMismatch => "browser executable does not match",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for VerificationError {}

/// Opaque failure from the injected procfs boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcReadError;

/// Injected Linux procfs boundary used by deterministic contract tests.
pub trait LinuxProcReader {
    fn start_identity(&self, pid: u32) -> Result<u64, ProcReadError>;
    fn executable(&self, pid: u32) -> Result<PathBuf, ProcReadError>;
}

/// Reader for the live Linux procfs.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcReader;

impl LinuxProcReader for ProcReader {
    fn start_identity(&self, pid: u32) -> Result<u64, ProcReadError> {
        let stat = fs::read(format!("/proc/{pid}/stat")).map_err(|_| ProcReadError)?;
        parse_start_identity(&stat).ok_or(ProcReadError)
    }

    fn executable(&self, pid: u32) -> Result<PathBuf, ProcReadError> {
        // Canonicalize the proc-owned link itself below. Following its target
        // pathname separately would introduce a replacement race.
        Ok(PathBuf::from(format!("/proc/{pid}/exe")))
    }
}

/// Verifies a live process against the desktop-owned expected browser path.
pub fn verify_browser_process(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
) -> Result<AuthorizedBrowserProcess, VerificationError> {
    verify_browser_process_with_reader(observed, expected_executable, &ProcReader)
}

/// Verifies using an injected procfs boundary.
#[doc(hidden)]
pub fn verify_browser_process_with_reader(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
    reader: &impl LinuxProcReader,
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
        .executable(observed.pid)
        .map_err(|_| VerificationError::ProcessExecutableInvalid)?;
    if !actual.is_absolute() || actual.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(VerificationError::ProcessExecutableInvalid);
    }

    let expected = canonical_executable(expected_executable)
        .map_err(|_| VerificationError::ExpectedExecutableInvalid)?;
    let actual =
        canonical_executable(&actual).map_err(|_| VerificationError::ProcessExecutableInvalid)?;

    let after = reader
        .start_identity(observed.pid)
        .map_err(|_| VerificationError::ProcessUnavailable)?;
    if after != observed.start_identity || after != before {
        return Err(VerificationError::ProcessIdentityChanged);
    }
    if actual.as_os_str().as_bytes() != expected.as_os_str().as_bytes() {
        return Err(VerificationError::ExecutableMismatch);
    }

    Ok(AuthorizedBrowserProcess(()))
}

fn canonical_executable(path: &Path) -> std::io::Result<PathBuf> {
    fs::canonicalize(path)
}

fn parse_start_identity(stat: &[u8]) -> Option<u64> {
    // `comm` is parenthesized and may itself contain spaces or `)` bytes. Work
    // backwards from its final delimiter, then select field 22 (starttime).
    let comm_end = stat.iter().rposition(|byte| *byte == b')')?;
    let remaining = std::str::from_utf8(stat.get(comm_end + 1..)?).ok()?;
    remaining.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_start_identity;

    #[test]
    fn parses_starttime_after_a_difficult_comm_field() {
        let mut fields = vec!["S"; 19];
        fields.push("98765");
        assert_eq!(
            parse_start_identity(
                format!("42 (name ) with spaces) {}", fields.join(" ")).as_bytes()
            ),
            Some(98765)
        );
    }
}
