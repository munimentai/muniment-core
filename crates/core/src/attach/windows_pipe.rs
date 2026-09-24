//! Platform-independent Windows attach pipe path derivation.
//!
//! The pipe path is the per-user prefix, derived from the SID, plus a random
//! suffix. The runtime generates the suffix once and stores the full path in an
//! owner-only file under `%LocalAppData%`. Another OS user cannot read that file,
//! so another user cannot create the pipe before the runtime does.

use crate::windows_task::is_canonical_sid;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const PIPE_PREFIX: &str = r"\\.\pipe\Muniment\attach-v1-";
/// The hex characters of the random pipe suffix.
const SUFFIX_LENGTH: usize = 32;

/// The directory under `%LocalAppData%` that holds the pipe name file.
pub const WINDOWS_ATTACH_PIPE_NAME_DIRECTORY: &str = "ai.muniment.desktop";
/// The owner-only file that holds the full attach pipe path.
pub const WINDOWS_ATTACH_PIPE_NAME_FILE: &str = "attach-pipe-name";

/// A failure to derive a Windows attach pipe path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPipePathError {
    InvalidSid,
    InvalidSuffix,
    InvalidPath,
}

/// Returns the pipe name file under the `%LocalAppData%` root.
pub fn windows_attach_pipe_name_file(local_app_data: &Path) -> PathBuf {
    local_app_data
        .join(WINDOWS_ATTACH_PIPE_NAME_DIRECTORY)
        .join(WINDOWS_ATTACH_PIPE_NAME_FILE)
}

/// Derives the per-user Windows attach pipe path from a canonical SID string and
/// the runtime's random suffix.
pub fn windows_attach_pipe_path(sid: &str, suffix: &str) -> Result<String, WindowsPipePathError> {
    let prefix = windows_attach_pipe_prefix(sid)?;
    if !is_valid_suffix(suffix) {
        return Err(WindowsPipePathError::InvalidSuffix);
    }
    Ok(format!("{prefix}{suffix}"))
}

/// Generates a new random pipe suffix.
pub fn new_windows_attach_pipe_suffix() -> Result<String, WindowsPipePathError> {
    let mut bytes = [0_u8; SUFFIX_LENGTH / 2];
    getrandom::fill(&mut bytes).map_err(|_| WindowsPipePathError::InvalidSuffix)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Checks a stored pipe path against the current user's SID.
pub fn validate_windows_attach_pipe_path(
    sid: &str,
    path: &str,
) -> Result<String, WindowsPipePathError> {
    let prefix = windows_attach_pipe_prefix(sid)?;
    let suffix = path
        .strip_prefix(&prefix)
        .ok_or(WindowsPipePathError::InvalidPath)?;
    windows_attach_pipe_path(sid, suffix).map_err(|_| WindowsPipePathError::InvalidPath)
}

fn windows_attach_pipe_prefix(sid: &str) -> Result<String, WindowsPipePathError> {
    if !is_canonical_sid(sid) {
        return Err(WindowsPipePathError::InvalidSid);
    }

    let digest = Sha256::digest(sid.to_ascii_uppercase().as_bytes());
    let mut user_hash = format!("{digest:x}");
    user_hash.truncate(32);
    Ok(format!("{PIPE_PREFIX}{user_hash}-"))
}

fn is_valid_suffix(suffix: &str) -> bool {
    suffix.len() == SUFFIX_LENGTH
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
