//! Platform-independent Windows attach pipe path derivation.

use crate::windows_task::is_canonical_sid;
use sha2::{Digest, Sha256};

const PIPE_PREFIX: &str = r"\\.\pipe\Muniment\attach-v1-";

/// A failure to derive a Windows attach pipe path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPipePathError {
    InvalidSid,
}

/// Derives the per-user Windows attach pipe path from a canonical SID string.
pub fn windows_attach_pipe_path(sid: &str) -> Result<String, WindowsPipePathError> {
    if !is_canonical_sid(sid) {
        return Err(WindowsPipePathError::InvalidSid);
    }

    let digest = Sha256::digest(sid.to_ascii_uppercase().as_bytes());
    let mut user_hash = format!("{digest:x}");
    user_hash.truncate(32);
    Ok(format!("{PIPE_PREFIX}{user_hash}"))
}
