//! Windows peer identity verification for attach pipes.

use std::fmt;

/// Opaque failure from the injected Windows identity boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsPeerReadError;

/// Injected boundary around connected-peer and process-token SID reads.
pub trait WindowsAttachPeerReader {
    fn connected_peer_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError>;
    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError>;
}

/// A bounded failure returned before attach protocol traffic starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPeerError {
    IdentityUnavailable,
    WrongOwner,
}

impl fmt::Display for WindowsPeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityUnavailable => "attach peer identity is unavailable",
            Self::WrongOwner => "attach peer has the wrong owner",
        })
    }
}

impl std::error::Error for WindowsPeerError {}

/// Verifies a connected attach pipe through an injected identity boundary.
pub fn verify_windows_attach_peer_with_reader(
    reader: &impl WindowsAttachPeerReader,
) -> Result<(), WindowsPeerError> {
    let peer_sid = reader
        .connected_peer_sid()
        .map_err(|_| WindowsPeerError::IdentityUnavailable)?;
    let local_sid = reader
        .local_process_user_sid()
        .map_err(|_| WindowsPeerError::IdentityUnavailable)?;
    if peer_sid != local_sid {
        return Err(WindowsPeerError::WrongOwner);
    }
    Ok(())
}
