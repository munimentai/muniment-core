//! macOS peer identity verification for attach sockets.

use std::fmt;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use super::MacosPeerReadError;

/// Injected boundary around `getpeereid` and `geteuid`.
pub trait MacosAttachPeerReader {
    fn peer_effective_uid(&self, socket: RawFd) -> Result<libc::uid_t, MacosPeerReadError>;
    fn local_effective_uid(&self) -> libc::uid_t;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MacosNativePeerReader;

impl MacosAttachPeerReader for MacosNativePeerReader {
    fn peer_effective_uid(&self, socket: RawFd) -> Result<libc::uid_t, MacosPeerReadError> {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(socket, &mut uid, &mut gid) } != 0 {
            return Err(MacosPeerReadError);
        }
        Ok(uid)
    }

    fn local_effective_uid(&self) -> libc::uid_t {
        unsafe { libc::geteuid() }
    }
}

/// A bounded failure returned before attach protocol traffic starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosPeerError {
    IdentityUnavailable,
    WrongUid,
}

impl fmt::Display for MacosPeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::IdentityUnavailable => "attach peer identity is unavailable",
            Self::WrongUid => "attach peer has the wrong owner",
        })
    }
}

impl std::error::Error for MacosPeerError {}

/// Verifies a connected attach stream before the caller reads or writes a frame.
pub fn verify_macos_attach_peer(stream: &UnixStream) -> Result<(), MacosPeerError> {
    verify_macos_attach_peer_with_reader(stream, &MacosNativePeerReader)
}

/// Verifies a connected attach stream through an injected identity boundary.
#[doc(hidden)]
pub fn verify_macos_attach_peer_with_reader(
    stream: &UnixStream,
    reader: &impl MacosAttachPeerReader,
) -> Result<(), MacosPeerError> {
    let peer_uid = reader
        .peer_effective_uid(stream.as_raw_fd())
        .map_err(|_| MacosPeerError::IdentityUnavailable)?;
    if peer_uid != reader.local_effective_uid() {
        return Err(MacosPeerError::WrongUid);
    }
    Ok(())
}
