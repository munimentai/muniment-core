//! Windows attach session negotiation.

use std::time::Instant;

use super::{
    decode_frame, encode_frame, negotiate_first, read_exact_before,
    verify_windows_attach_peer_with_reader, welcome, write_all_before, DeadlineStream,
    FirstMessage, VersionRange, WindowsAttachPeerReader, WindowsPeerError, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachSessionError {
    Read,
    PeerRejected(WindowsPeerError),
    MalformedFrame,
    Randomness,
    Write,
}

/// Writes one Welcome frame after the prefix and peer checks pass.
pub fn serve_windows_attach_session_with_reader<S: DeadlineStream>(
    stream: &mut S,
    reader: &impl WindowsAttachPeerReader,
    desktop_version: &str,
    deadline: Instant,
) -> Result<(), WindowsAttachSessionError> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)
        .map_err(|_| WindowsAttachSessionError::Read)?;
    verify_windows_attach_peer_with_reader(reader)
        .map_err(WindowsAttachSessionError::PeerRejected)?;

    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(WindowsAttachSessionError::MalformedFrame);
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)
        .map_err(|_| WindowsAttachSessionError::Read)?;
    let message = decode_frame::<FirstMessage>(&frame)
        .map_err(|_| WindowsAttachSessionError::MalformedFrame)?
        .ok_or(WindowsAttachSessionError::MalformedFrame)?
        .0;
    let selected = negotiate_first(message, VersionRange { min: 1, max: 1 })
        .map_err(|_| WindowsAttachSessionError::MalformedFrame)?;

    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| WindowsAttachSessionError::Randomness)?;
    let server_nonce: String = random[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let approval_challenge: String = random[16..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let response = welcome(selected, desktop_version, server_nonce, approval_challenge);
    let response =
        encode_frame(&response).map_err(|_| WindowsAttachSessionError::MalformedFrame)?;
    write_all_before(stream, &response, deadline).map_err(|_| WindowsAttachSessionError::Write)
}

#[cfg(target_os = "windows")]
/// Serves a connected native Windows attach stream.
pub fn serve_windows_attach_session(
    mut stream: super::WindowsAttachStream,
    desktop_version: &str,
    deadline: Instant,
) -> Result<(), WindowsAttachSessionError> {
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};

    use super::NativeWindowsAttachPeerReader;

    let handle = stream.as_raw_handle();
    let handle = unsafe { BorrowedHandle::borrow_raw(handle) };
    let reader = NativeWindowsAttachPeerReader::new(handle);
    serve_windows_attach_session_with_reader(&mut stream, &reader, desktop_version, deadline)
}
