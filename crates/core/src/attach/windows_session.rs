//! Windows attach session negotiation.

use std::path::Path;
use std::time::Instant;

use super::{
    admit_desktop_client_over_stream_with_prefix, decode_frame, encode_frame,
    name_windows_attach_connection_route, negotiate_first, read_exact_before,
    verify_windows_attach_peer_with_reader, welcome, write_all_before, AdmittedDesktopClient,
    DeadlineStream, DesktopClientAdmissionError, FirstMessage, VersionRange,
    WindowsAttachConnectionRoute, WindowsAttachPeerReader, WindowsAttachRouteReader,
    WindowsPeerError, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachSessionError {
    Read,
    PeerRejected(WindowsPeerError),
    DesktopClientAdmission(DesktopClientAdmissionError),
    MalformedFrame,
    Randomness,
    Write,
}

/// The route selected for an admitted Windows attach session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsAttachSessionOutcome {
    Companion,
    DesktopClient(AdmittedDesktopClient),
}

/// Serves the exchange for the selected route after the prefix and peer checks pass.
pub fn serve_windows_attach_session_with_reader<S: DeadlineStream>(
    stream: &mut S,
    peer_reader: &impl WindowsAttachPeerReader,
    route_reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: Option<&Path>,
    desktop_version: &str,
    deadline: Instant,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)
        .map_err(|_| WindowsAttachSessionError::Read)?;
    verify_windows_attach_peer_with_reader(peer_reader)
        .map_err(WindowsAttachSessionError::PeerRejected)?;
    let route = expected_desktop_executable
        .map_or(WindowsAttachConnectionRoute::Companion, |path| {
            name_windows_attach_connection_route(route_reader, path)
        });

    if route == WindowsAttachConnectionRoute::DesktopClient {
        return admit_desktop_client_over_stream_with_prefix(
            stream,
            prefix,
            desktop_version,
            None,
            deadline,
        )
        .map(WindowsAttachSessionOutcome::DesktopClient)
        .map_err(WindowsAttachSessionError::DesktopClientAdmission);
    }

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
    write_all_before(stream, &response, deadline).map_err(|_| WindowsAttachSessionError::Write)?;
    Ok(WindowsAttachSessionOutcome::Companion)
}

#[cfg(target_os = "windows")]
/// Serves a connected native Windows attach stream.
pub fn serve_windows_attach_session(
    mut stream: super::WindowsAttachStream,
    desktop_version: &str,
    deadline: Instant,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError> {
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};

    use super::{NativeWindowsAttachPeerReader, NativeWindowsAttachRouteReader};
    use crate::windows_payload::resolve_live_windows_desktop_executable;

    let handle = stream.as_raw_handle();
    let peer_reader =
        NativeWindowsAttachPeerReader::new(unsafe { BorrowedHandle::borrow_raw(handle) });
    let route_reader =
        NativeWindowsAttachRouteReader::new(unsafe { BorrowedHandle::borrow_raw(handle) });
    let expected_desktop_executable = resolve_live_windows_desktop_executable().ok().flatten();
    serve_windows_attach_session_with_reader(
        &mut stream,
        &peer_reader,
        &route_reader,
        expected_desktop_executable.as_deref(),
        desktop_version,
        deadline,
    )
}
