//! macOS attach session negotiation.

use std::path::Path;
use std::time::Instant;

use super::desktop_service_message::CompanionProvenance;
use super::thread_service::ThreadListService;
use super::{
    admit_desktop_client_over_stream_with_prefix, decode_frame, encode_frame,
    name_macos_attach_connection_route, negotiate_first, read_exact_before, welcome,
    write_all_before, AdmittedDesktopClient, AttachSessionError, DeadlineStream,
    DesktopClientAdmissionError, FirstMessage, MacosAttachConnectionRoute, MacosAttachRouteReader,
    VersionRange, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachSessionError {
    Read,
    DesktopClientAdmission(DesktopClientAdmissionError),
    DesktopClientSession(AttachSessionError),
    MalformedFrame,
    Randomness,
    Write,
}

/// The route selected for an admitted macOS attach session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacosAttachSessionOutcome {
    Companion,
    DesktopClient(AdmittedDesktopClient),
}

#[cfg(target_os = "macos")]
/// Serves a verified native macOS attach stream.
pub fn serve_macos_attach_session<H: ThreadListService>(
    mut stream: std::os::unix::net::UnixStream,
    expected_desktop_executable: &Path,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError> {
    let route = {
        let route_reader = super::NativeMacosAttachRouteReader::new(&stream);
        name_macos_attach_connection_route(&route_reader, expected_desktop_executable)
    };
    serve_macos_attach_route(&mut stream, route, desktop_version, deadline, service)
}

/// Serves a verified macOS attach stream through an injected route boundary.
pub fn serve_macos_attach_session_with_reader<S, H>(
    stream: &mut S,
    route_reader: &impl MacosAttachRouteReader,
    expected_desktop_executable: &Path,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    S: DeadlineStream,
    H: ThreadListService,
{
    let route = name_macos_attach_connection_route(route_reader, expected_desktop_executable);
    serve_macos_attach_route(stream, route, desktop_version, deadline, service)
}

#[cfg(unix)]
fn serve_macos_attach_route<S, H>(
    stream: &mut S,
    route: MacosAttachConnectionRoute,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    S: DeadlineStream,
    H: ThreadListService,
{
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline).map_err(|_| MacosAttachSessionError::Read)?;

    match route {
        MacosAttachConnectionRoute::DesktopClient { peer_pid } => {
            let admitted = admit_desktop_client_over_stream_with_prefix(
                stream,
                prefix,
                desktop_version,
                None,
                deadline,
            )
            .map_err(MacosAttachSessionError::DesktopClientAdmission)?;
            service.bind_authorized_client(&admitted.client_identity);
            super::desktop_session::serve_desktop_client_requests(
                stream,
                &admitted.capability,
                &admitted.workspace,
                CompanionProvenance {
                    profile: "desktop-owner".into(),
                    companion_kind: admitted.companion_kind.clone(),
                    companion_version: admitted.companion_version.clone(),
                    peer_uid: 0,
                    peer_pid,
                },
                service,
            )
            .map_err(MacosAttachSessionError::DesktopClientSession)?;
            Ok(MacosAttachSessionOutcome::DesktopClient(admitted))
        }
        MacosAttachConnectionRoute::Companion => {
            serve_companion_exchange(stream, prefix, desktop_version, deadline)?;
            Ok(MacosAttachSessionOutcome::Companion)
        }
    }
}

fn serve_companion_exchange<S: DeadlineStream>(
    stream: &mut S,
    prefix: [u8; 4],
    desktop_version: &str,
    deadline: Instant,
) -> Result<(), MacosAttachSessionError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(MacosAttachSessionError::MalformedFrame);
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)
        .map_err(|_| MacosAttachSessionError::Read)?;
    let message = decode_frame::<FirstMessage>(&frame)
        .map_err(|_| MacosAttachSessionError::MalformedFrame)?
        .ok_or(MacosAttachSessionError::MalformedFrame)?
        .0;
    let selected = negotiate_first(message, VersionRange { min: 1, max: 1 })
        .map_err(|_| MacosAttachSessionError::MalformedFrame)?;

    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| MacosAttachSessionError::Randomness)?;
    let server_nonce: String = random[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let approval_challenge: String = random[16..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let response = welcome(selected, desktop_version, server_nonce, approval_challenge);
    let response = encode_frame(&response).map_err(|_| MacosAttachSessionError::MalformedFrame)?;
    write_all_before(stream, &response, deadline).map_err(|_| MacosAttachSessionError::Write)
}
