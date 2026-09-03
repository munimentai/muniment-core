//! macOS attach session negotiation.

use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use super::desktop_service_message::CompanionProvenance;
use super::live_connections::LiveConnectionRegistry;
use super::thread_service::ThreadListService;
use super::{
    admit_desktop_client_over_stream_with_frame, decode_frame, encode_frame,
    name_macos_attach_connection_route, name_macos_desktop_attach_connection_route,
    negotiate_first, read_exact_before, welcome, write_all_before, AdmittedDesktopClient, Approval,
    ApprovalCoordinator, ApprovalWaiter, AttachSessionError, DeadlineStream,
    DesktopClientAdmissionError, FirstMessage, MacosAttachConnectionRoute, MacosAttachRouteReader,
    ProtocolError, VersionRange, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachSessionError {
    Read,
    ApprovalPresenterUnavailable,
    DesktopClientAdmission(DesktopClientAdmissionError),
    DesktopClientSession(AttachSessionError),
    CompanionSession(AttachSessionError),
    MalformedFrame,
    Randomness,
    Write,
}

/// The route selected for an admitted macOS attach session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacosAttachSessionOutcome {
    ApprovalPresenter,
    Companion,
    DesktopClient(AdmittedDesktopClient),
}

#[cfg(target_os = "macos")]
/// Serves every macOS route with the state shared by one runtime activation.
pub fn serve_macos_attach_session_with_state<H, W>(
    stream: UnixStream,
    expected_desktop_executable: &Path,
    desktop_version: &str,
    timeout: Duration,
    service: &mut H,
    approval: Option<Approval>,
    coordinator: ApprovalCoordinator,
    approvals: W,
    registry: &LiveConnectionRegistry,
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    H: ThreadListService,
    W: ApprovalWaiter,
{
    let route = {
        let route_reader = super::NativeMacosAttachRouteReader::new(&stream);
        name_macos_attach_connection_route(&route_reader, expected_desktop_executable)
    };
    serve_macos_attach_route_with_state(
        stream,
        route,
        unsafe { libc::geteuid() },
        desktop_version,
        timeout,
        service,
        approval,
        coordinator,
        approvals,
        registry,
        |_| {},
    )
}

#[cfg(unix)]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn serve_macos_attach_session_with_reader_and_state<H, W>(
    stream: UnixStream,
    route_reader: &impl MacosAttachRouteReader,
    peer_uid: u32,
    expected_desktop_executable: &Path,
    desktop_version: &str,
    timeout: Duration,
    service: &mut H,
    approval: Option<Approval>,
    coordinator: ApprovalCoordinator,
    approvals: W,
    registry: &LiveConnectionRegistry,
    pairing_identity_observer: impl FnOnce(&str),
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    H: ThreadListService,
    W: ApprovalWaiter,
{
    let route = name_macos_attach_connection_route(route_reader, expected_desktop_executable);
    serve_macos_attach_route_with_state(
        stream,
        route,
        peer_uid,
        desktop_version,
        timeout,
        service,
        approval,
        coordinator,
        approvals,
        registry,
        pairing_identity_observer,
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_macos_attach_route_with_state<H, W>(
    mut stream: UnixStream,
    route: MacosAttachConnectionRoute,
    peer_uid: u32,
    desktop_version: &str,
    timeout: Duration,
    service: &mut H,
    approval: Option<Approval>,
    coordinator: ApprovalCoordinator,
    approvals: W,
    registry: &LiveConnectionRegistry,
    pairing_identity_observer: impl FnOnce(&str),
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    H: ThreadListService,
    W: ApprovalWaiter,
{
    use super::companion_pairing::{
        serve_pairing_exchange, AuthorizationSessionDependencies, NoMigration, PairingPeer,
        PairingSession, SessionClock, SessionTokens,
    };
    use super::{serve_approval_presenter, ApprovalPresenterConnection};

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(MacosAttachSessionError::Read)?;
    let mut prefix = [0_u8; 4];
    read_exact_before(&mut stream, &mut prefix, deadline)
        .map_err(|_| MacosAttachSessionError::Read)?;
    let frame = read_first_frame(&mut stream, prefix, deadline)?;
    let route = match route {
        MacosAttachConnectionRoute::DesktopClient { peer_pid } => {
            name_macos_desktop_attach_connection_route(peer_pid, &frame)
        }
        route => route,
    };

    match route {
        MacosAttachConnectionRoute::ApprovalPresenter => {
            let admitted = admit_desktop_client_over_stream_with_frame(
                &mut stream,
                &frame,
                desktop_version,
                None,
                deadline,
            )
            .map_err(MacosAttachSessionError::DesktopClientAdmission)?;
            let connection = ApprovalPresenterConnection::new(stream, admitted.capability);
            let Some(session) = serve_approval_presenter(coordinator, connection) else {
                return Err(MacosAttachSessionError::ApprovalPresenterUnavailable);
            };
            session.wait_until_closed();
            Ok(MacosAttachSessionOutcome::ApprovalPresenter)
        }
        MacosAttachConnectionRoute::DesktopClient { peer_pid } => serve_desktop_client(
            &mut stream,
            &frame,
            (peer_uid, peer_pid),
            desktop_version,
            deadline,
            approval.as_ref(),
            service,
        ),
        MacosAttachConnectionRoute::Companion { peer_pid } => {
            let mut random = |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| ());
            let companion_identity = format!("{peer_uid}:{peer_pid}");
            pairing_identity_observer(&companion_identity);
            serve_pairing_exchange(
                &mut stream,
                PairingSession {
                    peer: PairingPeer {
                        companion_identity,
                        peer_uid,
                        peer_pid,
                    },
                    first_frame: Some(&frame),
                    registry,
                    handoff_nonce: None,
                },
                desktop_version,
                deadline.saturating_duration_since(Instant::now()),
                AuthorizationSessionDependencies {
                    fill_random: &mut random,
                    clock: SessionClock(Instant::now()),
                    tokens: SessionTokens,
                    approvals,
                },
                service,
                NoMigration,
            )
            .map_err(MacosAttachSessionError::CompanionSession)?;
            Ok(MacosAttachSessionOutcome::Companion)
        }
    }
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
    serve_macos_attach_route(
        &mut stream,
        route,
        unsafe { libc::geteuid() },
        desktop_version,
        deadline,
        service,
    )
}

/// Serves a verified macOS attach stream through an injected route boundary.
pub fn serve_macos_attach_session_with_reader<S, H>(
    stream: &mut S,
    route_reader: &impl MacosAttachRouteReader,
    peer_uid: u32,
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
    serve_macos_attach_route(stream, route, peer_uid, desktop_version, deadline, service)
}

#[cfg(unix)]
fn serve_macos_attach_route<S, H>(
    stream: &mut S,
    route: MacosAttachConnectionRoute,
    peer_uid: u32,
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
            let frame = read_first_frame(stream, prefix, deadline)?;
            match name_macos_desktop_attach_connection_route(peer_pid, &frame) {
                MacosAttachConnectionRoute::ApprovalPresenter => {
                    super::desktop_admission::write_protocol_error(
                        stream,
                        ProtocolError::unauthorized(),
                        deadline,
                    );
                    Err(MacosAttachSessionError::ApprovalPresenterUnavailable)
                }
                MacosAttachConnectionRoute::DesktopClient { peer_pid } => serve_desktop_client(
                    stream,
                    &frame,
                    (peer_uid, peer_pid),
                    desktop_version,
                    deadline,
                    None,
                    service,
                ),
                MacosAttachConnectionRoute::Companion { .. } => {
                    serve_companion_exchange_with_frame(stream, &frame, desktop_version, deadline)?;
                    Ok(MacosAttachSessionOutcome::Companion)
                }
            }
        }
        MacosAttachConnectionRoute::ApprovalPresenter => {
            super::desktop_admission::write_protocol_error(
                stream,
                ProtocolError::unauthorized(),
                deadline,
            );
            Err(MacosAttachSessionError::ApprovalPresenterUnavailable)
        }
        MacosAttachConnectionRoute::Companion { .. } => {
            serve_companion_exchange(stream, prefix, desktop_version, deadline)?;
            Ok(MacosAttachSessionOutcome::Companion)
        }
    }
}

fn read_first_frame<S: DeadlineStream>(
    stream: &mut S,
    prefix: [u8; 4],
    deadline: Instant,
) -> Result<Vec<u8>, MacosAttachSessionError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        super::desktop_admission::write_protocol_error(
            stream,
            ProtocolError::payload_too_large(),
            deadline,
        );
        return Err(MacosAttachSessionError::DesktopClientAdmission(
            DesktopClientAdmissionError::PayloadTooLarge,
        ));
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline).map_err(|error| {
        MacosAttachSessionError::DesktopClientAdmission(if super::deadline_io::is_timeout(&error) {
            DesktopClientAdmissionError::Timeout
        } else {
            DesktopClientAdmissionError::Closed
        })
    })?;
    Ok(frame)
}

fn serve_desktop_client<S, H>(
    stream: &mut S,
    frame: &[u8],
    peer: (u32, u32),
    desktop_version: &str,
    deadline: Instant,
    approval: Option<&Approval>,
    service: &mut H,
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    S: DeadlineStream,
    H: ThreadListService,
{
    let (peer_uid, peer_pid) = peer;
    let admitted = admit_desktop_client_over_stream_with_frame(
        stream,
        frame,
        desktop_version,
        approval,
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
            peer_uid,
            peer_pid,
        },
        service,
    )
    .map_err(MacosAttachSessionError::DesktopClientSession)?;
    Ok(MacosAttachSessionOutcome::DesktopClient(admitted))
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
    serve_companion_exchange_with_frame(stream, &frame, desktop_version, deadline)
}

fn serve_companion_exchange_with_frame<S: DeadlineStream>(
    stream: &mut S,
    frame: &[u8],
    desktop_version: &str,
    deadline: Instant,
) -> Result<(), MacosAttachSessionError> {
    let message = decode_frame::<FirstMessage>(frame)
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
