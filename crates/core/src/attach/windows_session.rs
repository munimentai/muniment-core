//! Windows attach session negotiation.

use std::path::Path;
use std::time::Instant;

use super::desktop_service_message::CompanionProvenance;
use super::live_connections::LiveConnectionRegistry;
use super::thread_service::ThreadListService;
use super::{
    admit_desktop_client_over_stream_with_frame, decode_frame, encode_frame,
    name_windows_attach_connection_route, name_windows_desktop_attach_connection_route,
    negotiate_first, read_exact_before, verify_windows_attach_peer_with_reader, welcome,
    write_all_before, AdmittedDesktopClient, AttachSessionError, DeadlineStream,
    DesktopClientAdmissionError, FirstMessage, ProtocolError, VersionRange,
    WindowsAttachConnectionRoute, WindowsAttachPeerReader, WindowsAttachRouteReader,
    WindowsPeerError, MAX_FRAME_LENGTH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachSessionError {
    Read,
    ApprovalPresenterUnavailable,
    PeerRejected(WindowsPeerError),
    DesktopClientAdmission(DesktopClientAdmissionError),
    DesktopClientSession(AttachSessionError),
    CompanionSession(AttachSessionError),
    ServiceOpen,
    MalformedFrame,
    Randomness,
    Write,
}

/// The route selected for an admitted Windows attach session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowsAttachSessionOutcome {
    ApprovalPresenter,
    Companion,
    DesktopClient(AdmittedDesktopClient),
}

fn admit_windows_attach_route<S: DeadlineStream>(
    stream: &mut S,
    peer_reader: &impl WindowsAttachPeerReader,
    route_reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: Option<&Path>,
    desktop_version: &str,
    deadline: Instant,
) -> Result<Option<(AdmittedDesktopClient, u32)>, WindowsAttachSessionError> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)
        .map_err(|_| WindowsAttachSessionError::Read)?;
    verify_windows_attach_peer_with_reader(peer_reader)
        .map_err(WindowsAttachSessionError::PeerRejected)?;
    let route = expected_desktop_executable
        .map_or(WindowsAttachConnectionRoute::Companion, |path| {
            name_windows_attach_connection_route(route_reader, path)
        });

    if let WindowsAttachConnectionRoute::DesktopClient { peer_pid } = route {
        let frame = read_desktop_first_frame(stream, prefix, deadline)?;
        return match name_windows_desktop_attach_connection_route(peer_pid, &frame) {
            WindowsAttachConnectionRoute::ApprovalPresenter => {
                super::desktop_admission::write_protocol_error(
                    stream,
                    ProtocolError::unauthorized(),
                    deadline,
                );
                Err(WindowsAttachSessionError::ApprovalPresenterUnavailable)
            }
            WindowsAttachConnectionRoute::DesktopClient { peer_pid } => {
                admit_desktop_client_over_stream_with_frame(
                    stream,
                    &frame,
                    desktop_version,
                    None,
                    deadline,
                )
                .map(|admitted| Some((admitted, peer_pid)))
                .map_err(WindowsAttachSessionError::DesktopClientAdmission)
            }
            WindowsAttachConnectionRoute::Companion => {
                serve_companion_exchange_with_frame(stream, &frame, desktop_version, deadline)?;
                Ok(None)
            }
        };
    }

    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(WindowsAttachSessionError::MalformedFrame);
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)
        .map_err(|_| WindowsAttachSessionError::Read)?;
    serve_companion_exchange_with_frame(stream, &frame, desktop_version, deadline)?;
    Ok(None)
}

fn read_desktop_first_frame<S: DeadlineStream>(
    stream: &mut S,
    prefix: [u8; 4],
    deadline: Instant,
) -> Result<Vec<u8>, WindowsAttachSessionError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        super::desktop_admission::write_protocol_error(
            stream,
            ProtocolError::payload_too_large(),
            deadline,
        );
        return Err(WindowsAttachSessionError::DesktopClientAdmission(
            DesktopClientAdmissionError::PayloadTooLarge,
        ));
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline).map_err(|error| {
        WindowsAttachSessionError::DesktopClientAdmission(
            if super::deadline_io::is_timeout(&error) {
                DesktopClientAdmissionError::Timeout
            } else {
                DesktopClientAdmissionError::Closed
            },
        )
    })?;
    Ok(frame)
}

fn serve_companion_exchange_with_frame<S: DeadlineStream>(
    stream: &mut S,
    frame: &[u8],
    desktop_version: &str,
    deadline: Instant,
) -> Result<(), WindowsAttachSessionError> {
    let message = decode_frame::<FirstMessage>(frame)
        .map_err(|_| WindowsAttachSessionError::MalformedFrame)?
        .filter(|(_, consumed)| *consumed == frame.len())
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

fn serve_admitted_desktop_client<S: DeadlineStream, H: ThreadListService>(
    stream: &mut S,
    admitted: AdmittedDesktopClient,
    peer_pid: u32,
    service: &mut H,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError> {
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
    .map_err(WindowsAttachSessionError::DesktopClientSession)?;
    Ok(WindowsAttachSessionOutcome::DesktopClient(admitted))
}

/// Serves the exchange for the selected route after the prefix and peer checks pass.
pub fn serve_windows_attach_session_with_reader<S, H>(
    stream: &mut S,
    peer_reader: &impl WindowsAttachPeerReader,
    route_reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: Option<&Path>,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError>
where
    S: DeadlineStream,
    H: ThreadListService,
{
    match admit_windows_attach_route(
        stream,
        peer_reader,
        route_reader,
        expected_desktop_executable,
        desktop_version,
        deadline,
    )? {
        Some((admitted, peer_pid)) => {
            serve_admitted_desktop_client(stream, admitted, peer_pid, service)
        }
        None => Ok(WindowsAttachSessionOutcome::Companion),
    }
}

/// Opens a service only after the Windows desktop client passes admission.
pub fn serve_windows_attach_session_with_reader_factory<S, H, F, E>(
    stream: &mut S,
    peer_reader: &impl WindowsAttachPeerReader,
    route_reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: Option<&Path>,
    desktop_version: &str,
    deadline: Instant,
    service_factory: F,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError>
where
    S: DeadlineStream,
    H: ThreadListService,
    F: FnOnce() -> Result<H, E>,
{
    let Some((admitted, peer_pid)) = admit_windows_attach_route(
        stream,
        peer_reader,
        route_reader,
        expected_desktop_executable,
        desktop_version,
        deadline,
    )?
    else {
        return Ok(WindowsAttachSessionOutcome::Companion);
    };
    let mut service = service_factory().map_err(|_| WindowsAttachSessionError::ServiceOpen)?;
    serve_admitted_desktop_client(stream, admitted, peer_pid, &mut service)
}

/// Serves every Windows route with the state shared by one runtime activation.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn serve_windows_attach_session_with_reader_and_state<S, H, W>(
    stream: &mut S,
    peer_reader: &impl WindowsAttachPeerReader,
    route_reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: Option<&Path>,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
    approval: Option<super::Approval>,
    coordinator: super::ApprovalCoordinator,
    approvals: W,
    registry: &LiveConnectionRegistry,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError>
where
    S: DeadlineStream + super::ApprovalPresenterStream,
    H: ThreadListService,
    W: super::ApprovalWaiter,
{
    use super::companion_pairing::{
        serve_pairing_exchange, AuthorizationSessionDependencies, NoMigration, PairingPeer,
        PairingSession, SessionClock, SessionTokens,
    };
    use super::{serve_approval_presenter, ApprovalPresenterConnection};

    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)
        .map_err(|_| WindowsAttachSessionError::Read)?;
    verify_windows_attach_peer_with_reader(peer_reader)
        .map_err(WindowsAttachSessionError::PeerRejected)?;
    let peer_pid = route_reader
        .peer_process()
        .map(|(peer_pid, _)| peer_pid)
        .unwrap_or(0);
    let initial_route = expected_desktop_executable
        .map(|path| name_windows_attach_connection_route(route_reader, path))
        .unwrap_or(WindowsAttachConnectionRoute::Companion);
    let frame = read_desktop_first_frame(stream, prefix, deadline)?;
    let route = match initial_route {
        WindowsAttachConnectionRoute::DesktopClient { peer_pid } => {
            name_windows_desktop_attach_connection_route(peer_pid, &frame)
        }
        route => route,
    };

    match route {
        WindowsAttachConnectionRoute::ApprovalPresenter => {
            let admitted = admit_desktop_client_over_stream_with_frame(
                stream,
                &frame,
                desktop_version,
                None,
                deadline,
            )
            .map_err(WindowsAttachSessionError::DesktopClientAdmission)?;
            let owned_stream = stream
                .try_clone_presenter_stream()
                .map_err(|_| WindowsAttachSessionError::ApprovalPresenterUnavailable)?;
            let connection = ApprovalPresenterConnection::new(owned_stream, admitted.capability);
            let Some(session) = serve_approval_presenter(coordinator, connection) else {
                return Err(WindowsAttachSessionError::ApprovalPresenterUnavailable);
            };
            session.wait_until_closed();
            Ok(WindowsAttachSessionOutcome::ApprovalPresenter)
        }
        WindowsAttachConnectionRoute::DesktopClient { peer_pid } => {
            let admitted = admit_desktop_client_over_stream_with_frame(
                stream,
                &frame,
                desktop_version,
                approval.as_ref(),
                deadline,
            )
            .map_err(WindowsAttachSessionError::DesktopClientAdmission)?;
            serve_admitted_desktop_client(stream, admitted, peer_pid, service)
        }
        WindowsAttachConnectionRoute::Companion => {
            let mut random = |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| ());
            serve_pairing_exchange(
                stream,
                PairingSession {
                    peer: PairingPeer {
                        companion_identity: format!("0:{peer_pid}"),
                        peer_uid: 0,
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
            .map_err(WindowsAttachSessionError::CompanionSession)?;
            Ok(WindowsAttachSessionOutcome::Companion)
        }
    }
}

#[cfg(target_os = "windows")]
/// Serves a connected native Windows stream with shared activation state.
#[allow(clippy::too_many_arguments)]
pub fn serve_windows_attach_session_with_state<H, W>(
    mut stream: super::WindowsAttachStream,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
    approval: Option<super::Approval>,
    coordinator: super::ApprovalCoordinator,
    approvals: W,
    registry: &LiveConnectionRegistry,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError>
where
    H: ThreadListService,
    W: super::ApprovalWaiter,
{
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};

    use super::{NativeWindowsAttachPeerReader, NativeWindowsAttachRouteReader};
    use crate::windows_payload::resolve_live_windows_desktop_executable;

    let handle = stream.as_raw_handle();
    let peer_reader =
        NativeWindowsAttachPeerReader::new(unsafe { BorrowedHandle::borrow_raw(handle) });
    let route_reader =
        NativeWindowsAttachRouteReader::new(unsafe { BorrowedHandle::borrow_raw(handle) });
    let expected_desktop_executable = resolve_live_windows_desktop_executable().ok().flatten();
    serve_windows_attach_session_with_reader_and_state(
        &mut stream,
        &peer_reader,
        &route_reader,
        expected_desktop_executable.as_deref(),
        desktop_version,
        deadline,
        service,
        approval,
        coordinator,
        approvals,
        registry,
    )
}

#[cfg(target_os = "windows")]
/// Serves a connected native Windows attach stream.
pub fn serve_windows_attach_session<H: ThreadListService>(
    mut stream: super::WindowsAttachStream,
    desktop_version: &str,
    deadline: Instant,
    service: &mut H,
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
        service,
    )
}

#[cfg(target_os = "windows")]
/// Serves a connected native Windows attach stream with a desktop service factory.
pub fn serve_windows_attach_session_with_factory<H, F, E>(
    mut stream: super::WindowsAttachStream,
    desktop_version: &str,
    deadline: Instant,
    service_factory: F,
) -> Result<WindowsAttachSessionOutcome, WindowsAttachSessionError>
where
    H: ThreadListService,
    F: FnOnce() -> Result<H, E>,
{
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};

    use super::{NativeWindowsAttachPeerReader, NativeWindowsAttachRouteReader};
    use crate::windows_payload::resolve_live_windows_desktop_executable;

    let handle = stream.as_raw_handle();
    let peer_reader =
        NativeWindowsAttachPeerReader::new(unsafe { BorrowedHandle::borrow_raw(handle) });
    let route_reader =
        NativeWindowsAttachRouteReader::new(unsafe { BorrowedHandle::borrow_raw(handle) });
    let expected_desktop_executable = resolve_live_windows_desktop_executable().ok().flatten();
    serve_windows_attach_session_with_reader_factory(
        &mut stream,
        &peer_reader,
        &route_reader,
        expected_desktop_executable.as_deref(),
        desktop_version,
        deadline,
        service_factory,
    )
}
