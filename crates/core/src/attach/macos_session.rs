//! macOS attach session negotiation.

use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use super::desktop_service_message::CompanionProvenance;
use super::live_connections::LiveConnectionRegistry;
use super::thread_service::ThreadListService;
use super::{
    admit_approval_presenter_over_stream_with_frame, admit_desktop_client_over_stream_with_frame,
    name_macos_attach_connection_route, name_macos_desktop_attach_connection_route,
    read_exact_before, AdmittedDesktopClient, Approval, ApprovalCoordinator, ApprovalWaiter,
    AttachSessionError, DeadlineStream, DesktopClientAdmissionError, MacosAttachConnectionRoute,
    MacosAttachRouteReader, ProtocolError, MAX_FRAME_LENGTH,
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
#[allow(clippy::too_many_arguments)]
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
            let admitted = admit_approval_presenter_over_stream_with_frame(
                &mut stream,
                &frame,
                desktop_version,
                deadline,
            )
            .map_err(MacosAttachSessionError::DesktopClientAdmission)?;
            let connection = ApprovalPresenterConnection::new(stream, admitted.capability);
            let Some(session) = serve_approval_presenter(coordinator.clone(), connection) else {
                if let Some(line) = coordinator.presenter_refusal_diagnostic() {
                    crate::runtime_eprintln!("{line}");
                }
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
    // The deadline bounds admission only. The request loop has no session lifetime bound.
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
