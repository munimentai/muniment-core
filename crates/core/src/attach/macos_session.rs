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

struct AdmissionDiagnostic {
    started: Instant,
    admission_started: Instant,
    route: MacosAttachConnectionRoute,
    peer_pid: u32,
    code_check: serde_json::Value,
    bound: Duration,
    io_failure: std::cell::RefCell<Option<(String, std::io::Error)>>,
}

struct AdmissionStream<'a, S: ?Sized> {
    stream: &'a mut S,
    diagnostic: &'a AdmissionDiagnostic,
}

impl<S: DeadlineStream + ?Sized> std::io::Read for AdmissionStream<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let result = self.stream.read(bytes);
        match &result {
            Ok(0) if !bytes.is_empty() => self
                .diagnostic
                .io_failed("read", &std::io::ErrorKind::UnexpectedEof.into()),
            Err(error) => self.diagnostic.io_failed("read", error),
            _ => {}
        }
        result
    }
}

impl<S: DeadlineStream + ?Sized> std::io::Write for AdmissionStream<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = self.stream.write(bytes);
        if let Err(error) = &result {
            self.diagnostic.io_failed("write", error);
        }
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl<S: DeadlineStream + ?Sized> DeadlineStream for AdmissionStream<'_, S> {
    fn wait_until_readable(&self, deadline: Instant) -> super::ReadableWait {
        self.stream.wait_until_readable(deadline)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }
}

impl AdmissionDiagnostic {
    fn route(reader: &impl MacosAttachRouteReader, expected: &Path, bound: Duration) -> Self {
        let started = Instant::now();
        let route = name_macos_attach_connection_route(reader, expected);
        let peer_pid = match route {
            MacosAttachConnectionRoute::DesktopClient { peer_pid }
            | MacosAttachConnectionRoute::Companion { peer_pid } => peer_pid,
            MacosAttachConnectionRoute::ApprovalPresenter => 0,
        };
        Self {
            started,
            admission_started: Instant::now(),
            route,
            peer_pid,
            code_check: reader.code_check_diagnostic(),
            bound,
            io_failure: Default::default(),
        }
    }

    fn stream<'a, S: DeadlineStream + ?Sized>(
        &'a self,
        stream: &'a mut S,
    ) -> AdmissionStream<'a, S> {
        AdmissionStream {
            stream,
            diagnostic: self,
        }
    }

    fn io_failed(&self, operation: &str, error: &std::io::Error) {
        if error.kind() != std::io::ErrorKind::Interrupted {
            let copy = error
                .raw_os_error()
                .map_or_else(|| error.kind().into(), std::io::Error::from_raw_os_error);
            *self.io_failure.borrow_mut() = Some((operation.to_owned(), copy));
        }
    }

    fn envelope(&self, phase: &str, error: Option<&str>, closed_by: &str) -> serde_json::Value {
        let now = Instant::now();
        let failure = self.io_failure.borrow();
        let io_error = failure.as_ref().map(|(operation, error)| {
            serde_json::json!({
                "operation": operation,
                "kind": format!("{:?}", error.kind()),
                "os_error": error.raw_os_error(),
            })
        });
        let closed_by = failure
            .as_ref()
            .map_or(closed_by, |(_, error)| io_closed_by(error));
        serde_json::json!({
            "event": "macos_attach_admission",
            "observer": "runtime",
            "runtime_pid": std::process::id(),
            "peer_pid": self.peer_pid,
            "phase": phase,
            "route": format!("{:?}", self.route),
            "code_check": self.code_check,
            "closed_by": closed_by,
            "error": error,
            "io_error": io_error,
            "elapsed_ms": now.duration_since(self.started).as_millis(),
            "route_elapsed_ms": self.admission_started.duration_since(self.started).as_millis(),
            "admission_elapsed_ms": now.duration_since(self.admission_started).as_millis(),
            "admission_bound_ms": self.bound.as_millis(),
        })
    }

    fn record(&self, phase: &str, error: Option<&str>, closed_by: &str) {
        crate::runtime_eprintln!(
            "muniment-runtime: {}",
            self.envelope(phase, error, closed_by)
        );
    }

    fn failure(&self, phase: &str, error: &MacosAttachSessionError) {
        let closed_by = match error {
            MacosAttachSessionError::DesktopClientAdmission(
                DesktopClientAdmissionError::Closed,
            ) => "peer_or_transport",
            _ => "runtime",
        };
        self.record(phase, Some(&format!("{error:?}")), closed_by);
    }
}

fn io_closed_by(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => "peer",
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset => "peer_or_transport",
        _ => "runtime",
    }
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
    let diagnostic = {
        let route_reader = super::NativeMacosAttachRouteReader::new(&stream);
        AdmissionDiagnostic::route(&route_reader, expected_desktop_executable, timeout)
    };
    serve_macos_attach_route_with_state(
        stream,
        diagnostic,
        unsafe { libc::geteuid() },
        desktop_version,
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
    let diagnostic = AdmissionDiagnostic::route(route_reader, expected_desktop_executable, timeout);
    serve_macos_attach_route_with_state(
        stream,
        diagnostic,
        peer_uid,
        desktop_version,
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
    mut diagnostic: AdmissionDiagnostic,
    peer_uid: u32,
    desktop_version: &str,
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

    let deadline = diagnostic
        .admission_started
        .checked_add(diagnostic.bound)
        .ok_or_else(|| {
            diagnostic.failure("deadline", &MacosAttachSessionError::Read);
            MacosAttachSessionError::Read
        })?;
    let mut prefix = [0_u8; 4];
    read_exact_before(&mut diagnostic.stream(&mut stream), &mut prefix, deadline).map_err(
        |error| {
            diagnostic.record(
                "hello-prefix",
                Some(&format!("{error:?}")),
                io_closed_by(&error),
            );
            MacosAttachSessionError::Read
        },
    )?;
    let frame = read_first_frame(&mut diagnostic.stream(&mut stream), prefix, deadline)
        .inspect_err(|error| {
            diagnostic.failure("hello-frame", error);
        })?;
    let route = match diagnostic.route {
        MacosAttachConnectionRoute::DesktopClient { peer_pid } => {
            name_macos_desktop_attach_connection_route(peer_pid, &frame)
        }
        route => route,
    };
    diagnostic.route = route;

    match route {
        MacosAttachConnectionRoute::ApprovalPresenter => {
            let admitted = admit_approval_presenter_over_stream_with_frame(
                &mut diagnostic.stream(&mut stream),
                &frame,
                desktop_version,
                deadline,
            )
            .map_err(MacosAttachSessionError::DesktopClientAdmission)
            .inspect_err(|error| diagnostic.failure("presenter-handshake", error))?;
            diagnostic.record("presenter-handshake", None, "none");
            let connection = ApprovalPresenterConnection::new(stream, admitted.capability);
            let Some(session) = serve_approval_presenter(coordinator.clone(), connection) else {
                if let Some(line) = coordinator.presenter_refusal_diagnostic() {
                    crate::runtime_eprintln!("{line}");
                }
                diagnostic.failure(
                    "presenter-claim",
                    &MacosAttachSessionError::ApprovalPresenterUnavailable,
                );
                return Err(MacosAttachSessionError::ApprovalPresenterUnavailable);
            };
            session.wait_until_closed();
            Ok(MacosAttachSessionOutcome::ApprovalPresenter)
        }
        MacosAttachConnectionRoute::DesktopClient { peer_pid } => {
            let admitted = admit_desktop_client_over_stream_with_frame(
                &mut diagnostic.stream(&mut stream),
                &frame,
                desktop_version,
                approval.as_ref(),
                deadline,
            )
            .map_err(MacosAttachSessionError::DesktopClientAdmission)
            .inspect_err(|error| diagnostic.failure("desktop-handshake", error))?;
            diagnostic.record("desktop-handshake", None, "none");
            serve_desktop_client(&mut stream, admitted, (peer_uid, peer_pid), service)
        }
        MacosAttachConnectionRoute::Companion { peer_pid } => {
            diagnostic.record("companion-route", None, "none");
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
    admitted: AdmittedDesktopClient,
    peer: (u32, u32),
    service: &mut H,
) -> Result<MacosAttachSessionOutcome, MacosAttachSessionError>
where
    S: DeadlineStream,
    H: ThreadListService,
{
    let (peer_uid, peer_pid) = peer;
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Reader(bool);
    impl MacosAttachRouteReader for Reader {
        fn peer_process(
            &self,
        ) -> Result<(u32, std::path::PathBuf), super::super::MacosPeerReadError> {
            Ok((42, std::env::current_exe().unwrap()))
        }
        fn peer_code_matches(&self, _: &Path) -> bool {
            self.0
        }
        fn code_check_diagnostic(&self) -> serde_json::Value {
            serde_json::json!({"matched": self.0, "sec_code_check_validity": if self.0 { 0 } else { -67030 }})
        }
    }

    #[test]
    fn admission_envelope_preserves_route_code_check_and_bounds() {
        for matched in [false, true] {
            let diagnostic = AdmissionDiagnostic::route(
                &Reader(matched),
                &std::env::current_exe().unwrap(),
                Duration::from_secs(5),
            );
            let envelope = diagnostic.envelope("desktop-handshake", Some("Timeout"), "runtime");
            assert_eq!(envelope["closed_by"], "runtime");
            assert_eq!(envelope["observer"], "runtime");
            assert_eq!(envelope["peer_pid"], 42);
            assert_eq!(envelope["code_check"]["matched"], matched);
            assert_eq!(
                envelope["code_check"]["sec_code_check_validity"],
                if matched { 0 } else { -67030 }
            );
            assert_eq!(
                envelope["route"],
                if matched {
                    "DesktopClient { peer_pid: 42 }"
                } else {
                    "Companion { peer_pid: 42 }"
                }
            );
            assert_eq!(envelope["admission_bound_ms"], 5000);
            for field in ["elapsed_ms", "route_elapsed_ms", "admission_elapsed_ms"] {
                assert!(envelope[field].is_number());
            }
        }
    }

    #[test]
    fn admission_envelope_distinguishes_peer_eof_from_a_local_timeout() {
        for eof in [false, true] {
            let diagnostic = AdmissionDiagnostic::route(
                &Reader(true),
                &std::env::current_exe().unwrap(),
                Duration::from_millis(5),
            );
            let (peer, mut server) = UnixStream::pair().unwrap();
            let _peer = (!eof).then_some(peer);
            let error = read_exact_before(
                &mut diagnostic.stream(&mut server),
                &mut [0],
                Instant::now() + diagnostic.bound,
            )
            .unwrap_err();
            let envelope =
                diagnostic.envelope("hello-prefix", Some(&format!("{error:?}")), "runtime");
            assert_eq!(envelope["closed_by"], if eof { "peer" } else { "runtime" });
            assert_eq!(envelope["io_error"]["operation"], "read");
            assert_eq!(envelope["io_error"]["kind"], format!("{:?}", error.kind()));
            assert_eq!(envelope["admission_bound_ms"], 5);
            if !eof {
                assert!(envelope["admission_elapsed_ms"].as_u64().unwrap() >= 5);
            }
        }
    }
}
