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
    io_bound: std::cell::Cell<Option<(Instant, Duration)>>,
    #[cfg(test)]
    records: std::cell::RefCell<Vec<serde_json::Value>>,
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
        match &result {
            Ok(0) if !bytes.is_empty() => self
                .diagnostic
                .io_failed("write", &std::io::ErrorKind::WriteZero.into()),
            Err(error) => self.diagnostic.io_failed("write", error),
            _ => {}
        }
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream
            .flush()
            .inspect_err(|error| self.diagnostic.io_failed("flush", error))
    }
}

impl<S: DeadlineStream + ?Sized> DeadlineStream for AdmissionStream<'_, S> {
    fn wait_until_readable(&self, deadline: Instant) -> super::ReadableWait {
        self.stream.wait_until_readable(deadline)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.diagnostic.set_timeout(
            "set_read_timeout",
            timeout,
            self.stream.set_read_timeout(timeout),
        )
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.diagnostic.set_timeout(
            "set_write_timeout",
            timeout,
            self.stream.set_write_timeout(timeout),
        )
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
            io_bound: Default::default(),
            #[cfg(test)]
            records: Default::default(),
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

    fn set_timeout(
        &self,
        operation: &str,
        timeout: Option<Duration>,
        result: std::io::Result<()>,
    ) -> std::io::Result<()> {
        if self.io_failure.borrow().is_none() {
            self.io_bound
                .set(timeout.map(|bound| (Instant::now(), bound)));
        }
        match result {
            // macOS rejects the timeout on a closed socket. Let I/O report the closure.
            Err(error)
                if error.kind() == std::io::ErrorKind::InvalidInput
                    && timeout != Some(Duration::ZERO) =>
            {
                Ok(())
            }
            Err(error) => {
                self.io_failed(operation, &error);
                Err(error)
            }
            Ok(()) => Ok(()),
        }
    }

    fn io_failed(&self, operation: &str, error: &std::io::Error) {
        if error.kind() != std::io::ErrorKind::Interrupted {
            let copy = error
                .raw_os_error()
                .map_or_else(|| error.kind().into(), std::io::Error::from_raw_os_error);
            self.io_failure
                .borrow_mut()
                .get_or_insert_with(|| (operation.to_owned(), copy));
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
            "io_elapsed_ms": self.io_bound.get().map(|(started, _)| now.saturating_duration_since(started).as_millis()),
            "io_bound_ms": self.io_bound.get().map(|(_, bound)| bound.as_millis()),
            "elapsed_ms": now.duration_since(self.started).as_millis(),
            "route_elapsed_ms": self.admission_started.duration_since(self.started).as_millis(),
            "admission_elapsed_ms": now.duration_since(self.admission_started).as_millis(),
            "admission_bound_ms": self.bound.as_millis(),
        })
    }

    fn record(&self, phase: &str, error: Option<&str>, closed_by: &str) {
        self.record_envelope(self.envelope(phase, error, closed_by));
    }

    fn record_envelope(&self, envelope: serde_json::Value) {
        crate::runtime_eprintln!("muniment-runtime: {envelope}");
        #[cfg(test)]
        self.records.borrow_mut().push(envelope);
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
    let mut diagnostic = {
        let route_reader = super::NativeMacosAttachRouteReader::new(&stream);
        AdmissionDiagnostic::route(&route_reader, expected_desktop_executable, timeout)
    };
    serve_macos_attach_route_with_state(
        stream,
        &mut diagnostic,
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
    let mut diagnostic =
        AdmissionDiagnostic::route(route_reader, expected_desktop_executable, timeout);
    serve_macos_attach_route_with_state(
        stream,
        &mut diagnostic,
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
    diagnostic: &mut AdmissionDiagnostic,
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
    use super::{
        approval_waiter_with_claims, serve_approval_presenter, ApprovalPresenterConnection,
    };

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
            diagnostic.record("presenter-handshake", None, "none");
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
            let mut approvals = approvals;
            let approvals = approval_waiter_with_claims(
                |challenge: &super::PairingChallenge,
                 kind: &str,
                 version: &str,
                 remaining: Duration| {
                    let started = Instant::now();
                    let decision = approvals.wait(challenge, kind, version, remaining);
                    // A zero bound drains repeat actions after approval. It is not a pairing attempt.
                    if !remaining.is_zero()
                        && !matches!(decision, Some(super::ApprovalDecision::Approve(_)))
                    {
                        let error = if decision.is_none() || started.elapsed() >= remaining {
                            "PairingTimeout"
                        } else {
                            "PairingDenied"
                        };
                        let mut envelope =
                            diagnostic.envelope("companion-pairing", Some(error), "runtime");
                        envelope["pairing_elapsed_ms"] =
                            serde_json::json!(started.elapsed().as_millis());
                        envelope["pairing_bound_ms"] = serde_json::json!(remaining.as_millis());
                        diagnostic.record_envelope(envelope);
                    }
                    decision
                },
            );
            serve_pairing_exchange(
                &mut diagnostic.stream(&mut stream),
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
            .map_err(MacosAttachSessionError::CompanionSession)
            .inspect_err(|error| diagnostic.failure("companion-exchange", error))?;
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

    fn hello(kind: &str) -> Vec<u8> {
        super::super::encode_frame(&serde_json::json!({
            "protocol": "muniment.attach/1", "client": {"kind": kind, "version": "1.0.0"},
            "supported": {"min": 1, "max": 1}, "client_nonce": "nonce",
            "authorized_client_id": "018f0000-0000-7000-8000-000000000099",
        }))
        .unwrap()
    }

    #[derive(Default)]
    struct Service(usize);
    impl ThreadListService for Service {
        fn list_threads(
            &mut self,
            _: &str,
            _: super::super::thread_service::ThreadListRequest,
        ) -> Result<super::super::thread_service::ThreadListPage, ProtocolError> {
            self.0 += 1;
            Ok(super::super::thread_service::ThreadListPage {
                threads: vec![],
                next_cursor: None,
            })
        }
    }

    #[test]
    fn admitted_desktop_continues_after_an_interrupted_partial_request() {
        use std::io::{Read, Write};
        struct InterruptedRequest {
            input: std::io::Cursor<Vec<u8>>,
            output: Vec<u8>,
            interrupt_at: usize,
            interrupted: bool,
        }
        impl Read for InterruptedRequest {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                let position = self.input.position() as usize;
                if position == self.interrupt_at && !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let count = if self.interrupted {
                    bytes.len()
                } else {
                    bytes.len().min(self.interrupt_at - position)
                };
                self.input.read(&mut bytes[..count])
            }
        }
        impl Write for InterruptedRequest {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.output.write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl DeadlineStream for InterruptedRequest {
            fn wait_until_readable(&self, _: Instant) -> super::super::ReadableWait {
                if self.input.position() == self.input.get_ref().len() as u64 {
                    super::super::ReadableWait::Closed
                } else {
                    super::super::ReadableWait::Ready
                }
            }
            fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
                Ok(())
            }
            fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
                Ok(())
            }
        }
        for interrupt_at in [2, 6] {
            let mut stream = InterruptedRequest {
                input: std::io::Cursor::new(vec![]),
                output: vec![],
                interrupt_at,
                interrupted: false,
            };
            let admitted = admit_desktop_client_over_stream_with_frame(
                &mut stream,
                &hello("desktop-client"),
                "1.0.0",
                None,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            let request = super::super::encode_frame(&serde_json::json!({
                "protocol": "muniment.attach/1", "request_id": "018f0000-0000-7000-8000-000000000201",
                "operation": "thread.list", "capability": admitted.capability, "body": {"limit": 20},
            })).unwrap();
            stream.input = std::io::Cursor::new([request.clone(), request].concat());
            stream.output.clear();
            let mut service = Service::default();
            assert!(matches!(
                serve_desktop_client(&mut stream, admitted, (501, 42), &mut service),
                Ok(MacosAttachSessionOutcome::DesktopClient(_))
            ));
            assert!(stream.interrupted);
            assert_eq!(service.0, 2);
            let mut responses = stream.output.as_slice();
            for _ in 0..2 {
                let (response, consumed) =
                    super::super::decode_frame::<serde_json::Value>(responses)
                        .unwrap()
                        .unwrap();
                assert_eq!(response["ok"], true);
                responses = &responses[consumed..];
            }
            assert!(responses.is_empty());
        }
    }

    #[test]
    fn rejected_code_check_reports_companion_peer_closure_and_pairing_timeout() {
        use std::io::Write;
        for kind in ["desktop-client", "desktop"] {
            for peer_closed in [false, true] {
                let (mut peer, server) = UnixStream::pair().unwrap();
                peer.write_all(&hello(kind)).unwrap();
                let _peer = (!peer_closed).then_some(peer);
                let mut diagnostic = AdmissionDiagnostic::route(
                    &Reader(false),
                    &std::env::current_exe().unwrap(),
                    Duration::from_secs(1),
                );
                let outcome = serve_macos_attach_route_with_state(
                    server,
                    &mut diagnostic,
                    501,
                    "1.0.0",
                    &mut Service::default(),
                    None,
                    ApprovalCoordinator::default(),
                    |_: &super::super::PairingChallenge, _: Duration| None,
                    &LiveConnectionRegistry::default(),
                    |_| {},
                );
                let records = diagnostic.records.borrow();
                let envelope = records.last().unwrap();
                assert_eq!(envelope["route"], "Companion { peer_pid: 42 }");
                assert_eq!(envelope["code_check"]["sec_code_check_validity"], -67030);
                assert_eq!(envelope["admission_bound_ms"], 1000);
                assert!(envelope["elapsed_ms"].is_number());
                assert!(envelope["route_elapsed_ms"].is_number());
                assert!(envelope["admission_elapsed_ms"].is_number());
                if peer_closed {
                    assert_eq!(
                        outcome,
                        Err(MacosAttachSessionError::CompanionSession(
                            AttachSessionError::Closed
                        ))
                    );
                    assert_eq!(envelope["phase"], "companion-exchange");
                    assert_eq!(envelope["error"], "CompanionSession(Closed)");
                    assert_eq!(envelope["closed_by"], "peer_or_transport");
                    assert_eq!(envelope["io_error"]["operation"], "write");
                    assert_eq!(envelope["io_error"]["kind"], "BrokenPipe");
                } else {
                    assert_eq!(outcome, Ok(MacosAttachSessionOutcome::Companion));
                    assert_eq!(envelope["phase"], "companion-pairing");
                    assert_eq!(envelope["error"], "PairingTimeout");
                    assert_eq!(envelope["closed_by"], "runtime");
                    assert!(envelope["pairing_elapsed_ms"].is_number());
                    assert!(envelope["pairing_bound_ms"].as_u64().unwrap() > 0);
                    assert!(
                        envelope["pairing_bound_ms"].as_u64().unwrap()
                            <= super::super::CHALLENGE_LIFETIME.as_millis() as u64
                    );
                }
            }
        }
    }

    #[test]
    fn rejected_code_check_reports_a_pairing_write_timeout() {
        use std::io::Write;
        let (mut peer, mut server) = UnixStream::pair().unwrap();
        peer.write_all(&hello("desktop-client")).unwrap();
        server.set_nonblocking(true).unwrap();
        loop {
            match server.write(&[0; 8192]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        server.set_nonblocking(false).unwrap();
        let mut diagnostic = AdmissionDiagnostic::route(
            &Reader(false),
            &std::env::current_exe().unwrap(),
            Duration::from_millis(20),
        );
        let outcome = serve_macos_attach_route_with_state(
            server,
            &mut diagnostic,
            501,
            "1.0.0",
            &mut Service::default(),
            None,
            ApprovalCoordinator::default(),
            |_: &super::super::PairingChallenge, _: Duration| {
                panic!("the welcome must time out before approval")
            },
            &LiveConnectionRegistry::default(),
            |_| {},
        );
        assert_eq!(
            outcome,
            Err(MacosAttachSessionError::CompanionSession(
                AttachSessionError::Timeout
            ))
        );
        let records = diagnostic.records.borrow();
        let envelope = records.last().unwrap();
        assert_eq!(envelope["route"], "Companion { peer_pid: 42 }");
        assert_eq!(envelope["code_check"]["sec_code_check_validity"], -67030);
        assert_eq!(envelope["phase"], "companion-exchange");
        assert_eq!(envelope["error"], "CompanionSession(Timeout)");
        assert_eq!(envelope["closed_by"], "runtime");
        assert_eq!(envelope["io_error"]["operation"], "write");
        assert_eq!(envelope["admission_bound_ms"], 20);
        assert!(envelope["admission_elapsed_ms"].as_u64().unwrap() >= 20);
        assert!(
            envelope["io_elapsed_ms"].as_u64().unwrap()
                >= envelope["io_bound_ms"].as_u64().unwrap()
        );
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
