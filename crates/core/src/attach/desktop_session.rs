//! Platform-neutral desktop client request sessions.

use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use muniment_attach::{
    decode_frame, encode_frame, Envelope, ErrorEnvelope, Event, Failure, Operation, Protocol,
    ProtocolError, Request, Response, Success, MAX_FRAME_LENGTH,
};

use super::deadline_io::DeadlineStream;
use super::ReadableWait;

pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const READABLE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Closed outcomes from an attach session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachSessionError {
    Closed,
    Timeout,
    MalformedFrame,
    PayloadTooLarge,
    ProtocolIncompatible,
    Randomness,
    Authorization,
}

impl fmt::Display for AttachSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "attach stream closed",
            Self::Timeout => "attach hello timed out",
            Self::MalformedFrame => "attach frame is malformed",
            Self::PayloadTooLarge => "attach payload exceeds the allowed size",
            Self::ProtocolIncompatible => "attach protocol is incompatible",
            Self::Randomness => "attach session randomness is unavailable",
            Self::Authorization => "attach authorization failed",
        })
    }
}

impl std::error::Error for AttachSessionError {}

pub(super) struct DesktopDispatchResult {
    pub body: serde_json::Value,
    pub events: Vec<Event>,
}

pub(super) struct DesktopDispatchFailure {
    pub error: ProtocolError,
    pub events: Vec<Event>,
}

/// Platform service seam used by a desktop client request session.
pub(super) trait DesktopSessionService {
    type State;
    type Provenance: Clone;

    fn new_session_state(&self) -> Self::State;

    fn poll_run_streams(&mut self, state: &mut Self::State) -> Result<Vec<Event>, ProtocolError>;

    fn has_chat_subscription(&self, state: &Self::State) -> bool;

    #[cfg(target_os = "linux")]
    fn record_chat_delivery_failure(&mut self, run_id: &str, cause: &str);

    fn drain_chat_events(
        &mut self,
        state: &mut Self::State,
    ) -> Result<(Vec<Event>, bool), AttachSessionError>;

    fn dispatch_request(
        &mut self,
        request: Request,
        workspace: &str,
        provenance: Self::Provenance,
        state: &mut Self::State,
    ) -> Result<DesktopDispatchResult, DesktopDispatchFailure>;
}

/// Serves requests authorized by an admitted desktop client capability.
pub(super) fn serve_desktop_client_requests<S, H>(
    stream: &mut S,
    capability: &str,
    workspace: &str,
    provenance: H::Provenance,
    service: &mut H,
) -> Result<(), AttachSessionError>
where
    S: DeadlineStream + ?Sized,
    H: DesktopSessionService,
{
    serve_desktop_client_requests_with_diagnostics(
        stream,
        capability,
        workspace,
        provenance,
        service,
        |line| crate::runtime_eprintln!("{line}"),
    )
}

enum SessionClose {
    PeerDisconnected,
    ChatSubscriptionClosed,
    RunStreamFailed(ProtocolError),
}

pub(super) fn serve_desktop_client_requests_with_diagnostics<S, H>(
    stream: &mut S,
    capability: &str,
    workspace: &str,
    provenance: H::Provenance,
    service: &mut H,
    mut diagnostic: impl FnMut(String),
) -> Result<(), AttachSessionError>
where
    S: DeadlineStream + ?Sized,
    H: DesktopSessionService,
{
    let result = run_desktop_client_requests(
        stream,
        capability,
        workspace,
        provenance,
        service,
        &mut diagnostic,
    );
    let reason = match &result {
        Ok(SessionClose::PeerDisconnected) => "peer disconnected".into(),
        Ok(SessionClose::ChatSubscriptionClosed) => "chat subscription closed".into(),
        Ok(SessionClose::RunStreamFailed(error)) => format!("run stream failed {error}"),
        Err(error) => format!("{error:?}"),
    };
    diagnostic(format!(
        "muniment-runtime: desktop session closed reason={reason}"
    ));
    match result {
        Ok(SessionClose::RunStreamFailed(_)) => Err(AttachSessionError::Closed),
        other => other.map(|_| ()),
    }
}

fn run_desktop_client_requests<S, H>(
    stream: &mut S,
    capability: &str,
    workspace: &str,
    provenance: H::Provenance,
    service: &mut H,
    diagnostic: &mut impl FnMut(String),
) -> Result<SessionClose, AttachSessionError>
where
    S: DeadlineStream + ?Sized,
    H: DesktopSessionService,
{
    let mut state = service.new_session_state();
    loop {
        let live_events = match service.poll_run_streams(&mut state) {
            Ok(events) => events,
            Err(error) => {
                write_protocol_error(stream, error.clone(), Instant::now() + REQUEST_TIMEOUT);
                return Ok(SessionClose::RunStreamFailed(error));
            }
        };
        for event in live_events {
            let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
            #[cfg(target_os = "linux")]
            write_run_frame_before(
                stream,
                &frame,
                Instant::now() + REQUEST_TIMEOUT,
                service,
                diagnostic,
            )?;
            #[cfg(not(target_os = "linux"))]
            write_before(stream, &frame, Instant::now() + REQUEST_TIMEOUT)?;
        }
        if service.has_chat_subscription(&state) {
            let (events, closed) = service.drain_chat_events(&mut state)?;
            for event in events {
                #[cfg(target_os = "linux")]
                write_run_frame_before(
                    stream,
                    &encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?,
                    Instant::now() + REQUEST_TIMEOUT,
                    service,
                    diagnostic,
                )?;
                #[cfg(not(target_os = "linux"))]
                {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    write_before(stream, &frame, Instant::now() + REQUEST_TIMEOUT)?;
                }
            }
            if closed {
                return Ok(SessionClose::ChatSubscriptionClosed);
            }
        }

        match stream.wait_until_readable(Instant::now() + READABLE_POLL_INTERVAL) {
            ReadableWait::Ready => {}
            ReadableWait::Closed if service.has_chat_subscription(&state) => {
                return Err(AttachSessionError::Closed);
            }
            ReadableWait::Closed => return Ok(SessionClose::PeerDisconnected),
            ReadableWait::Timeout => continue,
        }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let request = match read_request_before(stream, deadline, diagnostic) {
            Ok(request) => request,
            Err(AttachSessionError::Closed) if service.has_chat_subscription(&state) => {
                return Err(AttachSessionError::Closed);
            }
            Err(AttachSessionError::Closed) => return Ok(SessionClose::PeerDisconnected),
            Err(error) => return Err(error),
        };
        let request_id = request.request_id.clone();
        let operation = request.operation;
        let sign_in_started = (operation == Operation::SessionSignIn).then(|| {
            diagnostic(
                "muniment-runtime: native-auth start method=RPC path=session.sign_in".into(),
            );
            Instant::now()
        });
        let dispatched = if request.capability != capability
            || matches!(
                request.operation,
                Operation::MigrationControl | Operation::ApprovalPresent
            ) {
            Err(DesktopDispatchFailure {
                error: ProtocolError::unauthorized(),
                events: Vec::new(),
            })
        } else {
            service.dispatch_request(request, workspace, provenance.clone(), &mut state)
        };
        if let Some(started) = sign_in_started {
            let outcome = match &dispatched {
                Ok(_) => "status=ok".into(),
                Err(failure) => format!("error={:?}", failure.error.code()),
            };
            diagnostic(format!(
                "muniment-runtime: native-auth end method=RPC path=session.sign_in {outcome} elapsed_ms={}",
                started.elapsed().as_millis(),
            ));
        }
        // Dispatch can wait for browser sign-in. Its elapsed time is not frame I/O time.
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        match dispatched {
            Ok(dispatched) => {
                let response = Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body: dispatched.body,
                };
                let frame =
                    encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?;
                #[cfg(target_os = "linux")]
                write_run_frame_before(stream, &frame, deadline, service, diagnostic)?;
                #[cfg(not(target_os = "linux"))]
                write_before(stream, &frame, deadline)?;
                for event in dispatched.events {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    #[cfg(target_os = "linux")]
                    write_run_frame_before(
                        stream,
                        &frame,
                        Instant::now() + REQUEST_TIMEOUT,
                        service,
                        diagnostic,
                    )?;
                    #[cfg(not(target_os = "linux"))]
                    write_before(stream, &frame, deadline)?;
                }
            }
            Err(failure) => {
                diagnostic(request_rejection_line(Some(operation), &failure.error));
                write_request_error(stream, Some(request_id), failure.error, deadline);
                for event in failure.events {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    #[cfg(target_os = "linux")]
                    write_run_frame_before(
                        stream,
                        &frame,
                        Instant::now() + REQUEST_TIMEOUT,
                        service,
                        diagnostic,
                    )?;
                    #[cfg(not(target_os = "linux"))]
                    write_before(stream, &frame, deadline)?;
                }
            }
        }
    }
}

fn request_rejection_line(operation: Option<Operation>, error: &ProtocolError) -> String {
    let operation = operation
        .map(|operation| serde_json::to_value(operation).expect("operation has a wire name"))
        .unwrap_or(serde_json::Value::String("unknown".into()));
    format!("muniment-runtime: desktop request rejected operation={operation} {error}")
}

fn read_request_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    deadline: Instant,
    diagnostic: &mut impl FnMut(String),
) -> Result<Request, AttachSessionError> {
    let mut prefix = [0u8; 4];
    read_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        diagnostic(request_rejection_line(
            None,
            &ProtocolError::payload_too_large(),
        ));
        write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
        return Err(AttachSessionError::PayloadTooLarge);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    read_before(stream, &mut frame[4..], deadline)?;
    match decode_frame::<Envelope>(&frame) {
        Ok(Some((Envelope::Request(request), consumed))) if consumed == frame.len() => Ok(request),
        _ => {
            diagnostic(request_rejection_line(
                None,
                &ProtocolError::malformed_frame(),
            ));
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            Err(AttachSessionError::MalformedFrame)
        }
    }
}

fn read_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), AttachSessionError> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(AttachSessionError::Timeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| AttachSessionError::Closed)?;
        match stream.read(bytes) {
            Ok(0) => return Err(AttachSessionError::Closed),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(AttachSessionError::Timeout);
            }
            Err(_) => return Err(AttachSessionError::Closed),
        }
    }
    Ok(())
}

fn write_request_error<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    request_id: Option<super::Id>,
    error: ProtocolError,
    deadline: Instant,
) {
    let envelope = ErrorEnvelope {
        protocol: Protocol,
        request_id,
        ok: Failure,
        error,
    };
    if let Ok(frame) = encode_frame(&envelope) {
        let _ = write_before(stream, &frame, deadline);
    }
}

#[cfg(target_os = "linux")]
fn write_run_frame_before<S: DeadlineStream + ?Sized, H: DesktopSessionService>(
    stream: &mut S,
    frame: &[u8],
    deadline: Instant,
    service: &mut H,
    diagnostic: &mut impl FnMut(String),
) -> Result<(), AttachSessionError> {
    write_frame_before(stream, frame, deadline, diagnostic).map_err(|failure| {
        if failure.error == AttachSessionError::Timeout {
            let (kind, run_id) = frame_identity(frame);
            if let Some(run_id) = run_id {
                service.record_chat_delivery_failure(&run_id, &format!(
                    "Reply delivery failed. The desktop missed the five-second {kind} frame deadline with {} bytes pending.", failure.pending,
                ));
            }
        }
        failure.error
    })
}

#[cfg(target_os = "linux")]
fn frame_identity(frame: &[u8]) -> (String, Option<String>) {
    let body_run_id = |body: &serde_json::Value, key| {
        body.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|id| uuid::Uuid::parse_str(id).is_ok())
            .map(str::to_owned)
    };
    match decode_frame::<Envelope>(frame) {
        Ok(Some((Envelope::Event(event), _))) => (
            serde_json::to_value(event.event)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".into()),
            event
                .run_id
                .map(|id| id.as_str().to_owned())
                .or_else(|| body_run_id(&event.body, "runId")),
        ),
        Ok(Some((Envelope::Response(response), _))) => {
            ("response".into(), body_run_id(&response.body, "run_id"))
        }
        Ok(Some((Envelope::Error(_), _))) => ("error".into(), None),
        _ => ("unknown".into(), None),
    }
}

#[cfg(target_os = "linux")]
fn write_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), AttachSessionError> {
    write_frame_before(stream, bytes, deadline, |line| {
        crate::runtime_eprintln!("{line}")
    })
    .map_err(|failure| failure.error)
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
struct FrameWriteFailure {
    error: AttachSessionError,
    pending: usize,
}

#[cfg(target_os = "linux")]
fn write_frame_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    frame: &[u8],
    deadline: Instant,
    mut diagnostic: impl FnMut(String),
) -> Result<(), FrameWriteFailure> {
    let mut pending = frame;
    let result = (|| {
        while !pending.is_empty() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(AttachSessionError::Timeout)?;
            stream
                .set_write_timeout(Some(remaining))
                .map_err(|_| AttachSessionError::Closed)?;
            match stream.write(pending) {
                Ok(0) => return Err(AttachSessionError::Closed),
                Ok(written) => pending = &pending[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if super::deadline_io::is_timeout(&error) => {
                    return Err(AttachSessionError::Timeout);
                }
                Err(_) => return Err(AttachSessionError::Closed),
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        let (kind, run_id) = frame_identity(frame);
        diagnostic(format!(
            "muniment-runtime: desktop frame write failed kind={kind:?} run_id={} bytes_pending={} bytes_total={} reason={error:?}",
            run_id.as_deref().unwrap_or("none"), pending.len(), frame.len(),
        ));
    }
    result.map_err(|error| FrameWriteFailure {
        error,
        pending: pending.len(),
    })
}

#[cfg(not(target_os = "linux"))]
fn write_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), AttachSessionError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(AttachSessionError::Timeout)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| AttachSessionError::Closed)?;
    stream.write_all(bytes).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            AttachSessionError::Timeout
        } else {
            AttachSessionError::Closed
        }
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::thread_service::{ThreadListPage, ThreadListRequest, ThreadListService};
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn dispatch_time_does_not_consume_the_response_frame_deadline() {
        struct SlowService;
        impl ThreadListService for SlowService {
            fn list_threads(
                &mut self,
                _: &str,
                _: ThreadListRequest,
            ) -> Result<ThreadListPage, ProtocolError> {
                std::thread::sleep(REQUEST_TIMEOUT + Duration::from_millis(10));
                Ok(ThreadListPage {
                    threads: Vec::new(),
                    next_cursor: None,
                })
            }
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            serve_desktop_client_requests_with_diagnostics(
                &mut server,
                "capability",
                "workspace",
                super::super::desktop_service_message::CompanionProvenance {
                    profile: "desktop-owner".into(),
                    companion_kind: "desktop-client".into(),
                    companion_version: "1.0.0".into(),
                    peer_uid: 1,
                    peer_pid: 2,
                },
                &mut SlowService,
                |_| {},
            )
        });
        client
            .write_all(
                &encode_frame(&serde_json::json!({
                    "protocol": "muniment.attach/1",
                    "request_id": "018f0000-0000-7000-8000-000000000201",
                    "operation": "thread.list", "capability": "capability", "body": {"limit": 20},
                }))
                .unwrap(),
            )
            .unwrap();
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).unwrap();
        let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
        client.read_exact(&mut body).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["ok"],
            true
        );
        drop(client);
        assert_eq!(worker.join().unwrap(), Ok(()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_frame_logs_its_kind_and_exact_pending_bytes_without_payloads() {
        struct Stalled {
            written: usize,
            allowance: usize,
        }
        impl Read for Stalled {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                unreachable!()
            }
        }
        impl Write for Stalled {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.written == self.allowance {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let count = bytes.len().min(self.allowance - self.written);
                self.written += count;
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl DeadlineStream for Stalled {
            fn wait_until_readable(&self, _: Instant) -> ReadableWait {
                unreachable!()
            }
            fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
            fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
        }
        let frame = encode_frame(&serde_json::json!({
            "protocol": "muniment.attach/1", "event": "chat.event",
            "subscription_id": "018f0000-0000-7000-8000-000000000201",
            "body": {"runId": "018f0000-0000-7000-8000-000000000202", "text": "secret-reply"},
        }))
        .unwrap();
        for allowance in [0, 2, frame.len() - 1] {
            let mut stream = Stalled {
                written: 0,
                allowance,
            };
            let mut lines = Vec::new();
            assert_eq!(
                write_frame_before(
                    &mut stream,
                    &frame,
                    Instant::now() + REQUEST_TIMEOUT,
                    |line| lines.push(line)
                ),
                Err(FrameWriteFailure {
                    error: AttachSessionError::Timeout,
                    pending: frame.len() - allowance
                })
            );
            assert_eq!(lines, [format!(
                "muniment-runtime: desktop frame write failed kind=\"chat.event\" run_id=018f0000-0000-7000-8000-000000000202 bytes_pending={} bytes_total={} reason=Timeout",
                frame.len() - allowance, frame.len(),
            )]);
        }
        let mut stream = Stalled {
            written: 0,
            allowance: frame.len(),
        };
        assert_eq!(
            write_frame_before(
                &mut stream,
                &frame,
                Instant::now() - Duration::from_millis(1),
                |_| {}
            ),
            Err(FrameWriteFailure {
                error: AttachSessionError::Timeout,
                pending: frame.len()
            })
        );
        assert_eq!(stream.written, 0);
        assert_eq!(
            write_frame_before(
                &mut stream,
                &frame,
                Instant::now() + REQUEST_TIMEOUT,
                |_| panic!("a complete frame must not log a failure")
            ),
            Ok(())
        );
        assert_eq!(stream.written, frame.len());

        #[derive(Default)]
        struct RecordingService {
            failure: Option<(String, String)>,
        }
        impl ThreadListService for RecordingService {
            fn list_threads(
                &mut self,
                _: &str,
                _: ThreadListRequest,
            ) -> Result<ThreadListPage, ProtocolError> {
                unreachable!()
            }
            fn record_chat_delivery_failure(&mut self, run_id: &str, cause: &str) {
                self.failure = Some((run_id.into(), cause.into()));
            }
        }
        let mut service = RecordingService::default();
        stream.written = 0;
        stream.allowance = 2;
        assert_eq!(
            write_run_frame_before(
                &mut stream,
                &frame,
                Instant::now() + REQUEST_TIMEOUT,
                &mut service,
                &mut |_| {}
            ),
            Err(AttachSessionError::Timeout)
        );
        let encoded_length = frame.len();
        assert_eq!(service.failure, Some((
            "018f0000-0000-7000-8000-000000000202".into(),
            format!("Reply delivery failed. The desktop missed the five-second chat.event frame deadline with {} bytes pending.", encoded_length - 2),
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_submission_response_and_run_stream_notify_the_run() {
        const RUN_ID: &str = "018f0000-0000-7000-8000-000000000202";
        struct StalledStream(std::io::Cursor<Vec<u8>>);
        impl Read for StalledStream {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.0.read(bytes)
            }
        }
        impl Write for StalledStream {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl DeadlineStream for StalledStream {
            fn wait_until_readable(&self, _: Instant) -> ReadableWait {
                ReadableWait::Ready
            }
            fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
            fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
        }
        struct RunService {
            event: Option<Event>,
            failures: Vec<(String, String)>,
        }
        impl DesktopSessionService for RunService {
            type State = ();
            type Provenance = ();
            fn new_session_state(&self) {}
            fn poll_run_streams(&mut self, _: &mut ()) -> Result<Vec<Event>, ProtocolError> {
                Ok(self.event.take().into_iter().collect())
            }
            fn has_chat_subscription(&self, _: &()) -> bool {
                false
            }
            fn record_chat_delivery_failure(&mut self, run_id: &str, cause: &str) {
                self.failures.push((run_id.into(), cause.into()));
            }
            fn drain_chat_events(
                &mut self,
                _: &mut (),
            ) -> Result<(Vec<Event>, bool), AttachSessionError> {
                unreachable!()
            }
            fn dispatch_request(
                &mut self,
                request: Request,
                _: &str,
                _: (),
                _: &mut (),
            ) -> Result<DesktopDispatchResult, DesktopDispatchFailure> {
                assert_eq!(request.operation, Operation::RunSubmit);
                Ok(DesktopDispatchResult {
                    body: serde_json::json!({"run_id": RUN_ID}),
                    events: vec![],
                })
            }
        }
        for kind in ["response", "run.event"] {
            let event_frame = encode_frame(&serde_json::json!({
                "protocol": "muniment.attach/1", "event": "run.event", "run_id": RUN_ID,
                "subscription_id": "018f0000-0000-7000-8000-000000000201", "body": {},
            }))
            .unwrap();
            let (Envelope::Event(event), _) =
                decode_frame::<Envelope>(&event_frame).unwrap().unwrap()
            else {
                panic!("expected a run event")
            };
            let mut service = RunService {
                event: (kind == "run.event").then_some(event),
                failures: vec![],
            };
            let request = encode_frame(&serde_json::json!({
                "protocol": "muniment.attach/1", "request_id": "018f0000-0000-7000-8000-000000000201",
                "operation": "run.submit", "capability": "capability", "body": {},
            })).unwrap();
            let mut lines = vec![];
            let result = serve_desktop_client_requests_with_diagnostics(
                &mut StalledStream(std::io::Cursor::new(request)),
                "capability",
                "workspace",
                (),
                &mut service,
                |line| lines.push(line),
            );
            assert_eq!(result, Err(AttachSessionError::Timeout));
            assert_eq!(service.failures.len(), 1);
            assert_eq!(service.failures[0].0, RUN_ID);
            assert!(service.failures[0]
                .1
                .contains(&format!("five-second {kind} frame deadline")));
            assert!(service.failures[0].1.contains("bytes pending"));
            assert!(lines[0].contains(&format!("kind={kind:?} run_id={RUN_ID}")));
            assert_eq!(
                lines[1],
                "muniment-runtime: desktop session closed reason=Timeout"
            );
        }
    }

    struct Service;

    impl ThreadListService for Service {
        fn list_threads(
            &mut self,
            _: &str,
            _: ThreadListRequest,
        ) -> Result<ThreadListPage, ProtocolError> {
            Err(ProtocolError::persistence_failed())
        }

        fn submit_run(
            &mut self,
            _: &str,
            _: super::super::desktop_service_message::RunSubmitRequest,
            _: &muniment_attach::Id,
            _: &muniment_attach::Id,
            _: super::super::desktop_service_message::CompanionProvenance,
        ) -> Result<super::super::desktop_service_message::RunSubmitAccepted, ProtocolError>
        {
            Err(crate::run_start::RunStartError::InvalidRequest(
                "Conversation history is unavailable.".into(),
            )
            .desktop_protocol_error())
        }
    }

    fn read_error(stream: &mut UnixStream) {
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix).unwrap();
        let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut body).unwrap();
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&body).unwrap()["ok"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn run_submit_logs_the_same_specific_reason_it_sends_on_the_wire() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            let mut lines = Vec::new();
            let result = serve_desktop_client_requests_with_diagnostics(
                &mut server,
                "capability",
                "workspace",
                super::super::desktop_service_message::CompanionProvenance {
                    profile: "desktop-owner".into(),
                    companion_kind: "desktop-client".into(),
                    companion_version: "1.0.0".into(),
                    peer_uid: 1,
                    peer_pid: 2,
                },
                &mut Service,
                |line| lines.push(line),
            );
            (result, lines)
        });
        let cases = [
            (
                serde_json::json!({"text": "hello", "files": []}),
                "Conversation history is unavailable.",
            ),
            (
                serde_json::json!({"text": "  ", "files": []}),
                "Enter a message before sending.",
            ),
            (
                serde_json::json!({"text": "x".repeat(super::super::desktop_dispatch::MAX_RUN_START_TEXT_LENGTH), "files": []}),
                "Conversation history is unavailable.",
            ),
            (
                serde_json::json!({"text": "x".repeat(super::super::desktop_dispatch::MAX_RUN_START_TEXT_LENGTH + 1), "files": []}),
                "The message exceeds the allowed size.",
            ),
            (
                serde_json::json!({"text": "hello", "files": [""]}),
                "A selected file path is invalid.",
            ),
            (
                serde_json::json!({"text": "hello", "files": [], "thread_id": "invalid"}),
                "The thread ID is invalid.",
            ),
            (
                serde_json::json!({"text": 0, "files": []}),
                "The run request body is invalid.",
            ),
        ];
        for (body, reason) in &cases {
            client
                .write_all(
                    &encode_frame(&serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": "018f0000-0000-7000-8000-000000000201",
                        "idempotency_key": "018f0000-0000-7000-8000-000000000202",
                        "operation": "run.submit", "capability": "capability", "body": body,
                    }))
                    .unwrap(),
                )
                .unwrap();
            let mut prefix = [0; 4];
            client.read_exact(&mut prefix).unwrap();
            let mut frame = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
            frame[..4].copy_from_slice(&prefix);
            client.read_exact(&mut frame[4..]).unwrap();
            let (Envelope::Error(envelope), _) = decode_frame::<Envelope>(&frame).unwrap().unwrap()
            else {
                panic!("expected a run rejection");
            };
            assert_eq!(
                serde_json::to_value(envelope.error).unwrap()["details"]["reason"],
                *reason
            );
        }
        drop(client);
        let (result, lines) = worker.join().unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(lines.len(), cases.len() + 1);
        for (line, (_, reason)) in lines.iter().zip(cases) {
            assert_eq!(line, &format!(
                "muniment-runtime: desktop request rejected operation=\"run.submit\" code=\"invalid_request\" reason={}",
                serde_json::json!(reason),
            ));
        }
    }

    #[test]
    fn invalid_frames_log_one_rejection_and_one_close() {
        for (frame, error, code) in [
            (
                encode_frame(&serde_json::json!({"operation": "secret\nrun.submit"})).unwrap(),
                AttachSessionError::MalformedFrame,
                "malformed_frame",
            ),
            (
                ((MAX_FRAME_LENGTH + 1) as u32).to_be_bytes().to_vec(),
                AttachSessionError::PayloadTooLarge,
                "payload_too_large",
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let worker = std::thread::spawn(move || {
                let mut lines = Vec::new();
                let result = serve_desktop_client_requests_with_diagnostics(
                    &mut server,
                    "capability",
                    "workspace",
                    super::super::desktop_service_message::CompanionProvenance {
                        profile: "desktop-owner".into(),
                        companion_kind: "desktop-client".into(),
                        companion_version: "1.0.0".into(),
                        peer_uid: 1,
                        peer_pid: 2,
                    },
                    &mut Service,
                    |line| lines.push(line),
                );
                (result, lines)
            });
            client.write_all(&frame).unwrap();
            read_error(&mut client);
            let (result, lines) = worker.join().unwrap();
            assert_eq!(result, Err(error));
            assert_eq!(lines.len(), 2);
            assert!(lines[0]
                .starts_with("muniment-runtime: desktop request rejected operation=\"unknown\" "));
            assert!(lines[0].contains(&format!("code=\"{code}\"")));
            assert_eq!(
                lines[1],
                format!("muniment-runtime: desktop session closed reason={error:?}")
            );
            assert!(!lines.join("").contains("secret"));
        }
    }

    #[test]
    fn runtime_service_log_records_each_rejection_and_one_close_without_request_secrets() {
        let directory =
            std::env::temp_dir().join(format!("muniment-session-log-{}", uuid::Uuid::new_v4()));
        let log_directory = directory.clone();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            serve_desktop_client_requests_with_diagnostics(
                &mut server,
                "secret-capability",
                "workspace",
                super::super::desktop_service_message::CompanionProvenance {
                    profile: "desktop-owner".into(),
                    companion_kind: "desktop-client".into(),
                    companion_version: "1.0.0".into(),
                    peer_uid: 1,
                    peer_pid: 2,
                },
                &mut Service,
                |line| {
                    crate::runtime_diagnostics::write_runtime_service_record(
                        &log_directory,
                        format_args!("{line}"),
                    )
                    .unwrap()
                },
            )
        });
        for capability in ["wrong-secret", "secret-capability"] {
            client
                .write_all(
                    &encode_frame(&serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": "018f0000-0000-7000-8000-000000000201",
                        "operation": "thread.list", "capability": capability,
                        "body": {"limit": 20},
                    }))
                    .unwrap(),
                )
                .unwrap();
            read_error(&mut client);
        }
        drop(client);
        assert_eq!(worker.join().unwrap(), Ok(()));
        let lines = std::fs::read_to_string(directory.join("runtime-service.log")).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert_eq!(lines, concat!(
            "muniment-runtime: desktop request rejected operation=\"thread.list\" code=\"unauthorized\" reason=\"The capability is not authorized.\"\n",
            "muniment-runtime: desktop request rejected operation=\"thread.list\" code=\"persistence_failed\" reason=\"The request could not be committed.\"\n",
            "muniment-runtime: desktop session closed reason=peer disconnected\n",
        ));
    }
}

fn write_protocol_error<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    error: ProtocolError,
    deadline: Instant,
) {
    let envelope = ErrorEnvelope {
        protocol: Protocol,
        request_id: None,
        ok: Failure,
        error,
    };
    if let Ok(frame) = encode_frame(&envelope) {
        let _ = write_before(stream, &frame, deadline);
    }
}
