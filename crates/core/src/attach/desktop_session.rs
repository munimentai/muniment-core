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

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
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

fn serve_desktop_client_requests_with_diagnostics<S, H>(
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
            write_before(stream, &frame, Instant::now() + REQUEST_TIMEOUT)?;
        }
        if service.has_chat_subscription(&state) {
            let (events, closed) = service.drain_chat_events(&mut state)?;
            for event in events {
                let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                write_before(stream, &frame, Instant::now() + REQUEST_TIMEOUT)?;
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
        if request.capability != capability
            || matches!(
                request.operation,
                Operation::MigrationControl | Operation::ApprovalPresent
            )
        {
            let error = ProtocolError::unauthorized();
            diagnostic(request_rejection_line(Some(operation), &error));
            write_request_error(stream, Some(request_id), error, deadline);
            continue;
        }
        match service.dispatch_request(request, workspace, provenance.clone(), &mut state) {
            Ok(dispatched) => {
                let response = Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body: dispatched.body,
                };
                write_before(
                    stream,
                    &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
                    deadline,
                )?;
                for event in dispatched.events {
                    write_before(
                        stream,
                        &encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?,
                        deadline,
                    )?;
                }
            }
            Err(failure) => {
                diagnostic(request_rejection_line(Some(operation), &failure.error));
                write_request_error(stream, Some(request_id), failure.error, deadline);
                for event in failure.events {
                    write_before(
                        stream,
                        &encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?,
                        deadline,
                    )?;
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

    struct Service;

    impl ThreadListService for Service {
        fn list_threads(
            &mut self,
            _: &str,
            _: ThreadListRequest,
        ) -> Result<ThreadListPage, ProtocolError> {
            Err(ProtocolError::persistence_failed())
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
