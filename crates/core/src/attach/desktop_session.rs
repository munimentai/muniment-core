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
    let mut state = service.new_session_state();
    loop {
        let live_events = match service.poll_run_streams(&mut state) {
            Ok(events) => events,
            Err(error) => {
                write_protocol_error(stream, error, Instant::now() + REQUEST_TIMEOUT);
                return Err(AttachSessionError::Closed);
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
                return Ok(());
            }
        }

        match stream.wait_until_readable(Instant::now() + READABLE_POLL_INTERVAL) {
            ReadableWait::Ready => {}
            ReadableWait::Closed if service.has_chat_subscription(&state) => {
                return Err(AttachSessionError::Closed);
            }
            ReadableWait::Closed => return Ok(()),
            ReadableWait::Timeout => continue,
        }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let request = match read_request_before(stream, deadline) {
            Ok(request) => request,
            Err(AttachSessionError::Closed) if service.has_chat_subscription(&state) => {
                return Err(AttachSessionError::Closed);
            }
            Err(AttachSessionError::Closed) => return Ok(()),
            Err(error) => return Err(error),
        };
        let request_id = request.request_id.clone();
        if request.capability != capability
            || matches!(
                request.operation,
                Operation::MigrationControl | Operation::ApprovalPresent
            )
        {
            write_request_error(
                stream,
                Some(request_id),
                ProtocolError::unauthorized(),
                deadline,
            );
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

fn read_request_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Request, AttachSessionError> {
    let mut prefix = [0u8; 4];
    read_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
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
