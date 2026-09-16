//! Platform-neutral companion request sessions.

use std::io;
use std::time::{Duration, Instant};

use super::desktop_dispatch::{dispatch_request, poll_run_streams, SessionRegistries};
use super::desktop_service_message::CompanionProvenance;
use super::live_connections::{LiveConnectionState, RegisteredConnection};
use super::thread_service::ThreadListService;
#[cfg(target_os = "linux")]
use super::Request;
use super::{
    encode_frame, AttachSessionError, AuthorizationClock, AuthorizationState,
    AuthorizationTokenGenerator, ConnectionBinding, DeadlineStream, Envelope, ErrorEnvelope, Event,
    EventName, Failure, Operation, Protocol, ProtocolError, ReadableWait, Response, Success,
    MAX_FRAME_LENGTH,
};

pub(super) struct AuthorizedSession<'a> {
    pub binding: &'a ConnectionBinding,
    pub provenance: &'a CompanionProvenance,
    pub workspace: &'a str,
    pub connection: &'a RegisteredConnection,
}

#[cfg(target_os = "linux")]
pub(super) fn read_request_before<S: DeadlineStream + ?Sized>(
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
    match super::decode_frame::<Envelope>(&frame) {
        Ok(Some((Envelope::Request(request), consumed))) if consumed == frame.len() => Ok(request),
        _ => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            Err(AttachSessionError::MalformedFrame)
        }
    }
}

pub(super) fn read_before<S: DeadlineStream + ?Sized>(
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
                return Err(AttachSessionError::Timeout)
            }
            Err(_) => return Err(AttachSessionError::Closed),
        }
    }
    Ok(())
}

pub(super) fn serve_requests<C, G, S, H>(
    stream: &mut S,
    timeout: Duration,
    session: AuthorizedSession<'_>,
    authorization: &mut AuthorizationState<C, G>,
    service: &mut H,
) -> Result<(), AttachSessionError>
where
    C: AuthorizationClock,
    G: AuthorizationTokenGenerator,
    S: DeadlineStream + ?Sized,
    H: ThreadListService,
{
    let mut subscriptions = Vec::new();
    let mut registries = SessionRegistries::default();
    let artifact_clock_origin = (authorization.now(), Instant::now());
    loop {
        let gate = session
            .connection
            .gate
            .lock()
            .expect("credential admission gate");
        let state = session
            .connection
            .connection
            .state
            .lock()
            .expect("live connection state");
        match *state {
            LiveConnectionState::Blocked => {
                drop(state);
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            LiveConnectionState::Revoked => {
                send_revocation(stream, timeout, session.connection)?;
                return Ok(());
            }
            LiveConnectionState::Active => {}
        }
        // Give an already-buffered request a chance to supply its correlation ID even when
        // the grant has just expired. Validation below still prevents stale dispatch.
        let (authorization_expired, idle_remaining) = match authorization.remaining_lifetime() {
            Ok(remaining) => (false, remaining.max(Duration::from_millis(1))),
            Err(_) => (true, Duration::from_millis(1)),
        };
        let idle_deadline = Instant::now()
            .checked_add(idle_remaining)
            .ok_or(AttachSessionError::Timeout)?;
        let artifact_now =
            artifact_clock_origin.1 + authorization.now().saturating_sub(artifact_clock_origin.0);
        for transfer_id in registries.artifact_transfers.remove_expired(artifact_now) {
            let deadline = (Instant::now() + timeout).min(idle_deadline);
            write_request_error(stream, None, ProtocolError::slow_consumer(), deadline);
            let closed = Event {
                protocol: Protocol,
                subscription_id: transfer_id,
                event: EventName::StreamClosed,
                run_id: None,
                run_seq: None,
                body: serde_json::json!({"code": "slow_consumer", "resumable": true}),
            };
            write_before(
                stream,
                &encode_frame(&closed).map_err(|_| AttachSessionError::MalformedFrame)?,
                deadline,
            )?;
        }
        let live_events = if authorization_expired {
            Vec::new()
        } else {
            match poll_run_streams(service, &mut subscriptions) {
                Ok(events) => events,
                Err(error) => {
                    write_protocol_error(stream, error, Instant::now() + timeout);
                    return Err(AttachSessionError::Closed);
                }
            }
        };
        for event in live_events {
            let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
            write_before(
                stream,
                &frame,
                (Instant::now() + timeout).min(idle_deadline),
            )?;
        }
        drop(state);
        drop(gate);
        let artifact_wait_deadline = registries
            .artifact_transfers
            .nearest_acknowledgement_deadline()
            .map(|deadline| Instant::now() + deadline.saturating_duration_since(artifact_now));
        let poll_deadline = artifact_wait_deadline
            .unwrap_or(idle_deadline)
            .min(Instant::now() + Duration::from_millis(50))
            .min(idle_deadline);
        let mut prefix = [0; 4];
        match stream.wait_until_readable(poll_deadline) {
            ReadableWait::Ready => {}
            ReadableWait::Closed => return Ok(()),
            ReadableWait::Timeout => {
                if Instant::now() < idle_deadline {
                    continue;
                }
                let deadline = Instant::now() + timeout;
                write_protocol_error(stream, ProtocolError::unauthorized(), deadline);
                return Err(AttachSessionError::Authorization);
            }
        }
        match read_before(stream, &mut prefix, idle_deadline) {
            Ok(()) => {}
            Err(AttachSessionError::Closed) => return Ok(()),
            Err(error) => return Err(error),
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(AttachSessionError::Timeout)?
            .min(idle_deadline);
        let frame = match read_frame_after_prefix(stream, prefix, deadline) {
            Ok(frame) => frame,
            Err(error @ AttachSessionError::PayloadTooLarge) => {
                write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
                return Err(error);
            }
            Err(error @ AttachSessionError::Timeout) => return Err(error),
            Err(error @ AttachSessionError::Closed) => return Err(error),
            Err(error) => {
                write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
                return Err(error);
            }
        };
        let request = match super::decode_frame::<Envelope>(&frame) {
            Ok(Some((Envelope::Request(request), consumed))) if consumed == frame.len() => request,
            _ => {
                write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
                return Err(AttachSessionError::MalformedFrame);
            }
        };
        let (admission_gate, admission) = loop {
            let gate = session
                .connection
                .gate
                .lock()
                .expect("credential admission gate");
            let state = session
                .connection
                .connection
                .state
                .lock()
                .expect("live connection state");
            match *state {
                LiveConnectionState::Active => break (gate, state),
                LiveConnectionState::Blocked => {
                    drop(state);
                    drop(gate);
                    std::thread::sleep(Duration::from_millis(50));
                }
                LiveConnectionState::Revoked => {
                    drop(state);
                    drop(gate);
                    send_revocation(stream, timeout, session.connection)?;
                    return Ok(());
                }
            }
        };
        if authorization_expired {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::unauthorized(),
                Instant::now() + timeout,
            );
            return Err(AttachSessionError::Authorization);
        }
        if service
            .drain_state()
            .is_some_and(|drain| drain.admit(request.operation).is_err())
        {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::runtime_draining(),
                deadline,
            );
            continue;
        }
        if matches!(
            request.operation,
            Operation::ThreadRename
                | Operation::ThreadDelete
                | Operation::ThreadSelect
                | Operation::ThreadSummaries
                | Operation::ThreadHistory
                | Operation::SessionStatus
                | Operation::EntitlementSnapshot
                | Operation::DeviceList
                | Operation::SessionSignIn
                | Operation::SessionSignOut
                | Operation::CompanionList
                | Operation::CompanionRevoke
                | Operation::CompanyList
                | Operation::CompanyCreate
                | Operation::CompanySelect
                | Operation::CompanyRename
                | Operation::ReaderDescribe
                | Operation::ReaderRun
                | Operation::ReaderQueue
                | Operation::RunChatEvents
                | Operation::RunSubmit
                | Operation::RunResume
                | Operation::RunSteer
                | Operation::RunFollowUp
                | Operation::RunPermissionAnswer
                | Operation::RetentionRecheck
        ) {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::unauthorized(),
                deadline,
            );
            return Err(AttachSessionError::Authorization);
        }
        let required_scope = match request.operation {
            Operation::WorkspaceOnboard | Operation::HomeEnsure => None,
            Operation::ThreadList
            | Operation::ThreadOpen
            | Operation::RunOpen
            | Operation::RunStream
            | Operation::RunCursorAck
            | Operation::ArtifactFetch
            | Operation::ArtifactWindow
            | Operation::RequestCancel
            | Operation::RecordSql
            | Operation::RecordKinds
            | Operation::RecordQuery
            | Operation::RecordEntity => Some("thread.read"),
            Operation::ThreadCreate
            | Operation::RunStart
            | Operation::RunCancel
            | Operation::PermissionAnswer
            | Operation::RecordPropose
            | Operation::RecordCommit => Some("run.write"),
            _ => None,
        };
        if authorization
            .validate_request_with_scope(
                &request.capability,
                session.binding,
                &session.provenance.profile,
                session.workspace,
                required_scope,
            )
            .is_err()
        {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::unauthorized(),
                deadline,
            );
            return Err(AttachSessionError::Authorization);
        }
        let request_id = request.request_id.clone();
        let artifact_now =
            artifact_clock_origin.1 + authorization.now().saturating_sub(artifact_clock_origin.0);
        registries.artifact_now = Some(artifact_now);
        let dispatched = dispatch_request(
            request,
            session.workspace,
            session.provenance.clone(),
            service,
            &mut subscriptions,
            &mut None,
            &mut registries,
        );
        let deadline = post_dispatch_deadline(
            Instant::now(),
            timeout,
            authorization.remaining_lifetime().unwrap_or_default(),
        )?;
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
                write_before(stream, &frame, deadline)?;
                for event in dispatched.events {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    write_before(stream, &frame, deadline)?;
                }
            }
            Err(failure) => {
                write_request_error(stream, Some(request_id), failure.error, deadline);
                for event in failure.events {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    write_before(stream, &frame, deadline)?;
                }
            }
        }
        drop(admission);
        drop(admission_gate);
    }
}

pub(super) fn post_dispatch_deadline(
    now: Instant,
    timeout: Duration,
    authorization_remaining: Duration,
) -> Result<Instant, AttachSessionError> {
    now.checked_add(timeout.min(authorization_remaining))
        .ok_or(AttachSessionError::Timeout)
}

pub(super) fn send_revocation<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    timeout: Duration,
    connection: &RegisteredConnection,
) -> Result<(), AttachSessionError> {
    let event = Event {
        protocol: Protocol,
        subscription_id: connection.connection.connection_event_id.clone(),
        event: EventName::CapabilityRevoked,
        run_id: None,
        run_seq: None,
        body: serde_json::json!({
            "capability": &connection.connection.capability,
            "reason": "companion_revoked",
        }),
    };
    let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
    write_before(stream, &frame, Instant::now() + timeout)?;
    stream.flush().map_err(|_| AttachSessionError::Closed)
}

pub(super) fn read_frame_after_prefix<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    prefix: [u8; 4],
    deadline: Instant,
) -> Result<Vec<u8>, AttachSessionError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(AttachSessionError::PayloadTooLarge);
    }
    let mut frame = vec![0; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_before(stream, &mut frame[4..], deadline)?;
    Ok(frame)
}

pub(super) fn write_request_error<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    request_id: Option<super::Id>,
    error: ProtocolError,
    deadline: Instant,
) {
    // Desktop diagnostics can name local paths. Companion errors keep the public persistence reason.
    let error = if error.code() == super::ErrorCode::PersistenceFailed {
        ProtocolError::persistence_failed()
    } else {
        error
    };
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    #[test]
    fn companion_wire_redacts_desktop_persistence_diagnostics() {
        let request_id = super::super::Id::new("01900000-0000-7000-8000-000000000001").unwrap();
        for error in [
            ProtocolError::persistence_failed_with_reason(
                "Conversation history lock failed: poisoned lock",
            ),
            ProtocolError::persistence_failed_with_reason(
                "Conversation history journal failed: no such table: thread_events",
            ),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write_request_error(
                &mut server,
                Some(request_id.clone()),
                error,
                Instant::now() + Duration::from_secs(2),
            );
            let mut prefix = [0; 4];
            client.read_exact(&mut prefix).unwrap();
            let mut frame = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
            frame[..4].copy_from_slice(&prefix);
            client.read_exact(&mut frame[4..]).unwrap();
            let (Envelope::Error(envelope), _) = super::super::decode_frame::<Envelope>(&frame)
                .unwrap()
                .unwrap()
            else {
                panic!("the companion must receive an error");
            };
            assert_eq!(envelope.request_id, Some(request_id.clone()));
            assert_eq!(envelope.error, ProtocolError::persistence_failed());
        }
    }
}

pub(super) fn write_before<S: DeadlineStream + ?Sized>(
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

pub(super) fn write_protocol_error<S: DeadlineStream + ?Sized>(
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
