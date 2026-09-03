use crate::client_stream::{
    map_io_error, read_approval_value, read_approval_value_with_prefix, read_exact_before,
    read_value, write_all_before,
};
use crate::desktop_client_stop::ShutdownHook;
use crate::protocol_helpers::{
    deadline, fresh_nonce, fresh_request_id, is_hex_secret, map_frame_error, parse_message,
    reject_protocol_error,
};
use crate::{
    encode_frame, ApprovalDecision, ApprovalPresentRequest, ApprovalPresenterServeOutcome,
    Authorization, AuthorizationSummary, Client, ClientError, ClientStream, Envelope,
    ErrorEnvelope, Hello, Id, Operation, PeerAuthorizedGrant, Protocol, Request, Response,
    VersionRange, Welcome, MAX_TEXT_LENGTH,
};
use serde_json::Value;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const MAX_APPROVAL_DEADLINE_MS: u64 = 120_000;

/// A connection-bound client for the peer-authorized approval presenter session.
pub struct ApprovalPresenterClient {
    stream: Box<dyn ClientStream + Send>,
    capability: String,
    summary: AuthorizationSummary,
    io_timeout: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct ApprovalPresenterStopHandle {
    pub(crate) inner: Arc<(Mutex<ApprovalPresenterStopState>, Condvar)>,
}

#[derive(Default)]
pub(crate) struct ApprovalPresenterStopState {
    stopped: bool,
    shutdown: Option<ShutdownHook>,
}

impl std::fmt::Debug for ApprovalPresenterStopState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalPresenterStopState")
            .field("stopped", &self.stopped)
            .field("shutdown", &self.shutdown.is_some())
            .finish()
    }
}

impl ApprovalPresenterStopState {
    pub(crate) fn stopped(&self) -> bool {
        self.stopped
    }

    pub(crate) fn set_shutdown(&mut self, shutdown: Option<ShutdownHook>) {
        self.shutdown = shutdown;
    }
}

impl ApprovalPresenterStopHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        let (state, wake) = &*self.inner;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.stopped = true;
        if let Some(shutdown) = state.shutdown.take() {
            shutdown();
        }
        wake.notify_all();
    }

    #[doc(hidden)]
    pub fn register_shutdown(&self, shutdown: impl FnOnce() + Send + 'static) -> bool {
        let (state, _) = &*self.inner;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        if state.stopped {
            return false;
        }
        state.shutdown = Some(Box::new(shutdown));
        true
    }
}

pub trait ApprovalPresenterSupervisorStop {
    fn stopped(&self) -> bool;

    fn wait_for_retry(&self, retry_interval: Duration) -> bool;
}

impl ApprovalPresenterSupervisorStop for ApprovalPresenterStopHandle {
    fn stopped(&self) -> bool {
        self.inner
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stopped
    }

    fn wait_for_retry(&self, retry_interval: Duration) -> bool {
        let (state, wake) = &*self.inner;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.shutdown = None;
        if state.stopped {
            return false;
        }
        let (state, _) = wake
            .wait_timeout_while(state, retry_interval, |state| !state.stopped)
            .unwrap_or_else(|error| error.into_inner());
        !state.stopped
    }
}

pub fn serve_approval_presenter_with<S>(
    mut connect: impl FnMut() -> Option<ApprovalPresenterClient>,
    stop: S,
    retry_interval: Duration,
    mut observe: impl FnMut(bool),
    mut choose: impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
) where
    S: ApprovalPresenterSupervisorStop,
{
    loop {
        if stop.stopped() {
            return;
        }

        if let Some(mut presenter) = connect() {
            observe(true);
            let _ = presenter.serve(&mut choose);
            observe(false);
        }

        if !stop.wait_for_retry(retry_interval) {
            return;
        }
    }
}

impl std::fmt::Debug for ApprovalPresenterClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApprovalPresenterClient { .. }")
    }
}

impl ApprovalPresenterClient {
    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn authorization_summary(&self) -> AuthorizationSummary {
        self.summary.clone()
    }

    pub fn present(
        &mut self,
        choose: impl FnOnce(&ApprovalPresentRequest) -> ApprovalDecision,
    ) -> Result<(), ClientError> {
        let request_deadline = deadline(self.io_timeout);
        let envelope: Envelope =
            serde_json::from_value(read_approval_value(&mut *self.stream, request_deadline)?)
                .map_err(|_| ClientError::UnexpectedMessage)?;
        let Envelope::Request(request) = envelope else {
            return Err(ClientError::UnexpectedMessage);
        };

        self.answer_present_request(request, choose)
    }

    fn answer_present_request(
        &mut self,
        request: Request,
        choose: impl FnOnce(&ApprovalPresentRequest) -> ApprovalDecision,
    ) -> Result<(), ClientError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            challenge: String,
            claimed_kind: String,
            claimed_version: String,
            workspace: String,
            scopes: Vec<String>,
            deadline_ms: u64,
        }

        let body = serde_json::from_value::<Body>(request.body.clone());
        let valid_text = |value: &str| {
            !value.is_empty()
                && value.len() <= MAX_TEXT_LENGTH
                && !value.chars().any(char::is_control)
        };
        let valid = request.capability == self.capability
            && request.operation == Operation::ApprovalPresent
            && request.idempotency_key.is_none()
            && body.as_ref().is_ok_and(|body| {
                valid_text(&body.challenge)
                    && valid_text(&body.claimed_kind)
                    && valid_text(&body.claimed_version)
                    && valid_text(&body.workspace)
                    && body.scopes.len() <= crate::MAX_JSON_COLLECTION_ENTRIES
                    && body.scopes.iter().all(|scope| valid_text(scope))
                    && (1..=MAX_APPROVAL_DEADLINE_MS).contains(&body.deadline_ms)
            });
        if !valid {
            let error = ErrorEnvelope {
                protocol: Protocol,
                request_id: Some(request.request_id),
                ok: crate::Failure,
                error: crate::ProtocolError::unauthorized(),
            };
            let bytes = encode_frame(&error).map_err(map_frame_error)?;
            write_all_before(&mut *self.stream, &bytes, deadline(self.io_timeout))?;
            return Err(ClientError::UnexpectedMessage);
        }

        let body = body.expect("validated approval request body");
        let approval = ApprovalPresentRequest {
            challenge: body.challenge,
            claimed_kind: body.claimed_kind,
            claimed_version: body.claimed_version,
            workspace: body.workspace,
            scopes: body.scopes,
            deadline_ms: body.deadline_ms,
        };
        let decision = choose(&approval);
        let response = Response {
            protocol: Protocol,
            request_id: request.request_id,
            ok: crate::Success,
            body: serde_json::json!({
                "challenge": approval.challenge,
                "decision": decision,
            }),
        };
        let bytes = encode_frame(&response).map_err(map_frame_error)?;
        write_all_before(&mut *self.stream, &bytes, deadline(self.io_timeout))
    }

    pub fn serve(
        &mut self,
        mut choose: impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
    ) -> Result<ApprovalPresenterServeOutcome, ClientError> {
        loop {
            self.stream
                .set_read_timeout(None)
                .map_err(|_| ClientError::DesktopUnavailable)?;
            let mut first = [0u8; 1];
            match self.stream.read(&mut first).map_err(map_io_error)? {
                0 => return Ok(ApprovalPresenterServeOutcome::ConnectionClosed),
                1 => {}
                _ => unreachable!("a one-byte read returned more than one byte"),
            }

            let request_deadline = deadline(self.io_timeout);
            let mut prefix = [0u8; 4];
            prefix[0] = first[0];
            read_exact_before(&mut *self.stream, &mut prefix[1..], request_deadline)?;
            let value =
                read_approval_value_with_prefix(&mut *self.stream, prefix, request_deadline)?;
            self.present_value(value, &mut choose)?;
        }
    }

    fn present_value(
        &mut self,
        value: Value,
        choose: &mut impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
    ) -> Result<(), ClientError> {
        let envelope: Envelope =
            serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)?;
        let Envelope::Request(request) = envelope else {
            return Err(ClientError::UnexpectedMessage);
        };

        self.answer_present_request(request, |approval| choose(approval))
    }
}

pub fn handshake_approval_presenter(
    mut stream: Box<dyn ClientStream + Send>,
    client_version: &str,
    io_timeout: Duration,
) -> Result<ApprovalPresenterClient, ClientError> {
    let hello = Hello {
        protocol: Protocol,
        client: Client {
            kind: "desktop".into(),
            version: client_version.into(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: fresh_nonce()?,
        authorized_client_id: Id::new(fresh_request_id()?.as_str())
            .map_err(|_| ClientError::UnexpectedMessage)?,
        authorized_client_credential: None,
    };
    let bytes = encode_frame(&hello).map_err(map_frame_error)?;
    write_all_before(&mut *stream, &bytes, deadline(io_timeout))?;

    let welcome_value = read_value(&mut *stream, deadline(io_timeout))?;
    reject_protocol_error(&welcome_value)?;
    let welcome: Welcome = parse_message(welcome_value)?;
    if welcome.selected != 1
        || welcome.authorization != Authorization::Authorized
        || !is_hex_secret(&welcome.server_nonce, 32)
    {
        return Err(ClientError::UnexpectedMessage);
    }

    let authorized_value = read_value(&mut *stream, deadline(io_timeout))?;
    reject_protocol_error(&authorized_value)?;
    if authorized_value
        .get("authorized_client_credential")
        .is_some()
    {
        return Err(ClientError::UnexpectedMessage);
    }
    let authorized: PeerAuthorizedGrant = parse_message(authorized_value)?;
    if !is_hex_secret(&authorized.capability, 64)
        || authorized.expires_at == 0
        || authorized.expires_at > 8 * 60 * 60
        || authorized.idle_timeout_seconds == 0
        || authorized.idle_timeout_seconds > 15 * 60
    {
        return Err(ClientError::UnexpectedMessage);
    }
    Ok(ApprovalPresenterClient {
        stream,
        capability: authorized.capability,
        summary: AuthorizationSummary {
            expires_in_seconds: authorized.expires_at,
            idle_timeout_seconds: authorized.idle_timeout_seconds,
        },
        io_timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};

    struct FixtureStream {
        reads: VecDeque<u8>,
    }

    impl FixtureStream {
        fn with_request(challenge: &str) -> Self {
            let request = Request {
                protocol: Protocol,
                request_id: Id::new("00000000000000000000000000000191").unwrap(),
                operation: Operation::ApprovalPresent,
                capability: "33".repeat(32),
                idempotency_key: None,
                body: serde_json::json!({
                    "challenge": challenge,
                    "claimed_kind": "cli",
                    "claimed_version": "0.0.1",
                    "workspace": "/workspace",
                    "scopes": ["thread:list"],
                    "deadline_ms": 1_000,
                }),
            };
            Self {
                reads: VecDeque::from(encode_frame(&request).unwrap()),
            }
        }
    }

    impl Read for FixtureStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = bytes.len().min(self.reads.len());
            for byte in &mut bytes[..count] {
                *byte = self.reads.pop_front().unwrap();
            }
            Ok(count)
        }
    }

    impl Write for FixtureStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ClientStream for FixtureStream {
        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    struct StopAfterRetries {
        retries: Cell<usize>,
    }

    impl ApprovalPresenterSupervisorStop for &StopAfterRetries {
        fn stopped(&self) -> bool {
            false
        }

        fn wait_for_retry(&self, _retry_interval: Duration) -> bool {
            let retries = self.retries.get() + 1;
            self.retries.set(retries);
            retries < 2
        }
    }

    fn client(challenge: &str) -> ApprovalPresenterClient {
        ApprovalPresenterClient {
            stream: Box::new(FixtureStream::with_request(challenge)),
            capability: "33".repeat(32),
            summary: AuthorizationSummary {
                expires_in_seconds: 60,
                idle_timeout_seconds: 30,
            },
            io_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn reconnects_and_serves_presenter_requests_through_the_seams() {
        let stop = StopAfterRetries {
            retries: Cell::new(0),
        };
        let mut clients = VecDeque::from([client("first"), client("second")]);
        let mut observed = Vec::new();
        let mut presented = Vec::new();

        serve_approval_presenter_with(
            || clients.pop_front(),
            &stop,
            Duration::ZERO,
            |connected| observed.push(connected),
            |request| {
                presented.push(request.challenge.clone());
                ApprovalDecision::Approve
            },
        );

        assert_eq!(observed, [true, false, true, false]);
        assert_eq!(presented, ["first", "second"]);
        assert!(clients.is_empty());
    }

    #[test]
    fn a_stopped_supervisor_does_not_connect_or_register_shutdown() {
        let stop = ApprovalPresenterStopHandle::new();
        stop.stop();
        let connects = Cell::new(0);

        serve_approval_presenter_with(
            || {
                connects.set(connects.get() + 1);
                None
            },
            stop.clone(),
            Duration::ZERO,
            |_| panic!("a stopped supervisor must not report a connection"),
            |_| panic!("a stopped supervisor must not present a request"),
        );

        assert_eq!(connects.get(), 0);
        assert!(!stop
            .register_shutdown(|| { panic!("a stopped supervisor must not register shutdown") }));
    }
}
