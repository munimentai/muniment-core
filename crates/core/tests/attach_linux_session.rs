#![cfg(target_os = "linux")]

use muniment_core::attach::linux::{
    run_authenticated_session_with, run_authenticated_session_with_authorization, ApprovalDecision,
    AttachSessionError, AuthorizationSessionDependencies, CompanionProvenance, PeerCredentials,
    RedactedThreadSummary, RunStartAccepted, RunStartRequest, RunStreamPage, ThreadListPage,
    ThreadListRequest, ThreadListService, ThreadOpenRequest, MAX_RUN_START_CONTEXT_LENGTH,
    MAX_RUN_START_TEXT_LENGTH,
};
use muniment_core::attach::{
    decode_frame, encode_frame, Approval, AuthorizationClock, AuthorizationTokenGenerator,
    Authorized, Envelope, ErrorAction, ErrorCode, ErrorEnvelope, Event, EventName, Hello, Id,
    Operation, Protocol, Request, Response, VersionRange, Welcome, CHALLENGE_LIFETIME,
    MAX_FRAME_LENGTH, MAX_JSON_DEPTH, MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS,
};
use muniment_core::journal::{
    EventEnvelope, EventPayload, Provenance, RunEventProjection, RunJournal,
};
use serde_json::json;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

fn credentials() -> PeerCredentials {
    PeerCredentials {
        pid: std::process::id() as libc::pid_t,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}

fn hello(min: u32, max: u32) -> Vec<u8> {
    encode_frame(&Hello {
        protocol: Protocol,
        client: muniment_core::attach::Client {
            kind: "cli".into(),
            version: "1.0.0".into(),
        },
        supported: VersionRange { min, max },
        client_nonce: "client-nonce".into(),
    })
    .unwrap()
}

fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> T {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut bytes = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
    bytes[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut bytes[4..]).unwrap();
    decode_frame(&bytes).unwrap().unwrap().0
}

#[derive(Clone)]
struct TestClock(Rc<Cell<Duration>>);
impl AuthorizationClock for TestClock {
    fn now(&self) -> Duration {
        self.0.get()
    }
}
struct TestTokens(u8);
impl AuthorizationTokenGenerator for TestTokens {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), muniment_core::attach::AuthorizationRandomnessError> {
        bytes.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}

struct FailingTokens {
    calls_before_failure: usize,
}
impl AuthorizationTokenGenerator for FailingTokens {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), muniment_core::attach::AuthorizationRandomnessError> {
        if self.calls_before_failure == 0 {
            return Err(muniment_core::attach::AuthorizationRandomnessError);
        }
        self.calls_before_failure -= 1;
        bytes.fill(1);
        Ok(())
    }
}
fn approval() -> Approval {
    Approval {
        profile: "profile-1".into(),
        workspace: "workspace-1".into(),
        scopes: BTreeSet::from(["thread.read".into()]),
        lifetime: Duration::from_secs(3600),
    }
}

fn unavailable_service(
    _: &str,
    _: ThreadListRequest,
) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
    panic!("request must not dispatch")
}

#[derive(Default)]
struct StartService {
    calls: Vec<(String, RunStartRequest, Id, Id, CompanionProvenance)>,
    output: Option<RunStartAccepted>,
}

struct StreamService {
    page: RunStreamPage,
}

impl ThreadListService for StreamService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        _: u64,
    ) -> Result<RunStreamPage, muniment_core::attach::ProtocolError> {
        assert_eq!(workspace, "workspace-1");
        assert_eq!(run_id, self.page.run_id);
        Ok(self.page.clone())
    }
}

fn stream_projection(run_id: &str, run_seq: u64, event_type: String) -> RunEventProjection {
    RunEventProjection {
        run_id: run_id.into(),
        run_seq,
        event_type,
        event_version: 1,
        recorded_at: "2026-07-16T03:00:00Z".into(),
    }
}

fn projected_run_event_frame_len(run_id: &str, run_seq: u64, event_type: &str) -> usize {
    encode_frame(&Event {
        protocol: Protocol,
        subscription_id: Id::new("0".repeat(32)).unwrap(),
        event: EventName::RunEvent,
        run_id: Some(Id::new(run_id.to_owned()).unwrap()),
        run_seq: Some(run_seq),
        body: json!({
            "event_type": event_type,
            "event_version": 1,
            "recorded_at": "2026-07-16T03:00:00Z",
            "payload": {"withheld": true},
        }),
    })
    .unwrap()
    .len()
}

impl ThreadListService for StartService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn start_run(
        &mut self,
        workspace: &str,
        request: RunStartRequest,
        request_id: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<RunStartAccepted, muniment_core::attach::ProtocolError> {
        self.calls.push((
            workspace.into(),
            request,
            request_id.clone(),
            idempotency_key.clone(),
            provenance,
        ));
        Ok(self.output.clone().unwrap_or_else(|| RunStartAccepted {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            committed_seq: 2,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        }))
    }
}

#[test]
fn authorization_randomness_failures_close_without_authorized() {
    for calls_before_failure in [0, 1] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        let result = run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: FailingTokens {
                    calls_before_failure,
                },
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut unavailable_service,
        );
        assert_eq!(result, Err(AttachSessionError::Randomness));
        if calls_before_failure == 1 {
            let _: Welcome = read_frame(&mut client);
        }
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn approval_continues_into_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(1, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let clock = TestClock(Rc::new(Cell::new(Duration::ZERO)));
    let mut service = |_: &str, _: ThreadListRequest| {
        Ok(ThreadListPage {
            threads: vec![],
            next_cursor: None,
        })
    };
    assert_eq!(
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |b: &mut [u8]| {
                    b.fill(9);
                    Ok(())
                },
                clock,
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        ),
        Ok(())
    );
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(welcome.approval_challenge, "01".repeat(16));
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.capability, "02".repeat(32));
    assert_eq!(authorized.expires_at, 3600);
    assert_eq!(authorized.idle_timeout_seconds, 900);
    let response: Response = read_frame(&mut client);
    assert_eq!(response.request_id, Id::new(format!("{:032x}", 1)).unwrap());
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn approval_after_hello_timeout_but_before_challenge_expiry_is_sent() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let now = Rc::new(Cell::new(Duration::ZERO));
    client.shutdown(Shutdown::Write).unwrap();
    let decision_clock = now.clone();
    let decided = Rc::new(Cell::new(false));
    let decision_made = decided.clone();
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |b: &mut [u8]| {
                b.fill(9);
                Ok(())
            },
            clock: TestClock(now),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, remaining: Duration| {
                if decision_made.replace(true) {
                    return None;
                }
                assert_eq!(remaining, CHALLENGE_LIFETIME);
                decision_clock.set(Duration::from_secs(6));
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut unavailable_service,
    );
    assert_eq!(result, Ok(()));
    let _: Welcome = read_frame(&mut client);
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.capability, "02".repeat(32));
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn second_approval_after_consumption_cannot_write_another_grant() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let calls = Rc::new(Cell::new(0));
    let approval_calls = calls.clone();
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |b: &mut [u8]| {
                b.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                approval_calls.set(approval_calls.get() + 1);
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut unavailable_service,
    );
    assert_eq!(result, Ok(()));
    assert_eq!(calls.get(), 2);
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn denial_and_expired_challenge_close_without_authorized() {
    for expired in [false, true] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let decision_clock = now.clone();
        let result = run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |b: &mut [u8]| {
                    b.fill(9);
                    Ok(())
                },
                clock: TestClock(now),
                tokens: TestTokens(1),
                approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    if expired {
                        decision_clock.set(CHALLENGE_LIFETIME + Duration::from_nanos(1));
                        Some(ApprovalDecision::Approve(approval()))
                    } else {
                        Some(ApprovalDecision::Deny)
                    }
                },
            },
            &mut unavailable_service,
        );
        assert_eq!(
            result,
            if expired {
                Err(AttachSessionError::Timeout)
            } else {
                Ok(())
            }
        );
        let _: Welcome = read_frame(&mut client);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn fragmented_hello_receives_deterministic_welcome_then_closes() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let task = thread::spawn(move || {
        run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |bytes| {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = index as u8;
                }
                Ok(())
            },
        )
    });
    let frame = hello(1, 1);
    for part in frame.chunks(3) {
        client.write_all(part).unwrap();
    }
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(welcome.selected, 1);
    assert_eq!(welcome.desktop_version, "0.1.0");
    assert_eq!(welcome.server_nonce, "000102030405060708090a0b0c0d0e0f");
    assert_eq!(welcome.approval_challenge.len(), 32);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    assert_eq!(task.join().unwrap(), Ok(()));
}

#[test]
fn hello_deadline_is_short_and_closes_without_a_response() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let start = Instant::now();
    let result = run_authenticated_session_with(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(20),
        |_| Ok(()),
    );
    assert_eq!(result, Err(AttachSessionError::Timeout));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn incompatibility_actions_are_framed_and_terminal() {
    for (range, action) in [
        ((0, 0), ErrorAction::UpgradeCompanion),
        ((2, 2), ErrorAction::UpgradeDesktop),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(range.0, range.1)).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            run_authenticated_session_with(
                server,
                credentials(),
                "0.1.0",
                Duration::from_secs(1),
                |_| Ok(())
            ),
            Err(AttachSessionError::ProtocolIncompatible)
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.action(), Some(action));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

fn raw_frame(payload: &[u8]) -> Vec<u8> {
    [&(payload.len() as u32).to_be_bytes()[..], payload].concat()
}

#[test]
fn malformed_first_messages_are_redacted_terminal_and_never_negotiate() {
    let non_hello = encode_frame(&json!({
        "protocol": "muniment.attach/1",
        "request_id": "00000000000000000000000000000001",
        "operation": "thread.list",
        "capability": "/home/user/secret",
        "body": {"raw": "do not disclose"}
    }))
    .unwrap();
    let nested = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    let cases = [
        (non_hello, AttachSessionError::MalformedFrame, true),
        (
            raw_frame(&[0xff]),
            AttachSessionError::MalformedFrame,
            false,
        ),
        (
            raw_frame(br#"{"raw":"do not disclose""#),
            AttachSessionError::MalformedFrame,
            false,
        ),
        (
            raw_frame(nested.as_bytes()),
            AttachSessionError::MalformedFrame,
            false,
        ),
    ];

    for (mut first, expected, queue_second) in cases {
        if queue_second {
            // A queued valid hello proves a terminal first-message failure does not proceed.
            first.extend_from_slice(&hello(1, 1));
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&first).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let random_calls = Cell::new(0);
        let result = run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |_| {
                random_calls.set(random_calls.get() + 1);
                Ok(())
            },
        );

        assert_eq!(result, Err(expected));
        assert_eq!(random_calls.get(), 0);
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.protocol, Protocol);
        assert_eq!(error.request_id, None);
        assert_eq!(error.error.code(), ErrorCode::MalformedFrame);
        let visible = serde_json::to_string(&error).unwrap();
        for forbidden in ["/home", "secret", "do not disclose", "thread.list", "pid"] {
            assert!(!visible.contains(forbidden));
        }
        let terminal_read = client.read(&mut [0]);
        if queue_second {
            // Linux reports reset when the peer closes with deliberately unread input.
            assert!(matches!(terminal_read, Ok(0) | Err(_)));
        } else {
            assert_eq!(terminal_read.unwrap(), 0);
        }
    }
}

#[test]
fn oversized_declared_length_is_redacted_terminal_and_never_negotiate() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes())
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let random_calls = Cell::new(0);

    assert_eq!(
        run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |_| {
                random_calls.set(random_calls.get() + 1);
                Ok(())
            },
        ),
        Err(AttachSessionError::PayloadTooLarge)
    );
    assert_eq!(random_calls.get(), 0);
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.protocol, Protocol);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::PayloadTooLarge);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn eof_is_terminal_without_a_response_or_negotiation() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&[0, 0]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let random_calls = Cell::new(0);

    assert_eq!(
        run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |_| {
                random_calls.set(random_calls.get() + 1);
                Ok(())
            },
        ),
        Err(AttachSessionError::Closed)
    );
    assert_eq!(random_calls.get(), 0);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

fn request(id: u128, operation: Operation, body: serde_json::Value) -> Vec<u8> {
    encode_frame(&Request {
        protocol: Protocol,
        request_id: Id::new(format!("{id:032x}")).unwrap(),
        operation,
        capability: "02".repeat(32),
        idempotency_key: None,
        body,
    })
    .unwrap()
}

fn request_with_idempotency(id: u128, operation: Operation, body: serde_json::Value) -> Vec<u8> {
    encode_frame(&Request {
        protocol: Protocol,
        request_id: Id::new(format!("{id:032x}")).unwrap(),
        operation,
        capability: "02".repeat(32),
        idempotency_key: Some(Id::new(format!("{:032x}", id + 1000)).unwrap()),
        body,
    })
    .unwrap()
}

fn prompt(run_id: &str, title: &str, recorded_at: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: run_id.replacen("a100", "a200", 1),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "user.prompt.submitted".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: recorded_at.into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({"prompt": title, "secret": "/home/user/private"}),
        },
        provenance: Provenance {
            source: "test".into(),
            source_version: "1".into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

fn dispatch_session<S>(
    client: &mut UnixStream,
    server: UnixStream,
    clock: TestClock,
    service: &mut S,
) -> Result<(), AttachSessionError>
where
    S: muniment_core::attach::linux::ThreadListService,
{
    dispatch_session_with_approval(client, server, clock, approval(), service)
}

fn dispatch_session_with_approval<S>(
    client: &mut UnixStream,
    server: UnixStream,
    clock: TestClock,
    approved: Approval,
    service: &mut S,
) -> Result<(), AttachSessionError>
where
    S: muniment_core::attach::linux::ThreadListService,
{
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock,
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approved.clone()))
            },
        },
        service,
    );
    let _: Welcome = read_frame(client);
    let _: Authorized = read_frame(client);
    result
}

#[test]
fn authorized_thread_list_is_bounded_paginated_and_correlated() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            10,
            Operation::ThreadList,
            json!({"limit": 100, "cursor": "opaque-page-2"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let calls = Cell::new(0);
    let mut service = |workspace: &str, request: ThreadListRequest| {
        calls.set(calls.get() + 1);
        assert_eq!(workspace, "workspace-1");
        assert_eq!(request.limit, 100);
        assert_eq!(request.cursor.as_deref(), Some("opaque-page-2"));
        Ok(ThreadListPage {
            threads: vec![RedactedThreadSummary {
                thread_id: "thread-1".into(),
                title: "Safe title".into(),
                updated_at: "2026-07-16T00:00:00Z".into(),
            }],
            next_cursor: Some("opaque-page-3".into()),
        })
    };
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.request_id,
        Id::new(format!("{:032x}", 10)).unwrap()
    );
    assert_eq!(response.body["next_cursor"], "opaque-page-3");
    assert_eq!(calls.get(), 1);
}

#[test]
fn authorized_run_stream_catches_up_in_order_with_redacted_projection() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000011";
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN, "private prompt", "2026-07-16T03:00:00Z"))
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            41,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(response.body["run_id"], RUN);
    assert_eq!(response.body["first_available_run_seq"], 1);
    assert_eq!(response.body["current_run_seq"], 1);
    let subscription = response.body["subscription_id"].as_str().unwrap();
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected run event")
    };
    assert_eq!(event.event, EventName::RunEvent);
    assert_eq!(event.subscription_id.as_str(), subscription);
    assert_eq!(event.run_seq, Some(1));
    assert_eq!(event.body["payload"]["withheld"], true);
    assert!(!event.body.to_string().contains("private"));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.subscription_id.as_str(), subscription);
}

#[test]
fn run_stream_does_not_read_or_emit_an_oversized_inline_payload() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000012";
    let secret = "payload-secret-".repeat(MAX_FRAME_LENGTH);
    let mut event = prompt(RUN, "placeholder", "2026-07-16T03:00:00Z");
    event.payload = EventPayload::Inline {
        payload_json: json!({"secret": secret}),
    };
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append(0, &event).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            42,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    let event: Envelope = read_frame(&mut client);
    let caught_up: Envelope = read_frame(&mut client);
    let encoded = format!("{response:?}{event:?}{caught_up:?}");
    assert!(!encoded.contains("payload-secret"));
    assert!(encoded.len() < 10_000);
}

#[test]
fn run_stream_rejects_missing_scope_other_workspace_and_strictly_malformed_bodies() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000013";
    let cases = [
        (
            false,
            json!({"run_id": RUN, "after_run_seq": 0}),
            ErrorCode::Unauthorized,
        ),
        (
            true,
            json!({"run_id": RUN, "after_run_seq": 0}),
            ErrorCode::InvalidRequest,
        ),
        (true, json!({"run_id": RUN}), ErrorCode::InvalidRequest),
        (
            true,
            json!({"run_id": RUN, "after_run_seq": -1}),
            ErrorCode::InvalidRequest,
        ),
        (
            true,
            json!({"run_id": RUN, "after_run_seq": 0, "extra": true}),
            ErrorCode::InvalidRequest,
        ),
    ];
    for (has_scope, body, expected) in cases {
        let mut journal = RunJournal::open(":memory:").unwrap();
        journal
            .append(0, &prompt(RUN, "private", "2026-07-16T03:00:00Z"))
            .unwrap();
        journal.bind_run_workspace(RUN, "workspace-2").unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(43, Operation::RunStream, body))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        if !has_scope {
            approved.scopes.clear();
        }
        let _ = dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut journal,
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), expected);
        assert!(!serde_json::to_string(&error).unwrap().contains("private"));
    }
}

#[test]
fn run_stream_rejects_missing_removed_ahead_and_expired_cursors() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000014";
    for (present, after, expected) in [
        (false, 0, ErrorCode::InvalidRequest),
        (true, 2, ErrorCode::InvalidCursor),
    ] {
        let mut journal = RunJournal::open(":memory:").unwrap();
        if present {
            journal
                .append(0, &prompt(RUN, "private", "2026-07-16T03:00:00Z"))
                .unwrap();
            journal.bind_run_workspace(RUN, "workspace-1").unwrap();
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(
                44,
                Operation::RunStream,
                json!({"run_id": RUN, "after_run_seq": after}),
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        )
        .unwrap();
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), expected);
    }

    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN, "private", "2026-07-16T03:00:00Z"))
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    journal.delete_run(RUN).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            45,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    dispatch_session(
        &mut client,
        server,
        TestClock(Rc::new(Cell::new(Duration::ZERO))),
        &mut journal,
    )
    .unwrap();
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
}

#[test]
fn run_stream_resumes_in_order_without_duplicates_and_marks_only_exhausted_catch_up() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000015";
    let mut events = Vec::new();
    for seq in 1..=3 {
        let mut event = prompt(RUN, "private", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a200-0000-7000-8000-{seq:012x}");
        event.run_seq = seq;
        event.event_type = format!("safe.event.{seq}");
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            46,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 1}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    dispatch_session(
        &mut client,
        server,
        TestClock(Rc::new(Cell::new(Duration::ZERO))),
        &mut journal,
    )
    .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"].as_str().unwrap();
    for expected_seq in [2, 3] {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected event")
        };
        assert_eq!(event.event, EventName::RunEvent);
        assert_eq!(event.subscription_id.as_str(), subscription);
        assert_eq!(event.run_id.as_ref().unwrap().as_str(), RUN);
        assert_eq!(event.run_seq, Some(expected_seq));
        assert!(!event.body.to_string().contains("private"));
    }
    let Envelope::Event(caught) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught up")
    };
    assert_eq!(caught.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught.run_seq, Some(3));
}

#[test]
fn run_stream_event_window_ack_resumes_and_catches_up_once() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000016";
    let events = (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
        .map(|seq| stream_projection(RUN, seq, "safe.event".into()))
        .collect();
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            47,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut sequences = Vec::new();
    for _ in 0..MAX_RUN_STREAM_WINDOW_EVENTS {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected event")
        };
        assert_eq!(event.event, EventName::RunEvent);
        sequences.push(event.run_seq.unwrap());
    }
    assert_eq!(sequences.len(), MAX_RUN_STREAM_WINDOW_EVENTS);
    assert_eq!(sequences.first(), Some(&1));
    assert_eq!(
        sequences.last(),
        Some(&(MAX_RUN_STREAM_WINDOW_EVENTS as u64))
    );

    client
        .write_all(&request(
            48,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let ack: Response = read_frame(&mut client);
    assert_eq!(ack.body["through_run_seq"], MAX_RUN_STREAM_WINDOW_EVENTS);
    let Envelope::Event(last) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed event")
    };
    assert_eq!(last.run_seq, Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);

    client
        .write_all(&request(
            49,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let duplicate: Response = read_frame(&mut client);
    assert_eq!(
        duplicate.body["through_run_seq"],
        MAX_RUN_STREAM_WINDOW_EVENTS
    );
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

fn assert_redacted_request_error(error: &ErrorEnvelope, request: u128, code: ErrorCode) {
    assert_eq!(
        error.request_id.as_ref().map(Id::as_str),
        Some(format!("{request:032x}").as_str())
    );
    assert_eq!(error.error.code(), code);
    assert_eq!(
        serde_json::to_value(&error.error).unwrap().get("details"),
        None
    );
}

#[test]
fn run_cursor_ack_rejections_are_correlated_redacted_and_stream_local() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000019";
    let events = (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
        .map(|seq| stream_projection(RUN, seq, "safe.event".into()))
        .collect();
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);

    client
        .write_all(&request(
            60,
            Operation::RunCursorAck,
            json!({"subscription_id": "0".repeat(32), "through_run_seq": 0}),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut client), 60, ErrorCode::InvalidCursor);
    for (request_id, body) in [
        (
            61,
            json!({"subscription_id": "not-an-id", "through_run_seq": 0}),
        ),
        (62, json!({"subscription_id": "0".repeat(32)})),
        (
            63,
            json!({"subscription_id": "0".repeat(32), "through_run_seq": "1"}),
        ),
        (
            64,
            json!({
                "subscription_id": "0".repeat(32),
                "through_run_seq": 0,
                "workspace": "workspace-2",
                "run_id": "0190a100-0000-7000-8000-000000000020"
            }),
        ),
    ] {
        client
            .write_all(&request(request_id, Operation::RunCursorAck, body))
            .unwrap();
        assert_redacted_request_error(
            &read_frame(&mut client),
            request_id,
            ErrorCode::InvalidRequest,
        );
    }

    let mut subscriptions = Vec::new();
    for request_id in [65, 66, 69] {
        client
            .write_all(&request(
                request_id,
                Operation::RunStream,
                json!({"run_id": RUN, "after_run_seq": 0}),
            ))
            .unwrap();
        let response: Response = read_frame(&mut client);
        subscriptions.push(
            response.body["subscription_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        for expected in 1..=MAX_RUN_STREAM_WINDOW_EVENTS as u64 {
            let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
                panic!("expected run event")
            };
            assert_eq!(
                event.subscription_id.as_str(),
                subscriptions.last().unwrap()
            );
            assert_eq!(event.run_seq, Some(expected));
            assert_eq!(event.body["payload"]["withheld"], true);
        }
    }

    client
        .write_all(&request(
            67,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[0],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS + 1,
            }),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut client), 67, ErrorCode::InvalidCursor);
    let Envelope::Event(closed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected stream close")
    };
    assert_eq!(closed.event, EventName::StreamClosed);
    assert_eq!(closed.subscription_id.as_str(), subscriptions[0]);
    assert_eq!(closed.run_id.as_ref().unwrap().as_str(), RUN);
    assert_eq!(closed.run_seq, Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64));
    assert_eq!(
        closed.body,
        json!({"code": "invalid_cursor", "resumable": true})
    );

    client
        .write_all(&request(
            68,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[1],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(response.request_id.as_str(), format!("{:032x}", 68));
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed event")
    };
    assert_eq!(resumed.subscription_id.as_str(), subscriptions[1]);
    assert_eq!(
        resumed.run_seq,
        Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1)
    );
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.subscription_id.as_str(), subscriptions[1]);

    client
        .write_all(&request(
            70,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[2],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS - 1,
            }),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed event")
    };
    assert_eq!(resumed.subscription_id.as_str(), subscriptions[2]);
    assert_eq!(
        resumed.run_seq,
        Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1)
    );
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.subscription_id.as_str(), subscriptions[2]);

    client
        .write_all(&request(
            71,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[2],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS - 2,
            }),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut client), 71, ErrorCode::InvalidCursor);
    let Envelope::Event(closed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected stream close")
    };
    assert_eq!(closed.event, EventName::StreamClosed);
    assert_eq!(closed.subscription_id.as_str(), subscriptions[2]);
    assert_eq!(closed.body["code"], "invalid_cursor");

    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn run_cursor_ack_subscription_ids_are_isolated_between_connections() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000021";
    let page = RunStreamPage {
        run_id: RUN.into(),
        first_available_run_seq: 1,
        current_run_seq: MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1,
        events: (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
            .map(|seq| stream_projection(RUN, seq, "safe.event".into()))
            .collect(),
        exhausted: true,
    };
    let mut clients = Vec::new();
    let mut threads = Vec::new();
    for _ in 0..2 {
        let mut service = StreamService { page: page.clone() };
        let (mut client, server) = UnixStream::pair().unwrap();
        threads.push(thread::spawn(move || {
            run_authenticated_session_with_authorization(
                server,
                credentials(),
                "0.1.0",
                Duration::from_secs(2),
                AuthorizationSessionDependencies {
                    fill_random: |bytes: &mut [u8]| {
                        bytes.fill(9);
                        Ok(())
                    },
                    clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                    tokens: TestTokens(1),
                    approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                        Some(ApprovalDecision::Approve(approval()))
                    },
                },
                &mut service,
            )
        }));
        client.write_all(&hello(1, 1)).unwrap();
        let _: Welcome = read_frame(&mut client);
        let _: Authorized = read_frame(&mut client);
        clients.push(client);
    }

    clients[0]
        .write_all(&request(
            72,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut clients[0]);
    let foreign_subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..MAX_RUN_STREAM_WINDOW_EVENTS {
        let _: Envelope = read_frame(&mut clients[0]);
    }

    clients[1]
        .write_all(&request(
            73,
            Operation::RunCursorAck,
            json!({
                "subscription_id": foreign_subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut clients[1]), 73, ErrorCode::InvalidCursor);

    clients[0]
        .write_all(&request(
            74,
            Operation::RunCursorAck,
            json!({
                "subscription_id": foreign_subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let _: Response = read_frame(&mut clients[0]);
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut clients[0]) else {
        panic!("expected owner connection to resume")
    };
    assert_eq!(
        resumed.run_seq,
        Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1)
    );
    assert_eq!(resumed.subscription_id.as_str(), foreign_subscription);
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut clients[0]) else {
        panic!("expected owner connection caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.subscription_id.as_str(), foreign_subscription);

    for client in &mut clients {
        client.shutdown(Shutdown::Write).unwrap();
    }
    for server_thread in threads {
        assert_eq!(server_thread.join().unwrap(), Ok(()));
    }
}

#[test]
fn real_journal_run_stream_fetches_next_page_after_window_ack() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000018";
    let events = (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
        .map(|seq| {
            let mut event = prompt(RUN, "private", "2026-07-16T03:00:00Z");
            event.event_id = format!("0190a200-0000-7000-8001-{seq:012x}");
            event.run_seq = seq;
            event
        })
        .collect::<Vec<_>>();
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut journal,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            50,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for expected in 1..=MAX_RUN_STREAM_WINDOW_EVENTS as u64 {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected first-page event")
        };
        assert_eq!(event.run_seq, Some(expected));
    }
    client
        .write_all(&request(
            51,
            Operation::RunCursorAck,
            json!({"subscription_id": subscription, "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected second-page event")
    };
    assert_eq!(event.run_seq, Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn run_stream_byte_window_counts_exact_framed_bytes_and_pauses_one_byte_over() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000017";
    let event_count = MAX_RUN_STREAM_WINDOW_BYTES.div_ceil(60_000);
    let base_target = MAX_RUN_STREAM_WINDOW_BYTES / event_count;
    let remainder = MAX_RUN_STREAM_WINDOW_BYTES % event_count;
    let targets = (0..event_count)
        .map(|index| base_target + usize::from(index < remainder))
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    for (index, target) in targets.iter().copied().enumerate() {
        let seq = index as u64 + 1;
        let base = projected_run_event_frame_len(RUN, seq, "x") - 1;
        let event_type = "x".repeat(target - base);
        assert_eq!(projected_run_event_frame_len(RUN, seq, &event_type), target);
        assert!(target <= MAX_FRAME_LENGTH + 4);
        events.push(stream_projection(RUN, seq, event_type));
    }
    let over_seq = events.len() as u64 + 1;
    events.push(stream_projection(RUN, over_seq, "one-byte-over".into()));
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: over_seq,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            48,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body["window"]["max_bytes"],
        MAX_RUN_STREAM_WINDOW_BYTES
    );
    let mut event_bytes = 0;
    let mut sequences = Vec::new();
    for _ in 0..targets.len() {
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).unwrap();
        let mut frame = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
        frame[..4].copy_from_slice(&prefix);
        client.read_exact(&mut frame[4..]).unwrap();
        event_bytes += frame.len();
        let (Envelope::Event(event), _) = decode_frame(&frame).unwrap().unwrap() else {
            panic!("expected event")
        };
        assert_eq!(event.event, EventName::RunEvent);
        sequences.push(event.run_seq.unwrap());
    }
    assert_eq!(sequences.len(), targets.len());
    assert_eq!(sequences.last(), Some(&(targets.len() as u64)));
    assert_eq!(event_bytes, MAX_RUN_STREAM_WINDOW_BYTES);
    client
        .write_all(&request(
            49,
            Operation::RunCursorAck,
            json!({"subscription_id": response.body["subscription_id"], "through_run_seq": targets.len()}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected byte-window resumed event")
    };
    assert_eq!(resumed.run_seq, Some(over_seq));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn authorized_thread_list_pages_real_journal_summaries_without_payloads() {
    const RUN_A: &str = "0190a100-0000-7000-8000-000000000001";
    const RUN_B: &str = "0190a100-0000-7000-8000-000000000002";
    const RUN_C: &str = "0190a100-0000-7000-8000-000000000003";
    const HIDDEN_RUN: &str = "0190a100-0000-7000-8000-000000000004";
    let mut journal = RunJournal::open(":memory:").unwrap();
    for (run_id, title, recorded_at) in [
        (RUN_A, "first", "2026-07-16T03:00:00Z"),
        (RUN_B, "second", "2026-07-16T02:00:00Z"),
        (RUN_C, "third", "2026-07-16T01:00:00Z"),
    ] {
        journal
            .append(0, &prompt(run_id, title, recorded_at))
            .unwrap();
        journal.bind_run_workspace(run_id, "workspace-1").unwrap();
    }
    journal
        .append(0, &prompt(HIDDEN_RUN, "hidden", "2026-07-16T04:00:00Z"))
        .unwrap();
    journal
        .bind_run_workspace(HIDDEN_RUN, "workspace-2")
        .unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let client_thread = thread::spawn(move || {
        client.write_all(&hello(1, 1)).unwrap();
        let _: Welcome = read_frame(&mut client);
        let _: Authorized = read_frame(&mut client);
        client
            .write_all(&request(11, Operation::ThreadList, json!({"limit": 2})))
            .unwrap();
        let first: Response = read_frame(&mut client);
        client
            .write_all(&request(
                12,
                Operation::ThreadList,
                json!({"limit": 2, "cursor": first.body["next_cursor"]}),
            ))
            .unwrap();
        let second: Response = read_frame(&mut client);
        client.shutdown(Shutdown::Write).unwrap();
        (first, second)
    });
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut journal,
    );
    assert_eq!(result, Ok(()));
    let (first, second) = client_thread.join().unwrap();
    assert_eq!(
        first.body,
        json!({
            "threads": [
                {"thread_id": RUN_A, "title": "first", "updated_at": "2026-07-16T03:00:00Z"},
                {"thread_id": RUN_B, "title": "second", "updated_at": "2026-07-16T02:00:00Z"}
            ],
            "next_cursor": first.body["next_cursor"]
        })
    );
    assert_eq!(
        second.body,
        json!({
            "threads": [
                {"thread_id": RUN_C, "title": "third", "updated_at": "2026-07-16T01:00:00Z"}
            ]
        })
    );
    let encoded = format!("{}{}", first.body, second.body);
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("/home/user/private"));
}

#[test]
fn authorized_thread_open_pages_a_redacted_journal_projection() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    let mut journal = RunJournal::open(":memory:").unwrap();
    let first = prompt(RUN, "hello", "2026-07-16T03:00:00Z");
    let mut second = first.clone();
    second.event_id = "0190a200-0000-7000-8000-000000000002".into();
    second.run_seq = 2;
    second.event_type = "model.stream.delta".into();
    second.payload = EventPayload::Inline {
        payload_json: json!({"text": "answer", "secret": "/home/user/private"}),
    };
    journal.append_batch(0, &[first, second]).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let client_thread = thread::spawn(move || {
        client.write_all(&hello(1, 1)).unwrap();
        let _: Welcome = read_frame(&mut client);
        let _: Authorized = read_frame(&mut client);
        client
            .write_all(&request(
                40,
                Operation::ThreadOpen,
                json!({"thread_id": RUN, "limit": 1}),
            ))
            .unwrap();
        let first: Response = read_frame(&mut client);
        client
            .write_all(&request(
                41,
                Operation::ThreadOpen,
                json!({"thread_id": RUN, "limit": 1, "cursor": first.body["next_cursor"]}),
            ))
            .unwrap();
        let second: Response = read_frame(&mut client);
        client.shutdown(Shutdown::Write).unwrap();
        (first, second)
    });
    assert_eq!(
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| Some(
                    ApprovalDecision::Approve(approval())
                ),
            },
            &mut journal
        ),
        Ok(())
    );
    let (first, second) = client_thread.join().unwrap();
    assert_eq!(
        first.body["entries"],
        json!([{"run_seq": 1, "kind": "user_message", "text": "hello"}])
    );
    assert_eq!(
        second.body["entries"],
        json!([{"run_seq": 2, "kind": "assistant_message", "text": "answer"}])
    );
    assert!(!format!("{first:?}{second:?}").contains("/home"));
}

#[test]
fn projected_pages_preserve_cross_boundary_state_and_ignore_unknown_events() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    let mut events = Vec::new();
    for (seq, kind, payload) in [
        (1, "run.started", json!({})),
        (2, "model.stream.delta", json!({"text":"hello "})),
        (3, "future.event", json!({"private":"ignored"})),
        (4, "model.stream.delta", json!({"text":"world"})),
        (
            5,
            "tool.effect.started",
            json!({"effect_id":"tool-1","display_name":"Search"}),
        ),
        (
            6,
            "permission.requested",
            json!({"gate_id":"gate-1","kind":"confirm","title":"Allow?","message":"Proceed?"}),
        ),
        (7, "permission.resolved", json!({"gate_id":"gate-1"})),
        (8, "tool.effect.completed", json!({"effect_id":"tool-1"})),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a200-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = kind.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut attachment = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
    attachment.event_id = "0190a200-0000-7000-8000-000000000009".into();
    attachment.run_seq = 9;
    attachment.event_type = "chat.attachment.ingested".into();
    attachment.payload = EventPayload::Attachment {
        attachment: serde_json::from_value(json!({
            "sha256": "00".repeat(32), "display_name": "notes.txt", "byte_length": 12,
            "media_type": "text/plain"
        }))
        .unwrap(),
    };
    events.push(attachment);
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let first = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: RUN.into(),
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    let second = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: RUN.into(),
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(first.entries[0].text.as_deref(), Some("hello world"));
    assert_eq!(second.entries[0].kind, "tool_completed");
    assert_eq!(second.entries[0].text.as_deref(), Some("Search"));
    let third = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: RUN.into(),
                limit: 1,
                cursor: second.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(third.entries[0].kind, "attachment");
    assert_eq!(third.entries[0].text.as_deref(), Some("notes.txt"));
    assert!(third.next_cursor.is_none());
}

#[test]
fn large_escaped_projection_continues_losslessly_with_bounded_pages() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    let fragment = "\\\"\n".repeat(400);
    let expected = fragment.repeat(1000);
    let mut events = Vec::with_capacity(1001);
    for seq in 1..=1001 {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a200-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = if seq == 1 {
            "run.started"
        } else {
            "model.stream.delta"
        }
        .into();
        event.payload = EventPayload::Inline {
            payload_json: if seq == 1 {
                json!({})
            } else {
                json!({"text": fragment})
            },
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    // The journal projection seam itself is bounded; page formation does not
    // replay or retain all 1,001 source envelopes.
    assert_eq!(
        journal
            .projected_thread_entries("workspace-1", RUN, 1001, -1, 3)
            .unwrap()
            .len(),
        3
    );
    let mut cursor = None;
    let mut found = String::new();
    loop {
        let page = journal
            .open_thread(
                "workspace-1",
                ThreadOpenRequest {
                    thread_id: RUN.into(),
                    limit: 100,
                    cursor,
                },
            )
            .unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() < MAX_FRAME_LENGTH);
        for entry in page.entries {
            found.push_str(entry.text.as_deref().unwrap_or(""));
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(found, expected);
}

#[test]
fn thread_open_cursor_skips_removed_projection_ordinals_without_duplicates() {
    const RUN: &str = "0190a250-0000-7000-8000-000000000001";
    let mut events = Vec::new();
    for (seq, kind, payload) in [
        (1, "user.prompt.submitted", json!({"prompt":"first"})),
        (
            2,
            "permission.requested",
            json!({"gate_id":"gate-1","kind":"confirm","title":"Allow?","message":"Proceed?"}),
        ),
        (3, "user.prompt.submitted", json!({"prompt":"second"})),
        (4, "permission.resolved", json!({"gate_id":"gate-1"})),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a250-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = kind.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let mut cursor = None;
    let mut found = Vec::new();
    loop {
        let page = journal
            .open_thread(
                "workspace-1",
                ThreadOpenRequest {
                    thread_id: RUN.into(),
                    limit: 1,
                    cursor,
                },
            )
            .unwrap();
        found.extend(page.entries.into_iter().map(|entry| entry.text));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(found, [Some("first".into()), Some("second".into())]);
}

#[test]
fn thread_projection_cursor_keeps_its_snapshot_after_later_deltas() {
    const RUN: &str = "0190a300-0000-7000-8000-000000000001";
    let mut events = Vec::new();
    for (seq, kind, payload) in [
        (1, "run.started", json!({})),
        (2, "user.prompt.submitted", json!({"prompt":"question"})),
        (3, "model.stream.delta", json!({"text":"hello"})),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a300-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = kind.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let first = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: RUN.into(),
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();

    let mut later = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    later.event_id = "0190a300-0000-7000-8000-000000000004".into();
    later.run_seq = 4;
    later.event_type = "model.stream.delta".into();
    later.payload = EventPayload::Inline {
        payload_json: json!({"text":" world"}),
    };
    journal.append(3, &later).unwrap();

    let second = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: RUN.into(),
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(second.entries[0].text.as_deref(), Some("hello"));
}

#[test]
fn thread_open_rejects_bad_cursor_missing_thread_and_oversized_body_values() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    const OTHER_RUN: &str = "0190a100-0000-7000-8000-000000000002";
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN, "hello", "2026-07-16T03:00:00Z"))
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    journal
        .append(0, &prompt(OTHER_RUN, "hidden", "2026-07-16T03:01:00Z"))
        .unwrap();
    journal
        .bind_run_workspace(OTHER_RUN, "workspace-2")
        .unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            50,
            Operation::ThreadOpen,
            json!({"thread_id": RUN, "limit": 1, "cursor": "forged"}),
        ))
        .unwrap();
    client
        .write_all(&request(
            51,
            Operation::ThreadOpen,
            json!({"thread_id": "0190a100-0000-7000-8000-000000000099", "limit": 1}),
        ))
        .unwrap();
    client
        .write_all(&request(
            52,
            Operation::ThreadOpen,
            json!({"thread_id": RUN, "limit": 101}),
        ))
        .unwrap();
    for (id, body) in [
        (53, json!({"thread_id": "", "limit": 1})),
        (54, json!({"thread_id": "x".repeat(37), "limit": 1})),
        (55, json!({"thread_id": RUN, "limit": 1, "cursor": ""})),
        (
            56,
            json!({"thread_id": RUN, "limit": 1, "cursor": "x".repeat(1025)}),
        ),
        (
            57,
            json!({"thread_id": RUN, "limit": 1, "workspace": "other"}),
        ),
    ] {
        client
            .write_all(&request(id, Operation::ThreadOpen, body))
            .unwrap();
    }
    client
        .write_all(&request_with_idempotency(
            58,
            Operation::ThreadOpen,
            json!({"thread_id": RUN, "limit": 1}),
        ))
        .unwrap();
    client
        .write_all(&request(
            59,
            Operation::ThreadOpen,
            json!({"thread_id": OTHER_RUN, "limit": 1}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal
        ),
        Ok(())
    );
    let cursor: ErrorEnvelope = read_frame(&mut client);
    let missing: ErrorEnvelope = read_frame(&mut client);
    let oversized: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(cursor.error.code(), ErrorCode::InvalidCursor);
    assert_eq!(missing.error.code(), ErrorCode::InvalidRequest);
    assert_eq!(oversized.error.code(), ErrorCode::InvalidRequest);
    for id in 53..=58 {
        let hostile: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(
            hostile.request_id,
            Some(Id::new(format!("{id:032x}")).unwrap())
        );
        assert!(matches!(
            hostile.error.code(),
            ErrorCode::InvalidRequest | ErrorCode::IdempotencyKeyForbidden
        ));
        assert_eq!(
            serde_json::to_value(hostile.error).unwrap().get("details"),
            None
        );
    }
    let other_workspace: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(other_workspace.error.code(), missing.error.code());
    assert_eq!(
        serde_json::to_value(other_workspace.error)
            .unwrap()
            .get("details"),
        None
    );
    assert_eq!(
        serde_json::to_value(cursor.error).unwrap().get("details"),
        None
    );
    assert_eq!(
        serde_json::to_value(missing.error).unwrap().get("details"),
        None
    );
}

#[test]
fn journal_thread_list_maps_cursor_and_storage_failures_without_details() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    let cursor_error = journal
        .list_threads(
            "workspace-1",
            ThreadListRequest {
                limit: 1,
                cursor: Some("forged".into()),
            },
        )
        .unwrap_err();
    assert_eq!(cursor_error.code(), ErrorCode::InvalidRequest);

    let path = std::env::temp_dir().join(format!(
        "muniment-thread-list-storage-failure-{}.sqlite3",
        std::process::id()
    ));
    let mut journal = RunJournal::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE events")
        .unwrap();
    let storage_error = journal
        .list_threads(
            "workspace-1",
            ThreadListRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap_err();
    assert_eq!(storage_error.code(), ErrorCode::PersistenceFailed);
    assert!(!serde_json::to_string(&storage_error)
        .unwrap()
        .contains("events"));
    drop(journal);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn malformed_post_authorization_request_is_redacted_and_terminal() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&raw_frame(br#"{"secret":"/home/user""#))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = |_: &str, _: ThreadListRequest| -> Result<ThreadListPage, _> {
        panic!("malformed input must not dispatch")
    };
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service
        ),
        Err(AttachSessionError::MalformedFrame)
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::MalformedFrame);
    assert!(!serde_json::to_string(&error).unwrap().contains("/home"));
}

#[test]
fn authorization_is_rechecked_before_every_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(20, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client
        .write_all(&request(21, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let now = Rc::new(Cell::new(Duration::ZERO));
    let advance = now.clone();
    let calls = Cell::new(0);
    let mut service = move |_: &str, _: ThreadListRequest| {
        calls.set(calls.get() + 1);
        advance.set(Duration::from_secs(3601));
        Ok(ThreadListPage {
            threads: vec![],
            next_cursor: None,
        })
    };
    assert_eq!(
        dispatch_session(&mut client, server, TestClock(now), &mut service),
        Err(AttachSessionError::Authorization)
    );
    let _: Response = read_frame(&mut client);
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(
        error.request_id,
        Some(Id::new(format!("{:032x}", 21)).unwrap())
    );
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
}

#[test]
fn thread_open_without_read_scope_fails_closed_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(30, Operation::ThreadOpen, json!({})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = |_: &str, _: ThreadListRequest| -> Result<ThreadListPage, _> {
        panic!("unsupported operations must not dispatch")
    };
    let mut approved = approval();
    approved.scopes.clear();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service
        ),
        Err(AttachSessionError::Authorization)
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(
        error.request_id,
        Some(Id::new(format!("{:032x}", 30)).unwrap())
    );
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
}

#[test]
fn authorized_run_start_dispatches_once_with_bounded_input_and_provenance() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request_with_idempotency(
            70,
            Operation::RunStart,
            json!({"text": "Do the work", "context": {"selection": "safe"}}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = StartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body,
        json!({
            "run_id": "0190a100-0000-7000-8000-000000000001",
            "committed_seq": 2,
            "accepted_at": "2026-07-17T00:00:00Z"
        })
    );
    assert_eq!(service.calls.len(), 1);
    let (workspace, body, request_id, key, provenance) = &service.calls[0];
    assert_eq!(workspace, "workspace-1");
    assert_eq!(body.text, "Do the work");
    assert_eq!(body.context, Some(json!({"selection": "safe"})));
    assert_eq!(request_id, &Id::new(format!("{:032x}", 70)).unwrap());
    assert_eq!(key, &Id::new(format!("{:032x}", 1070)).unwrap());
    assert_eq!(provenance.profile, "profile-1");
    assert_eq!(provenance.companion_kind, "cli");
    assert_eq!(provenance.companion_version, "1.0.0");
    assert_eq!(provenance.peer_uid, unsafe { libc::geteuid() });
}

#[test]
fn operations_outside_run_start_remain_unsupported_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(79, Operation::RunOpen, json!({})))
        .unwrap();
    client
        .write_all(&request_with_idempotency(
            80,
            Operation::RunSteer,
            json!({"text": "private steer"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = StartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Ok(())
    );
    for id in [79, 80] {
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(
            error.request_id,
            Some(Id::new(format!("{id:032x}")).unwrap())
        );
        assert_eq!(error.error.code(), ErrorCode::UnsupportedOperation);
    }
    assert!(service.calls.is_empty());
}

#[test]
fn run_start_rejects_missing_scope_key_and_hostile_bodies_without_dispatch() {
    let cases = [
        (
            false,
            request_with_idempotency(71, Operation::RunStart, json!({"text": "secret prompt"})),
        ),
        (
            true,
            request(72, Operation::RunStart, json!({"text": "secret prompt"})),
        ),
        (
            true,
            request_with_idempotency(73, Operation::RunStart, json!({"text": ""})),
        ),
        (
            true,
            request_with_idempotency(
                74,
                Operation::RunStart,
                json!({"text": "x", "actor_id": "forged"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                75,
                Operation::RunStart,
                json!({"text": "x".repeat(MAX_RUN_START_TEXT_LENGTH + 1)}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                76,
                Operation::RunStart,
                json!({"text": "x", "context": vec!["x".repeat(40_000); MAX_RUN_START_CONTEXT_LENGTH / 40_000 + 1]}),
            ),
        ),
    ];
    for (has_scope, frame) in cases {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client.write_all(&frame).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        if has_scope {
            approved.scopes.insert("run.write".into());
        }
        let mut service = StartService::default();
        let _ = dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert!(matches!(
            error.error.code(),
            ErrorCode::Unauthorized | ErrorCode::IdempotencyKeyRequired | ErrorCode::InvalidRequest
        ));
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("secret prompt"));
        assert!(!encoded.contains("forged"));
        assert!(service.calls.is_empty());
    }
}

#[test]
fn malformed_run_start_service_output_is_a_redacted_closed_error() {
    let valid_run_id = "0190a100-0000-7000-8000-000000000001";
    let cases = [
        RunStartAccepted {
            run_id: "not-a-run-id".into(),
            committed_seq: 2,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            committed_seq: 0,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            committed_seq: 2,
            accepted_at: String::new(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            committed_seq: 2,
            accepted_at: "private malformed timestamp".into(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            committed_seq: 2,
            accepted_at: "private oversized timestamp".repeat(MAX_FRAME_LENGTH),
        },
    ];
    let mut expected_error = None;
    for (offset, output) in cases.into_iter().enumerate() {
        let id = 81 + offset as u128;
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request_with_idempotency(
                id,
                Operation::RunStart,
                json!({"text": "private prompt"}),
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        approved.scopes.insert("run.write".into());
        let mut service = StartService {
            output: Some(output),
            ..Default::default()
        };
        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approved,
                &mut service,
            ),
            Ok(())
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(
            error.request_id,
            Some(Id::new(format!("{id:032x}")).unwrap())
        );
        assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("private prompt"));
        assert!(!encoded.contains("private malformed timestamp"));
        assert!(!encoded.contains("private oversized timestamp"));
        assert!(!encoded.contains("profile-1"));
        assert!(!encoded.contains("1.0.0"));
        let error_value = serde_json::to_value(error.error).unwrap();
        assert_eq!(error_value.get("details"), None);
        if let Some(expected) = &expected_error {
            assert_eq!(&error_value, expected);
        } else {
            expected_error = Some(error_value);
        }
        assert_eq!(service.calls.len(), 1);
    }
}

#[test]
fn invalid_run_start_idempotency_key_is_terminal_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(
            &encode_frame(&json!({
                "protocol": "muniment.attach/1",
                "request_id": format!("{:032x}", 78),
                "operation": "run.start",
                "capability": "02".repeat(32),
                "idempotency_key": "invalid secret key",
                "body": {"text": "private prompt"}
            }))
            .unwrap(),
        )
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = StartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Err(AttachSessionError::MalformedFrame)
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::MalformedFrame);
    let encoded = serde_json::to_string(&error).unwrap();
    assert!(!encoded.contains("private prompt"));
    assert!(!encoded.contains("invalid secret key"));
    assert!(service.calls.is_empty());
}

#[test]
fn idle_expiry_is_typed_as_unauthorized_not_malformed() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let now = Rc::new(Cell::new(Duration::ZERO));
    let advance = now.clone();
    let calls = Rc::new(Cell::new(0));
    let approval_calls = calls.clone();
    let mut service = unavailable_service;
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(20),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(now),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                if approval_calls.replace(approval_calls.get() + 1) == 0 {
                    Some(ApprovalDecision::Approve(approval()))
                } else {
                    advance.set(Duration::from_secs(901));
                    None
                }
            },
        },
        &mut service,
    );
    assert_eq!(result, Err(AttachSessionError::Authorization));
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
}

#[test]
fn fragmented_request_frame_deadline_is_not_reported_as_malformed() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let frame = request(40, Operation::ThreadList, json!({"limit": 1}));
    client.write_all(&frame[..5]).unwrap();
    let mut service = unavailable_service;
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(20),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut service,
    );
    assert_eq!(result, Err(AttachSessionError::Timeout));
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}
