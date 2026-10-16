use super::*;
use std::net::TcpListener;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Mutex;

use crate::relay_encryption::{
    open_event, seal_command, CommandHeader, CommandKind, DirectionKey, OpenedEvent, SealedEvent,
};

const VECTORS: &str = include_str!(
    "../../../../protocol-fixtures/muniment.relay-encryption/1/relay-encryption-v1.json"
);

fn keys() -> RelayKeys {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let pairing = &vectors["pairing"];
    RelayKeys {
        pair_id: pairing["pair_id"].as_str().unwrap().to_owned(),
        desktop_to_phone: DirectionKey::decode(pairing["desktop_to_phone_key"].as_str().unwrap())
            .unwrap(),
        phone_to_desktop: DirectionKey::decode(pairing["phone_to_desktop_key"].as_str().unwrap())
            .unwrap(),
    }
}

struct FakeAccount {
    api_base: String,
    keys: Mutex<Option<RelayKeys>>,
}

impl RelayAccount for FakeAccount {
    fn keys(&self) -> Option<RelayKeys> {
        self.keys.lock().unwrap().clone()
    }

    fn connection(&self, pair_id: &str) -> Option<RelayConnection> {
        (self.keys()?.pair_id == pair_id).then(|| RelayConnection {
            api_base: self.api_base.clone(),
            access_token: "test-access-token".into(),
        })
    }
}

#[derive(Default)]
struct FakeRuntime {
    events: Mutex<Option<SyncSender<ChatEvent>>>,
    calls: Mutex<Vec<String>>,
}

impl RelayRuntime for FakeRuntime {
    fn subscribe(&self) -> Option<ChatEventSubscription> {
        let (sender, receiver) = sync_channel(64);
        *self.events.lock().unwrap() = Some(sender);
        Some(ChatEventSubscription::detached(receiver))
    }

    fn stop(&self, run_id: &str) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("stop {run_id}"));
        Ok(())
    }

    fn queue(&self, run_id: &str, delivery: ChatDelivery, text: &str) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{delivery:?} {run_id} {text}"));
        Ok(())
    }

    fn answer(
        &self,
        run_id: &str,
        gate_id: &str,
        answer: ChatPermissionAnswer,
    ) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("answer {run_id} {gate_id} {}", answer.decision()));
        Ok(())
    }
}

impl FakeRuntime {
    fn emit(&self, event: ChatEvent) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // A publisher that resubscribes drops the earlier stream.
            if let Some(sender) = self.events.lock().unwrap().as_ref() {
                if sender.send(event.clone()).is_ok() {
                    return;
                }
            }
            assert!(Instant::now() < deadline, "the publisher never subscribed");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_call(&self, count: usize) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let calls = self.calls.lock().unwrap().clone();
            if calls.len() >= count {
                return calls;
            }
            assert!(Instant::now() < deadline, "the runtime saw {calls:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

const RUN: &str = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

fn run_event(phase: &str, text: &str) -> ChatEvent {
    ChatEvent {
        run_id: RUN.into(),
        thread_id: Some("thread_local_0001".into()),
        phase: phase.into(),
        text: text.into(),
        prompt_accepted: true,
        turn_started: true,
        routing_stage: None,
        prompt_storage_notice: None,
        failure_reason: None,
        receipt: None,
        tool_activity: Vec::new(),
        attachments: Vec::new(),
        recalls: Vec::new(),
        applied_diffs: Vec::new(),
        pending_permission: None,
        delta: None,
        seq: None,
    }
}

/// The cloud side of one connection, as a test drives it.
struct StubRelay {
    socket: WebSocket<TcpStream>,
    authorization: String,
}

impl StubRelay {
    // The handshake callback's error type is tungstenite's own response.
    #[allow(clippy::result_large_err)]
    fn accept(listener: &TcpListener) -> Self {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut authorization = String::new();
        let socket = tungstenite::accept_hdr(
            stream,
            |request: &tungstenite::handshake::server::Request,
             response: tungstenite::handshake::server::Response| {
                assert_eq!(request.uri().path(), EVENTS_PATH);
                authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                Ok(response)
            },
        )
        .unwrap();
        let mut relay = Self {
            socket,
            authorization,
        };
        relay.send(json!({
            "type": "connection.ready",
            "service": "api",
            "version": "v1",
            "time": "2026-07-10T16:00:00.000Z",
            "data": {
                "protocol": RELAY_PROTOCOL,
                "session_relay_protocols": [RELAY_PROTOCOL],
                "connection_id": "con_desktop_0001",
                "org_id": "org_synthetic_0001",
                "user_id": "usr_synthetic_0001",
                "device_id": "11111111-1111-4111-8111-111111111111",
                "client_role": "desktop",
                "expires_at": "2099-01-01T00:00:00.000Z",
                "actor": {
                    "user_id": "usr_synthetic_0001",
                    "device_id": "11111111-1111-4111-8111-111111111111",
                    "role": "desktop",
                },
            },
        }));
        relay
    }

    fn send(&mut self, message: Value) {
        self.socket
            .send(Message::text(message.to_string()))
            .unwrap();
    }

    /// The next relay message of type `kind`, skipping heartbeats.
    fn next(&mut self, kind: &str) -> Value {
        loop {
            let message = match self.socket.read().unwrap() {
                Message::Text(text) => serde_json::from_str::<Value>(text.as_str()).unwrap(),
                _ => continue,
            };
            assert_eq!(message["protocol"], RELAY_PROTOCOL);
            assert_eq!(message["connection_id"], "con_desktop_0001");
            assert_eq!(message["actor"]["role"], "desktop");
            assert_eq!(message["actor"]["user_id"], "usr_synthetic_0001");
            assert_eq!(message["sequence"], 0);
            if message["type"] == kind {
                return message;
            }
            assert_eq!(message["type"], "session.event", "unexpected {message}");
        }
    }

    /// The next sealed event, opened with the phone's view of the keys.
    fn next_event(&mut self, keys: &RelayKeys) -> (EventHeader, OpenedEvent) {
        let message = self.next("session.event");
        let sealed: SealedEvent = serde_json::from_value(message["payload"].clone()).unwrap();
        let opened = open_event(
            &keys.desktop_to_phone,
            &sealed,
            message["session_id"].as_str().unwrap(),
        )
        .unwrap();
        (sealed.header, opened)
    }

    fn command(
        &mut self,
        keys: &RelayKeys,
        header: &CommandHeader,
        counter: u64,
        content: &CommandContent,
    ) {
        let sealed = seal_command(&keys.phone_to_desktop, header, counter, content).unwrap();
        self.forward(header, serde_json::to_value(sealed).unwrap());
    }

    fn forward(&mut self, header: &CommandHeader, payload: Value) {
        self.send(json!({
            "protocol": RELAY_PROTOCOL,
            "type": header.command_kind.envelope_type(),
            "message_id": header.command_id,
            "session_id": header.session_id,
            "connection_id": "con_mobile_0001",
            "device_id": "33333333-3333-4333-8333-333333333333",
            "actor": {
                "user_id": "usr_synthetic_0001",
                "device_id": "33333333-3333-4333-8333-333333333333",
                "role": "mobile",
            },
            "sequence": 0,
            "timestamp": relay_encryption::timestamp(Utc::now()),
            "payload": payload,
        }));
    }
}

fn command_header(
    kind: CommandKind,
    command_id: &str,
    session_id: &str,
    run_id: &str,
    gate_id: Option<&str>,
) -> CommandHeader {
    let now = Utc::now();
    CommandHeader {
        contract_version: relay_encryption::CONTRACT_VERSION.into(),
        header_type: "command".into(),
        command_kind: kind,
        command_id: command_id.into(),
        session_id: session_id.into(),
        run_id: run_id.into(),
        gate_id: gate_id.map(str::to_owned),
        created_at: relay_encryption::timestamp(now),
        expires_at: relay_encryption::timestamp(now + chrono::Duration::seconds(30)),
    }
}

fn temporary_state(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "muniment-relay-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn timing() -> RelayTiming {
    RelayTiming {
        idle_poll: Duration::from_millis(20),
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(100),
        read_tick: Duration::from_millis(10),
        silence_limit: Duration::from_secs(30),
        pair_check: Duration::from_millis(50),
    }
}

#[test]
fn the_publisher_registers_seals_applies_and_receipts() {
    let keys = keys();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let account = Arc::new(FakeAccount {
        api_base: format!("http://{}", listener.local_addr().unwrap()),
        keys: Mutex::new(Some(keys.clone())),
    });
    let runtime = Arc::new(FakeRuntime::default());
    let profile = temporary_state("publisher");
    let publisher = RelayPublisher::start_with_timing(
        account.clone(),
        runtime.clone(),
        relay_state_path(&profile),
        timing(),
    );
    let mut relay = StubRelay::accept(&listener);
    assert_eq!(relay.authorization, "Bearer test-access-token");

    // The relay's application heartbeat gets its pong.
    relay.send(json!({
        "protocol": RELAY_PROTOCOL, "type": "control.heartbeat", "message_id": "msg_ping_0001",
        "session_id": null, "connection_id": "con_desktop_0001",
        "device_id": "11111111-1111-4111-8111-111111111111",
        "actor": {"user_id": "usr_synthetic_0001", "device_id": "11111111-1111-4111-8111-111111111111", "role": "desktop"},
        "sequence": 0, "timestamp": "2026-07-10T16:00:01.000Z", "payload": {"kind": "ping", "nonce": "n-301"},
    }));
    let pong = relay.next("control.heartbeat");
    assert_eq!(pong["payload"], json!({"kind": "pong", "nonce": "n-301"}));

    // A device-wide notice is no run, and a live run registers a session and
    // publishes sealed events.
    let mut notice = run_event("sign-in-link", "https://example.test/sign-in");
    notice.run_id = "sign-in".into();
    runtime.emit(notice);
    runtime.emit(run_event("streaming", "Hello"));
    let register = relay.next("session.register");
    let session_id = register["session_id"].as_str().unwrap().to_owned();
    assert!(relay_encryption::valid_id(&session_id));
    assert_eq!(register["payload"]["run_id"], RUN);
    assert_eq!(register["payload"]["state"], "running");
    assert_eq!(
        register["payload"]["client_protocols"],
        json!([RELAY_PROTOCOL])
    );
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.sequence, "1");
    assert_eq!(header.phase, Phase::Running);
    assert_eq!(opened.content, EventContent::RunStatus { detail: None });
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.sequence, "2");
    assert_eq!(header.run_id, RUN);
    assert_eq!(
        opened.content,
        EventContent::AssistantDelta {
            text: "Hello".into()
        }
    );
    let first_counter = opened.counter;

    // A streamed delta extends the text.
    let mut delta = run_event("streaming", ", phone");
    delta.delta = Some(crate::run_events::ChatTextDelta::new(5));
    runtime.emit(delta);
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.sequence, "3");
    assert!(opened.counter > first_counter);
    assert_eq!(
        opened.content,
        EventContent::AssistantDelta {
            text: ", phone".into()
        }
    );

    // A sealed steer reaches the runtime and earns an applied receipt.
    let steer = command_header(
        CommandKind::Steer,
        "cmd_test_steer_0001",
        &session_id,
        RUN,
        None,
    );
    let content = CommandContent::Steer {
        text: "Focus on the tests".into(),
    };
    relay.command(&keys, &steer, 1, &content);
    let receipt = relay.next("command.receipt");
    assert_eq!(receipt["session_id"], session_id.as_str());
    assert_eq!(receipt["payload"]["command_id"], "cmd_test_steer_0001");
    assert_eq!(receipt["payload"]["stage"], "applied");
    assert_eq!(receipt["payload"]["result"], "steered");
    assert_eq!(
        runtime.wait_for_call(1),
        [format!("Steer {RUN} Focus on the tests")]
    );

    // The same sealed command again is a replay: the receipt repeats and
    // the runtime applies nothing more.
    let sealed = seal_command(&keys.phone_to_desktop, &steer, 1, &content).unwrap();
    relay.forward(&steer, serde_json::to_value(sealed).unwrap());
    let repeated = relay.next("command.receipt");
    assert_eq!(repeated["payload"], receipt["payload"]);
    assert_eq!(runtime.calls.lock().unwrap().len(), 1);

    // A permission gate opens in the header and the ask travels sealed.
    let mut asking = run_event("pending-permission", "Hello, phone");
    asking.pending_permission = Some(ChatPendingPermission {
        gate_id: "gate_local_0001".into(),
        request: PermissionRequest::Confirm {
            title: "Run tests".into(),
            message: "cargo test".into(),
            timeout: None,
        },
        diff: None,
    });
    runtime.emit(asking);
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.phase, Phase::WaitingForPermission);
    let window = header.permission.clone().unwrap();
    assert_eq!(window.gate_id, "gate_local_0001");
    let EventContent::PermissionAsk {
        gate_id,
        kind,
        summary,
        request_digest,
    } = opened.content
    else {
        panic!("expected an ask");
    };
    assert_eq!(
        (gate_id.as_str(), kind.as_str(), summary.as_str()),
        ("gate_local_0001", "confirm", "Run tests: cargo test")
    );

    // A changed header never opens: the desktop rejects it and asks for a new pair.
    let answer = command_header(
        CommandKind::PermissionAnswer,
        "cmd_test_answer_0001",
        &session_id,
        RUN,
        Some("gate_local_0001"),
    );
    let answer_content = CommandContent::PermissionAnswer {
        gate_id: "gate_local_0001".into(),
        decision: AnswerDecision::Allow,
        request_digest: request_digest.clone(),
    };
    let mut tampered = seal_command(&keys.phone_to_desktop, &answer, 2, &answer_content).unwrap();
    tampered.header.expires_at =
        relay_encryption::timestamp(Utc::now() + chrono::Duration::seconds(29));
    relay.forward(&answer, serde_json::to_value(&tampered).unwrap());
    let failure = relay.next("command.failure");
    assert_eq!(failure["payload"]["command_id"], "cmd_test_answer_0001");
    assert_eq!(failure["payload"]["terminal_status"], "rejected");
    assert_eq!(failure["payload"]["code"], "invalid_command");
    assert!(relay_key_mismatch(&profile, &keys.pair_id));

    // The phone's sealed allow answers the gate with a null result.
    relay.command(&keys, &answer, 3, &answer_content);
    let receipt = relay.next("command.receipt");
    assert_eq!(receipt["payload"]["gate_id"], "gate_local_0001");
    assert_eq!(receipt["payload"]["result"], Value::Null);
    let calls = runtime.wait_for_call(2);
    assert_eq!(
        calls[1],
        format!(
            "answer {RUN} gate_local_0001 {}",
            json!({"type": "confirm", "value": true})
        )
    );

    // The gate closes with the phone's decision, and the run ends.
    runtime.emit(run_event("streaming", "Hello, phone"));
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.phase, Phase::Running);
    assert_eq!(header.permission, None);
    assert_eq!(
        opened.content,
        EventContent::PermissionResolved {
            gate_id: "gate_local_0001".into(),
            decision: GateDecision::Allow
        }
    );
    runtime.emit(run_event("complete", "Hello, phone"));
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.phase, Phase::Completed);
    assert_eq!(opened.content, EventContent::RunStatus { detail: None });

    // A command for an ended run is rejected.
    let stop = command_header(
        CommandKind::Stop,
        "cmd_test_stop_0001",
        &session_id,
        RUN,
        None,
    );
    relay.command(
        &keys,
        &stop,
        4,
        &CommandContent::Stop {
            reason: relay_encryption::StopReason::UserRequested,
        },
    );
    let failure = relay.next("command.failure");
    assert_eq!(failure["payload"]["command_id"], "cmd_test_stop_0001");
    assert_eq!(runtime.calls.lock().unwrap().len(), 2);

    // Revoking the pair closes the connection.
    *account.keys.lock().unwrap() = None;
    let closed = loop {
        match relay.socket.read() {
            Ok(Message::Close(_)) | Err(_) => break true,
            Ok(_) => continue,
        }
    };
    assert!(closed);
    publisher.stop();
    let state = load_state(&relay_state_path(&profile), &keys.pair_id);
    assert!(state.send_reserved >= 1);
    assert_eq!(state.commands.highest, 4);
    std::fs::remove_dir_all(profile).unwrap();
}

#[test]
fn a_publisher_without_keys_never_connects() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let account = Arc::new(FakeAccount {
        api_base: format!("http://{}", listener.local_addr().unwrap()),
        keys: Mutex::new(None),
    });
    let profile = temporary_state("idle");
    let publisher = RelayPublisher::start_with_timing(
        account,
        Arc::new(FakeRuntime::default()),
        relay_state_path(&profile),
        timing(),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(listener.accept().is_err(), "no connection without keys");
    publisher.stop();
    std::fs::remove_dir_all(profile).unwrap();
}

#[test]
fn the_publisher_reconnects_and_registers_its_live_runs_again() {
    let keys = keys();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let account = Arc::new(FakeAccount {
        api_base: format!("http://{}", listener.local_addr().unwrap()),
        keys: Mutex::new(Some(keys.clone())),
    });
    let runtime = Arc::new(FakeRuntime::default());
    let profile = temporary_state("reconnect");
    let publisher = RelayPublisher::start_with_timing(
        account,
        runtime.clone(),
        relay_state_path(&profile),
        timing(),
    );
    let mut relay = StubRelay::accept(&listener);
    runtime.emit(run_event("streaming", "One"));
    let first = relay.next("session.register");
    let (header, _) = relay.next_event(&keys);
    assert_eq!(header.sequence, "1");
    relay.next_event(&keys);
    drop(relay);

    // The next connection re-registers the same session, and its sequence
    // and the sealed text continue where they stopped.
    let mut relay = StubRelay::accept(&listener);
    runtime.emit(run_event("streaming", "One two"));
    let second = relay.next("session.register");
    assert_eq!(second["session_id"], first["session_id"]);
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.sequence, "3");
    assert_eq!(
        opened.content,
        EventContent::RunStatus { detail: None },
        "a registration restates the run's status"
    );
    let (header, opened) = relay.next_event(&keys);
    assert_eq!(header.sequence, "4");
    assert_eq!(
        opened.content,
        EventContent::AssistantDelta {
            text: " two".into()
        }
    );
    publisher.stop();
    std::fs::remove_dir_all(profile).unwrap();
}

#[test]
fn deltas_split_long_text_and_redact_credentials() {
    let long = "é".repeat(MAX_DELTA_BYTES);
    let pieces = deltas(&long);
    assert_eq!(pieces.len(), 2);
    let joined: String = pieces
        .iter()
        .map(|piece| match piece {
            EventContent::AssistantDelta { text } => text.as_str(),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(joined, long);
    let secret = format!("token: sk-ant-api03-{}", "a".repeat(90));
    let redacted = redact(&secret);
    assert!(redacted.contains("[redacted]"), "{redacted}");
    assert!(!redacted.contains(&"a".repeat(90)));
}

#[test]
fn events_url_follows_the_api_scheme() {
    assert_eq!(
        events_url("https://api.example.test").unwrap().as_str(),
        "wss://api.example.test/v1/events"
    );
    assert_eq!(
        events_url("http://127.0.0.1:8080/").unwrap().as_str(),
        "ws://127.0.0.1:8080/v1/events"
    );
    assert!(events_url("ftp://example.test").is_err());
}

#[test]
fn a_deny_cancels_and_an_allow_needs_a_yes_or_no_gate() {
    let now = Utc::now();
    let gate = |request| {
        open_gate(
            &ChatPendingPermission {
                gate_id: "gate with spaces".into(),
                request,
                diff: None,
            },
            now,
        )
    };
    let select = gate(PermissionRequest::Select {
        title: "Pick".into(),
        options: vec!["A".into()],
        timeout: Some(60_000),
    });
    assert!(relay_encryption::valid_id(&select.relay_id));
    assert_eq!(select.expires - now, chrono::Duration::seconds(60));
    assert!(local_answer(&select, AnswerDecision::Allow).is_none());
    assert!(matches!(
        local_answer(&select, AnswerDecision::Deny),
        Some(ChatPermissionAnswer::Cancelled)
    ));
    let code = gate(PermissionRequest::CodeDiff {
        effect_id: "effect".into(),
        code_diff_id: "diff".into(),
        diff_sha256: "a".into(),
        write_plan_sha256: "b".into(),
    });
    assert_eq!(code.expires - now, chrono::Duration::minutes(5));
    assert!(matches!(
        local_answer(&code, AnswerDecision::Allow),
        Some(ChatPermissionAnswer::CodeDiff { gate_id, .. }) if gate_id == "gate with spaces"
    ));
}
