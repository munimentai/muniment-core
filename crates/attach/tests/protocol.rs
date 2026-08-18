use muniment_attach::*;
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixture_temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-fixtures-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn exporter(root: &PathBuf, check: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_export-attach-fixtures"));
    command.arg(root);
    if check {
        command.arg("--check");
    }
    command.output().unwrap()
}

fn generated_fixture_dir() -> PathBuf {
    let root = fixture_temp_dir();
    let output = exporter(&root, false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    root
}

fn assert_check_failure(root: &PathBuf, classification: &str, filename: &str) {
    let output = exporter(root, true);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(classification), "{stderr}");
    assert!(stderr.contains(filename), "{stderr}");
}

#[test]
fn fixture_exporter_check_accepts_a_clean_corpus() {
    let root = generated_fixture_dir();
    assert!(exporter(&root, true).status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fixture_exporter_check_reports_missing_without_writing() {
    let root = generated_fixture_dir();
    let fixture = root.join("muniment.attach/1/request-thread-list.json");
    fs::remove_file(&fixture).unwrap();
    assert_check_failure(&root, "missing:", "request-thread-list.json");
    assert!(!fixture.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fixture_exporter_check_reports_extra_without_writing() {
    let root = generated_fixture_dir();
    let fixture = root.join("muniment.attach/1/extra.json");
    fs::write(&fixture, b"{}\n").unwrap();
    assert_check_failure(&root, "extra:", "extra.json");
    assert_eq!(fs::read(&fixture).unwrap(), b"{}\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fixture_exporter_check_reports_stale_without_writing() {
    let root = generated_fixture_dir();
    let fixture = root.join("muniment.attach/1/response-run-start.json");
    fs::write(&fixture, b"{}\n").unwrap();
    assert_check_failure(&root, "stale:", "response-run-start.json");
    assert_eq!(fs::read(&fixture).unwrap(), b"{}\n");
    fs::remove_dir_all(root).unwrap();
}

fn canonical_fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol-fixtures/muniment.attach/1")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn canonical_run_start_fixtures_match_client_contracts() {
    let request: Envelope =
        serde_json::from_value(canonical_fixture("request-run-start.json")).unwrap();
    let Envelope::Request(request) = request else {
        panic!("expected request fixture");
    };
    assert_eq!(request.operation, Operation::RunStart);
    assert_eq!(
        request.body,
        json!({
            "text": "Summarize the selected file.",
            "context": {"selected_file": "src/main.rs"}
        })
    );

    let response: Envelope =
        serde_json::from_value(canonical_fixture("response-run-start.json")).unwrap();
    let Envelope::Response(response) = response else {
        panic!("expected response fixture");
    };
    assert_eq!(response.request_id, request.request_id);
    #[cfg(feature = "client")]
    {
        let accepted: RunStartAccepted = serde_json::from_value(response.body).unwrap();
        assert_eq!(accepted.committed_seq, 1);
    }
    #[cfg(not(feature = "client"))]
    assert_eq!(response.body["committed_seq"], 1);
}

#[test]
fn canonical_desktop_run_fixtures_round_trip_byte_for_byte() {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol-fixtures/muniment.attach/1");
    let requests = [
        (
            "request-run-submit.json",
            Operation::RunSubmit,
            json!({
                "text": "Summarize the selected file.",
                "files": ["/work/repo/src/main.rs"],
                "thread_id": null
            }),
        ),
        (
            "request-run-resume.json",
            Operation::RunResume,
            json!({"run_id": "00000000000000000000000000000191"}),
        ),
        (
            "request-run-permission-answer.json",
            Operation::RunPermissionAnswer,
            json!({
                "run_id": "00000000000000000000000000000191",
                "gate_id": "permission-1",
                "answer": {"type": "confirm", "value": true}
            }),
        ),
    ];

    for (name, operation, body) in requests {
        let bytes = fs::read(directory.join(name)).unwrap();
        let request: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request.operation, operation);
        let wire_name = serde_json::to_value(operation).unwrap();
        assert_eq!(wire_name, json!(operation.as_str()));
        assert_eq!(
            serde_json::from_value::<Operation>(wire_name).unwrap(),
            operation
        );
        assert!(request.operation.requires_idempotency_key());
        assert!(request.idempotency_key.is_some());
        assert_eq!(request.body, body);
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        assert_eq!(encoded, bytes);
    }

    let bytes = fs::read(directory.join("response-run-submit.json")).unwrap();
    let response: Response = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.request_id,
        Id::new("00000000000000000000000000000080").unwrap()
    );
    assert_eq!(
        response.body,
        json!({
            "run_id": "00000000000000000000000000000191",
            "thread_id": "00000000000000000000000000000192",
            "attachments": [{
                "displayName": "main.rs",
                "byteLength": 128,
                "mediaType": "text/rust"
            }],
            "committed_seq": 1,
            "accepted_at": "2026-07-17T00:00:00Z"
        })
    );
    let mut encoded = serde_json::to_vec(&response).unwrap();
    encoded.push(b'\n');
    assert_eq!(encoded, bytes);
}

#[test]
fn canonical_thread_create_fixtures_match_client_contracts() {
    let request: Envelope =
        serde_json::from_value(canonical_fixture("request-thread-create.json")).unwrap();
    let Envelope::Request(request) = request else {
        panic!("expected request fixture");
    };
    assert_eq!(request.operation, Operation::ThreadCreate);
    assert_eq!(request.body, json!({}));
    assert!(request.idempotency_key.is_some());

    let response: Envelope =
        serde_json::from_value(canonical_fixture("response-thread-create.json")).unwrap();
    let Envelope::Response(response) = response else {
        panic!("expected response fixture");
    };
    assert_eq!(response.request_id, request.request_id);
    #[cfg(feature = "client")]
    serde_json::from_value::<muniment_attach::ThreadCreateAccepted>(response.body).unwrap();
}

#[test]
fn canonical_thread_read_fixtures_decode_to_their_operations() {
    for (name, operation) in [
        ("request-thread-summaries.json", Operation::ThreadSummaries),
        ("request-thread-history.json", Operation::ThreadHistory),
    ] {
        let envelope: Envelope = serde_json::from_value(canonical_fixture(name)).unwrap();
        let Envelope::Request(request) = envelope else {
            panic!("expected request fixture");
        };
        assert_eq!(request.operation, operation);
    }
}

#[test]
fn canonical_thread_select_fixtures_match_the_wire_contract() {
    let request: Request =
        serde_json::from_value(canonical_fixture("request-thread-select.json")).unwrap();
    assert_eq!(request.operation, Operation::ThreadSelect);
    assert_eq!(request.operation.as_str(), "thread.select");
    assert_eq!(
        serde_json::to_value(request.operation).unwrap(),
        json!("thread.select")
    );
    assert!(!request.operation.requires_idempotency_key());
    assert!(request.idempotency_key.is_none());
    assert_eq!(request.body, json!({"thread_id": "thread-1"}));

    let response: Response =
        serde_json::from_value(canonical_fixture("response-thread-select.json")).unwrap();
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.body, json!({}));
}

#[test]
fn canonical_retention_recheck_fixtures_match_the_wire_contract() {
    let request: Request =
        serde_json::from_value(canonical_fixture("request-retention-recheck.json")).unwrap();
    assert_eq!(request.operation, Operation::RetentionRecheck);
    assert_eq!(request.operation.as_str(), "retention.recheck");
    assert_eq!(
        serde_json::to_value(request.operation).unwrap(),
        json!("retention.recheck")
    );
    assert!(!request.operation.requires_idempotency_key());
    assert!(request.idempotency_key.is_none());
    assert_eq!(request.body, json!({}));

    let response: Response =
        serde_json::from_value(canonical_fixture("response-retention-recheck.json")).unwrap();
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.body, json!({}));
}

#[test]
fn canonical_chat_event_fixtures_round_trip_byte_for_byte() {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol-fixtures/muniment.attach/1");

    let request_bytes = fs::read(directory.join("request-run-chat-events.json")).unwrap();
    let request: Request = serde_json::from_slice(&request_bytes).unwrap();
    assert_eq!(request.operation, Operation::RunChatEvents);
    assert_eq!(request.operation.as_str(), "run.chat_events");
    assert!(!request.operation.requires_idempotency_key());
    assert_eq!(request.body, json!({}));
    let mut encoded_request = serde_json::to_vec(&request).unwrap();
    encoded_request.push(b'\n');
    assert_eq!(encoded_request, request_bytes);

    let event_bytes = fs::read(directory.join("event-chat-event.json")).unwrap();
    let event: Event = serde_json::from_slice(&event_bytes).unwrap();
    assert_eq!(event.event, EventName::ChatEvent);
    assert_eq!(
        event.subscription_id.as_str(),
        "00000000000000000000000000000190"
    );
    assert!(event.run_id.is_none());
    assert!(event.run_seq.is_none());
    assert_eq!(
        event.body,
        json!({
            "runId": "00000000000000000000000000000191",
            "phase": "running",
            "text": "Review the selected file.",
            "toolActivity": [],
            "attachments": [],
            "recalls": [],
            "appliedDiffs": []
        })
    );
    let mut encoded_event = serde_json::to_vec(&event).unwrap();
    encoded_event.push(b'\n');
    assert_eq!(encoded_event, event_bytes);
}

#[test]
fn canonical_cursor_ack_and_permission_fixtures_match_client_contracts() {
    let request: Envelope =
        serde_json::from_value(canonical_fixture("request-run-cursor-ack.json")).unwrap();
    let Envelope::Request(request) = request else {
        panic!("expected request fixture");
    };
    assert_eq!(request.operation, Operation::RunCursorAck);
    assert_eq!(
        request.body,
        json!({
            "subscription_id": "00000000000000000000000000000190",
            "through_run_seq": 7
        })
    );

    let event: Envelope =
        serde_json::from_value(canonical_fixture("event-permission-pending.json")).unwrap();
    let Envelope::Event(event) = event else {
        panic!("expected event fixture");
    };
    assert_eq!(event.event, EventName::PermissionPending);
    #[cfg(feature = "client")]
    {
        let permission: PendingPermission = serde_json::from_value(event.body).unwrap();
        assert_eq!(permission.kind, PermissionKind::Confirm);
    }
    #[cfg(not(feature = "client"))]
    assert_eq!(event.body["kind"], "confirm");
}

#[test]
fn canonical_command_and_artifact_fixtures_match_the_pinned_contract() {
    for (name, operation, text) in [
        (
            "request-run-steer.json",
            Operation::RunSteer,
            "Focus on error handling.",
        ),
        (
            "request-run-follow-up.json",
            Operation::RunFollowUp,
            "Now suggest tests.",
        ),
    ] {
        let Envelope::Request(request) = serde_json::from_value(canonical_fixture(name)).unwrap()
        else {
            panic!("expected request fixture");
        };
        assert_eq!(request.operation, operation);
        assert_eq!(request.body["text"], text);
        assert!(request.body.get("prompt").is_none());
        Id::new(request.body["run_id"].as_str().unwrap().to_owned()).unwrap();
    }

    let transfer_id = "00000000000000000000000000000190";
    let artifact_id = "00000000000000000000000000000192";
    let sha256 = "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d";
    Id::new(transfer_id.to_owned()).unwrap();
    Id::new(artifact_id.to_owned()).unwrap();

    let Envelope::Request(window) =
        serde_json::from_value(canonical_fixture("request-artifact-window.json")).unwrap()
    else {
        panic!("expected artifact window request");
    };
    assert_eq!(window.operation, Operation::ArtifactWindow);
    assert_eq!(
        window.body,
        json!({"transfer_id": transfer_id, "ack_through_chunk": -1, "max_chunks": 1})
    );

    let Envelope::Event(chunk) =
        serde_json::from_value(canonical_fixture("event-artifact-chunk.json")).unwrap()
    else {
        panic!("expected artifact chunk event");
    };
    assert_eq!(chunk.subscription_id.as_str(), transfer_id);
    assert_eq!(chunk.run_id, None);
    assert_eq!(chunk.run_seq, None);
    assert_eq!(chunk.body["artifact_id"], artifact_id);
    assert_eq!(chunk.body["chunk_index"], 0);
    assert_eq!(chunk.body["offset"], 0);
    assert_eq!(chunk.body["byte_length"], 7);
    assert_eq!(chunk.body["chunk_sha256"], sha256);
    assert_eq!(chunk.body["data"], "Zml4dHVyZQ==");

    let Envelope::Event(complete) =
        serde_json::from_value(canonical_fixture("event-artifact-complete.json")).unwrap()
    else {
        panic!("expected artifact complete event");
    };
    assert_eq!(complete.subscription_id.as_str(), transfer_id);
    assert_eq!(complete.body["transfer_id"], transfer_id);
    assert_eq!(complete.body["artifact_id"], artifact_id);
    assert_eq!(complete.body["total_bytes"], 7);
    assert_eq!(complete.body["sha256"], sha256);

    let Envelope::Request(cancel) =
        serde_json::from_value(canonical_fixture("request-request-cancel.json")).unwrap()
    else {
        panic!("expected cancellation request");
    };
    assert_eq!(cancel.operation, Operation::RequestCancel);
    assert_eq!(cancel.body["kind"], "request");
    Id::new(cancel.body["request_id"].as_str().unwrap().to_owned()).unwrap();

    let Envelope::Event(closed) =
        serde_json::from_value(canonical_fixture("event-stream-closed.json")).unwrap()
    else {
        panic!("expected stream close event");
    };
    assert_eq!(closed.event, EventName::StreamClosed);
    assert_eq!(closed.body, json!({"code": "cancelled", "resumable": true}));
}

fn id(n: u128) -> Id {
    Id::new(format!("{n:032x}")).unwrap()
}

fn round_trip(value: Envelope) {
    let encoded = encode_frame(&value).unwrap();
    let (decoded, consumed) = decode_frame::<Envelope>(&encoded).unwrap().unwrap();
    assert_eq!(decoded, value);
    assert_eq!(consumed, encoded.len());
    assert_eq!(encode_frame(&decoded).unwrap(), encoded);
}

#[test]
fn all_envelope_kinds_round_trip() {
    round_trip(Envelope::Request(Request {
        protocol: Protocol,
        request_id: id(1),
        operation: Operation::RunStart,
        capability: "connection-capability".into(),
        idempotency_key: Some(id(2)),
        body: json!({"text":"hello"}),
    }));
    round_trip(Envelope::Response(Response {
        protocol: Protocol,
        request_id: id(1),
        ok: Success,
        body: json!({"accepted":true}),
    }));
    round_trip(Envelope::Error(ErrorEnvelope {
        protocol: Protocol,
        request_id: Some(id(1)),
        ok: Failure,
        error: ProtocolError::malformed_frame(),
    }));
    round_trip(Envelope::Event(Event {
        protocol: Protocol,
        subscription_id: id(3),
        event: EventName::RunEvent,
        run_id: Some(id(4)),
        run_seq: Some(7),
        body: json!({"kind":"message"}),
    }));
}

#[test]
fn envelope_discriminants_are_fixed_on_encode_and_decode() {
    assert_eq!(serde_json::to_value(Success).unwrap(), true);
    assert_eq!(serde_json::to_value(Failure).unwrap(), false);
    assert!(serde_json::from_value::<Success>(json!(false)).is_err());
    assert!(serde_json::from_value::<Failure>(json!(true)).is_err());

    let response = Response {
        protocol: Protocol,
        request_id: id(1),
        ok: Success,
        body: json!({}),
    };
    let error = ErrorEnvelope {
        protocol: Protocol,
        request_id: None,
        ok: Failure,
        error: ProtocolError::malformed_frame(),
    };
    assert_eq!(serde_json::to_value(response).unwrap()["ok"], true);
    assert_eq!(serde_json::to_value(error).unwrap()["ok"], false);
}

#[test]
fn frame_errors_and_incremental_decode_are_bounded() {
    let oversized = ((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes();
    assert!(matches!(
        decode_frame::<Value>(&oversized),
        Err(FrameError::PayloadTooLarge)
    ));

    let valid = encode_frame(&json!({"hello":"world"})).unwrap();
    for split in 0..valid.len() {
        assert!(decode_frame::<Value>(&valid[..split]).unwrap().is_none());
    }
    assert_eq!(
        decode_frame::<Value>(&valid).unwrap().unwrap().0,
        json!({"hello":"world"})
    );

    let truncated = [&(10u32.to_be_bytes())[..], b"{}"].concat();
    assert!(decode_frame::<Value>(&truncated).unwrap().is_none());
    let invalid_utf8 = [&(1u32.to_be_bytes())[..], &[0xff]].concat();
    assert!(matches!(
        decode_frame::<Value>(&invalid_utf8),
        Err(FrameError::InvalidUtf8)
    ));
    let invalid_json = [&(1u32.to_be_bytes())[..], b"{"].concat();
    assert!(matches!(
        decode_frame::<Value>(&invalid_json),
        Err(FrameError::InvalidJson)
    ));
}

#[test]
fn envelope_ids_are_bounded_uuid_strings() {
    let bad = json!({
        "protocol": PROTOCOL, "request_id": "x".repeat(MAX_ID_LENGTH + 1),
        "operation": "thread.list", "capability": "c", "body": {}
    });
    let frame = encode_frame(&bad).unwrap();
    assert!(matches!(
        decode_frame::<Envelope>(&frame),
        Err(FrameError::InvalidJson)
    ));
}

fn raw_json_frame(payload: &[u8]) -> Vec<u8> {
    [&(payload.len() as u32).to_be_bytes()[..], payload].concat()
}

#[test]
fn frame_structural_limits_are_enforced_independently() {
    let nested = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert!(matches!(
        decode_frame::<Value>(&raw_json_frame(nested.as_bytes())),
        Err(FrameError::StructureLimit)
    ));

    let long_string = serde_json::to_string(&"x".repeat(MAX_TEXT_LENGTH + 1)).unwrap();
    assert!(matches!(
        decode_frame::<Value>(&raw_json_frame(long_string.as_bytes())),
        Err(FrameError::StructureLimit)
    ));

    // Each object entry contributes its key and string value to the string count.
    let too_many_strings = Value::Object(
        (0..(MAX_JSON_STRINGS / 2 + 1))
            .map(|i| (format!("k{i}"), json!("v")))
            .collect(),
    );
    let payload = serde_json::to_vec(&too_many_strings).unwrap();
    assert!(matches!(
        decode_frame::<Value>(&raw_json_frame(&payload)),
        Err(FrameError::StructureLimit)
    ));

    let too_many_entries = Value::Array(vec![Value::Null; MAX_JSON_COLLECTION_ENTRIES + 1]);
    let payload = serde_json::to_vec(&too_many_entries).unwrap();
    assert!(matches!(
        decode_frame::<Value>(&raw_json_frame(&payload)),
        Err(FrameError::StructureLimit)
    ));
}

#[test]
fn hello_welcome_and_version_overlap() {
    let hello = Hello {
        protocol: Protocol,
        client: Client {
            kind: "cli".into(),
            version: "1.0.0".into(),
        },
        supported: VersionRange { min: 1, max: 2 },
        client_nonce: "client-nonce".into(),
        authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000099").unwrap(),
        authorized_client_credential: None,
    };
    let selected =
        negotiate_first(FirstMessage::Hello(hello), VersionRange { min: 1, max: 1 }).unwrap();
    let welcome = welcome(selected, "0.1.0", "server-nonce", "challenge");
    assert_eq!(welcome.selected, 1);
    assert_eq!(welcome.authorization, Authorization::PairingRequired);
    assert_eq!(
        serde_json::to_value(welcome).unwrap()["authorization"],
        "pairing_required"
    );
}

#[test]
fn runtime_version_compatibility_compares_numeric_segments() {
    assert!(runtime_version_meets_minimum("1.2.3", "1.2.3"));
    assert!(runtime_version_meets_minimum("1.10.0", "1.2.9"));
    assert!(!runtime_version_meets_minimum("1.2.2", "1.2.3"));
    assert!(!runtime_version_meets_minimum("1.2", "1.2.1"));
    assert!(runtime_version_meets_minimum("1.2.0", "1.2"));

    for malformed in ["", "1..2", "1.2-beta", " 1.2", "1.2."] {
        assert!(!runtime_version_meets_minimum(malformed, "1.0.0"));
    }
}

#[test]
fn authorized_round_trips_and_ignores_future_optional_fields() {
    let message = authorized(
        "profile-id",
        "connection-capability",
        3600,
        900,
        [(
            "workspace-1".into(),
            ["thread.read".into()].into_iter().collect(),
        )]
        .into_iter()
        .collect(),
    );
    let encoded = encode_frame(&message).unwrap();
    let decoded = decode_frame::<Authorized>(&encoded).unwrap().unwrap().0;
    assert_eq!(decoded, message);

    let mut value = serde_json::to_value(&message).unwrap();
    value["future_optional"] = json!(true);
    assert_eq!(
        serde_json::from_value::<Authorized>(value).unwrap(),
        message
    );
}

#[test]
fn handshake_wire_debug_redacts_secrets() {
    let welcome = welcome(1, "0.1.0", "server-nonce", "secret-challenge")
        .with_handoff_nonce("secret-handoff-nonce");
    let authorized = authorized(
        "profile-id",
        "secret-capability",
        3600,
        900,
        Default::default(),
    );
    let request = Request {
        protocol: Protocol,
        request_id: id(1),
        operation: Operation::ThreadList,
        capability: "secret-capability".into(),
        idempotency_key: None,
        body: json!({"cursor": "secret-cursor"}),
    };
    let response = Response {
        protocol: Protocol,
        request_id: id(1),
        ok: Success,
        body: json!({"next_cursor": "secret-cursor"}),
    };

    let welcome_debug = format!("{welcome:?}");
    assert!(!welcome_debug.contains("secret-challenge"));
    assert!(!welcome_debug.contains("secret-handoff-nonce"));
    assert!(welcome_debug.contains("handoff_nonce: \"[REDACTED]\""));
    assert!(!format!("{authorized:?}").contains("secret-capability"));
    assert!(!format!("{request:?}").contains("secret-capability"));
    assert!(!format!("{request:?}").contains("secret-cursor"));
    assert!(!format!("{response:?}").contains("secret-cursor"));
}

#[test]
fn welcome_round_trips_with_and_without_a_handoff_nonce() {
    let without_nonce = welcome(1, "0.1.0", "server-nonce", "challenge");
    let encoded = serde_json::to_value(&without_nonce).unwrap();
    assert!(encoded.get("handoff_nonce").is_none());
    assert_eq!(
        serde_json::from_value::<Welcome>(encoded).unwrap(),
        without_nonce
    );

    let with_nonce =
        welcome(1, "0.1.0", "server-nonce", "challenge").with_handoff_nonce("handoff-nonce");
    let encoded = serde_json::to_value(&with_nonce).unwrap();
    assert_eq!(encoded["handoff_nonce"], "handoff-nonce");
    assert_eq!(
        serde_json::from_value::<Welcome>(encoded).unwrap(),
        with_nonce
    );
}

#[test]
fn hello_first_rejects_operation_shapes_but_allows_future_optional_fields() {
    let hybrid = json!({
        "protocol": PROTOCOL,
        "client": {"kind": "cli", "version": "1.0.0"},
        "supported": {"min": 1, "max": 1},
        "client_nonce": "client-nonce",
        "authorized_client_id": id(99),
        "request_id": id(1),
        "operation": "thread.list",
        "capability": "connection-capability",
        "body": {}
    });
    let first = serde_json::from_value::<FirstMessage>(hybrid).unwrap();
    assert!(matches!(first, FirstMessage::Other(_)));
    assert!(matches!(
        negotiate_first(first, VersionRange { min: 1, max: 1 }),
        Err(NegotiationError::HelloRequired)
    ));

    let future_hello = json!({
        "protocol": PROTOCOL,
        "client": {"kind": "cli", "version": "1.0.0"},
        "supported": {"min": 1, "max": 1},
        "client_nonce": "client-nonce",
        "authorized_client_id": id(99),
        "future_optional": {"enabled": true}
    });
    let first = serde_json::from_value::<FirstMessage>(future_hello).unwrap();
    assert!(matches!(
        negotiate_first(first, VersionRange { min: 1, max: 1 }),
        Ok(1)
    ));
}

#[test]
fn incompatibility_is_actionable_and_discloses_no_runtime_state() {
    let error = negotiate_version(
        VersionRange { min: 2, max: 2 },
        VersionRange { min: 1, max: 1 },
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProtocolIncompatible);
    assert_eq!(error.action(), Some(ErrorAction::UpgradeDesktop));
    let serialized = serde_json::to_string(&error).unwrap();
    for forbidden in ["profile", "session", "workspace", "entitlement", "runtime"] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn error_schema_rejects_arbitrary_messages_and_mismatched_details() {
    let approved = [
        ProtocolError::malformed_frame(),
        ProtocolError::payload_too_large(),
        ProtocolError::protocol_incompatible(
            VersionRange { min: 1, max: 1 },
            ErrorAction::UpgradeCompanion,
        ),
    ];
    let serialized = serde_json::to_string(&approved).unwrap();
    assert!(!serialized.contains("/home/user/.env"));

    let injected = json!({
        "code": "malformed_frame",
        "message": "/home/user/.env contains TOKEN=secret",
        "retryable": false
    });
    assert!(serde_json::from_value::<ProtocolError>(injected).is_err());

    let mismatched = json!({
        "code": "payload_too_large",
        "message": "The frame is malformed.",
        "retryable": false
    });
    assert!(serde_json::from_value::<ProtocolError>(mismatched).is_err());

    let secret_detail = json!({
        "code": "protocol_incompatible",
        "message": "The companion and desktop protocol versions are incompatible.",
        "retryable": false,
        "action": "upgrade_companion",
        "details": {
            "supported": {"min": 1, "max": 1},
            "token": "secret"
        }
    });
    assert!(serde_json::from_value::<ProtocolError>(secret_detail).is_err());
}

#[test]
fn envelope_shapes_reject_conflicting_fields_but_allow_future_optional_fields() {
    let mixed = json!({
        "protocol": PROTOCOL,
        "request_id": id(1),
        "operation": "thread.list",
        "capability": "c",
        "ok": true,
        "body": {}
    });
    assert!(serde_json::from_value::<Envelope>(mixed).is_err());

    let mixed_event = json!({
        "protocol": PROTOCOL,
        "subscription_id": id(2),
        "event": "run.event",
        "request_id": id(1),
        "body": {}
    });
    assert!(serde_json::from_value::<Envelope>(mixed_event).is_err());

    let future_response = json!({
        "protocol": PROTOCOL,
        "request_id": id(1),
        "ok": true,
        "body": {},
        "future_optional": "ignored"
    });
    assert!(matches!(
        serde_json::from_value::<Envelope>(future_response).unwrap(),
        Envelope::Response(_)
    ));
}

#[test]
fn unknown_v1_events_are_representable_and_ignorable() {
    let event = json!({
        "protocol": PROTOCOL,
        "subscription_id": id(3),
        "event": "future.optional_event",
        "body": {}
    });
    let Envelope::Event(event) = serde_json::from_value::<Envelope>(event).unwrap() else {
        panic!("expected event envelope");
    };
    let EventName::Unknown(name) = event.event else {
        panic!("expected unknown event name");
    };
    assert_eq!(name.as_str(), "future.optional_event");
}

#[test]
fn peer_grant_uses_empty_workspace_authority() {
    let grant = PeerAuthorizedGrant {
        capability: "capability".into(),
        expires_at: 60,
        idle_timeout_seconds: 30,
    };
    assert_eq!(
        serde_json::to_string(&grant).unwrap(),
        r#"{"profile_id":"","capability":"capability","expires_at":60,"idle_timeout_seconds":30,"workspace_scopes":{}}"#
    );

    let mut invalid = serde_json::to_value(grant).unwrap();
    invalid["profile_id"] = json!("profile-1");
    assert!(serde_json::from_value::<PeerAuthorizedGrant>(invalid).is_err());

    let invalid = json!({
        "profile_id": "",
        "capability": "capability",
        "expires_at": 60,
        "idle_timeout_seconds": 30,
        "workspace_scopes": {"/work/signed": ["threads:read"]}
    });
    assert!(serde_json::from_value::<PeerAuthorizedGrant>(invalid).is_err());
}

#[test]
fn desktop_client_grant_allows_empty_workspace_authority() {
    let empty_profile = json!({
        "profile_id": "",
        "capability": "capability",
        "expires_at": 60,
        "idle_timeout_seconds": 30,
        "workspace_scopes": {"/work/signed": ["threads:read"]}
    });
    assert!(serde_json::from_value::<DesktopClientAuthorizedGrant>(empty_profile).is_err());

    let empty_scopes = json!({
        "profile_id": "profile-1",
        "capability": "capability",
        "expires_at": 60,
        "idle_timeout_seconds": 30,
        "workspace_scopes": {}
    });
    let grant = serde_json::from_value::<DesktopClientAuthorizedGrant>(empty_scopes).unwrap();
    assert!(grant.workspace_scopes.is_empty());
}
