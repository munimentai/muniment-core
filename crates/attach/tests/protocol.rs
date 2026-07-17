use muniment_attach::*;
use serde_json::{json, Value};

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
fn authorized_round_trips_and_ignores_future_optional_fields() {
    let message = authorized(
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
    let welcome = welcome(1, "0.1.0", "server-nonce", "secret-challenge");
    let authorized = authorized("secret-capability", 3600, 900, Default::default());

    assert!(!format!("{welcome:?}").contains("secret-challenge"));
    assert!(!format!("{authorized:?}").contains("secret-capability"));
}

#[test]
fn hello_first_rejects_operation_shapes_but_allows_future_optional_fields() {
    let hybrid = json!({
        "protocol": PROTOCOL,
        "client": {"kind": "cli", "version": "1.0.0"},
        "supported": {"min": 1, "max": 1},
        "client_nonce": "client-nonce",
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
