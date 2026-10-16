use super::*;
use serde_json::json;

// The vectors of `muniment.relay-encryption/1` with pairing revision
// `muniment.remote-control-pairing/2`, copied unchanged from the cloud's
// conformance package `test/fixtures/relay-encryption/relay-encryption-v1.json`.
const VECTORS: &str = include_str!(
    "../../../../protocol-fixtures/muniment.relay-encryption/1/relay-encryption-v1.json"
);

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a string"))
}

fn bytes32(value: &Value, field: &str) -> [u8; 32] {
    decode_exact(text(value, field)).unwrap()
}

fn keys_of(pairing: &Value) -> RelayKeys {
    RelayKeys {
        pair_id: text(pairing, "pair_id").to_owned(),
        desktop_to_phone: DirectionKey::decode(text(pairing, "desktop_to_phone_key")).unwrap(),
        phone_to_desktop: DirectionKey::decode(text(pairing, "phone_to_desktop_key")).unwrap(),
    }
}

fn direction_key<'a>(keys: &'a RelayKeys, direction: &str) -> &'a DirectionKey {
    match direction {
        "desktop_to_phone" => &keys.desktop_to_phone,
        "phone_to_desktop" => &keys.phone_to_desktop,
        other => panic!("unknown direction {other}"),
    }
}

fn check_pairing_vector(pairing: &Value) {
    let desktop =
        AgreementKeyPair::from_private_bytes(bytes32(pairing, "desktop_agreement_private_key"));
    let mobile =
        AgreementKeyPair::from_private_bytes(bytes32(pairing, "mobile_agreement_private_key"));
    let desktop_key = text(pairing, "desktop_agreement_key");
    let mobile_key = text(pairing, "mobile_agreement_key");
    assert_eq!(desktop.public_key(), desktop_key);
    assert_eq!(mobile.public_key(), mobile_key);

    let transcript = proof_transcript(
        text(pairing, "desktop_device_id"),
        text(pairing, "mobile_device_id"),
        text(pairing, "challenge"),
        desktop_key,
        mobile_key,
    );
    assert_eq!(transcript, text(pairing, "proof_transcript"));
    let secret = PairingSecret::decode(text(pairing, "pairing_secret")).unwrap();
    let proof = text(pairing, "mobile_agreement_proof");
    assert_eq!(agreement_proof(&secret, &transcript), proof);
    assert!(verify_agreement_proof(&secret, &transcript, proof));

    let shared = desktop.agree(mobile_key).unwrap();
    assert_eq!(*shared, bytes32(pairing, "shared_secret"));
    assert_eq!(*mobile.agree(desktop_key).unwrap(), *shared);

    let pair_id = text(pairing, "pair_id");
    let desktop_raw = bytes32(pairing, "desktop_agreement_key");
    let mobile_raw = bytes32(pairing, "mobile_agreement_key");
    for (direction, field) in [
        ("desktop-to-phone", "desktop_to_phone_info"),
        ("phone-to-desktop", "phone_to_desktop_info"),
    ] {
        assert_eq!(
            encode(&key_info(direction, pair_id, &desktop_raw, &mobile_raw)),
            text(pairing, field)
        );
    }
    let derived = derive_relay_keys(&shared, &secret, pair_id, desktop_key, mobile_key).unwrap();
    assert_eq!(derived, keys_of(pairing));

    // The desktop's own path: its agreement completes against the pair the
    // cloud returns and yields the same keys.
    let mut agreement = DesktopAgreement::from_parts(desktop, secret);
    agreement.set_challenge(text(pairing, "challenge"));
    let authorized = AuthorizedAgreement {
        pair_id,
        desktop_device_id: text(pairing, "desktop_device_id"),
        mobile_device_id: text(pairing, "mobile_device_id"),
        desktop_agreement_key: desktop_key,
        mobile_agreement_key: mobile_key,
        mobile_agreement_proof: proof,
    };
    assert_eq!(agreement.complete(&authorized).unwrap(), keys_of(pairing));
}

fn desktop_agreement(pairing: &Value) -> DesktopAgreement {
    let mut agreement = DesktopAgreement::from_parts(
        AgreementKeyPair::from_private_bytes(bytes32(pairing, "desktop_agreement_private_key")),
        PairingSecret::decode(text(pairing, "pairing_secret")).unwrap(),
    );
    agreement.set_challenge(text(pairing, "challenge"));
    agreement
}

#[test]
fn every_pairing_vector_reproduces() {
    let vectors = vectors();
    assert_eq!(vectors["contract_version"], CONTRACT_VERSION);
    check_pairing_vector(&vectors["pairing"]);
    check_pairing_vector(&vectors["repaired_pairing"]);
}

#[test]
fn the_wire_bodies_carry_the_vector_keys_and_proof() {
    let vectors = vectors();
    let pairing = &vectors["pairing"];
    let wire = &vectors["pairing_wire"];
    assert_eq!(
        wire["challenge_request"],
        json!({
            "contract_version": PAIRING_CONTRACT_VERSION,
            "desktop_agreement_key": pairing["desktop_agreement_key"],
        })
    );
    let mut displayed = wire["challenge_response"]["qr"].clone();
    displayed["pairing_secret"] = pairing["pairing_secret"].clone();
    assert_eq!(displayed, wire["displayed_qr"]);
    let pair = &wire["pair_response"]["pair"];
    let secret = PairingSecret::decode(text(pairing, "pairing_secret")).unwrap();
    let transcript = proof_transcript(
        text(pair, "desktop_device_id"),
        text(pair, "mobile_device_id"),
        text(&wire["displayed_qr"], "challenge"),
        text(pair, "desktop_agreement_key"),
        text(pair, "mobile_agreement_key"),
    );
    assert!(verify_agreement_proof(
        &secret,
        &transcript,
        text(pair, "mobile_agreement_proof")
    ));
}

#[test]
fn the_desktop_refuses_a_substituted_key_or_proof() {
    let vectors = vectors();
    let pairing = &vectors["pairing"];
    let other = &vectors["repaired_pairing"];
    let field = |value: &Value, name: &str| text(value, name).to_owned();
    let cases = [
        // The cloud swaps in its own phone key and keeps the phone's proof.
        (
            field(other, "mobile_agreement_key"),
            field(pairing, "mobile_agreement_proof"),
            field(pairing, "desktop_agreement_key"),
            RelayCryptoError::ProofInvalid,
        ),
        // A proof made under another pairing secret.
        (
            field(pairing, "mobile_agreement_key"),
            field(other, "mobile_agreement_proof"),
            field(pairing, "desktop_agreement_key"),
            RelayCryptoError::ProofInvalid,
        ),
        // The pair names a desktop key this desktop never sent.
        (
            field(pairing, "mobile_agreement_key"),
            field(pairing, "mobile_agreement_proof"),
            field(other, "desktop_agreement_key"),
            RelayCryptoError::KeyMismatch,
        ),
    ];
    for (mobile_key, proof, desktop_key, expected) in &cases {
        let pair = AuthorizedAgreement {
            pair_id: text(pairing, "pair_id"),
            desktop_device_id: text(pairing, "desktop_device_id"),
            mobile_device_id: text(pairing, "mobile_device_id"),
            desktop_agreement_key: desktop_key,
            mobile_agreement_key: mobile_key,
            mobile_agreement_proof: proof,
        };
        assert_eq!(desktop_agreement(pairing).complete(&pair), Err(*expected));
    }
}

#[test]
fn a_small_order_phone_key_is_refused() {
    let vectors = vectors();
    let desktop = desktop_agreement(&vectors["pairing"]);
    assert_eq!(
        desktop.key_pair.agree(&encode(&[0; 32])),
        Err(RelayCryptoError::Agreement)
    );
}

#[test]
fn every_message_vector_reproduces() {
    let vectors = vectors();
    let keys = keys_of(&vectors["pairing"]);
    let messages = vectors["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 9);
    for message in messages {
        let name = text(message, "name");
        let relay = &message["relay_message"];
        let key = direction_key(&keys, text(message, "direction"));
        let plaintext = text(message, "plaintext");
        let nonce = text(&relay["payload"], "nonce");
        let ciphertext = text(&relay["payload"], "ciphertext");
        if relay["type"] == "session.event" {
            let sealed: SealedEvent = serde_json::from_value(relay["payload"].clone()).unwrap();
            assert_eq!(
                associated_data(&sealed.header),
                text(message, "aad"),
                "{name}"
            );
            let resealed =
                seal_with_nonce(key, &sealed.header, plaintext.as_bytes(), nonce).unwrap();
            assert_eq!(resealed.ciphertext, ciphertext, "{name}");
            let opened = open_event(key, &sealed, text(relay, "session_id")).unwrap();
            assert_eq!(
                plaintext_bytes(opened.counter, &opened.content).as_slice(),
                plaintext.as_bytes(),
                "{name}"
            );
            assert_eq!(
                serde_json::to_value(&sealed).unwrap(),
                relay["payload"],
                "{name}"
            );
        } else {
            let sealed: SealedCommand = serde_json::from_value(relay["payload"].clone()).unwrap();
            assert_eq!(
                associated_data(&sealed.header),
                text(message, "aad"),
                "{name}"
            );
            let resealed =
                seal_with_nonce(key, &sealed.header, plaintext.as_bytes(), nonce).unwrap();
            assert_eq!(resealed.ciphertext, ciphertext, "{name}");
            let opened = open_command(
                key,
                &sealed,
                CommandEnvelope {
                    envelope_type: text(relay, "type"),
                    session_id: text(relay, "session_id"),
                    message_id: text(relay, "message_id"),
                },
            )
            .unwrap();
            assert_eq!(
                plaintext_bytes(opened.counter, &opened.content).as_slice(),
                plaintext.as_bytes(),
                "{name}"
            );
        }
    }
}

#[test]
fn every_negative_vector_fails_as_named() {
    let vectors = vectors();
    let current = keys_of(&vectors["pairing"]);
    let repaired = keys_of(&vectors["repaired_pairing"]);
    let negatives = vectors["negative_vectors"].as_array().unwrap();
    assert_eq!(negatives.len(), 6);
    for vector in negatives {
        let name = text(vector, "name");
        let keys = match text(vector, "keys") {
            "current" => &current,
            "repaired" => &repaired,
            other => panic!("unknown keys {other}"),
        };
        let key = direction_key(keys, text(vector, "direction"));
        let relay = &vector["relay_message"];
        let outcome = if relay["payload"]["header"]["header_type"] == "event" {
            let sealed: SealedEvent = serde_json::from_value(relay["payload"].clone()).unwrap();
            open_event(key, &sealed, text(relay, "session_id")).unwrap_err()
        } else {
            let sealed: SealedCommand = serde_json::from_value(relay["payload"].clone()).unwrap();
            open_command(
                key,
                &sealed,
                CommandEnvelope {
                    envelope_type: text(relay, "type"),
                    session_id: text(relay, "session_id"),
                    message_id: text(relay, "message_id"),
                },
            )
            .unwrap_err()
        };
        let expected = match text(vector, "outcome") {
            "authentication_failed" => RelayCryptoError::AuthenticationFailed,
            "binding_mismatch" => RelayCryptoError::BindingMismatch,
            other => panic!("unknown outcome {other}"),
        };
        assert_eq!(outcome, expected, "{name}");
    }
}

#[test]
fn the_replay_window_vector_reproduces() {
    let vectors = vectors();
    let window = &vectors["replay_window"];
    assert_eq!(window["window_size"], REPLAY_WINDOW);
    let mut replay = ReplayWindow::default();
    let received = window["received"].as_array().unwrap();
    let accepted = window["accepted"].as_array().unwrap();
    for (counter, expected) in received.iter().zip(accepted) {
        let counter: u64 = counter.as_str().unwrap().parse().unwrap();
        assert_eq!(
            replay.accept(counter),
            expected.as_bool().unwrap(),
            "counter {counter}"
        );
    }
    assert!(!replay.accept(0));
}

#[test]
fn a_changed_command_header_does_not_open() {
    let vectors = vectors();
    let keys = keys_of(&vectors["pairing"]);
    let message = vectors["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["name"] == "command_steer")
        .unwrap();
    let relay = &message["relay_message"];
    let sealed: SealedCommand = serde_json::from_value(relay["payload"].clone()).unwrap();
    let envelope = CommandEnvelope {
        envelope_type: text(relay, "type"),
        session_id: text(relay, "session_id"),
        message_id: text(relay, "message_id"),
    };
    let mut later = sealed.clone();
    later.header.expires_at = "2026-07-10T16:09:30.000Z".into();
    assert_eq!(
        open_command(&keys.phone_to_desktop, &later, envelope),
        Err(RelayCryptoError::AuthenticationFailed)
    );
    let mut moved = sealed.clone();
    moved.header.run_id = "run_synthetic_0002".into();
    assert_eq!(
        open_command(&keys.phone_to_desktop, &moved, envelope),
        Err(RelayCryptoError::AuthenticationFailed)
    );
    // An envelope for another session or message does not bind.
    assert_eq!(
        open_command(
            &keys.phone_to_desktop,
            &sealed,
            CommandEnvelope {
                session_id: "ses_synthetic_0002",
                ..envelope
            }
        ),
        Err(RelayCryptoError::BindingMismatch)
    );
    assert_eq!(
        open_command(
            &keys.phone_to_desktop,
            &sealed,
            CommandEnvelope {
                envelope_type: "command.follow_up",
                ..envelope
            }
        ),
        Err(RelayCryptoError::BindingMismatch)
    );
    assert!(open_command(&keys.phone_to_desktop, &sealed, envelope).is_ok());
}

#[test]
fn a_sealed_event_opens_with_its_key_alone() {
    let vectors = vectors();
    let keys = keys_of(&vectors["pairing"]);
    let gate = GateWindow {
        gate_id: "gate_local_0001".into(),
        requested_at: "2026-07-10T16:02:32.000Z".into(),
        expires_at: "2026-07-10T16:07:32.000Z".into(),
    };
    let header = EventHeader::new(
        "ses_local_0001",
        "run_local_0001",
        7,
        Phase::WaitingForPermission,
        Some(gate),
        "2026-07-10T16:02:32.000Z",
    );
    let content = EventContent::PermissionAsk {
        gate_id: "gate_local_0001".into(),
        kind: "confirm".into(),
        summary: "Run the tests".into(),
        request_digest: format!("sha256:{}", "a".repeat(64)),
    };
    let sealed = seal_event(&keys.desktop_to_phone, &header, 12, &content).unwrap();
    let again = seal_event(&keys.desktop_to_phone, &header, 12, &content).unwrap();
    assert_ne!(sealed.nonce, again.nonce, "every seal draws a fresh nonce");
    let opened = open_event(&keys.desktop_to_phone, &sealed, "ses_local_0001").unwrap();
    assert_eq!(opened.counter, 12);
    assert_eq!(opened.content, content);
    assert_eq!(
        open_event(&keys.phone_to_desktop, &sealed, "ses_local_0001"),
        Err(RelayCryptoError::AuthenticationFailed)
    );
    // An ask outside a waiting header never seals.
    let running = EventHeader::new(
        "ses_local_0001",
        "run_local_0001",
        8,
        Phase::Running,
        None,
        "2026-07-10T16:02:33.000Z",
    );
    assert_eq!(
        seal_event(&keys.desktop_to_phone, &running, 13, &content),
        Err(RelayCryptoError::BindingMismatch)
    );
}

#[test]
fn canonical_json_sorts_members_at_every_depth() {
    let value = json!({"b": {"z": 1, "a": [{"y": null, "x": "s"}]}, "a": true});
    assert_eq!(
        canonical_json(&value),
        r#"{"a":true,"b":{"a":[{"x":"s","y":null}],"z":1}}"#
    );
}

#[test]
fn the_send_counter_persists_a_block_before_it_uses_a_value() {
    let mut persisted = Vec::new();
    let mut counter = SendCounter::default();
    for expected in 1..=3 {
        let value = counter
            .next(|mark| {
                persisted.push(mark);
                Ok::<_, RelayCryptoError>(())
            })
            .unwrap();
        assert_eq!(value, expected);
    }
    assert_eq!(persisted, [COUNTER_BLOCK]);
    let mut resumed = SendCounter::resume(COUNTER_BLOCK);
    let value = resumed
        .next(|mark| {
            persisted.push(mark);
            Ok::<_, RelayCryptoError>(())
        })
        .unwrap();
    assert_eq!(value, COUNTER_BLOCK + 1);
    assert_eq!(persisted, [COUNTER_BLOCK, 2 * COUNTER_BLOCK]);
    let mut failing = SendCounter::resume(4);
    assert!(failing.next(|_| Err(RelayCryptoError::Random)).is_err());
    assert_eq!(failing.reserved(), 4, "a failed store uses no value");
    let mut exhausted = SendCounter::resume(MAX_MESSAGES_PER_KEY);
    assert_eq!(
        exhausted.next(|_| Ok::<_, RelayCryptoError>(())),
        Err(RelayCryptoError::Exhausted)
    );
}

#[test]
fn stored_keys_round_trip_and_never_print() {
    let keys = keys_of(&vectors()["pairing"]);
    let secret = keys.to_secret();
    assert_eq!(RelayKeys::from_secret(&secret).unwrap(), keys);
    let printed = format!("{keys:?}");
    assert!(!printed.contains(&keys.desktop_to_phone.encode()));
    assert!(!printed.contains(&keys.phone_to_desktop.encode()));
    assert!(RelayKeys::from_secret("{}").is_err());
}

#[test]
fn timestamps_use_three_fractional_digits() {
    let time = chrono::DateTime::parse_from_rfc3339("2026-07-10T16:02:32.5+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert_eq!(timestamp(time), "2026-07-10T16:02:32.500Z");
    assert!(valid_timestamp("2026-07-10T16:02:32.500Z"));
    assert!(!valid_timestamp("2026-07-10T16:02:32Z"));
    assert!(valid_id("ses_synthetic_0001"));
    assert!(!valid_id("short"));
    assert!(valid_uuid("22222222-2222-4222-8222-222222222222"));
}
