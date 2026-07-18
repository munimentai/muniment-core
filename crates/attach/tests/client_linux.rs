#![cfg(all(target_os = "linux", feature = "client"))]

use muniment_attach::{
    authorized, encode_frame, handshake_stream, welcome, ClientError, ErrorAction, ErrorEnvelope,
    Event, EventName, Failure, Id, Protocol, ProtocolError, Response, RunStreamMessage, Success,
    VersionRange, MAX_FRAME_LENGTH,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const SHORT: Duration = Duration::from_millis(100);
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

fn read_client_frame(stream: &mut UnixStream) {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut payload = vec![0; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut payload).unwrap();
}

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-client-test-{}-{}.sock",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn pathname_socket_handles_fragmented_success_frames() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_client_frame(&mut stream);
        let welcome = encode_frame(&welcome(1, "0.0.1", "11".repeat(16), "22".repeat(16))).unwrap();
        for byte in welcome {
            stream.write_all(&[byte]).unwrap();
        }
        let grant = authorized(
            "33".repeat(32),
            3600,
            900,
            BTreeMap::from([("workspace".into(), BTreeSet::from(["thread.read".into()]))]),
        );
        let grant = encode_frame(&grant).unwrap();
        for chunk in grant.chunks(2) {
            stream.write_all(chunk).unwrap();
        }
    });
    let stream = UnixStream::connect(&path).unwrap();
    let mut prompted = false;
    let client = handshake_stream(stream, "0.0.1", SHORT, SHORT, || prompted = true).unwrap();
    let summary = client.authorization_summary();
    assert!(prompted);
    assert_eq!(summary.expires_in_seconds, 3600);
    assert_eq!(summary.idle_timeout_seconds, 900);
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

fn complete_pairing(server: &mut UnixStream) {
    read_client_frame(server);
    server
        .write_all(&encode_frame(&welcome(1, "0.0.1", "11".repeat(16), "22".repeat(16))).unwrap())
        .unwrap();
    server
        .write_all(
            &encode_frame(&authorized(
                "33".repeat(32),
                3600,
                900,
                BTreeMap::from([("workspace".into(), BTreeSet::from(["thread.read".into()]))]),
            ))
            .unwrap(),
        )
        .unwrap();
}

fn read_client_value(server: &mut UnixStream) -> serde_json::Value {
    let mut prefix = [0; 4];
    server.read_exact(&mut prefix).unwrap();
    let mut payload = vec![0; u32::from_be_bytes(prefix) as usize];
    server.read_exact(&mut payload).unwrap();
    serde_json::from_slice(&payload).unwrap()
}

#[test]
fn run_stream_uses_exact_envelope_and_reads_fragmented_catch_up() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        assert_eq!(
            request,
            serde_json::json!({
                "protocol": "muniment.attach/1",
                "request_id": request_id,
                "operation": "run.stream",
                "capability": "33".repeat(32),
                "body": { "run_id": run_id, "after_run_seq": 3 }
            })
        );
        let response = encode_frame(&Response {
            protocol: Protocol,
            request_id: Id::new(request_id).unwrap(),
            ok: Success,
            body: serde_json::json!({
                "subscription_id": subscription_id,
                "run_id": run_id,
                "first_available_run_seq": 1,
                "current_run_seq": 5,
                "window": { "max_events": 1024, "max_bytes": 4194304 }
            }),
        })
        .unwrap();
        for byte in response {
            server.write_all(&[byte]).unwrap();
        }
        for sequence in [4, 5] {
            let frame = encode_frame(&Event {
                protocol: Protocol,
                subscription_id: Id::new(subscription_id).unwrap(),
                event: EventName::RunEvent,
                run_id: Some(Id::new(run_id).unwrap()),
                run_seq: Some(sequence),
                body: serde_json::json!({
                    "event_type": "assistant.message",
                    "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:00Z",
                    "payload": { "withheld": true }
                }),
            })
            .unwrap();
            for chunk in frame.chunks(3) {
                server.write_all(chunk).unwrap();
            }
        }
        server
            .write_all(
                &encode_frame(&Event {
                    protocol: Protocol,
                    subscription_id: Id::new(subscription_id).unwrap(),
                    event: EventName::SubscriptionCaughtUp,
                    run_id: Some(Id::new(run_id).unwrap()),
                    run_seq: Some(5),
                    body: serde_json::json!({}),
                })
                .unwrap(),
            )
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let summary = client.subscribe_run(run_id, 3).unwrap();
    assert_eq!(summary.current_run_seq, 5);
    for sequence in [4, 5] {
        let RunStreamMessage::Event(event) = client.read_run_stream_message().unwrap() else {
            panic!("expected run event")
        };
        assert_eq!(event.run_seq, sequence);
        assert!(!format!("{event:?}").contains("withheld"));
    }
    assert_eq!(
        client.read_run_stream_message().unwrap(),
        RunStreamMessage::CaughtUp { current_run_seq: 5 }
    );
    worker.join().unwrap();
}

#[test]
fn run_stream_reads_and_acknowledges_live_events_after_catch_up() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                    ok: Success,
                    body: valid_run_stream_summary(run_id, subscription_id),
                })
                .unwrap(),
            )
            .unwrap();
        for envelope in [
            run_stream_event(
                subscription_id,
                run_id,
                1,
                "run.event",
                serde_json::json!({
                    "event_type": "run.started", "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:00Z", "payload": { "withheld": true }
                }),
            ),
            run_stream_event(
                subscription_id,
                run_id,
                2,
                "run.event",
                serde_json::json!({
                    "event_type": "assistant.message", "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:01Z", "payload": { "withheld": true }
                }),
            ),
            run_stream_event(
                subscription_id,
                run_id,
                2,
                "subscription.caught_up",
                serde_json::json!({}),
            ),
            run_stream_event(
                subscription_id,
                run_id,
                3,
                "run.event",
                serde_json::json!({
                    "event_type": "assistant.message", "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:02Z", "payload": { "withheld": true }
                }),
            ),
            run_stream_event(
                subscription_id,
                run_id,
                4,
                "run.event",
                serde_json::json!({
                    "event_type": "run.finished", "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:03Z", "payload": { "withheld": true }
                }),
            ),
        ] {
            server.write_all(&encode_frame(&envelope).unwrap()).unwrap();
        }
        let acknowledgement = read_client_value(&mut server);
        let request_id = acknowledgement["request_id"].as_str().unwrap();
        assert_eq!(acknowledgement["operation"], "run.cursor_ack");
        assert_eq!(
            acknowledgement["body"],
            serde_json::json!({
                "subscription_id": subscription_id,
                "through_run_seq": 4,
            })
        );
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "subscription_id": subscription_id,
                        "through_run_seq": 4,
                    }),
                })
                .unwrap(),
            )
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    for sequence in [1, 2] {
        assert!(
            matches!(client.read_run_stream_message(), Ok(RunStreamMessage::Event(event)) if event.run_seq == sequence)
        );
    }
    assert_eq!(
        client.read_run_stream_message().unwrap(),
        RunStreamMessage::CaughtUp { current_run_seq: 2 }
    );
    for sequence in [3, 4] {
        assert!(
            matches!(client.read_run_stream_message(), Ok(RunStreamMessage::Event(event)) if event.run_seq == sequence)
        );
    }
    client.acknowledge_run_cursor(4).unwrap();
    worker.join().unwrap();
}

#[test]
fn run_stream_rejects_invalid_input_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        assert!(server.read(&mut [0]).is_err());
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.subscribe_run("not-a-run-id", 0),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.subscribe_run("01900000-0000-7000-8000-000000000001", u64::MAX),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn run_stream_acknowledges_paused_window_and_resumes_without_duplicates() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "subscription_id": subscription_id, "run_id": run_id,
                        "first_available_run_seq": 1, "current_run_seq": 2,
                        "window": { "max_events": 1, "max_bytes": 4194304 }
                    }),
                })
                .unwrap(),
            )
            .unwrap();
        server
            .write_all(
                &encode_frame(&Event {
                    protocol: Protocol,
                    subscription_id: Id::new(subscription_id).unwrap(),
                    event: EventName::RunEvent,
                    run_id: Some(Id::new(run_id).unwrap()),
                    run_seq: Some(1),
                    body: serde_json::json!({
                        "event_type": "run.started", "event_version": 1,
                        "recorded_at": "2026-07-17T00:00:00Z",
                        "payload": { "withheld": true }
                    }),
                })
                .unwrap(),
            )
            .unwrap();
        let acknowledgement = read_client_value(&mut server);
        let request_id = acknowledgement["request_id"].as_str().unwrap();
        assert_eq!(acknowledgement["operation"], "run.cursor_ack");
        assert_eq!(
            acknowledgement["body"],
            serde_json::json!({
                "subscription_id": subscription_id,
                "through_run_seq": 1,
            })
        );
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "subscription_id": subscription_id,
                        "through_run_seq": 1,
                    }),
                })
                .unwrap(),
            )
            .unwrap();
        for envelope in [
            run_stream_event(
                subscription_id,
                run_id,
                2,
                "run.event",
                serde_json::json!({
                    "event_type": "run.finished", "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:01Z",
                    "payload": { "withheld": true }
                }),
            ),
            run_stream_event(
                subscription_id,
                run_id,
                2,
                "subscription.caught_up",
                serde_json::json!({}),
            ),
        ] {
            server.write_all(&encode_frame(&envelope).unwrap()).unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    assert!(
        matches!(client.read_run_stream_message(), Ok(RunStreamMessage::Event(event)) if event.run_seq == 1)
    );
    assert_eq!(
        client.acknowledge_run_cursor(0),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.acknowledge_run_cursor(2),
        Err(ClientError::UnexpectedMessage)
    );
    client.acknowledge_run_cursor(1).unwrap();
    assert_eq!(
        client.acknowledge_run_cursor(1),
        Err(ClientError::UnexpectedMessage)
    );
    assert!(
        matches!(client.read_run_stream_message(), Ok(RunStreamMessage::Event(event)) if event.run_seq == 2)
    );
    assert_eq!(
        client.read_run_stream_message().unwrap(),
        RunStreamMessage::CaughtUp { current_run_seq: 2 }
    );
    worker.join().unwrap();
}

#[test]
fn run_cursor_ack_rejects_uncorrelated_malformed_and_interleaved_responses() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    for response_kind in 0..5 {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let subscribe = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(subscribe["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: valid_run_stream_summary(run_id, subscription_id),
                    })
                    .unwrap(),
                )
                .unwrap();
            server
                .write_all(
                    &encode_frame(&run_stream_event(
                        subscription_id,
                        run_id,
                        1,
                        "run.event",
                        serde_json::json!({
                            "event_type": "run.started", "event_version": 1,
                            "recorded_at": "2026-07-17T00:00:00Z",
                            "payload": { "withheld": true }
                        }),
                    ))
                    .unwrap(),
                )
                .unwrap();
            let acknowledgement = read_client_value(&mut server);
            let request_id = acknowledgement["request_id"].as_str().unwrap();
            let hostile = match response_kind {
                0 => serde_json::to_value(Response {
                    protocol: Protocol,
                    request_id: Id::new("00000000-0000-0000-0000-000000000000").unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "subscription_id": subscription_id, "through_run_seq": 1
                    }),
                })
                .unwrap(),
                1 => serde_json::json!({
                    "protocol": "muniment.attach/1", "request_id": request_id, "ok": true,
                    "body": { "subscription_id": "01900000-0000-7000-8000-000000000003", "through_run_seq": 1 }
                }),
                2 => serde_json::json!({
                    "protocol": "muniment.attach/1", "request_id": request_id, "ok": true,
                    "body": { "subscription_id": subscription_id, "through_run_seq": 2 }
                }),
                3 => serde_json::json!({
                    "protocol": "muniment.attach/1", "request_id": request_id, "ok": true,
                    "body": { "subscription_id": subscription_id, "through_run_seq": 1,
                              "hostile-secret": "must-not-leak" }
                }),
                _ => run_stream_event(
                    subscription_id,
                    run_id,
                    2,
                    "run.event",
                    serde_json::json!({ "hostile-secret": "must-not-leak" }),
                ),
            };
            server.write_all(&encode_frame(&hostile).unwrap()).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        client.subscribe_run(run_id, 0).unwrap();
        client.read_run_stream_message().unwrap();
        let error = client.acknowledge_run_cursor(1).unwrap_err();
        assert_eq!(error, ClientError::UnexpectedMessage);
        assert!(!format!("{error:?}").contains("must-not-leak"));
        worker.join().unwrap();
    }
}

fn valid_run_stream_summary(run_id: &str, subscription_id: &str) -> serde_json::Value {
    serde_json::json!({
        "subscription_id": subscription_id,
        "run_id": run_id,
        "first_available_run_seq": 1,
        "current_run_seq": 2,
        "window": { "max_events": 1024, "max_bytes": 4194304 }
    })
}

fn run_stream_event(
    subscription_id: &str,
    run_id: &str,
    run_seq: u64,
    event: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "protocol": "muniment.attach/1",
        "subscription_id": subscription_id,
        "event": event,
        "run_id": run_id,
        "run_seq": run_seq,
        "body": body
    })
}

#[test]
fn run_stream_rejects_hostile_subscription_responses_and_maps_errors() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let mut unknown = valid_run_stream_summary(run_id, subscription_id);
    unknown["secret"] = serde_json::json!("not allowed");
    for (body, wrong_correlation, error, expected) in [
        (
            Some(valid_run_stream_summary(run_id, subscription_id)),
            true,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            None,
            false,
            Some(ProtocolError::unauthorized()),
            ClientError::AuthorizationExpired,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": "x".repeat(65), "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 1, "max_bytes": 1 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (Some(unknown), false, None, ClientError::UnexpectedMessage),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 3, "current_run_seq": 2,
                "window": { "max_events": 1, "max_bytes": 1 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 0, "max_bytes": 4194305 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 1025, "max_bytes": 1 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let request_id = if wrong_correlation {
                Id::new("00000000-0000-0000-0000-000000000000").unwrap()
            } else {
                Id::new(request["request_id"].as_str().unwrap()).unwrap()
            };
            let frame = if let Some(error) = error {
                encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(request_id),
                    ok: Failure,
                    error,
                })
                .unwrap()
            } else {
                encode_frame(&Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body: body.unwrap(),
                })
                .unwrap()
            };
            server.write_all(&frame).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(client.subscribe_run(run_id, 0), Err(expected));
        worker.join().unwrap();
    }
}

#[test]
fn run_stream_rejects_hostile_event_envelopes_without_leaking_bodies() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let valid_body = serde_json::json!({
        "event_type": "run.started", "event_version": 1,
        "recorded_at": "2026-07-17T00:00:00Z", "payload": { "withheld": true }
    });
    let cases = [
        run_stream_event(
            "01900000-0000-7000-8000-000000000003",
            run_id,
            1,
            "run.event",
            valid_body.clone(),
        ),
        run_stream_event(
            subscription_id,
            "01900000-0000-7000-8000-000000000003",
            1,
            "run.event",
            valid_body.clone(),
        ),
        run_stream_event(subscription_id, run_id, 0, "run.event", valid_body.clone()),
        run_stream_event(subscription_id, run_id, 2, "run.event", valid_body.clone()),
        run_stream_event(subscription_id, run_id, 3, "run.event", valid_body.clone()),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "run.event",
            serde_json::json!({
                "event_type": " \n\t", "event_version": 1,
                "recorded_at": "2026-07-17T00:00:00Z",
                "payload": { "withheld": true, "hostile-secret": "must-not-leak" }
            }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            2,
            "subscription.caught_up",
            serde_json::json!({}),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "subscription.caught_up",
            serde_json::json!({}),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "unknown.event",
            serde_json::json!({}),
        ),
        serde_json::json!({
            "protocol": "muniment.attach/1", "request_id": subscription_id,
            "ok": true, "body": {}
        }),
    ];

    for hostile in cases {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: valid_run_stream_summary(run_id, subscription_id),
                    })
                    .unwrap(),
                )
                .unwrap();
            server.write_all(&encode_frame(&hostile).unwrap()).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        client.subscribe_run(run_id, 0).unwrap();
        let error = client.read_run_stream_message().unwrap_err();
        assert_eq!(error, ClientError::UnexpectedMessage);
        assert!(!format!("{error:?}").contains("must-not-leak"));
        worker.join().unwrap();
    }
}

#[test]
fn run_stream_rejects_hostile_live_events_after_catch_up() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let valid_body = serde_json::json!({
        "event_type": "assistant.message", "event_version": 1,
        "recorded_at": "2026-07-17T00:00:02Z", "payload": { "withheld": true }
    });
    let cases = [
        run_stream_event(subscription_id, run_id, 4, "run.event", valid_body.clone()),
        run_stream_event(subscription_id, run_id, 2, "run.event", valid_body.clone()),
        run_stream_event(
            "01900000-0000-7000-8000-000000000003",
            run_id,
            3,
            "run.event",
            valid_body.clone(),
        ),
        run_stream_event(
            subscription_id,
            "01900000-0000-7000-8000-000000000003",
            3,
            "run.event",
            valid_body.clone(),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            3,
            "run.event",
            serde_json::json!({
                "event_type": "assistant.message", "event_version": 1,
                "recorded_at": "2026-07-17T00:00:02Z",
                "payload": { "withheld": true, "hostile-secret": "must-not-leak" }
            }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            3,
            "subscription.caught_up",
            serde_json::json!({}),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            3,
            "unknown.event",
            serde_json::json!({ "hostile-secret": "must-not-leak" }),
        ),
    ];

    for hostile in cases {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: valid_run_stream_summary(run_id, subscription_id),
                    })
                    .unwrap(),
                )
                .unwrap();
            let body = serde_json::json!({
                "event_type": "assistant.message", "event_version": 1,
                "recorded_at": "2026-07-17T00:00:00Z", "payload": { "withheld": true }
            });
            for envelope in [
                run_stream_event(subscription_id, run_id, 1, "run.event", body.clone()),
                run_stream_event(subscription_id, run_id, 2, "run.event", body),
                run_stream_event(
                    subscription_id,
                    run_id,
                    2,
                    "subscription.caught_up",
                    serde_json::json!({}),
                ),
                hostile,
            ] {
                server.write_all(&encode_frame(&envelope).unwrap()).unwrap();
            }
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        client.subscribe_run(run_id, 0).unwrap();
        client.read_run_stream_message().unwrap();
        client.read_run_stream_message().unwrap();
        assert!(matches!(
            client.read_run_stream_message(),
            Ok(RunStreamMessage::CaughtUp { current_run_seq: 2 })
        ));
        let error = client.read_run_stream_message().unwrap_err();
        assert_eq!(error, ClientError::UnexpectedMessage);
        assert!(!format!("{error:?}").contains("must-not-leak"));
        worker.join().unwrap();
    }
}

#[test]
fn run_stream_rejects_duplicate_and_invalid_caught_up_and_bad_frames() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    for (tail, expected) in [
        (
            encode_frame(&run_stream_event(
                subscription_id,
                run_id,
                1,
                "subscription.caught_up",
                serde_json::json!({ "unexpected": true }),
            ))
            .unwrap(),
            ClientError::UnexpectedMessage,
        ),
        (
            {
                let mut bytes = 1u32.to_be_bytes().to_vec();
                bytes.push(b'{');
                bytes
            },
            ClientError::MalformedFrame,
        ),
        (
            ((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes().to_vec(),
            ClientError::PayloadTooLarge,
        ),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: valid_run_stream_summary(run_id, subscription_id),
                    })
                    .unwrap(),
                )
                .unwrap();
            server.write_all(&tail).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        client.subscribe_run(run_id, 0).unwrap();
        assert_eq!(client.read_run_stream_message(), Err(expected));
        worker.join().unwrap();
    }

    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                    ok: Success,
                    body: valid_run_stream_summary(run_id, subscription_id),
                })
                .unwrap(),
            )
            .unwrap();
        for sequence in [1, 2] {
            server
                .write_all(
                    &encode_frame(&run_stream_event(
                        subscription_id,
                        run_id,
                        sequence,
                        "run.event",
                        serde_json::json!({
                            "event_type": "run.started", "event_version": 1,
                            "recorded_at": "2026-07-17T00:00:00Z",
                            "payload": { "withheld": true }
                        }),
                    ))
                    .unwrap(),
                )
                .unwrap();
        }
        let caught_up = run_stream_event(
            subscription_id,
            run_id,
            2,
            "subscription.caught_up",
            serde_json::json!({}),
        );
        server
            .write_all(&encode_frame(&caught_up).unwrap())
            .unwrap();
        server
            .write_all(&encode_frame(&caught_up).unwrap())
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    client.read_run_stream_message().unwrap();
    client.read_run_stream_message().unwrap();
    client.read_run_stream_message().unwrap();
    assert_eq!(
        client.read_run_stream_message(),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn run_start_uses_exact_envelope_fresh_ids_and_accepts_receipts() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let mut seen = BTreeSet::new();
        for (text, context) in [
            ("first prompt", Some(serde_json::json!({"cwd": "/tmp"}))),
            ("second prompt", None),
        ] {
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            let idempotency_key = request["idempotency_key"].as_str().unwrap().to_owned();
            let mut body = serde_json::json!({"text": text});
            if let Some(context) = context {
                body["context"] = context;
            }
            assert_eq!(
                request,
                serde_json::json!({
                    "protocol": "muniment.attach/1",
                    "request_id": request_id,
                    "operation": "run.start",
                    "capability": "33".repeat(32),
                    "idempotency_key": idempotency_key,
                    "body": body,
                })
            );
            assert_eq!(request_id.as_bytes()[14], b'7');
            assert_eq!(idempotency_key.as_bytes()[14], b'7');
            assert_ne!(request_id, idempotency_key);
            assert!(seen.insert(request_id.clone()));
            assert!(seen.insert(idempotency_key));
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "run_id": "01900000-0000-7000-8000-000000000001",
                            "committed_seq": 2,
                            "accepted_at": "2026-07-17T00:00:00Z"
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let accepted = client
        .start_run("first prompt", Some(serde_json::json!({"cwd": "/tmp"})))
        .unwrap();
    assert_eq!(accepted.committed_seq, 2);
    assert!(!format!("{accepted:?}").contains("first prompt"));
    client.start_run("second prompt", None).unwrap();
    worker.join().unwrap();
}

#[test]
fn run_start_rejects_invalid_input_without_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        let mut byte = [0];
        assert!(matches!(
            server.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.start_run(" \n\t", None),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.start_run(&"x".repeat(32 * 1024 + 1), None),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.start_run("prompt", Some(serde_json::json!("x".repeat(64 * 1024)))),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn run_start_rejects_hostile_receipts_and_maps_errors() {
    for (body, expected) in [
        (
            Some(
                serde_json::json!({"run_id":"bad", "committed_seq":2, "accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001", "committed_seq":0, "accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001", "committed_seq":2, "accepted_at":"not a timestamp"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"x".repeat(65), "committed_seq":2, "accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001", "committed_seq":2, "accepted_at":"2026-07-17T00:00:00Z", "prompt":"leaked"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (None, ClientError::AuthorizationExpired),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let request_id = Id::new(request["request_id"].as_str().unwrap()).unwrap();
            let bytes = if let Some(body) = body {
                encode_frame(&Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body,
                })
                .unwrap()
            } else {
                encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(request_id),
                    ok: Failure,
                    error: ProtocolError::unauthorized(),
                })
                .unwrap()
            };
            server.write_all(&bytes).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(client.start_run("prompt", None), Err(expected));
        worker.join().unwrap();
    }
}

#[test]
fn run_start_rejects_correlation_mismatch() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        read_client_frame(&mut server);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new("00000000-0000-0000-0000-000000000000").unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "run_id": "01900000-0000-7000-8000-000000000001",
                        "committed_seq": 2,
                        "accepted_at": "2026-07-17T00:00:00Z"
                    }),
                })
                .unwrap(),
            )
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.start_run("prompt", None),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn thread_list_uses_exact_envelope_and_accepts_fragmented_page() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        assert_eq!(request["protocol"], "muniment.attach/1");
        assert_eq!(request["operation"], "thread.list");
        assert_eq!(request["capability"], "33".repeat(32));
        assert_eq!(request["body"], serde_json::json!({"limit": 100}));
        assert!(request.get("idempotency_key").is_none());
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(&request_id).unwrap(),
            ok: Success,
            body: serde_json::json!({
                "threads": [{"thread_id":"opaque-1", "title":"First", "updated_at":"2026-07-17T00:00:00Z"}],
                "next_cursor": "private-cursor"
            }),
        };
        for byte in encode_frame(&response).unwrap() {
            server.write_all(&[byte]).unwrap();
        }
        let request = read_client_value(&mut server);
        assert_eq!(
            request["body"],
            serde_json::json!({
                "limit": 100,
                "cursor": "private-cursor"
            })
        );
        assert_ne!(request["request_id"], request_id);
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({"threads": []}),
        };
        for chunk in encode_frame(&response).unwrap().chunks(2) {
            server.write_all(chunk).unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let page = client.list_threads(None).unwrap();
    assert_eq!(page.threads[0].thread_id, "opaque-1");
    assert!(page.next_cursor.is_some());
    assert!(!format!("{page:?}").contains("private-cursor"));
    let page = client.list_threads(page.next_cursor.as_deref()).unwrap();
    assert!(page.threads.is_empty());
    assert!(page.next_cursor.is_none());
    worker.join().unwrap();
}

#[test]
fn thread_open_uses_exact_envelope_and_accepts_fragmented_pages() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let first = read_client_value(&mut server);
        assert_eq!(first["operation"], "thread.open");
        assert_eq!(first["capability"], "33".repeat(32));
        assert_eq!(
            first["body"],
            serde_json::json!({"thread_id": "thread-1", "limit": 100})
        );
        assert!(first.get("idempotency_key").is_none());
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(first["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({
                "thread_id": "thread-1",
                "entries": [{"run_seq": 1, "kind": "message", "text": "hello"}],
                "next_cursor": "private-cursor"
            }),
        };
        for byte in encode_frame(&response).unwrap() {
            server.write_all(&[byte]).unwrap();
        }
        let second = read_client_value(&mut server);
        assert_eq!(
            second["body"],
            serde_json::json!({
                "thread_id": "thread-1", "limit": 100, "cursor": "private-cursor"
            })
        );
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(second["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({"thread_id": "thread-1", "entries": []}),
        };
        for chunk in encode_frame(&response).unwrap().chunks(2) {
            server.write_all(chunk).unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let first = client.open_thread("thread-1", None).unwrap();
    assert_eq!(first.entries[0].text.as_deref(), Some("hello"));
    assert!(!format!("{first:?}").contains("private-cursor"));
    let second = client
        .open_thread("thread-1", first.next_cursor.as_deref())
        .unwrap();
    assert!(second.entries.is_empty());
    worker.join().unwrap();
}

#[test]
fn thread_open_rejects_invalid_response_fields() {
    for body in [
        serde_json::json!({"thread_id": "other", "entries": []}),
        serde_json::json!({"thread_id": "thread-1", "entries": [{"run_seq": 0, "kind": "message"}]}),
        serde_json::json!({"thread_id": "thread-1", "entries": [{"run_seq": 1, "kind": ""}]}),
        serde_json::json!({"thread_id": "thread-1", "entries": [], "next_cursor": ""}),
        serde_json::json!({"thread_id": "thread-1", "entries": [], "capability": "secret"}),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body,
                    })
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(
            client.open_thread("thread-1", None),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
}

#[test]
fn thread_list_rejects_correlation_mismatch_and_maps_protocol_errors() {
    for (error, expected) in [
        (None, ClientError::UnexpectedMessage),
        (
            Some(ProtocolError::unauthorized()),
            ClientError::AuthorizationExpired,
        ),
        (
            Some(ProtocolError::persistence_failed()),
            ClientError::DesktopFailed,
        ),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let request_id = if error.is_none() {
                Id::new("00000000-0000-0000-0000-000000000000").unwrap()
            } else {
                Id::new(request["request_id"].as_str().unwrap()).unwrap()
            };
            let bytes = if let Some(error) = error {
                encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(request_id),
                    ok: Failure,
                    error,
                })
                .unwrap()
            } else {
                encode_frame(&Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body: serde_json::json!({"threads": []}),
                })
                .unwrap()
            };
            server.write_all(&bytes).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(client.list_threads(None), Err(expected));
        worker.join().unwrap();
    }
}

#[test]
fn thread_list_rejects_hybrid_success_and_error_envelopes() {
    for hybrid in [
        serde_json::json!({
            "protocol": "muniment.attach/1",
            "ok": true,
            "body": {"threads": []},
            "error": {"code": "invalid_request", "message": "server-secret", "action": "retry"}
        }),
        serde_json::json!({
            "protocol": "muniment.attach/1",
            "ok": false,
            "error": {"code": "invalid_request", "message": "server-secret", "action": "retry"},
            "body": {"threads": []}
        }),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let mut hybrid = hybrid;
            hybrid["request_id"] = request["request_id"].clone();
            server.write_all(&encode_frame(&hybrid).unwrap()).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(
            client.list_threads(None),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
}

#[test]
fn thread_list_timeout_is_absolute_and_client_debug_is_redacted() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        read_client_frame(&mut server);
        for byte in encode_frame(&serde_json::json!({"unused": true})).unwrap() {
            if server.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(30));
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let debug = format!("{client:?}");
    assert!(!debug.contains(&"33".repeat(32)));
    assert!(!debug.contains("UnixStream"));
    let started = Instant::now();
    assert_eq!(client.list_threads(None), Err(ClientError::Timeout));
    assert!(started.elapsed() < Duration::from_millis(250));
    worker.join().unwrap();
}

#[test]
fn continuous_partial_progress_cannot_extend_receive_deadlines() {
    let welcome = encode_frame(&welcome(1, "0.0.1", "11".repeat(16), "22".repeat(16))).unwrap();
    let grant = encode_frame(&authorized("33".repeat(32), 3600, 900, BTreeMap::new())).unwrap();

    for (first, drip) in [(None, welcome.clone()), (Some(welcome), grant)] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            read_client_frame(&mut server);
            if let Some(first) = first {
                server.write_all(&first).unwrap();
            }
            for byte in drip {
                if server.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let started = Instant::now();
        assert_eq!(
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap_err(),
            ClientError::Timeout
        );
        assert!(started.elapsed() < Duration::from_millis(250));
        sender.join().unwrap();
    }
}

#[test]
fn hybrid_messages_are_rejected_at_both_handshake_stages() {
    let valid_welcome =
        encode_frame(&welcome(1, "0.0.1", "11".repeat(16), "22".repeat(16))).unwrap();
    let hybrids = [
        (
            None,
            serde_json::json!({
                "selected": 1,
                "desktop_version": "0.0.1",
                "server_nonce": "11".repeat(16),
                "authorization": "pairing_required",
                "approval_challenge": "22".repeat(16),
                "operation": "thread.list",
                "capability": "secret"
            }),
        ),
        (
            Some(valid_welcome),
            serde_json::json!({
                "capability": "33".repeat(32),
                "expires_at": 3600,
                "idle_timeout_seconds": 900,
                "workspace_scopes": {},
                "ok": true,
                "request_id": "request",
                "body": {}
            }),
        ),
    ];

    for (first, hybrid) in hybrids {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            read_client_frame(&mut server);
            if let Some(first) = first {
                server.write_all(&first).unwrap();
            }
            server.write_all(&encode_frame(&hybrid).unwrap()).unwrap();
        });
        assert_eq!(
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap_err(),
            ClientError::UnexpectedMessage
        );
        sender.join().unwrap();
    }
}

#[test]
fn timeout_and_early_close_are_distinct_and_redacted() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let hold = thread::spawn(move || {
        read_client_frame(&mut server);
        thread::sleep(Duration::from_millis(150));
    });
    assert_eq!(
        handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap_err(),
        ClientError::Timeout
    );
    hold.join().unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    server.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap_err(),
        ClientError::ConnectionClosed
    );
}

#[test]
fn malformed_and_oversized_frames_are_rejected_before_allocation() {
    for (response, expected) in [
        (
            {
                let mut bytes = (1u32).to_be_bytes().to_vec();
                bytes.push(b'{');
                bytes
            },
            ClientError::MalformedFrame,
        ),
        (
            ((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes().to_vec(),
            ClientError::PayloadTooLarge,
        ),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            read_client_frame(&mut server);
            server.write_all(&response).unwrap();
        });
        assert_eq!(
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap_err(),
            expected
        );
        sender.join().unwrap();
    }
}

#[test]
fn incompatible_error_and_selected_version_are_rejected() {
    let incompatible = ErrorEnvelope {
        protocol: Protocol,
        request_id: None,
        ok: Failure,
        error: ProtocolError::protocol_incompatible(
            VersionRange { min: 2, max: 2 },
            ErrorAction::UpgradeCompanion,
        ),
    };
    for response in [
        encode_frame(&incompatible).unwrap(),
        encode_frame(&welcome(2, "0.0.1", "11".repeat(16), "22".repeat(16))).unwrap(),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            read_client_frame(&mut server);
            server.write_all(&response).unwrap();
        });
        assert_eq!(
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap_err(),
            ClientError::ProtocolIncompatible
        );
        sender.join().unwrap();
    }
}

#[test]
fn errors_and_handshake_debug_output_do_not_expose_secrets() {
    let text = format!(
        "{:?} {}",
        ClientError::ConnectionClosed,
        ClientError::ConnectionClosed
    );
    for secret in [
        "/runtime/private.sock",
        "nonce-secret",
        "challenge-secret",
        "capability-secret",
    ] {
        assert!(!text.contains(secret));
    }
    let welcome = welcome(1, "0.0.1", "nonce-secret", "challenge-secret");
    let grant = authorized("capability-secret", 1, 1, BTreeMap::new());
    assert!(!format!("{welcome:?}").contains("nonce-secret"));
    assert!(!format!("{welcome:?}").contains("challenge-secret"));
    assert!(!format!("{grant:?}").contains("capability-secret"));
}
