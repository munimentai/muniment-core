#![cfg(all(target_os = "linux", feature = "client"))]

use muniment_attach::{
    authorized, connect_approval_presenter_at, connect_desktop_client, connect_desktop_client_at,
    encode_frame, handshake_approval_presenter_stream, handshake_desktop_client_stream,
    handshake_migration_control_stream, handshake_stream, handshake_stream_with_credential,
    reconnect_welcome, serve_desktop_client_at, welcome, ApprovalDecision,
    ApprovalPresenterServeOutcome, ArtifactWindowGrant, ChatPermissionAnswer, ClientError,
    DesktopClientHolder, DesktopClientStopHandle, ErrorAction, ErrorEnvelope, Event, EventName,
    Failure, Id, MigrationControlFailure, MigrationControlOutcome, Operation, PermissionDecision,
    PermissionKind, Protocol, ProtocolError, RedactedRunEvent, Response, RunOpenPage,
    RunStreamMessage, Success, VersionRange, MAX_FRAME_LENGTH,
};
use muniment_attach::{serve_approval_presenter_at, ApprovalPresenterStopHandle};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SHORT: Duration = Duration::from_millis(100);
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);
static ENVIRONMENT: Mutex<()> = Mutex::new(());

unsafe extern "C" {
    fn listen(socket: i32, backlog: i32) -> i32;
}

fn complete_approval_presenter_handshake(server: &mut UnixStream) {
    let hello = read_client_value(server);
    assert_eq!(hello["client"]["kind"], "desktop");
    assert!(hello.get("authorized_client_credential").is_none());
    server
        .write_all(&encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap())
        .unwrap();
    server
        .write_all(
            &encode_frame(&serde_json::json!({
                "profile_id": "",
                "capability": "33".repeat(32),
                "expires_at": 60,
                "idle_timeout_seconds": 60,
                "workspace_scopes": {},
            }))
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn approval_presenter_handshake_accepts_only_a_credential_free_grant() {
    for include_credential in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let hello = read_client_value(&mut server);
            assert_eq!(hello["client"]["kind"], "desktop");
            assert!(hello.get("authorized_client_credential").is_none());
            server
                .write_all(
                    &encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap(),
                )
                .unwrap();
            let mut grant = serde_json::json!({
                "profile_id": "",
                "capability": "33".repeat(32),
                "expires_at": 60,
                "idle_timeout_seconds": 60,
                "workspace_scopes": {},
            });
            if include_credential {
                grant["authorized_client_credential"] = serde_json::json!("44".repeat(32));
            }
            server.write_all(&encode_frame(&grant).unwrap()).unwrap();
        });
        let result = handshake_approval_presenter_stream(client, "0.0.1", SHORT);
        if include_credential {
            assert_eq!(result.unwrap_err(), ClientError::UnexpectedMessage);
        } else {
            assert_eq!(result.unwrap().capability(), "33".repeat(32));
        }
        worker.join().unwrap();
    }
}

#[test]
fn approval_presenter_hands_the_request_to_the_caller_and_sends_the_choice() {
    for (decision, expected) in [
        (ApprovalDecision::Approve, "approve"),
        (ApprovalDecision::Deny, "deny"),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_approval_presenter_handshake(&mut server);
            server
                .write_all(
                    &encode_frame(&serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": "00000000000000000000000000000073",
                        "operation": "approval.present",
                        "capability": "33".repeat(32),
                        "body": {
                            "challenge": "fixture-challenge",
                            "claimed_kind": "editor-extension",
                            "claimed_version": "0.0.1",
                            "workspace": "workspace-1",
                            "scopes": ["thread.read"],
                            "deadline_ms": 120_000,
                        }
                    }))
                    .unwrap(),
                )
                .unwrap();
            let mut prefix = [0; 4];
            server.read_exact(&mut prefix).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(prefix) as usize];
            server.read_exact(&mut bytes).unwrap();
            if expected == "approve" {
                assert_eq!(
                    bytes,
                    br#"{"protocol":"muniment.attach/1","request_id":"00000000000000000000000000000073","ok":true,"body":{"challenge":"fixture-challenge","decision":"approve"}}"#
                );
            }
            let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(response["request_id"], "00000000000000000000000000000073");
            assert_eq!(response["body"]["challenge"], "fixture-challenge");
            assert_eq!(response["body"]["decision"], expected);
        });
        let mut presenter = handshake_approval_presenter_stream(client, "0.0.1", SHORT).unwrap();
        presenter
            .present(|request| {
                assert_eq!(request.challenge, "fixture-challenge");
                assert_eq!(request.claimed_kind, "editor-extension");
                assert_eq!(request.claimed_version, "0.0.1");
                assert_eq!(request.workspace, "workspace-1");
                assert_eq!(request.scopes, ["thread.read"]);
                assert_eq!(request.deadline_ms, 120_000);
                decision
            })
            .unwrap();
        worker.join().unwrap();
    }
}

#[test]
fn approval_presenter_resets_the_io_deadline_after_a_delayed_choice() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_approval_presenter_handshake(&mut server);
        server
            .write_all(&encode_frame(&approval_present_request()).unwrap())
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let answer = read_client_value(&mut server);
        assert_eq!(answer["body"]["decision"], "approve");
    });
    let mut presenter = handshake_approval_presenter_stream(client, "0.0.1", SHORT).unwrap();
    presenter
        .present(|_| {
            thread::sleep(SHORT + SHORT);
            ApprovalDecision::Approve
        })
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn approval_presenter_resets_the_io_deadline_after_a_slow_invalid_request() {
    let io_timeout = Duration::from_millis(400);
    let (client, mut server) = UnixStream::pair().unwrap();
    let mut filler = client.try_clone().unwrap();
    let (handshake_done_tx, handshake_done_rx) = std::sync::mpsc::channel();
    let (filled_bytes_tx, filled_bytes_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        complete_approval_presenter_handshake(&mut server);
        handshake_done_tx.send(()).unwrap();
        let filled_bytes = filled_bytes_rx.recv().unwrap();
        let mut request = approval_present_request();
        request["body"]["deadline_ms"] = serde_json::json!(0);
        let frame = encode_frame(&request).unwrap();
        let split = frame.len() - 1;
        server.write_all(&frame[..split]).unwrap();
        thread::sleep(io_timeout / 2);
        server.write_all(&frame[split..]).unwrap();
        thread::sleep(io_timeout * 3 / 4);
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut filled = vec![0; filled_bytes];
        server.read_exact(&mut filled).unwrap();
        let answer = read_client_value(&mut server);
        assert_eq!(answer["error"]["code"], "unauthorized");
    });
    let mut presenter = handshake_approval_presenter_stream(client, "0.0.1", io_timeout).unwrap();
    handshake_done_rx.recv().unwrap();
    filler.set_nonblocking(true).unwrap();
    let bytes = [0; 4096];
    let mut filled_bytes = 0;
    loop {
        match filler.write(&bytes) {
            Ok(written) => filled_bytes += written,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            result => {
                result.unwrap();
            }
        }
    }
    filler.set_nonblocking(false).unwrap();
    filled_bytes_tx.send(filled_bytes).unwrap();
    assert_eq!(
        presenter.present(|_| panic!("invalid request reached the caller")),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn approval_presenter_times_out_while_reading_a_request() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_approval_presenter_handshake(&mut server);
        thread::sleep(SHORT + SHORT);
    });
    let mut presenter = handshake_approval_presenter_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(
        presenter.present(|_| ApprovalDecision::Deny),
        Err(ClientError::Timeout)
    );
    worker.join().unwrap();
}

#[test]
fn approval_presenter_connects_and_serves_until_the_peer_closes() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        complete_approval_presenter_handshake(&mut stream);
        for (request_id, challenge, decision) in [
            ("00000000000000000000000000000073", "first", "approve"),
            ("00000000000000000000000000000074", "second", "deny"),
        ] {
            let mut request = approval_present_request();
            request["request_id"] = serde_json::json!(request_id);
            request["body"]["challenge"] = serde_json::json!(challenge);
            stream.write_all(&encode_frame(&request).unwrap()).unwrap();
            let response = read_client_value(&mut stream);
            assert_eq!(response["request_id"], request_id);
            assert_eq!(response["body"]["challenge"], challenge);
            assert_eq!(response["body"]["decision"], decision);
        }
    });

    let mut presenter = connect_approval_presenter_at(&path, "0.0.1", SHORT).unwrap();
    let outcome = presenter
        .serve(|request| match request.challenge.as_str() {
            "first" => ApprovalDecision::Approve,
            "second" => ApprovalDecision::Deny,
            _ => panic!("unexpected challenge"),
        })
        .unwrap();
    assert_eq!(outcome, ApprovalPresenterServeOutcome::ConnectionClosed);
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn approval_presenter_reconnects_and_stops() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = ApprovalPresenterStopHandle::new();
    let worker_stop = stop.clone();
    let (connected_tx, connected) = mpsc::channel();
    let (check_tx, wait_for_stop) = mpsc::channel();
    let (observed_tx, observed) = mpsc::channel();
    let server = thread::spawn(move || {
        for (request_id, challenge) in [
            ("00000000000000000000000000000073", "first"),
            ("00000000000000000000000000000074", "second"),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            complete_approval_presenter_handshake(&mut stream);
            let mut request = approval_present_request();
            request["request_id"] = serde_json::json!(request_id);
            request["body"]["challenge"] = serde_json::json!(challenge);
            stream.write_all(&encode_frame(&request).unwrap()).unwrap();
            let response = read_client_value(&mut stream);
            assert_eq!(response["request_id"], request_id);
            assert_eq!(response["body"]["challenge"], challenge);
            if challenge == "second" {
                connected_tx.send(()).unwrap();
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).unwrap(), 0);
            }
        }
        listener.set_nonblocking(true).unwrap();
        wait_for_stop.recv_timeout(SHORT).unwrap();
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    });

    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_approval_presenter_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            Duration::from_millis(10),
            worker_stop,
            move |presenting| observed_tx.send(presenting).unwrap(),
            |_| ApprovalDecision::Approve,
        );
    });
    connected.recv_timeout(SHORT + SHORT).unwrap();
    stop.stop();
    worker.join().unwrap();
    assert_eq!(
        observed.try_iter().collect::<Vec<_>>(),
        [true, false, true, false]
    );
    thread::sleep(Duration::from_millis(30));
    check_tx.send(()).unwrap();
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn approval_presenter_retries_failed_connect_and_refused_handshake() {
    let path = socket_path();
    let retry = Duration::from_millis(100);
    let stop = ApprovalPresenterStopHandle::new();
    let worker_stop = stop.clone();
    let path_for_worker = path.clone();
    let started_at = Instant::now();
    let worker = thread::spawn(move || {
        serve_approval_presenter_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            retry,
            worker_stop,
            |_| {},
            |_| ApprovalDecision::Approve,
        );
    });

    thread::sleep(Duration::from_millis(30));
    let listener = UnixListener::bind(&path).unwrap();
    let (mut refused, _) = listener.accept().unwrap();
    assert!(started_at.elapsed() >= retry.saturating_sub(Duration::from_millis(5)));
    read_client_frame(&mut refused);
    refused
        .write_all(
            &encode_frame(&ErrorEnvelope {
                protocol: Protocol,
                request_id: None,
                ok: Failure,
                error: ProtocolError::unauthorized(),
            })
            .unwrap(),
        )
        .unwrap();
    drop(refused);
    let refused_at = Instant::now();

    let (mut accepted, _) = listener.accept().unwrap();
    assert!(refused_at.elapsed() >= retry.saturating_sub(Duration::from_millis(5)));
    complete_approval_presenter_handshake(&mut accepted);
    stop.stop();
    worker.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn approval_presenter_stop_interrupts_a_blocked_connect() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    // SAFETY: The listener owns a valid socket descriptor for this call.
    assert_eq!(unsafe { listen(listener.as_raw_fd(), 0) }, 0);
    let queued = UnixStream::connect(&path).unwrap();
    let stop = ApprovalPresenterStopHandle::new();
    let worker_stop = stop.clone();
    let path_for_worker = path.clone();
    let (returned_tx, returned) = mpsc::channel();
    let worker = thread::spawn(move || {
        serve_approval_presenter_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            |_| {},
            |_| ApprovalDecision::Approve,
        );
        returned_tx.send(()).unwrap();
    });
    thread::sleep(Duration::from_millis(20));

    let (stopped, stopped_rx) = mpsc::channel();
    let stopper = thread::spawn(move || {
        stop.stop();
        stopped.send(()).unwrap();
    });
    assert!(
        stopped_rx.recv_timeout(SHORT).is_ok(),
        "stop did not interrupt the blocked connection attempt"
    );
    assert!(
        returned.recv_timeout(SHORT).is_ok(),
        "serve did not return while the connection attempt was blocked"
    );
    stopper.join().unwrap();
    worker.join().unwrap();
    drop(queued);
    drop(listener);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn approval_presenter_rejects_an_endpoint_with_a_nul_byte() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut endpoint = path.as_os_str().as_bytes().to_vec();
    endpoint.extend_from_slice(b"\0ignored");
    let endpoint = PathBuf::from(std::ffi::OsString::from_vec(endpoint));
    let stop = ApprovalPresenterStopHandle::new();
    let worker_stop = stop.clone();
    let worker = thread::spawn(move || {
        serve_approval_presenter_at(
            &endpoint,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            |_| {},
            |_| ApprovalDecision::Approve,
        );
    });

    thread::sleep(Duration::from_millis(20));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    stop.stop();
    worker.join().unwrap();
    drop(listener);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn approval_presenter_maps_an_unreachable_endpoint() {
    let path = socket_path();
    assert_eq!(
        connect_approval_presenter_at(&path, "0.0.1", SHORT).unwrap_err(),
        ClientError::DesktopUnavailable
    );
}

fn approval_present_request() -> serde_json::Value {
    serde_json::json!({
        "protocol": "muniment.attach/1",
        "request_id": "00000000000000000000000000000073",
        "operation": "approval.present",
        "capability": "33".repeat(32),
        "body": {
            "challenge": "fixture-challenge",
            "claimed_kind": "editor-extension",
            "claimed_version": "0.0.1",
            "workspace": "workspace-1",
            "scopes": ["thread.read"],
            "deadline_ms": 120_000,
        }
    })
}

#[test]
fn approval_presenter_rejects_unauthorized_requests_without_asking_the_caller() {
    let mut cases = vec![
        serde_json::json!({"capability": "44".repeat(32)}),
        serde_json::json!({"operation": "migration.control"}),
        serde_json::json!({"body": {"deadline_ms": 0}}),
        serde_json::json!({"body": {"deadline_ms": 120_001}}),
    ];
    for field in ["challenge", "claimed_kind", "claimed_version", "workspace"] {
        for value in [
            String::new(),
            "bad\nvalue".into(),
            "x".repeat(64 * 1024 + 1),
        ] {
            cases.push(serde_json::json!({"body": {field: value}}));
        }
    }
    for scope in [
        String::new(),
        "bad\nvalue".into(),
        "x".repeat(64 * 1024 + 1),
    ] {
        cases.push(serde_json::json!({"body": {"scopes": [scope]}}));
    }
    for change in cases {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_approval_presenter_handshake(&mut server);
            let mut request = serde_json::json!({
                "protocol": "muniment.attach/1",
                "request_id": "00000000000000000000000000000073",
                "operation": "approval.present",
                "capability": "33".repeat(32),
                "body": {
                    "challenge": "challenge",
                    "claimed_kind": "cli",
                    "claimed_version": "0.0.1",
                    "workspace": "workspace",
                    "scopes": ["thread.read"],
                    "deadline_ms": 1,
                }
            });
            for (key, value) in change.as_object().unwrap() {
                if key == "body" {
                    for (body_key, body_value) in value.as_object().unwrap() {
                        request["body"][body_key] = body_value.clone();
                    }
                } else {
                    request[key] = value.clone();
                }
            }
            let bytes = serde_json::to_vec(&request).unwrap();
            server
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            server.write_all(&bytes).unwrap();
            let answer = read_client_value(&mut server);
            assert_eq!(answer["request_id"], request["request_id"]);
            assert_eq!(answer["error"]["code"], "unauthorized");
        });
        let mut presenter = handshake_approval_presenter_stream(client, "0.0.1", SHORT).unwrap();
        assert_eq!(
            presenter.present(|_| panic!("invalid request reached the caller")),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
}

#[test]
fn migration_handshake_accepts_only_a_credential_free_grant() {
    for include_credential in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            read_client_frame(&mut server);
            server
                .write_all(
                    &encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap(),
                )
                .unwrap();
            let mut grant = serde_json::json!({
                "profile_id": "",
                "capability": "33".repeat(32),
                "expires_at": 60,
                "idle_timeout_seconds": 60,
                "workspace_scopes": {},
            });
            if include_credential {
                grant["authorized_client_credential"] = serde_json::json!("44".repeat(32));
            }
            server.write_all(&encode_frame(&grant).unwrap()).unwrap();
        });

        let result = handshake_migration_control_stream(client, "0.0.1", SHORT);
        if include_credential {
            assert_eq!(result.unwrap_err(), ClientError::UnexpectedMessage);
        } else {
            let client = result.unwrap();
            assert_eq!(client.capability(), "33".repeat(32));
            assert_eq!(client.authorization_summary().expires_in_seconds, 60);
        }
        sender.join().unwrap();
    }
}

fn complete_migration_handshake(server: &mut UnixStream) {
    read_client_frame(server);
    server
        .write_all(&encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap())
        .unwrap();
    server
        .write_all(
            &encode_frame(&serde_json::json!({
                "profile_id": "",
                "capability": "33".repeat(32),
                "expires_at": 60,
                "idle_timeout_seconds": 60,
                "workspace_scopes": {},
            }))
            .unwrap(),
        )
        .unwrap();
}

fn complete_desktop_client_handshake(server: &mut UnixStream) {
    complete_desktop_client_handshake_with_version(server, "0.0.1");
}

fn complete_desktop_client_handshake_with_version(server: &mut UnixStream, version: &str) {
    let hello = read_client_value(server);
    assert_eq!(hello["client"]["kind"], "desktop-client");
    assert!(hello.get("authorized_client_credential").is_none());
    server
        .write_all(&encode_frame(&reconnect_welcome(1, version, "11".repeat(16), "")).unwrap())
        .unwrap();
    server
        .write_all(
            &encode_frame(&serde_json::json!({
                "profile_id": "profile-1",
                "capability": "33".repeat(32),
                "expires_at": 60,
                "idle_timeout_seconds": 30,
                "workspace_scopes": {"/work/signed": ["threads:read"]},
            }))
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn desktop_client_holder_is_unavailable_without_a_connection() {
    let holder = DesktopClientHolder::new();
    assert_eq!(holder.runtime_version(), None);
    assert_eq!(
        holder.request(Operation::ThreadList, None, serde_json::json!({})),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.rename_thread("thread-1", "Renamed thread"),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.delete_thread("thread-1"),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.thread_select("thread-1"),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.recheck_retention(),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(holder.sign_in(), Err(ClientError::DesktopUnavailable));
    assert_eq!(
        holder.thread_summaries(50, None),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.thread_history("thread-1", 100, None),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.run_submit("prompt", &[], None),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.run_cancel("01900000-0000-7000-8000-000000000001"),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.run_resume("01900000-0000-7000-8000-000000000001"),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.run_steer("01900000-0000-7000-8000-000000000001", "text"),
        Err(ClientError::DesktopUnavailable)
    );
    assert_eq!(
        holder.run_follow_up("01900000-0000-7000-8000-000000000001", "text"),
        Err(ClientError::DesktopUnavailable)
    );
}

#[test]
fn desktop_thread_select_matches_the_fixtures_and_maps_a_protocol_error() {
    let request_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/request-thread-select.json"
    ))
    .unwrap();
    let response_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/response-thread-select.json"
    ))
    .unwrap();
    let thread_id = request_fixture["body"]["thread_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let server_thread_id = thread_id.clone();
    let expected_body = response_fixture["body"].clone();
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        for error in [false, true] {
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            assert_eq!(request["operation"], request_fixture["operation"]);
            assert_eq!(
                request["body"],
                serde_json::json!({"thread_id": server_thread_id})
            );
            assert!(request.get("idempotency_key").is_none());
            let frame = if error {
                encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(Id::new(request_id).unwrap()),
                    ok: Failure,
                    error: ProtocolError::unauthorized(),
                })
            } else {
                encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: expected_body.clone(),
                })
            };
            server.write_all(&frame.unwrap()).unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(
        client.thread_select(""),
        Err(ClientError::UnexpectedMessage)
    );
    client.thread_select(&thread_id).unwrap();
    assert_eq!(
        client.thread_select(&thread_id),
        Err(ClientError::AuthorizationExpired)
    );
    worker.join().unwrap();
}

#[test]
fn desktop_recheck_retention_matches_the_fixtures_and_maps_a_protocol_error() {
    let request_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/request-retention-recheck.json"
    ))
    .unwrap();
    let response_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/response-retention-recheck.json"
    ))
    .unwrap();
    let expected_body = response_fixture["body"].clone();
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        for error in [false, true] {
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            assert_eq!(request["operation"], request_fixture["operation"]);
            assert_eq!(request["body"], request_fixture["body"]);
            assert!(request.get("idempotency_key").is_none());
            let frame = if error {
                encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(Id::new(request_id).unwrap()),
                    ok: Failure,
                    error: ProtocolError::persistence_failed(),
                })
            } else {
                encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: expected_body.clone(),
                })
            };
            server.write_all(&frame.unwrap()).unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    client.recheck_retention().unwrap();
    assert_eq!(client.recheck_retention(), Err(ClientError::DesktopFailed));
    worker.join().unwrap();
}

#[test]
fn desktop_run_resume_matches_the_fixture_and_maps_a_protocol_error() {
    let response_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/response-run-resume.json"
    ))
    .unwrap();
    let expected_body = response_fixture["body"].clone();
    let run_id = expected_body["run_id"].as_str().unwrap().to_owned();
    let server_run_id = run_id.clone();
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        for error in [false, true] {
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            assert_eq!(request["operation"], "run.resume");
            assert_eq!(
                request["body"],
                serde_json::json!({"run_id": server_run_id})
            );
            let idempotency_key = request["idempotency_key"].as_str().unwrap();
            assert_ne!(idempotency_key, request_id);
            let frame = if error {
                encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(Id::new(request_id).unwrap()),
                    ok: Failure,
                    error: ProtocolError::unauthorized(),
                })
            } else {
                encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: expected_body.clone(),
                })
            };
            server.write_all(&frame.unwrap()).unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    let accepted = client.run_resume(&run_id).unwrap();
    assert_eq!(accepted.run_id, run_id);
    assert_eq!(accepted.thread_id, "00000000000000000000000000000192");
    assert_eq!(accepted.committed_seq, 2);
    assert_eq!(accepted.accepted_at, "2026-07-17T00:00:00Z");
    assert_eq!(
        client.run_resume(&run_id),
        Err(ClientError::AuthorizationExpired)
    );
    worker.join().unwrap();
}

#[test]
fn desktop_run_cancel_holder_returns_success_and_disconnects_on_client_error() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let observer_stop = stop.clone();
    let holder = DesktopClientHolder::new();
    let worker_holder = holder.clone();
    let worker_stop = stop.clone();
    let (observed_tx, observed) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut stream);
        for accepted_at in ["2026-07-17T00:00:00Z", "bad"] {
            let request = read_client_value(&mut stream);
            assert_eq!(request["operation"], "run.cancel");
            assert_eq!(
                request["body"],
                serde_json::json!({
                    "run_id": "01900000-0000-7000-8000-000000000001",
                })
            );
            stream
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "run_id": "01900000-0000-7000-8000-000000000001",
                            "accepted_at": accepted_at,
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            worker_holder,
            move |connected| {
                observed_tx.send(connected).unwrap();
                if !connected {
                    observer_stop.stop();
                }
            },
        );
    });

    let run_id = "01900000-0000-7000-8000-000000000001";
    assert_eq!(observed.recv_timeout(SHORT), Ok(true));
    let accepted = holder.run_cancel(run_id).unwrap();
    assert_eq!(accepted.run_id, run_id);
    assert_eq!(accepted.accepted_at, "2026-07-17T00:00:00Z");
    assert_eq!(
        holder.run_cancel(run_id),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(observed.recv_timeout(SHORT), Ok(false));
    worker.join().unwrap();
    server.join().unwrap();
    assert_eq!(
        holder.run_cancel(run_id),
        Err(ClientError::DesktopUnavailable)
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_run_submit_matches_the_fixture_and_validates_the_result() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        let mut keys = BTreeSet::new();
        for thread_id in [None, Some("01900000-0000-7000-8000-000000000002")] {
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            let key = request["idempotency_key"].as_str().unwrap().to_owned();
            assert_eq!(request["operation"], "run.submit");
            assert_eq!(
                request["body"],
                serde_json::json!({
                    "text": "Summarize the selected file.",
                    "files": ["/work/repo/src/main.rs"],
                    "thread_id": thread_id
                })
            );
            assert_ne!(request_id, key);
            assert!(keys.insert(key));
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "run_id": "01900000-0000-7000-8000-000000000001",
                            "thread_id": "01900000-0000-7000-8000-000000000002",
                            "attachments": [{
                                "displayName": "main.rs",
                                "byteLength": 128,
                                "mediaType": "text/rust"
                            }],
                            "committed_seq": 1,
                            "accepted_at": "2026-07-17T00:00:00Z"
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let files = ["/work/repo/src/main.rs".to_owned()];
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    let accepted = client
        .run_submit("Summarize the selected file.", &files, None)
        .unwrap();
    assert_eq!(accepted.attachments[0].display_name, "main.rs");
    client
        .run_submit(
            "Summarize the selected file.",
            &files,
            Some("01900000-0000-7000-8000-000000000002"),
        )
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn desktop_run_submit_rejects_invalid_results() {
    for body in [
        serde_json::json!({"run_id":"bad","thread_id":"01900000-0000-7000-8000-000000000002","attachments":[],"committed_seq":1,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001","thread_id":"01900000-0000-7000-8000-000000000003","attachments":[],"committed_seq":1,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001","thread_id":"01900000-0000-7000-8000-000000000002","attachments":[],"committed_seq":0,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001","thread_id":"01900000-0000-7000-8000-000000000002","attachments":[],"committed_seq":1,"accepted_at":"bad"}),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
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
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        assert_eq!(
            client.run_submit("prompt", &[], Some("01900000-0000-7000-8000-000000000002")),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
}

#[test]
fn desktop_run_messages_match_the_fixtures_and_use_fresh_keys() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        let mut keys = BTreeSet::new();
        for (operation, text) in [
            ("run.steer", "Focus on error handling."),
            ("run.follow_up", "Now suggest tests."),
        ] {
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], operation);
            assert_eq!(
                request["body"],
                serde_json::json!({
                    "run_id": "01900000-0000-7000-8000-000000000001",
                    "text": text,
                })
            );
            let request_id = request["request_id"].as_str().unwrap();
            let key = request["idempotency_key"].as_str().unwrap();
            assert_ne!(request_id, key);
            assert!(keys.insert(key.to_owned()));
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "run_id": "01900000-0000-7000-8000-000000000001",
                            "accepted_at": "2026-07-17T00:00:00Z",
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    client
        .run_steer(
            "01900000-0000-7000-8000-000000000001",
            "Focus on error handling.",
        )
        .unwrap();
    client
        .run_follow_up("01900000-0000-7000-8000-000000000001", "Now suggest tests.")
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn desktop_run_messages_reject_invalid_input_and_receipts() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        for body in [
            serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000002","accepted_at":"2026-07-17T00:00:00Z"}),
            serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001","accepted_at":"bad"}),
            serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001","accepted_at":"2026-07-17T00:00:00Z","extra":true}),
        ] {
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
        }
    });
    let run_id = "01900000-0000-7000-8000-000000000001";
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(
        client.run_steer("bad", "text"),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.run_steer(run_id, "   "),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.run_follow_up(run_id, &"x".repeat(32 * 1024 + 1)),
        Err(ClientError::UnexpectedMessage)
    );
    for call in 0..3 {
        let result = if call == 1 {
            client.run_follow_up(run_id, "text")
        } else {
            client.run_steer(run_id, "text")
        };
        assert_eq!(result, Err(ClientError::UnexpectedMessage));
    }
    worker.join().unwrap();
}

#[test]
fn desktop_thread_mutations_match_the_golden_request_bodies() {
    let rename_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/request-thread-rename.json"
    ))
    .unwrap();
    let delete_fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/request-thread-delete.json"
    ))
    .unwrap();
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        let mut keys = BTreeSet::new();
        for (operation, fixture) in [
            ("thread.rename", rename_fixture),
            ("thread.delete", delete_fixture),
        ] {
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], operation);
            assert_eq!(request["body"], fixture["body"]);
            let request_id = request["request_id"].as_str().unwrap();
            let key = request["idempotency_key"].as_str().unwrap();
            assert_ne!(request_id, key);
            assert_eq!(key.as_bytes()[14], b'7');
            assert!(keys.insert(key.to_owned()));
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({}),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    client.rename_thread("thread-1", "Renamed thread").unwrap();
    client.delete_thread("thread-1").unwrap();
    worker.join().unwrap();
}

#[test]
fn desktop_thread_mutations_reject_invalid_input_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(
        client.rename_thread("", "title"),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.rename_thread("thread-1", ""),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.delete_thread(""),
        Err(ClientError::UnexpectedMessage)
    );
    drop(client);
    worker.join().unwrap();
}

#[test]
fn desktop_thread_mutations_reject_invalid_answers_and_map_errors() {
    for rename in [true, false] {
        for (answer, expected) in [
            ("uncorrelated", ClientError::UnexpectedMessage),
            ("hybrid", ClientError::UnexpectedMessage),
            ("nonempty", ClientError::UnexpectedMessage),
            ("error", ClientError::ThreadNotFound),
        ] {
            let (client, mut server) = UnixStream::pair().unwrap();
            let worker = thread::spawn(move || {
                complete_desktop_client_handshake(&mut server);
                let request = read_client_value(&mut server);
                let request_id = request["request_id"].as_str().unwrap();
                if answer == "error" {
                    server
                        .write_all(
                            &encode_frame(&ErrorEnvelope {
                                protocol: Protocol,
                                request_id: Some(Id::new(request_id).unwrap()),
                                ok: Failure,
                                error: ProtocolError::thread_not_found(),
                            })
                            .unwrap(),
                        )
                        .unwrap();
                    return;
                }
                let value = match answer {
                    "uncorrelated" => serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": "00000000000000000000000000000074",
                        "ok": true,
                        "body": {}
                    }),
                    "hybrid" => serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": request_id,
                        "ok": true,
                        "body": {},
                        "error": {"code": "thread_not_found", "message": "missing"}
                    }),
                    "nonempty" => serde_json::json!({
                        "protocol": "muniment.attach/1",
                        "request_id": request_id,
                        "ok": true,
                        "body": {"accepted": true}
                    }),
                    _ => unreachable!(),
                };
                server.write_all(&encode_frame(&value).unwrap()).unwrap();
            });
            let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
            let result = if rename {
                client.rename_thread("thread-1", "Renamed thread")
            } else {
                client.delete_thread("thread-1")
            };
            assert_eq!(result, Err(expected));
            worker.join().unwrap();
        }
    }
}

#[test]
fn desktop_second_tranche_methods_send_and_validate_requests() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        let calls = [
            (
                "session.status",
                serde_json::json!({"signed_in": false, "subject": null, "expires_at": null}),
                false,
            ),
            (
                "entitlement.snapshot",
                serde_json::json!({"snapshot": null, "changed_snapshot_version": null}),
                false,
            ),
            ("device.list", serde_json::json!({"devices": []}), false),
            (
                "session.sign_in",
                serde_json::json!({"status": "signed_in"}),
                true,
            ),
            (
                "session.sign_out",
                serde_json::json!({"status": "signed_out"}),
                true,
            ),
            (
                "companion.list",
                serde_json::json!({"companions": []}),
                false,
            ),
            ("companion.revoke", serde_json::json!({}), true),
        ];
        let mut keys = BTreeSet::new();
        for (operation, body, mutating) in calls {
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], operation);
            assert_eq!(
                request["body"],
                if operation == "companion.revoke" {
                    serde_json::json!({"client_identity": "companion-1"})
                } else {
                    serde_json::json!({})
                }
            );
            if mutating {
                let key = request["idempotency_key"].as_str().unwrap();
                assert_ne!(request["request_id"], key);
                assert!(keys.insert(key.to_owned()));
            } else {
                assert!(request.get("idempotency_key").is_none());
            }
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
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    client.session_status().unwrap();
    client.entitlement_snapshot().unwrap();
    client.list_devices().unwrap();
    assert_eq!(
        client.sign_in().unwrap(),
        serde_json::json!({"status": "signed_in"})
    );
    client.sign_out().unwrap();
    client.list_companions().unwrap();
    client.revoke_companion("companion-1").unwrap();
    worker.join().unwrap();
}

#[test]
fn desktop_thread_read_methods_send_requests_and_return_bodies() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        for (operation, request_body, response_body) in [
            (
                "thread.summaries",
                serde_json::json!({"limit": 50, "cursor": "thread-cursor-1"}),
                serde_json::json!({"summaries": [], "next_cursor": null}),
            ),
            (
                "thread.history",
                serde_json::json!({
                    "thread_id": "thread-1",
                    "limit": 100,
                    "cursor": "message-cursor-1"
                }),
                serde_json::json!({
                    "thread_id": "thread-1",
                    "entries": [],
                    "next_cursor": null
                }),
            ),
        ] {
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], operation);
            assert_eq!(request["body"], request_body);
            assert!(request.get("idempotency_key").is_none());
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: response_body,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(
        client
            .thread_summaries(50, Some("thread-cursor-1"))
            .unwrap(),
        serde_json::json!({"summaries": [], "next_cursor": null})
    );
    assert_eq!(
        client
            .thread_history("thread-1", 100, Some("message-cursor-1"))
            .unwrap(),
        serde_json::json!({"thread_id": "thread-1", "entries": [], "next_cursor": null})
    );
    worker.join().unwrap();
}

#[test]
fn desktop_chat_subscription_reads_events_and_refuses_other_frames() {
    for refusal in [None, Some("subscription"), Some("event")] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], "run.chat_events");
            assert_eq!(request["body"], serde_json::json!({}));
            assert!(request.get("idempotency_key").is_none());
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "subscription_id": "00000000000000000000000000000190"
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
            let subscription_id = if refusal == Some("subscription") {
                "00000000000000000000000000000191"
            } else {
                "00000000000000000000000000000190"
            };
            let event = if refusal == Some("event") {
                EventName::ArtifactComplete
            } else {
                EventName::ChatEvent
            };
            server
                .write_all(
                    &encode_frame(&Event {
                        protocol: Protocol,
                        subscription_id: Id::new(subscription_id).unwrap(),
                        event,
                        run_id: None,
                        run_seq: None,
                        body: serde_json::json!({"phase": "running"}),
                    })
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        assert_eq!(
            client.subscribe_chat_events().unwrap(),
            "00000000000000000000000000000190"
        );
        let result = client.read_chat_event();
        if refusal.is_some() {
            assert_eq!(result, Err(ClientError::UnexpectedMessage));
        } else {
            assert_eq!(result.unwrap(), serde_json::json!({"phase": "running"}));
        }
        worker.join().unwrap();
    }
}

#[test]
fn desktop_chat_subscription_maps_revocation_and_disconnect() {
    for revoked in [true, false] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "subscription_id": "00000000000000000000000000000190"
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
            if revoked {
                server
                    .write_all(
                        &encode_frame(&Event {
                            protocol: Protocol,
                            subscription_id: Id::new("00000000000000000000000000000190").unwrap(),
                            event: EventName::CapabilityRevoked,
                            run_id: None,
                            run_seq: None,
                            body: serde_json::json!({
                                "capability": "33".repeat(32),
                                "reason": "signed out"
                            }),
                        })
                        .unwrap(),
                    )
                    .unwrap();
            }
        });
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        client.subscribe_chat_events().unwrap();
        assert_eq!(
            client.read_chat_event(),
            Err(if revoked {
                ClientError::CapabilityRevoked
            } else {
                ClientError::DesktopUnavailable
            })
        );
        worker.join().unwrap();
    }
}

#[test]
fn desktop_revoke_companion_rejects_invalid_identity_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(
        client.revoke_companion(""),
        Err(ClientError::UnexpectedMessage)
    );
    assert_eq!(
        client.revoke_companion(&"x".repeat(64 * 1024 + 1)),
        Err(ClientError::UnexpectedMessage)
    );
    drop(client);
    worker.join().unwrap();
}

#[test]
fn desktop_second_tranche_methods_reject_missing_answer_keys() {
    for call in 0..7 {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: serde_json::json!({"unexpected": true}),
                    })
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        let result = match call {
            0 => client.session_status(),
            1 => client.entitlement_snapshot(),
            2 => client.list_devices(),
            3 => client.sign_in(),
            4 => client.sign_out(),
            5 => client.list_companions(),
            6 => client.revoke_companion("companion-1"),
            _ => unreachable!(),
        };
        assert_eq!(result, Err(ClientError::UnexpectedMessage));
        worker.join().unwrap();
    }
}

#[test]
fn desktop_sign_in_failure_disconnects_the_held_client() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let observer_stop = stop.clone();
    let holder = DesktopClientHolder::new();
    let worker_holder = holder.clone();
    let worker_stop = stop.clone();
    let (observed_tx, observed) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut stream);
        let request = read_client_value(&mut stream);
        assert_eq!(request["operation"], "session.sign_in");
    });
    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            worker_holder,
            move |connected| {
                observed_tx.send(connected).unwrap();
                if !connected {
                    observer_stop.stop();
                }
            },
        );
    });

    assert_eq!(observed.recv_timeout(SHORT), Ok(true));
    assert_eq!(holder.sign_in(), Err(ClientError::ConnectionClosed));
    assert_eq!(observed.recv_timeout(SHORT), Ok(false));
    worker.join().unwrap();
    server.join().unwrap();
    assert_eq!(holder.sign_in(), Err(ClientError::DesktopUnavailable));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_supervisor_publishes_reconnects_and_stops() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let holder = DesktopClientHolder::new();
    let worker_stop = stop.clone();
    let worker_holder = holder.clone();
    let (observed_tx, observed) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        complete_desktop_client_handshake_with_version(&mut first, "1.2.3");
        let request = read_client_value(&mut first);
        assert_eq!(request["operation"], "thread.list");
        drop(first);

        let (mut second, _) = listener.accept().unwrap();
        complete_desktop_client_handshake_with_version(&mut second, "1.3.0");
        let request = read_client_value(&mut second);
        let request_id = request["request_id"].as_str().unwrap();
        second
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: serde_json::json!({"threads": []}),
                })
                .unwrap(),
            )
            .unwrap();
        let mut byte = [0];
        assert_eq!(second.read(&mut byte).unwrap(), 0);
    });
    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            Duration::from_millis(10),
            worker_stop,
            worker_holder,
            move |connected| observed_tx.send(connected).unwrap(),
        );
    });

    observed.recv_timeout(SHORT).unwrap();
    assert_eq!(holder.runtime_version().as_deref(), Some("1.2.3"));
    assert_eq!(
        holder.request(Operation::ThreadList, None, serde_json::json!({})),
        Err(ClientError::ConnectionClosed)
    );
    assert_eq!(observed.recv_timeout(SHORT), Ok(false));
    assert_eq!(holder.runtime_version(), None);
    assert_eq!(observed.recv_timeout(SHORT), Ok(true));
    assert_eq!(holder.runtime_version().as_deref(), Some("1.3.0"));
    assert!(holder
        .request(Operation::ThreadList, None, serde_json::json!({}))
        .is_ok());
    stop.stop();
    worker.join().unwrap();
    assert_eq!(observed.recv_timeout(SHORT), Ok(false));
    assert_eq!(holder.runtime_version(), None);
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_supervisor_retries_a_refused_handshake() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let worker_stop = stop.clone();
    let worker_holder = DesktopClientHolder::new();
    let server = thread::spawn(move || {
        let (mut refused, _) = listener.accept().unwrap();
        read_client_frame(&mut refused);
        refused
            .write_all(
                &encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: None,
                    ok: Failure,
                    error: ProtocolError::unauthorized(),
                })
                .unwrap(),
            )
            .unwrap();
        drop(refused);
        let (mut accepted, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut accepted);
        let mut byte = [0];
        assert_eq!(accepted.read(&mut byte).unwrap(), 0);
    });
    let path_for_worker = path.clone();
    let (connected_tx, connected) = mpsc::channel();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            Duration::from_millis(10),
            worker_stop,
            worker_holder,
            move |state| {
                if state {
                    connected_tx.send(()).unwrap();
                }
            },
        );
    });
    connected.recv_timeout(SHORT + SHORT).unwrap();
    stop.stop();
    worker.join().unwrap();
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_stop_serializes_publication_and_notifications() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let holder = DesktopClientHolder::new();
    let worker_stop = stop.clone();
    let worker_holder = holder.clone();
    let (observed_tx, observed) = mpsc::channel();
    let (publishing_tx, publishing) = mpsc::channel();
    let (release_tx, release) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut client);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    });
    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            worker_holder,
            move |connected| {
                if connected {
                    publishing_tx.send(()).unwrap();
                    release.recv().unwrap();
                }
                observed_tx.send(connected).unwrap();
            },
        );
    });

    publishing.recv_timeout(SHORT).unwrap();
    let (stopped_tx, stopped) = mpsc::channel();
    let stopper = thread::spawn(move || {
        stop.stop();
        stopped_tx.send(()).unwrap();
    });
    assert_eq!(
        stopped.recv_timeout(SHORT),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    release_tx.send(()).unwrap();
    assert_eq!(observed.recv_timeout(SHORT), Ok(true));
    stopped.recv_timeout(SHORT).unwrap();
    worker.join().unwrap();
    stopper.join().unwrap();
    assert_eq!(observed.recv_timeout(SHORT), Ok(false));
    assert_eq!(observed.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    assert_eq!(
        holder.request(Operation::ThreadList, None, serde_json::json!({})),
        Err(ClientError::DesktopUnavailable)
    );
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_connected_observer_can_stop_the_supervisor() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let holder = DesktopClientHolder::new();
    let worker_stop = stop.clone();
    let observer_stop = stop.clone();
    let worker_holder = holder.clone();
    let server = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut client);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    });
    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            worker_holder,
            move |connected| {
                if connected {
                    observer_stop.stop();
                }
            },
        );
    });

    worker.join().unwrap();
    assert_eq!(
        holder.request(Operation::ThreadList, None, serde_json::json!({})),
        Err(ClientError::DesktopUnavailable)
    );
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_supervisor_keeps_one_connection_until_failure() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let holder = DesktopClientHolder::new();
    let worker_stop = stop.clone();
    let worker_holder = holder.clone();
    let retry_interval = Duration::from_millis(60);
    let (healthy_tx, healthy) = mpsc::channel();
    let (fail_tx, fail) = mpsc::channel();
    let (reconnected_tx, reconnected) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut first);
        listener.set_nonblocking(true).unwrap();
        healthy_tx.send(()).unwrap();
        thread::sleep(retry_interval + Duration::from_millis(20));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        fail_tx.send(()).unwrap();
        let request = read_client_value(&mut first);
        assert_eq!(request["operation"], "thread.list");
        let failed_at = Instant::now();
        drop(first);
        listener.set_nonblocking(false).unwrap();
        let (mut second, _) = listener.accept().unwrap();
        assert!(failed_at.elapsed() >= retry_interval);
        complete_desktop_client_handshake(&mut second);
        reconnected_tx.send(()).unwrap();
        let mut byte = [0];
        assert_eq!(second.read(&mut byte).unwrap(), 0);
    });
    let path_for_worker = path.clone();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            retry_interval,
            worker_stop,
            worker_holder,
            |_| {},
        );
    });

    healthy.recv_timeout(SHORT).unwrap();
    fail.recv_timeout(SHORT + SHORT).unwrap();
    assert_eq!(
        holder.request(Operation::ThreadList, None, serde_json::json!({})),
        Err(ClientError::ConnectionClosed)
    );
    reconnected.recv_timeout(SHORT + SHORT).unwrap();
    stop.stop();
    worker.join().unwrap();
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_stop_interrupts_a_blocked_connect() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    // SAFETY: The listener owns a valid socket descriptor for this call.
    assert_eq!(unsafe { listen(listener.as_raw_fd(), 0) }, 0);
    let queued = UnixStream::connect(&path).unwrap();
    let stop = DesktopClientStopHandle::new();
    let worker_stop = stop.clone();
    let path_for_worker = path.clone();
    let (returned_tx, returned) = mpsc::channel();
    let worker = thread::spawn(move || {
        serve_desktop_client_at(
            &path_for_worker,
            "0.0.1",
            SHORT,
            SHORT,
            worker_stop,
            DesktopClientHolder::new(),
            |_| {},
        );
        returned_tx.send(()).unwrap();
    });
    thread::sleep(Duration::from_millis(20));
    stop.stop();
    returned.recv_timeout(SHORT).unwrap();
    worker.join().unwrap();
    drop(queued);
    drop(listener);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_handshake_returns_the_admitted_grant() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || complete_desktop_client_handshake(&mut server));
    let client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(client.capability(), "33".repeat(32));
    assert_eq!(client.profile_id(), "profile-1");
    assert_eq!(client.workspace_scopes().len(), 1);
    assert_eq!(
        client.workspace_scopes()["/work/signed"],
        BTreeSet::from(["threads:read".to_owned()])
    );
    assert_eq!(client.authorization_summary().expires_in_seconds, 60);
    assert_eq!(client.authorization_summary().idle_timeout_seconds, 30);
    worker.join().unwrap();
}

#[test]
fn desktop_client_handshake_rejects_invalid_welcome_and_grant_fields() {
    let cases = [
        (2, "authorized", "profile-1", 1, 64, false),
        (1, "pairing_required", "profile-1", 1, 64, false),
        (1, "authorized", "", 1, 64, false),
        (1, "authorized", "profile-1", 2, 64, false),
        (1, "authorized", "profile-1", 1, 63, false),
        (1, "authorized", "profile-1", 1, 65, false),
        (1, "authorized", "profile-1", 1, 64, true),
    ];
    for (selected, authorization, profile, scope_count, capability_len, credential) in cases {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            read_client_frame(&mut server);
            let mut welcome =
                serde_json::to_value(reconnect_welcome(selected, "0.0.1", "11".repeat(16), ""))
                    .unwrap();
            welcome["authorization"] = serde_json::json!(authorization);
            server.write_all(&encode_frame(&welcome).unwrap()).unwrap();
            if selected == 1 && authorization == "authorized" {
                let scopes = match scope_count {
                    0 => serde_json::json!({}),
                    1 => serde_json::json!({"one": []}),
                    _ => serde_json::json!({"one": [], "two": []}),
                };
                let mut grant = serde_json::json!({
                    "profile_id": profile,
                    "capability": "a".repeat(capability_len),
                    "expires_at": 60,
                    "idle_timeout_seconds": 30,
                    "workspace_scopes": scopes,
                });
                if credential {
                    grant["authorized_client_credential"] = serde_json::json!("44".repeat(32));
                }
                server.write_all(&encode_frame(&grant).unwrap()).unwrap();
            }
        });
        assert_eq!(
            handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap_err(),
            ClientError::UnexpectedMessage
        );
        worker.join().unwrap();
    }
}

#[test]
fn desktop_client_handshake_accepts_empty_workspace_authority() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        read_client_frame(&mut server);
        server
            .write_all(&encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap())
            .unwrap();
        server
            .write_all(
                &encode_frame(&serde_json::json!({
                    "profile_id": "desktop-owner",
                    "capability": "33".repeat(32),
                    "expires_at": 60,
                    "idle_timeout_seconds": 30,
                    "workspace_scopes": {},
                }))
                .unwrap(),
            )
            .unwrap();
    });

    let client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    assert_eq!(client.profile_id(), "desktop-owner");
    assert!(client.workspace_scopes().is_empty());
    worker.join().unwrap();
}

#[test]
fn desktop_client_handshake_rejects_a_nonhex_capability() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        read_client_frame(&mut server);
        server
            .write_all(&encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap())
            .unwrap();
        server
            .write_all(
                &encode_frame(&serde_json::json!({
                    "profile_id": "profile-1",
                    "capability": "g".repeat(64),
                    "expires_at": 60,
                    "idle_timeout_seconds": 30,
                    "workspace_scopes": {"one": []},
                }))
                .unwrap(),
            )
            .unwrap();
    });
    assert_eq!(
        handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap_err(),
        ClientError::UnexpectedMessage
    );
    worker.join().unwrap();
}

#[test]
fn desktop_client_sends_the_capability_and_checks_the_response_id() {
    for matching_id in [true, false] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], "thread.list");
            assert_eq!(request["capability"], "33".repeat(32));
            assert_eq!(request["body"], serde_json::json!({"limit": 20}));
            let request_id = if matching_id {
                request["request_id"].as_str().unwrap()
            } else {
                "00000000000000000000000000000073"
            };
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({"threads": []}),
                    })
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        let result = client.request(
            Operation::ThreadList,
            None,
            serde_json::json!({"limit": 20}),
        );
        if matching_id {
            assert_eq!(result.unwrap().body, serde_json::json!({"threads": []}));
        } else {
            assert_eq!(result.unwrap_err(), ClientError::UnexpectedMessage);
        }
        worker.join().unwrap();
    }
}

#[test]
fn desktop_client_connects_at_a_path() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let worker = thread::spawn(move || {
        let (mut server, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut server);
    });
    assert_eq!(
        connect_desktop_client_at(&path, "0.0.1", SHORT)
            .unwrap()
            .profile_id(),
        "profile-1"
    );
    worker.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn desktop_client_connects_through_the_runtime_directory() {
    let _environment = ENVIRONMENT.lock().unwrap();
    let runtime = std::env::temp_dir().join(format!(
        "muniment-client-runtime-test-{}-{}",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    ));
    let attach_directory = runtime.join("muniment");
    std::fs::create_dir_all(&attach_directory).unwrap();
    let path = attach_directory.join("attach-v1.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let previous_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", &runtime);
    let worker = thread::spawn(move || {
        let (mut server, _) = listener.accept().unwrap();
        complete_desktop_client_handshake(&mut server);
    });

    let client = connect_desktop_client("0.0.1");
    match previous_runtime {
        Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
        None => std::env::remove_var("XDG_RUNTIME_DIR"),
    }
    assert_eq!(client.unwrap().profile_id(), "profile-1");
    worker.join().unwrap();
    std::fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn migration_control_sends_authorized_request_and_checks_echo() {
    for response_nonce in ["handoff-nonce", "different-nonce"] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_migration_handshake(&mut server);
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            assert_eq!(
                request,
                serde_json::json!({
                    "protocol": "muniment.attach/1",
                    "request_id": request_id,
                    "operation": "migration.control",
                    "capability": "33".repeat(32),
                    "body": { "handoff_nonce": "handoff-nonce", "deadline_ms": 30_000 }
                })
            );
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({ "handoff_nonce": response_nonce }),
                    })
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_migration_control_stream(client, "0.0.1", SHORT).unwrap();
        let result = client.control_migration("handoff-nonce", 30_000);
        if response_nonce == "handoff-nonce" {
            assert_eq!(result.unwrap(), MigrationControlOutcome::Accepted);
        } else {
            assert_eq!(result.unwrap_err(), MigrationControlFailure::NonceMismatch);
        }
        worker.join().unwrap();
    }
}

#[test]
fn migration_control_maps_expected_refusals() {
    let cases = [
        (
            ProtocolError::migration_not_ready(),
            MigrationControlOutcome::MigrationNotReady { retryable: true },
        ),
        (
            ProtocolError::unauthorized(),
            MigrationControlOutcome::Unauthorized,
        ),
        (
            ProtocolError::unsupported_operation(),
            MigrationControlOutcome::UnsupportedOperation,
        ),
    ];
    for (error, expected) in cases {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_migration_handshake(&mut server);
            let request = read_client_value(&mut server);
            server
                .write_all(
                    &encode_frame(&ErrorEnvelope {
                        protocol: Protocol,
                        request_id: Some(Id::new(request["request_id"].as_str().unwrap()).unwrap()),
                        ok: Failure,
                        error,
                    })
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_migration_control_stream(client, "0.0.1", SHORT).unwrap();
        assert_eq!(
            client.control_migration("handoff-nonce", 30_000).unwrap(),
            expected
        );
        worker.join().unwrap();
    }
}

#[test]
fn migration_control_rejects_invalid_bounds_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_migration_handshake(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        let mut prefix = [0; 4];
        assert!(matches!(
            server.read_exact(&mut prefix).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    });
    let mut client = handshake_migration_control_stream(client, "0.0.1", SHORT).unwrap();
    for nonce in ["", "bad\nnonce", &"x".repeat(129)] {
        assert_eq!(
            client.control_migration(nonce, 1).unwrap_err(),
            MigrationControlFailure::InvalidNonce
        );
    }
    for deadline_ms in [0, 60_001] {
        assert_eq!(
            client
                .control_migration("handoff-nonce", deadline_ms)
                .unwrap_err(),
            MigrationControlFailure::InvalidDeadline
        );
    }
    worker.join().unwrap();
}

#[test]
fn reconnect_welcome_does_not_report_pairing_pending() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        read_client_frame(&mut server);
        server
            .write_all(
                &encode_frame(&reconnect_welcome(
                    1,
                    "0.0.1",
                    "11".repeat(16),
                    "22".repeat(16),
                ))
                .unwrap(),
            )
            .unwrap();
        server
            .write_all(
                &encode_frame(&muniment_attach::authorized_with_client_credential(
                    "profile-id",
                    "33".repeat(32),
                    3600,
                    900,
                    BTreeMap::new(),
                    "44".repeat(32),
                ))
                .unwrap(),
            )
            .unwrap();
    });
    let mut pending = 0;
    let client = handshake_stream_with_credential(
        client,
        "0.0.1",
        "018f0000-0000-7000-8000-000000000099",
        Some(&"44".repeat(32)),
        SHORT,
        SHORT,
        || pending += 1,
    )
    .unwrap();
    assert_eq!(pending, 0);
    assert_eq!(client.authorization_summary().expires_in_seconds, 3600);
    sender.join().unwrap();
}

#[test]
fn invalid_reconnect_welcome_reports_pairing_and_cannot_continue_without_approval() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        read_client_frame(&mut server);
        server
            .write_all(
                &encode_frame(&welcome(1, "0.0.1", "11".repeat(16), "22".repeat(16))).unwrap(),
            )
            .unwrap();
    });
    let mut pending = 0;
    assert_eq!(
        handshake_stream_with_credential(
            client,
            "0.0.1",
            "018f0000-0000-7000-8000-000000000099",
            Some(&"55".repeat(32)),
            SHORT,
            SHORT,
            || pending += 1,
        )
        .unwrap_err(),
        ClientError::ConnectionClosed
    );
    assert_eq!(pending, 1);
    sender.join().unwrap();
}

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
            "profile-id",
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
    assert_eq!(client.profile_id(), "profile-id");
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
                "profile-id",
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
                "window": { "max_events": 1024, "max_bytes": 4194304, "max_text_bytes": 262144 }
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
fn run_stream_decodes_pending_permissions_and_counts_them_for_acknowledgement() {
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
                "permission.pending",
                serde_json::json!({
                    "gate_id": "secret-gate", "kind": "confirm", "title": "Allow access?"
                }),
            ),
            run_stream_event(
                subscription_id,
                run_id,
                2,
                "run.event",
                serde_json::json!({
                    "event_type": "assistant.message", "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:00Z", "payload": { "withheld": true }
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
                "permission.pending",
                serde_json::json!({
                    "gate_id": "another-secret", "kind": "confirm", "title": "Run command?",
                    "message": "Sensitive command details"
                }),
            ),
        ] {
            server.write_all(&encode_frame(&envelope).unwrap()).unwrap();
        }
        let acknowledgement = read_client_value(&mut server);
        assert_eq!(acknowledgement["operation"], "run.cursor_ack");
        assert_eq!(acknowledgement["body"]["through_run_seq"], 3);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(acknowledgement["request_id"].as_str().unwrap()).unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "subscription_id": subscription_id, "through_run_seq": 3
                    }),
                })
                .unwrap(),
            )
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    let RunStreamMessage::PermissionPending(permission) = client.read_run_stream_message().unwrap()
    else {
        panic!("expected pending permission")
    };
    assert_eq!(permission.run_seq, 1);
    assert_eq!(permission.kind, PermissionKind::Confirm);
    assert_eq!(permission.gate_id, "secret-gate");
    assert_eq!(permission.title, "Allow access?");
    assert_eq!(permission.message, None);
    let debug = format!("{permission:?}");
    assert!(!debug.contains("secret-gate"));
    assert!(!debug.contains("Allow access?"));
    assert!(matches!(
        client.read_run_stream_message(),
        Ok(RunStreamMessage::Event(event)) if event.run_seq == 2
    ));
    assert_eq!(
        client.read_run_stream_message().unwrap(),
        RunStreamMessage::CaughtUp { current_run_seq: 2 }
    );
    let RunStreamMessage::PermissionPending(permission) = client.read_run_stream_message().unwrap()
    else {
        panic!("expected pending permission")
    };
    assert_eq!(permission.run_seq, 3);
    assert_eq!(
        permission.message.as_deref(),
        Some("Sensitive command details")
    );
    let debug = format!("{permission:?}");
    assert!(!debug.contains("another-secret"));
    assert!(!debug.contains("Run command?"));
    assert!(!debug.contains("Sensitive command details"));
    client.acknowledge_run_cursor(3).unwrap();
    worker.join().unwrap();
}

#[test]
fn run_stream_decodes_closed_and_revoked_events() {
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
        for event in [
            run_stream_event(
                subscription_id,
                run_id,
                2,
                "stream.closed",
                serde_json::json!({"code": "invalid_cursor", "resumable": true}),
            ),
            serde_json::to_value(Event {
                protocol: Protocol,
                subscription_id: Id::new("01900000-0000-7000-8000-000000000003").unwrap(),
                event: EventName::CapabilityRevoked,
                run_id: None,
                run_seq: None,
                body: serde_json::json!({
                    "capability": "fixture-capability", "reason": "authorization_revoked"
                }),
            })
            .unwrap(),
        ] {
            server.write_all(&encode_frame(&event).unwrap()).unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    assert_eq!(
        client.read_run_stream_message().unwrap(),
        RunStreamMessage::StreamClosed {
            code: "invalid_cursor".to_owned(),
            resumable: true,
        }
    );
    let revoked = client.read_run_stream_message().unwrap();
    assert_eq!(
        revoked,
        RunStreamMessage::CapabilityRevoked {
            capability: "fixture-capability".to_owned(),
            reason: "authorization_revoked".to_owned(),
        }
    );
    assert!(!format!("{revoked:?}").contains("fixture-capability"));
    worker.join().unwrap();
}

#[test]
fn run_stream_decodes_malformed_resumable_as_false() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    for body in [
        serde_json::json!({"code": "invalid_cursor"}),
        serde_json::json!({"code": "invalid_cursor", "resumable": "yes"}),
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
            server
                .write_all(
                    &encode_frame(&run_stream_event(
                        subscription_id,
                        run_id,
                        2,
                        "stream.closed",
                        body,
                    ))
                    .unwrap(),
                )
                .unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        client.subscribe_run(run_id, 0).unwrap();
        assert!(matches!(
            client.read_run_stream_message(),
            Ok(RunStreamMessage::StreamClosed {
                resumable: false,
                ..
            })
        ));
        worker.join().unwrap();
    }
}

#[test]
fn run_stream_rejects_malformed_revoked_bodies() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let malformed = run_stream_event(
        subscription_id,
        run_id,
        2,
        "capability.revoked",
        serde_json::json!({"capability": "fixture-capability"}),
    );
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
        server
            .write_all(&encode_frame(&malformed).unwrap())
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    assert_eq!(
        client.read_run_stream_message(),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn canonical_run_event_fixture_passes_client_validation() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let fixture: Event = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/event-run-stream.json"
    ))
    .unwrap();
    let run_id = fixture.run_id.as_ref().unwrap().as_str().to_owned();
    let subscription_id = fixture.subscription_id.as_str().to_owned();
    let server_run_id = run_id.clone();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                    ok: Success,
                    body: valid_run_stream_summary(&server_run_id, &subscription_id),
                })
                .unwrap(),
            )
            .unwrap();
        server.write_all(&encode_frame(&fixture).unwrap()).unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(&run_id, 0).unwrap();
    let RunStreamMessage::Event(event) = client.read_run_stream_message().unwrap() else {
        panic!("expected run event fixture");
    };
    assert_eq!(event.event_type, "assistant.message");
    worker.join().unwrap();
}

#[test]
fn canonical_tool_effect_fixture_passes_client_validation() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let fixture: Event = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment.attach/1/event-run-stream-tool-effect.json"
    ))
    .unwrap();
    let run_id = fixture.run_id.as_ref().unwrap().as_str().to_owned();
    let subscription_id = fixture.subscription_id.as_str().to_owned();
    let server_run_id = run_id.clone();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                    ok: Success,
                    body: valid_run_stream_summary(&server_run_id, &subscription_id),
                })
                .unwrap(),
            )
            .unwrap();
        server.write_all(&encode_frame(&fixture).unwrap()).unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(&run_id, 0).unwrap();
    let RunStreamMessage::Event(event) = client.read_run_stream_message().unwrap() else {
        panic!("expected tool effect fixture");
    };
    assert_eq!(event.event_type, "tool.effect.started");
    assert_eq!(event.effect_id.as_deref(), Some("tool-1"));
    assert_eq!(event.display_name.as_deref(), Some("Search"));
    worker.join().unwrap();
}

#[test]
fn run_stream_client_enforces_tool_effect_identity_bounds() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let boundary = "x".repeat(65_536);
    let valid = serde_json::json!({
        "event_type": "tool.effect.started", "event_version": 1,
        "recorded_at": "2026-07-17T00:00:02Z",
        "payload": { "effect_id": boundary, "display_name": boundary }
    });
    let invalid = [
        serde_json::json!({"effect_id": ""}),
        serde_json::json!({"effect_id": "x".repeat(65_537)}),
        serde_json::json!({"effect_id": "tool-1", "display_name": "x".repeat(65_537)}),
        serde_json::json!({"effect_id": "tool-1", "display_name": "terminal-name"}),
    ];

    for (event_type, payload, expected) in [("tool.effect.started", valid["payload"].clone(), None)]
        .into_iter()
        .chain(invalid.into_iter().enumerate().map(|(index, payload)| {
            let event_type = if index == 3 {
                "tool.effect.completed"
            } else {
                "tool.effect.started"
            };
            let error = if index == 1 || index == 2 {
                ClientError::MalformedFrame
            } else {
                ClientError::UnexpectedMessage
            };
            (event_type, payload, Some(error))
        }))
        .chain([(
            "tool.effect.failed",
            serde_json::json!({"effect_id": "tool-1", "display_name": "terminal-name"}),
            Some(ClientError::UnexpectedMessage),
        )])
    {
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
                "event_type": event_type, "event_version": 1,
                "recorded_at": "2026-07-17T00:00:02Z", "payload": payload
            });
            let event = serde_json::to_vec(&run_stream_event(
                subscription_id,
                run_id,
                1,
                "run.event",
                body,
            ))
            .unwrap();
            server
                .write_all(&(event.len() as u32).to_be_bytes())
                .unwrap();
            server.write_all(&event).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        client.subscribe_run(run_id, 0).unwrap();
        if let Some(expected) = expected {
            assert_eq!(client.read_run_stream_message(), Err(expected));
        } else {
            let RunStreamMessage::Event(event) = client.read_run_stream_message().unwrap() else {
                panic!("expected boundary tool effect")
            };
            assert_eq!(event.effect_id.as_ref().unwrap().len(), 65_536);
            assert_eq!(event.display_name.as_ref().unwrap().len(), 65_536);
        }
        worker.join().unwrap();
    }
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
fn run_stream_waits_past_the_request_timeout_for_a_live_event() {
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
                        "first_available_run_seq": 1, "current_run_seq": 1,
                        "window": { "max_events": 1024, "max_bytes": 4194304, "max_text_bytes": 262144 }
                    }),
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
                1,
                "subscription.caught_up",
                serde_json::json!({}),
            ),
        ] {
            server.write_all(&encode_frame(&envelope).unwrap()).unwrap();
        }
        thread::sleep(SHORT * 2);
        server
            .write_all(
                &encode_frame(&run_stream_event(
                    subscription_id,
                    run_id,
                    2,
                    "run.event",
                    serde_json::json!({
                        "event_type": "run.completed", "event_version": 1,
                        "recorded_at": "2026-07-17T00:00:01Z", "payload": { "withheld": true }
                    }),
                ))
                .unwrap(),
            )
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.subscribe_run(run_id, 0).unwrap();
    assert!(matches!(
        client.read_run_stream_message(),
        Ok(RunStreamMessage::Event(event)) if event.run_seq == 1
    ));
    assert_eq!(
        client.read_run_stream_message().unwrap(),
        RunStreamMessage::CaughtUp { current_run_seq: 1 }
    );
    assert!(matches!(
        client.read_run_stream_message(),
        Ok(RunStreamMessage::Event(event))
            if event.run_seq == 2 && event.event_type == "run.completed"
    ));
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
                        "window": { "max_events": 1, "max_bytes": 4194304, "max_text_bytes": 262144 }
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
        "window": { "max_events": 1024, "max_bytes": 4194304, "max_text_bytes": 262144 }
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
                "window": { "max_events": 1, "max_bytes": 1, "max_text_bytes": 1 }
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
                "window": { "max_events": 1, "max_bytes": 1, "max_text_bytes": 1 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 0, "max_bytes": 4194305, "max_text_bytes": 1 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 1025, "max_bytes": 1, "max_text_bytes": 1 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 1, "max_bytes": 1, "max_text_bytes": 0 }
            })),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(serde_json::json!({
                "subscription_id": subscription_id, "run_id": run_id,
                "first_available_run_seq": 1, "current_run_seq": 2,
                "window": { "max_events": 1, "max_bytes": 1, "max_text_bytes": 262145 }
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
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({ "kind": "confirm", "title": "Title" }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({
                "gate_id": "gate", "kind": "confirm", "title": "Title",
                "unexpected": "hostile-secret"
            }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({ "gate_id": " \n", "kind": "confirm", "title": "Title" }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({
                "gate_id": "g".repeat(257), "kind": "confirm", "title": "Title"
            }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({ "gate_id": "gate", "kind": "allow", "title": "Title" }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({ "gate_id": "gate", "kind": "confirm", "title": "\t" }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({
                "gate_id": "gate", "kind": "confirm", "title": "t".repeat(1025)
            }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({
                "gate_id": "gate", "kind": "confirm", "title": "Title",
                "message": null
            }),
        ),
        run_stream_event(
            subscription_id,
            run_id,
            1,
            "permission.pending",
            serde_json::json!({
                "gate_id": "gate", "kind": "confirm", "title": "Title",
                "message": "m".repeat(4097)
            }),
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
                            "thread_id": "01900000-0000-7000-8000-000000000002",
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
fn run_start_in_workspace_thread_sends_the_thread_binding() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let thread_id = "01900000-0000-7000-8000-000000000003";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        let request_id = request["request_id"].as_str().unwrap().to_owned();
        let idempotency_key = request["idempotency_key"].as_str().unwrap().to_owned();
        assert_eq!(
            request,
            serde_json::json!({
                "protocol": "muniment.attach/1",
                "request_id": request_id,
                "operation": "run.start",
                "capability": "33".repeat(32),
                "idempotency_key": idempotency_key,
                "body": {
                    "text": "continued prompt",
                    "workspace": "workspace",
                    "thread_id": thread_id
                }
            })
        );
        server
            .write_all(
                &encode_frame(&Response {
                    protocol: Protocol,
                    request_id: Id::new(request_id).unwrap(),
                    ok: Success,
                    body: serde_json::json!({
                        "run_id": "01900000-0000-7000-8000-000000000001",
                        "thread_id": thread_id,
                        "committed_seq": 1,
                        "accepted_at": "2026-07-17T00:00:00Z"
                    }),
                })
                .unwrap(),
            )
            .unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let accepted = client
        .start_run_in_workspace_thread("continued prompt", None, Some("workspace"), Some(thread_id))
        .unwrap();
    assert_eq!(accepted.thread_id, thread_id);
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
                serde_json::json!({"run_id":"bad", "thread_id":"01900000-0000-7000-8000-000000000002", "committed_seq":2, "accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001", "thread_id":"01900000-0000-7000-8000-000000000002", "committed_seq":0, "accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001", "thread_id":"01900000-0000-7000-8000-000000000002", "committed_seq":2, "accepted_at":"not a timestamp"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"x".repeat(65), "thread_id":"01900000-0000-7000-8000-000000000002", "committed_seq":2, "accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":"01900000-0000-7000-8000-000000000001", "thread_id":"01900000-0000-7000-8000-000000000002", "committed_seq":2, "accepted_at":"2026-07-17T00:00:00Z", "prompt":"leaked"}),
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
fn permission_answer_uses_exact_envelopes_and_fresh_ids() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let run_id = "01900000-0000-7000-8000-000000000001";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let mut seen = BTreeSet::new();
        for (gate_id, decision) in [("gate-a", "allow"), ("gate-b", "deny")] {
            let request = read_client_value(&mut server);
            let request_id = request["request_id"].as_str().unwrap().to_owned();
            let idempotency_key = request["idempotency_key"].as_str().unwrap().to_owned();
            assert_eq!(
                request,
                serde_json::json!({
                    "protocol": "muniment.attach/1", "request_id": request_id,
                    "operation": "permission.answer", "capability": "33".repeat(32),
                    "idempotency_key": idempotency_key,
                    "body": { "run_id": run_id, "gate_id": gate_id, "decision": decision }
                })
            );
            assert_eq!(request_id.as_bytes()[14], b'7');
            assert_eq!(idempotency_key.as_bytes()[14], b'7');
            assert!(seen.insert(request_id.clone()));
            assert!(seen.insert(idempotency_key));
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request_id).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "run_id": run_id, "gate_id": gate_id, "decision": decision,
                            "committed_seq": 2, "accepted_at": "2026-07-17T00:00:00Z"
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let accepted = client
        .answer_permission(run_id, "gate-a", PermissionDecision::Allow)
        .unwrap();
    assert!(!format!("{accepted:?}").contains("gate-a"));
    client
        .answer_permission(run_id, "gate-b", PermissionDecision::Deny)
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn permission_answer_rejects_invalid_input_without_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        assert!(server.read(&mut [0]).is_err());
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    for (run_id, gate_id) in [
        ("bad", "gate"),
        ("01900000-0000-7000-8000-000000000001", " "),
        ("01900000-0000-7000-8000-000000000001", &"x".repeat(257)),
    ] {
        assert_eq!(
            client.answer_permission(run_id, gate_id, PermissionDecision::Allow),
            Err(ClientError::UnexpectedMessage)
        );
    }
    worker.join().unwrap();
}

#[test]
fn permission_answer_rejects_hostile_receipts_and_maps_errors() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    for (body, expected) in [
        (
            Some(
                serde_json::json!({"run_id":run_id,"gate_id":"other","decision":"allow","committed_seq":2,"accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":run_id,"gate_id":"gate","decision":"deny","committed_seq":2,"accepted_at":"2026-07-17T00:00:00Z"}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (
            Some(
                serde_json::json!({"run_id":run_id,"gate_id":"gate","decision":"allow","committed_seq":0,"accepted_at":"bad","unknown":true}),
            ),
            ClientError::UnexpectedMessage,
        ),
        (None, ClientError::DesktopFailed),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let request_id = Id::new(request["request_id"].as_str().unwrap()).unwrap();
            let bytes = match body {
                Some(body) => encode_frame(&Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body,
                })
                .unwrap(),
                None => encode_frame(&ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(request_id),
                    ok: Failure,
                    error: ProtocolError::persistence_failed(),
                })
                .unwrap(),
            };
            server.write_all(&bytes).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(
            client.answer_permission(run_id, "gate", PermissionDecision::Allow),
            Err(expected)
        );
        worker.join().unwrap();
    }
}

#[test]
fn run_permission_answer_preserves_every_answer_and_uses_fresh_ids() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let answers = vec![
        ChatPermissionAnswer::Select("choice-a".into()),
        ChatPermissionAnswer::Confirm(true),
        ChatPermissionAnswer::Input("input text".into()),
        ChatPermissionAnswer::Editor("editor text\n".into()),
        ChatPermissionAnswer::Cancelled,
        ChatPermissionAnswer::CodeDiff {
            gate_id: "code-gate".into(),
            effect_id: "effect-1".into(),
            code_diff_id: "diff-1".into(),
            diff_sha256: "11".repeat(32),
            write_plan_sha256: "22".repeat(32),
        },
    ];
    let expected = answers.clone();
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_desktop_client_handshake(&mut server);
        let mut request_ids = BTreeSet::new();
        let mut idempotency_keys = BTreeSet::new();
        for (index, answer) in expected.into_iter().enumerate() {
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], "run.permission_answer");
            assert_eq!(request["body"]["run_id"], run_id);
            assert_eq!(request["body"]["gate_id"], format!("gate-{index}"));
            assert_eq!(
                request["body"]["answer"],
                serde_json::to_value(&answer).unwrap()
            );
            assert!(request_ids.insert(request["request_id"].as_str().unwrap().to_owned()));
            assert!(
                idempotency_keys.insert(request["idempotency_key"].as_str().unwrap().to_owned())
            );
            server
                .write_all(
                    &encode_frame(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: serde_json::json!({
                            "run_id": run_id,
                            "gate_id": format!("gate-{index}"),
                            "answer": answer,
                            "committed_seq": index + 1,
                            "accepted_at": "2026-07-17T00:00:00Z"
                        }),
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
    for (index, answer) in answers.into_iter().enumerate() {
        let accepted = client
            .run_permission_answer(run_id, &format!("gate-{index}"), answer.clone())
            .unwrap();
        assert_eq!(accepted.answer, answer);
    }
    worker.join().unwrap();
}

#[test]
fn run_permission_answer_rejects_invalid_input_and_receipts() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    for (bad_run_id, bad_gate_id) in [("bad", "gate"), (run_id, " \n"), (run_id, &"x".repeat(257))]
    {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
            assert_eq!(server.read(&mut [0]).unwrap(), 0);
        });
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        assert_eq!(
            client.run_permission_answer(
                bad_run_id,
                bad_gate_id,
                ChatPermissionAnswer::Confirm(true)
            ),
            Err(ClientError::UnexpectedMessage)
        );
        drop(client);
        worker.join().unwrap();
    }

    let hostile = [
        serde_json::json!({"run_id":"bad","gate_id":"gate","answer":{"type":"confirm","value":true},"committed_seq":1,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":run_id,"gate_id":"other","answer":{"type":"confirm","value":true},"committed_seq":1,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":run_id,"gate_id":"gate","answer":{"type":"confirm","value":false},"committed_seq":1,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":run_id,"gate_id":"gate","answer":{"type":"confirm","value":true},"committed_seq":0,"accepted_at":"2026-07-17T00:00:00Z"}),
        serde_json::json!({"run_id":run_id,"gate_id":"gate","answer":{"type":"confirm","value":true},"committed_seq":1,"accepted_at":"bad"}),
    ];
    for body in hostile {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_desktop_client_handshake(&mut server);
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
        let mut client = handshake_desktop_client_stream(client, "0.0.1", SHORT).unwrap();
        assert_eq!(
            client.run_permission_answer(run_id, "gate", ChatPermissionAnswer::Confirm(true)),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
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
fn thread_create_uses_exact_envelope_and_rejects_unknown_accept_fields() {
    for unknown_field in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            assert_eq!(request["operation"], "thread.create");
            assert_eq!(request["body"], serde_json::json!({}));
            assert!(request["idempotency_key"].as_str().is_some());
            let mut body = serde_json::json!({
                "thread_id": "0190a100-0000-7000-8000-000000000001"
            });
            if unknown_field {
                body["extra"] = serde_json::json!(true);
            }
            let response = Response {
                protocol: Protocol,
                request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                ok: Success,
                body,
            };
            server.write_all(&encode_frame(&response).unwrap()).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        let result = client.create_thread();
        if unknown_field {
            assert_eq!(result, Err(ClientError::UnexpectedMessage));
        } else {
            assert_eq!(
                result.unwrap().thread_id,
                "0190a100-0000-7000-8000-000000000001"
            );
        }
        worker.join().unwrap();
    }
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
fn run_open_uses_exact_envelope_and_returns_the_first_page() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let run_id = "01900000-0000-7000-8000-000000000001";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        assert_eq!(request["protocol"], "muniment.attach/1");
        assert_eq!(request["operation"], "run.open");
        assert_eq!(request["capability"], "33".repeat(32));
        assert_eq!(request["body"], serde_json::json!({"run_id": run_id}));
        assert!(request.get("idempotency_key").is_none());
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({
                "run_id": run_id,
                "first_available_run_seq": 1,
                "current_run_seq": 1,
                "events": [{
                    "run_seq": 1,
                    "event_type": "run.started",
                    "event_version": 1,
                    "recorded_at": "2026-07-17T00:00:00Z",
                    "text": "secret-event-text"
                }],
                "exhausted": true
            }),
        };
        for byte in encode_frame(&response).unwrap() {
            server.write_all(&[byte]).unwrap();
        }
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let page = client.open_run(run_id).unwrap();
    assert_eq!(
        &page,
        &RunOpenPage {
            run_id: run_id.into(),
            first_available_run_seq: 1,
            current_run_seq: 1,
            events: vec![RedactedRunEvent {
                run_seq: 1,
                event_type: "run.started".into(),
                event_version: 1,
                recorded_at: "2026-07-17T00:00:00Z".into(),
                text: Some("secret-event-text".into()),
                effect_id: None,
                display_name: None,
                receipt: None,
            }],
            exhausted: true,
        }
    );
    assert!(!format!("{page:?}").contains("secret-event-text"));
    assert_eq!(
        client.acknowledge_run_cursor(1),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn run_open_rejects_invalid_input_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        assert!(server.read(&mut [0]).is_err());
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.open_run("not-a-run-id"),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn artifact_window_uses_exact_envelope_and_returns_the_grant() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let transfer_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        assert_eq!(request["protocol"], "muniment.attach/1");
        assert_eq!(request["operation"], "artifact.window");
        assert_eq!(request["capability"], "33".repeat(32));
        assert_eq!(
            request["body"],
            serde_json::json!({
                "transfer_id": transfer_id,
                "ack_through_chunk": -1,
                "max_chunks": 1024
            })
        );
        assert!(request.get("idempotency_key").is_none());
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({"ack_through_chunk": -1, "granted_chunks": 512}),
        };
        server.write_all(&encode_frame(&response).unwrap()).unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client
            .grant_artifact_window(transfer_id, -1, 1_024)
            .unwrap(),
        ArtifactWindowGrant {
            ack_through_chunk: -1,
            granted_chunks: 512
        }
    );
    worker.join().unwrap();
}

#[test]
fn artifact_fetch_uses_exact_envelope_and_returns_transfer_metadata() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let artifact_id = "01900000-0000-7000-8000-000000000001";
    let transfer_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        assert_eq!(request["protocol"], "muniment.attach/1");
        assert_eq!(request["operation"], "artifact.fetch");
        assert_eq!(request["capability"], "33".repeat(32));
        assert_eq!(
            request["body"],
            serde_json::json!({"artifact_id": artifact_id})
        );
        assert!(request.get("idempotency_key").is_none());
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({
                "transfer_id": transfer_id,
                "artifact_id": artifact_id,
                "total_bytes": 7,
                "sha256": "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
                "chunk_bytes": 4,
                "chunk_count": 2
            }),
        };
        server.write_all(&encode_frame(&response).unwrap()).unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    let metadata = client.fetch_artifact(artifact_id).unwrap();
    assert_eq!(metadata.transfer_id, transfer_id);
    assert_eq!(metadata.artifact_id, artifact_id);
    assert_eq!(metadata.total_bytes, 7);
    assert_eq!(metadata.chunk_bytes, 4);
    assert_eq!(metadata.chunk_count, 2);
    assert_eq!(metadata.sha256.len(), 64);
    worker.join().unwrap();
}

#[test]
fn artifact_fetch_rejects_invalid_input_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        assert!(server.read(&mut [0]).is_err());
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.fetch_artifact("not-an-artifact-id"),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn subscription_cancel_uses_exact_envelope() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        assert_eq!(request["protocol"], "muniment.attach/1");
        assert_eq!(request["operation"], "request.cancel");
        assert_eq!(request["capability"], "33".repeat(32));
        assert_eq!(
            request["body"],
            serde_json::json!({
                "kind": "subscription",
                "subscription_id": subscription_id
            })
        );
        assert!(request.get("idempotency_key").is_none());
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({"subscription_id": subscription_id}),
        };
        server.write_all(&encode_frame(&response).unwrap()).unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    client.cancel_subscription(subscription_id).unwrap();
    worker.join().unwrap();
}

#[test]
fn subscription_cancel_rejects_invalid_input_before_writing() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        server.set_read_timeout(Some(SHORT)).unwrap();
        assert!(server.read(&mut [0]).is_err());
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.cancel_subscription("not-a-subscription-id"),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn subscription_cancel_maps_protocol_errors() {
    let subscription_id = "01900000-0000-7000-8000-000000000002";
    for error in [
        ProtocolError::subscription_not_found(),
        ProtocolError::already_completed(),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let response = ErrorEnvelope {
                protocol: Protocol,
                request_id: Some(Id::new(request["request_id"].as_str().unwrap()).unwrap()),
                ok: Failure,
                error,
            };
            server.write_all(&encode_frame(&response).unwrap()).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(
            client.cancel_subscription(subscription_id),
            Err(ClientError::RequestRejected)
        );
        worker.join().unwrap();
    }
}

#[test]
fn artifact_window_rejects_invalid_input_before_writing() {
    for (transfer_id, max_chunks) in [
        ("not-a-transfer-id", 1),
        ("01900000-0000-7000-8000-000000000002", 0),
        ("01900000-0000-7000-8000-000000000002", 1_025),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            server.set_read_timeout(Some(SHORT)).unwrap();
            assert!(server.read(&mut [0]).is_err());
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(
            client.grant_artifact_window(transfer_id, -1, max_chunks),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
}

#[test]
fn artifact_fetch_rejects_invalid_ids_and_unknown_fields() {
    let artifact_id = "01900000-0000-7000-8000-000000000001";
    for body in [
        serde_json::json!({
            "transfer_id": "not-a-transfer-id", "artifact_id": artifact_id,
            "total_bytes": 7, "sha256": "hash", "chunk_bytes": 4, "chunk_count": 2
        }),
        serde_json::json!({
            "transfer_id": "01900000-0000-7000-8000-000000000002",
            "artifact_id": "not-an-artifact-id", "total_bytes": 7, "sha256": "hash",
            "chunk_bytes": 4, "chunk_count": 2
        }),
        serde_json::json!({
            "transfer_id": "01900000-0000-7000-8000-000000000002",
            "artifact_id": artifact_id, "total_bytes": 7, "sha256": "hash",
            "chunk_bytes": 4, "chunk_count": 2, "extra": true
        }),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            complete_pairing(&mut server);
            let request = read_client_value(&mut server);
            let response = Response {
                protocol: Protocol,
                request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                ok: Success,
                body,
            };
            server.write_all(&encode_frame(&response).unwrap()).unwrap();
        });
        let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
        assert_eq!(
            client.fetch_artifact(artifact_id),
            Err(ClientError::UnexpectedMessage)
        );
        worker.join().unwrap();
    }
}

#[test]
fn artifact_window_rejects_unknown_response_fields() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let transfer_id = "01900000-0000-7000-8000-000000000002";
    let worker = thread::spawn(move || {
        complete_pairing(&mut server);
        let request = read_client_value(&mut server);
        let response = Response {
            protocol: Protocol,
            request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
            ok: Success,
            body: serde_json::json!({
                "ack_through_chunk": 4,
                "granted_chunks": 1,
                "extra": true
            }),
        };
        server.write_all(&encode_frame(&response).unwrap()).unwrap();
    });
    let mut client = handshake_stream(client, "0.0.1", SHORT, SHORT, || {}).unwrap();
    assert_eq!(
        client.grant_artifact_window(transfer_id, 4, 1),
        Err(ClientError::UnexpectedMessage)
    );
    worker.join().unwrap();
}

#[test]
fn run_open_rejects_invalid_response_fields_and_maps_protocol_errors() {
    let run_id = "01900000-0000-7000-8000-000000000001";
    let valid = serde_json::json!({
        "run_id": run_id,
        "first_available_run_seq": 1,
        "current_run_seq": 1,
        "events": [{
            "run_seq": 1,
            "event_type": "run.started",
            "event_version": 1,
            "recorded_at": "2026-07-17T00:00:00Z"
        }],
        "exhausted": true
    });
    let mut unknown = valid.clone();
    unknown["secret"] = serde_json::json!("not allowed");
    let mut mismatched = valid.clone();
    mismatched["run_id"] = serde_json::json!("01900000-0000-7000-8000-000000000002");
    let mut zero_first = valid.clone();
    zero_first["first_available_run_seq"] = serde_json::json!(0);
    let mut inverted = valid.clone();
    inverted["first_available_run_seq"] = serde_json::json!(2);
    inverted["current_run_seq"] = serde_json::json!(1);
    inverted["events"] = serde_json::json!([]);
    let mut bad_seq = valid.clone();
    bad_seq["events"] = serde_json::json!([{
        "run_seq": 2,
        "event_type": "run.started",
        "event_version": 1,
        "recorded_at": "2026-07-17T00:00:00Z"
    }]);
    for (body, wrong_correlation, error, expected) in [
        (Some(valid), true, None, ClientError::UnexpectedMessage),
        (
            None,
            false,
            Some(ProtocolError::unauthorized()),
            ClientError::AuthorizationExpired,
        ),
        (
            None,
            false,
            Some(ProtocolError::unsupported_operation()),
            ClientError::RequestRejected,
        ),
        (
            None,
            false,
            Some(ProtocolError::thread_not_found()),
            ClientError::ThreadNotFound,
        ),
        (
            None,
            false,
            Some(ProtocolError::persistence_failed()),
            ClientError::DesktopFailed,
        ),
        (Some(unknown), false, None, ClientError::UnexpectedMessage),
        (
            Some(mismatched),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (
            Some(zero_first),
            false,
            None,
            ClientError::UnexpectedMessage,
        ),
        (Some(inverted), false, None, ClientError::UnexpectedMessage),
        (Some(bad_seq), false, None, ClientError::UnexpectedMessage),
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
        assert_eq!(client.open_run(run_id), Err(expected));
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
    let grant = encode_frame(&authorized(
        "profile-id",
        "33".repeat(32),
        3600,
        900,
        BTreeMap::new(),
    ))
    .unwrap();

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
    let grant = authorized("profile-id", "capability-secret", 1, 1, BTreeMap::new());
    assert!(!format!("{welcome:?}").contains("nonce-secret"));
    assert!(!format!("{welcome:?}").contains("challenge-secret"));
    assert!(!format!("{grant:?}").contains("capability-secret"));
}
