#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::{
    decode_frame, encode_frame, serve_approval_presenter, ApprovalCoordinator,
    ApprovalPresenterConnection, ApprovalRequest, Envelope, Request,
};
use serde_json::json;

fn approval_request(challenge: &str) -> ApprovalRequest {
    ApprovalRequest {
        challenge: challenge.into(),
        claimed_kind: "cli".into(),
        claimed_version: "1".into(),
        workspace: "workspace-a".into(),
        scopes: BTreeSet::from(["thread.read".into()]),
    }
}

fn read_request(stream: &mut UnixStream) -> Request {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; 4 + u32::from_be_bytes(prefix) as usize];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    let (Envelope::Request(request), _) = decode_frame(&frame).unwrap().unwrap() else {
        panic!("presenter received a non-request envelope");
    };
    request
}

fn answer(stream: &mut UnixStream, request: &Request, decision: &str) {
    let response = encode_frame(&json!({
        "protocol": "muniment.attach/1",
        "request_id": request.request_id,
        "ok": true,
        "body": {
            "challenge": request.body["challenge"],
            "decision": decision,
        },
    }))
    .unwrap();
    stream.write_all(&response).unwrap();
}

#[test]
fn returns_each_presented_desktop_choice() {
    let coordinator = ApprovalCoordinator::default();
    let (runtime, mut desktop) = UnixStream::pair().unwrap();
    let session = serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(runtime, "presenter-capability"),
    )
    .unwrap();
    let server = thread::spawn(move || {
        for decision in ["approve", "deny"] {
            let request = read_request(&mut desktop);
            assert!(request.body["deadline_ms"].as_u64().unwrap() <= 120_000);
            answer(&mut desktop, &request, decision);
        }
    });

    assert!(coordinator.request(approval_request("approve"), Duration::from_secs(120)));
    assert!(!coordinator.request(approval_request("deny"), Duration::from_secs(120)));

    server.join().unwrap();
    drop(session);
}

#[test]
fn rejects_a_second_session_and_allows_one_after_release() {
    let coordinator = ApprovalCoordinator::default();
    let (first, _first_peer) = UnixStream::pair().unwrap();
    let session = serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(first, "first"),
    )
    .unwrap();
    let (second, _second_peer) = UnixStream::pair().unwrap();
    assert!(serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(second, "second"),
    )
    .is_none());

    drop(session);

    let (third, _third_peer) = UnixStream::pair().unwrap();
    assert!(serve_approval_presenter(
        coordinator,
        ApprovalPresenterConnection::new(third, "third"),
    )
    .is_some());
}

#[test]
fn a_closed_connection_denies_without_waiting_for_the_request_deadline() {
    let coordinator = ApprovalCoordinator::default();
    let (runtime, desktop) = UnixStream::pair().unwrap();
    let _session = serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(runtime, "presenter-capability"),
    )
    .unwrap();
    drop(desktop);

    let started = Instant::now();
    assert!(!coordinator.request(approval_request("closed"), Duration::from_secs(120)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_silent_connection_obeys_the_request_deadline() {
    let coordinator = ApprovalCoordinator::default();
    let (runtime, mut desktop) = UnixStream::pair().unwrap();
    let _session = serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(runtime, "presenter-capability"),
    )
    .unwrap();
    let server = thread::spawn(move || {
        let request = read_request(&mut desktop);
        assert!(request.body["deadline_ms"].as_u64().unwrap() <= 80);
        thread::sleep(Duration::from_millis(200));
    });

    let started = Instant::now();
    assert!(!coordinator.request(approval_request("silent"), Duration::from_millis(80)));
    assert!(started.elapsed() < Duration::from_millis(180));
    server.join().unwrap();
}

#[test]
fn a_request_queued_behind_a_presentation_obeys_its_deadline() {
    let coordinator = ApprovalCoordinator::default();
    let (runtime, mut desktop) = UnixStream::pair().unwrap();
    let _session = serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(runtime, "presenter-capability"),
    )
    .unwrap();
    let (presented_sender, presented) = mpsc::channel();
    let server = thread::spawn(move || {
        let _ = read_request(&mut desktop);
        presented_sender.send(()).unwrap();
        thread::sleep(Duration::from_millis(250));
    });
    let first_coordinator = coordinator.clone();
    let first = thread::spawn(move || {
        first_coordinator.request(approval_request("first"), Duration::from_millis(200))
    });
    presented.recv_timeout(Duration::from_secs(1)).unwrap();

    let started = Instant::now();
    assert!(!coordinator.request(approval_request("queued"), Duration::from_millis(50)));
    assert!(started.elapsed() < Duration::from_millis(150));
    assert!(!first.join().unwrap());
    server.join().unwrap();
}

#[test]
fn dropping_the_session_denies_an_in_flight_request() {
    let coordinator = ApprovalCoordinator::default();
    let (runtime, mut desktop) = UnixStream::pair().unwrap();
    let session = serve_approval_presenter(
        coordinator.clone(),
        ApprovalPresenterConnection::new(runtime, "presenter-capability"),
    )
    .unwrap();
    let (presented_sender, presented) = mpsc::channel();
    let server = thread::spawn(move || {
        let _ = read_request(&mut desktop);
        presented_sender.send(()).unwrap();
        let mut byte = [0_u8; 1];
        let _ = desktop.read(&mut byte);
    });
    let waiter = coordinator.clone();
    let request = thread::spawn(move || {
        waiter.request(approval_request("release"), Duration::from_secs(120))
    });
    presented.recv_timeout(Duration::from_secs(1)).unwrap();

    drop(session);

    assert!(!request.join().unwrap());
    server.join().unwrap();
    let (next, _next_peer) = UnixStream::pair().unwrap();
    assert!(
        serve_approval_presenter(coordinator, ApprovalPresenterConnection::new(next, "next"),)
            .is_some()
    );
}
