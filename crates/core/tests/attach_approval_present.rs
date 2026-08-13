#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use muniment_core::attach::{
    decode_frame, encode_frame, ApprovalPresenterConnection, ApprovalRequest, Envelope, Id,
    Operation, Request,
};
use serde_json::{json, Value};

fn approval_request() -> ApprovalRequest {
    ApprovalRequest {
        challenge: "challenge-a".into(),
        claimed_kind: "editor-extension".into(),
        claimed_version: "1.2.3".into(),
        workspace: "workspace-a".into(),
        scopes: BTreeSet::from(["run.write".into(), "thread.read".into()]),
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

fn run_answer(answer: impl FnOnce(&Request) -> Vec<u8> + Send + 'static) -> bool {
    let (client, mut presenter) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let request = read_request(&mut presenter);
        presenter.write_all(&answer(&request)).unwrap();
        request
    });
    let mut connection = ApprovalPresenterConnection::new(client, "presenter-capability");
    let approved = connection.present(&approval_request(), Duration::from_millis(250));
    let sent = server.join().unwrap();
    assert_eq!(sent.operation, Operation::ApprovalPresent);
    assert_eq!(sent.capability, "presenter-capability");
    assert_eq!(sent.idempotency_key, None);
    assert_eq!(
        sent.body,
        json!({
            "challenge": "challenge-a",
            "claimed_kind": "editor-extension",
            "claimed_version": "1.2.3",
            "workspace": "workspace-a",
            "scopes": ["run.write", "thread.read"],
            "deadline_ms": 250,
        })
    );
    approved
}

fn response(request_id: &Id, challenge: &str, decision: &str) -> Vec<u8> {
    encode_frame(&json!({
        "protocol": "muniment.attach/1",
        "request_id": request_id,
        "ok": true,
        "body": {"challenge": challenge, "decision": decision},
    }))
    .unwrap()
}

#[test]
fn returns_the_desktop_explicit_choice() {
    assert!(run_answer(|request| response(
        &request.request_id,
        "challenge-a",
        "approve"
    )));
    assert!(!run_answer(|request| response(
        &request.request_id,
        "challenge-a",
        "deny"
    )));
}

#[test]
fn rejects_uncorrelated_or_unknown_answers() {
    assert!(!run_answer(|_| response(
        &Id::new("00000000-0000-0000-0000-000000000001").unwrap(),
        "challenge-a",
        "approve"
    )));
    assert!(!run_answer(|request| response(
        &request.request_id,
        "challenge-b",
        "approve"
    )));
    assert!(!run_answer(|request| response(
        &request.request_id,
        "challenge-a",
        "later"
    )));
}

#[test]
fn rejects_a_malformed_frame_or_error_envelope() {
    assert!(!run_answer(|_| vec![0, 0, 0, 1, b'{']));
    assert!(!run_answer(|request| {
        encode_frame(&json!({
            "protocol": "muniment.attach/1",
            "request_id": request.request_id,
            "ok": false,
            "error": {
                "code": "invalid_request",
                "message": "invalid request",
            },
        }))
        .unwrap()
    }));
}

#[test]
fn returns_false_when_no_answer_arrives_before_the_deadline() {
    let (client, mut presenter) = UnixStream::pair().unwrap();
    let server = thread::spawn(move || {
        let _ = read_request(&mut presenter);
        thread::sleep(Duration::from_millis(75));
    });
    let mut connection = ApprovalPresenterConnection::new(client, "presenter-capability");

    assert!(!connection.present(&approval_request(), Duration::from_millis(20)));
    server.join().unwrap();
}

#[test]
fn canonical_response_fixture_matches_the_contract() {
    let bytes = include_bytes!(
        "../../../protocol-fixtures/muniment.attach/1/response-approval-present.json"
    );
    let fixture: Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(fixture["body"]["challenge"], "fixture-challenge");
    assert_eq!(fixture["body"]["decision"], "approve");
}
