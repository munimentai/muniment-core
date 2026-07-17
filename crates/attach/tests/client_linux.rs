#![cfg(all(target_os = "linux", feature = "client"))]

use muniment_attach::{
    authorized, encode_frame, handshake_stream, welcome, ClientError, ErrorAction, ErrorEnvelope,
    Failure, Protocol, ProtocolError, VersionRange, MAX_FRAME_LENGTH,
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
    let summary = handshake_stream(stream, "0.0.1", SHORT, SHORT, || prompted = true).unwrap();
    assert!(prompted);
    assert_eq!(summary.expires_in_seconds, 3600);
    assert_eq!(summary.idle_timeout_seconds, 900);
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
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
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}),
            Err(ClientError::Timeout)
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
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}),
            Err(ClientError::UnexpectedMessage)
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
        handshake_stream(client, "0.0.1", SHORT, SHORT, || {}),
        Err(ClientError::Timeout)
    );
    hold.join().unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    server.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        handshake_stream(client, "0.0.1", SHORT, SHORT, || {}),
        Err(ClientError::ConnectionClosed)
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
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}),
            Err(expected)
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
            handshake_stream(client, "0.0.1", SHORT, SHORT, || {}),
            Err(ClientError::ProtocolIncompatible)
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
