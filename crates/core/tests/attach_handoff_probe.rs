#![cfg(target_os = "linux")]

use muniment_core::attach::{
    confirm_handoff_probe, decode_frame, encode_frame, probe_handoff, read_handoff_probe_welcome,
    Authorization, HandoffProbeError, Hello, Welcome,
};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

struct TestSocket(PathBuf);

impl TestSocket {
    fn new() -> Self {
        let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "muniment-handoff-probe-{}-{sequence}.sock",
            std::process::id()
        )))
    }
}

impl Drop for TestSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn read_hello(stream: &mut UnixStream) -> Hello {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; 4 + u32::from_be_bytes(prefix) as usize];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    decode_frame(&frame).unwrap().unwrap().0
}

fn welcome() -> Welcome {
    Welcome {
        selected: 1,
        desktop_version: "1.0.0".into(),
        server_nonce: "server-nonce".into(),
        authorization: Authorization::Authorized,
        approval_challenge: "challenge".into(),
        handoff_nonce: Some("handoff-nonce".into()),
    }
}

#[test]
fn reads_one_welcome_and_confirms_its_handoff_nonce() {
    let socket = TestSocket::new();
    let listener = UnixListener::bind(&socket.0).unwrap();

    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = read_hello(&mut stream);
            assert_eq!(hello.client.kind, "desktop-handoff-probe");
            assert_eq!(hello.client_nonce.len(), 32);
            assert!(hello
                .client_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()));
            assert_eq!(hello.client_nonce, hello.client_nonce.to_ascii_lowercase());
            assert!(hello.authorized_client_credential.is_none());
            stream
                .write_all(&encode_frame(&welcome()).unwrap())
                .unwrap();
            let mut extra = [0_u8; 1];
            assert_eq!(stream.read(&mut extra).unwrap(), 0);
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        let received = read_handoff_probe_welcome(&socket.0, deadline).unwrap();
        assert!(
            confirm_handoff_probe(&received, "handoff-nonce", deadline, Instant::now()).is_ok()
        );
        server.join().unwrap();
    });
}

#[test]
fn reports_a_refused_connection() {
    let socket = TestSocket::new();
    assert_eq!(
        read_handoff_probe_welcome(&socket.0, Instant::now() + Duration::from_secs(1)),
        Err(HandoffProbeError::ConnectionRefused)
    );
}

#[test]
fn rejects_an_expired_deadline_before_connecting() {
    let socket = TestSocket::new();
    assert_eq!(
        read_handoff_probe_welcome(&socket.0, Instant::now()),
        Err(HandoffProbeError::ReadinessDeadlineReached)
    );
}

#[test]
fn reports_a_listener_that_closes_without_answering() {
    let socket = TestSocket::new();
    let listener = UnixListener::bind(&socket.0).unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            read_hello(&mut stream);
        });
        assert_eq!(
            read_handoff_probe_welcome(&socket.0, Instant::now() + Duration::from_secs(1)),
            Err(HandoffProbeError::ListenerClosed)
        );
        server.join().unwrap();
    });
}

#[test]
fn rejects_a_first_frame_that_is_not_a_welcome() {
    let socket = TestSocket::new();
    let listener = UnixListener::bind(&socket.0).unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            let hello = read_hello(&mut stream);
            stream.write_all(&encode_frame(&hello).unwrap()).unwrap();
        });
        assert_eq!(
            read_handoff_probe_welcome(&socket.0, Instant::now() + Duration::from_secs(1)),
            Err(HandoffProbeError::UnexpectedFirstFrame)
        );
        server.join().unwrap();
    });
}

#[test]
fn times_out_when_a_listener_stays_silent() {
    let socket = TestSocket::new();
    let listener = UnixListener::bind(&socket.0).unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            read_hello(&mut stream);
            thread::sleep(Duration::from_millis(100));
        });
        assert_eq!(
            read_handoff_probe_welcome(&socket.0, Instant::now() + Duration::from_millis(25)),
            Err(HandoffProbeError::ReadinessDeadlineReached)
        );
        server.join().unwrap();
    });
}

#[test]
fn confirms_after_the_listener_binds() {
    let socket = TestSocket::new();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            thread::sleep(Duration::from_millis(30));
            let listener = UnixListener::bind(&socket.0).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            read_hello(&mut stream);
            stream
                .write_all(&encode_frame(&welcome()).unwrap())
                .unwrap();
        });

        assert!(probe_handoff(
            &socket.0,
            "handoff-nonce",
            Instant::now() + Duration::from_secs(1),
        )
        .is_ok());
        server.join().unwrap();
    });
}

#[test]
fn stops_retrying_when_an_endpoint_never_binds() {
    let socket = TestSocket::new();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(35);

    assert_eq!(
        probe_handoff(&socket.0, "handoff-nonce", deadline),
        Err(HandoffProbeError::ReadinessDeadlineReached)
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(35));
    assert!(elapsed < Duration::from_secs(1));
}

#[test]
fn does_not_retry_a_mismatched_nonce() {
    let socket = TestSocket::new();
    let listener = UnixListener::bind(&socket.0).unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            read_hello(&mut stream);
            let mut response = welcome();
            response.handoff_nonce = Some("other-nonce".into());
            stream
                .write_all(&encode_frame(&response).unwrap())
                .unwrap();
            listener.set_nonblocking(true).unwrap();
            thread::sleep(Duration::from_millis(30));
            assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        });

        assert_eq!(
            probe_handoff(
                &socket.0,
                "handoff-nonce",
                Instant::now() + Duration::from_secs(1),
            ),
            Err(HandoffProbeError::NonceMismatch)
        );
        server.join().unwrap();
    });
}

#[test]
fn does_not_retry_a_missing_nonce() {
    let socket = TestSocket::new();
    let listener = UnixListener::bind(&socket.0).unwrap();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (mut stream, _) = listener.accept().unwrap();
            read_hello(&mut stream);
            let mut response = welcome();
            response.handoff_nonce = None;
            stream
                .write_all(&encode_frame(&response).unwrap())
                .unwrap();
            listener.set_nonblocking(true).unwrap();
            thread::sleep(Duration::from_millis(30));
            assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        });

        assert_eq!(
            probe_handoff(
                &socket.0,
                "handoff-nonce",
                Instant::now() + Duration::from_secs(1),
            ),
            Err(HandoffProbeError::MissingNonce)
        );
        server.join().unwrap();
    });
}
