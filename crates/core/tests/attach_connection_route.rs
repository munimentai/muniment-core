#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::linux::PeerCredentials;
use muniment_core::attach::{
    encode_frame, name_attach_connection_route, AttachConnectionRoute, Client, Hello, Id, Protocol,
    VersionRange,
};
use muniment_core::browser_control::{LinuxProcReader, ProcReadError};

struct FakeProcReader {
    executable: Option<PathBuf>,
}

impl LinuxProcReader for FakeProcReader {
    fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
        self.executable.as_ref().map(|_| 7).ok_or(ProcReadError)
    }

    fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
        self.executable.clone().ok_or(ProcReadError)
    }
}

fn credentials() -> PeerCredentials {
    PeerCredentials {
        pid: 424242,
        uid: 1000,
        gid: 1000,
    }
}

fn hello(kind: &str) -> Vec<u8> {
    encode_frame(&Hello {
        protocol: Protocol,
        client: Client {
            kind: kind.into(),
            version: "0.1.0".into(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: "client-nonce".into(),
        authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000099").unwrap(),
        authorized_client_credential: None,
    })
    .unwrap()
}

fn expected_and_reader() -> (PathBuf, FakeProcReader) {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    (
        executable.clone(),
        FakeProcReader {
            executable: Some(executable),
        },
    )
}

#[test]
fn verified_desktop_routes_to_approval_presenter_without_consuming_hello() {
    let (expected, reader) = expected_and_reader();
    let (mut client, server) = UnixStream::pair().unwrap();
    let frame = hello("desktop");
    client.write_all(&frame).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(17)))
        .unwrap();

    assert_eq!(
        name_attach_connection_route(
            &server,
            credentials(),
            &expected,
            &reader,
            Duration::from_secs(1),
        ),
        AttachConnectionRoute::ApprovalPresenter
    );
    assert_eq!(
        server.read_timeout().unwrap(),
        Some(Duration::from_secs(17))
    );
    let mut received = vec![0_u8; frame.len()];
    (&server).read_exact(&mut received).unwrap();
    assert_eq!(received, frame);
}

#[test]
fn verified_desktop_client_routes_to_desktop_client_without_consuming_hello() {
    let (expected, reader) = expected_and_reader();
    let (mut client, server) = UnixStream::pair().unwrap();
    let frame = hello("desktop-client");
    client.write_all(&frame).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(17)))
        .unwrap();

    assert_eq!(
        name_attach_connection_route(
            &server,
            credentials(),
            &expected,
            &reader,
            Duration::from_secs(1),
        ),
        AttachConnectionRoute::DesktopClient
    );
    assert_eq!(
        server.read_timeout().unwrap(),
        Some(Duration::from_secs(17))
    );
    let mut received = vec![0_u8; frame.len()];
    (&server).read_exact(&mut received).unwrap();
    assert_eq!(received, frame);
}

#[test]
fn handoff_probe_and_unknown_kind_route_to_companion() {
    let (expected, reader) = expected_and_reader();
    for kind in ["desktop-handoff-probe", "unknown"] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(kind)).unwrap();

        assert_eq!(
            name_attach_connection_route(
                &server,
                credentials(),
                &expected,
                &reader,
                Duration::from_secs(1),
            ),
            AttachConnectionRoute::Companion
        );
    }
}

#[test]
fn unverified_desktop_client_routes_to_companion() {
    let (expected, _) = expected_and_reader();
    let reader = FakeProcReader {
        executable: Some(fs::canonicalize("/bin/sh").unwrap()),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello("desktop-client")).unwrap();

    assert_eq!(
        name_attach_connection_route(
            &server,
            credentials(),
            &expected,
            &reader,
            Duration::from_secs(1),
        ),
        AttachConnectionRoute::Companion
    );
}

#[test]
fn unresolved_peer_routes_to_companion() {
    let expected = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader { executable: None };
    let (_client, server) = UnixStream::pair().unwrap();

    assert_eq!(
        name_attach_connection_route(
            &server,
            credentials(),
            &expected,
            &reader,
            Duration::from_secs(1),
        ),
        AttachConnectionRoute::Companion
    );
}

#[test]
fn oversized_and_malformed_frames_route_to_companion() {
    let (expected, reader) = expected_and_reader();
    for frame in [(4093_u32).to_be_bytes().to_vec(), vec![0, 0, 0, 1, 0xff]] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&frame).unwrap();
        assert_eq!(
            name_attach_connection_route(
                &server,
                credentials(),
                &expected,
                &reader,
                Duration::from_secs(1),
            ),
            AttachConnectionRoute::Companion
        );
    }
}

#[test]
fn expired_timeout_routes_to_companion() {
    let (expected, reader) = expected_and_reader();
    let (_client, server) = UnixStream::pair().unwrap();
    let started = Instant::now();

    assert_eq!(
        name_attach_connection_route(&server, credentials(), &expected, &reader, Duration::ZERO,),
        AttachConnectionRoute::Companion
    );
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[test]
fn delayed_prefix_and_incomplete_payload_share_one_timeout() {
    let (expected, reader) = expected_and_reader();
    let (mut client, server) = UnixStream::pair().unwrap();
    let timeout = Duration::from_millis(250);
    let previous_timeout = Duration::from_secs(17);
    server.set_read_timeout(Some(previous_timeout)).unwrap();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(180));
        client.write_all(&64_u32.to_be_bytes()).unwrap();
        thread::sleep(timeout);
    });
    let started = Instant::now();

    assert_eq!(
        name_attach_connection_route(&server, credentials(), &expected, &reader, timeout),
        AttachConnectionRoute::Companion
    );
    assert!(started.elapsed() < timeout + Duration::from_millis(125));
    assert_eq!(server.read_timeout().unwrap(), Some(previous_timeout));
    writer.join().unwrap();
}
