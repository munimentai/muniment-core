#![cfg(target_os = "macos")]

use muniment_core::attach::{
    accept_macos_attach_with_reader, decode_frame, encode_frame,
    serve_next_macos_attach_with_reader, verify_macos_attach_peer_with_reader, Client, Hello, Id,
    MacosAttachAcceptError, MacosAttachListener, MacosAttachPeerReader, MacosAttachStopEvent,
    MacosAttachWaitOutcome, MacosPeerError, MacosPeerReadError, Protocol, VersionRange, Welcome,
};
use std::cell::Cell;
use std::io::{self, Read};
use std::os::fd::RawFd;
use std::os::unix::net::{UnixListener, UnixStream};

struct FakePeerReader {
    peer_uid: Result<libc::uid_t, MacosPeerReadError>,
    local_uid: libc::uid_t,
    reads: Cell<usize>,
}

#[test]
fn listener_removes_its_endpoint_and_restarts_at_the_same_path() {
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-restart-{}.sock",
        std::process::id()
    ));
    {
        let listener = MacosAttachListener::bind(&path).unwrap();
        assert!(path.exists());
        drop(listener);
    }
    assert!(!path.exists());
    let listener = MacosAttachListener::bind(&path).unwrap();
    assert!(path.exists());
    drop(listener);
    assert!(!path.exists());
}

#[test]
fn listener_recovers_an_owned_stale_endpoint() {
    let path =
        std::env::temp_dir().join(format!("muniment-attach-stale-{}.sock", std::process::id()));
    drop(UnixListener::bind(&path).unwrap());

    let listener = MacosAttachListener::bind(&path).unwrap();
    assert!(path.exists());
    drop(listener);
    assert!(!path.exists());
}

#[test]
fn listener_preserves_a_live_endpoint() {
    let path =
        std::env::temp_dir().join(format!("muniment-attach-live-{}.sock", std::process::id()));
    let live = UnixListener::bind(&path).unwrap();

    assert_eq!(
        MacosAttachListener::bind(&path).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
    assert!(path.exists());

    drop(live);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn stop_signal_wakes_a_pending_accept() {
    let path =
        std::env::temp_dir().join(format!("muniment-attach-stop-{}.sock", std::process::id()));
    let listener = MacosAttachListener::bind(&path).unwrap();
    let stop = std::sync::Arc::new(MacosAttachStopEvent::new().unwrap());
    let signal = std::sync::Arc::clone(&stop);
    let signaler = std::thread::spawn(move || signal.signal().unwrap());

    assert!(matches!(
        listener.accept_until(&stop),
        Ok(MacosAttachWaitOutcome::Stopped)
    ));
    signaler.join().unwrap();
}

impl MacosAttachPeerReader for FakePeerReader {
    fn peer_effective_uid(&self, _socket: RawFd) -> Result<libc::uid_t, MacosPeerReadError> {
        self.reads.set(self.reads.get() + 1);
        self.peer_uid
    }

    fn local_effective_uid(&self) -> libc::uid_t {
        self.local_uid
    }
}

fn verify(reader: &FakePeerReader) -> Result<(), MacosPeerError> {
    let (stream, _peer) = UnixStream::pair().unwrap();
    verify_macos_attach_peer_with_reader(&stream, reader)
}

fn verify_and_assert_no_response(reader: &FakePeerReader) -> Result<(), MacosPeerError> {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let result = verify_macos_attach_peer_with_reader(&stream, reader);
    peer.set_nonblocking(true).unwrap();
    assert!(matches!(
        peer.read(&mut [0]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    result
}

fn accept_and_assert_no_response(reader: &FakePeerReader) {
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-peer-{}-{}.sock",
        std::process::id(),
        reader as *const FakePeerReader as usize
    ));
    let listener = UnixListener::bind(&path).unwrap();
    let mut client = UnixStream::connect(&path).unwrap();

    assert_eq!(
        accept_macos_attach_with_reader(&listener, reader).unwrap_err(),
        MacosAttachAcceptError::PeerRejected
    );
    client.set_nonblocking(true).unwrap();
    assert_eq!(client.read(&mut [0]).unwrap(), 0);

    drop(listener);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn accepts_a_matching_effective_uid() {
    let reader = FakePeerReader {
        peer_uid: Ok(501),
        local_uid: 501,
        reads: Cell::new(0),
    };

    assert_eq!(verify(&reader), Ok(()));
    assert_eq!(reader.reads.get(), 1);
}

#[test]
fn rejects_a_mismatched_effective_uid() {
    let reader = FakePeerReader {
        peer_uid: Ok(502),
        local_uid: 501,
        reads: Cell::new(0),
    };

    assert_eq!(
        verify_and_assert_no_response(&reader),
        Err(MacosPeerError::WrongUid)
    );
    assert_eq!(reader.reads.get(), 1);
    accept_and_assert_no_response(&reader);
}

#[test]
fn rejects_a_peer_identity_syscall_failure() {
    let reader = FakePeerReader {
        peer_uid: Err(MacosPeerReadError),
        local_uid: 501,
        reads: Cell::new(0),
    };

    assert_eq!(
        verify_and_assert_no_response(&reader),
        Err(MacosPeerError::IdentityUnavailable)
    );
    assert_eq!(reader.reads.get(), 1);
    accept_and_assert_no_response(&reader);
}

#[test]
fn verified_listener_stream_serves_a_valid_first_frame() {
    use std::io::Write;

    let reader = FakePeerReader {
        peer_uid: Ok(501),
        local_uid: 501,
        reads: Cell::new(0),
    };
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-session-{}.sock",
        std::process::id()
    ));
    let listener = UnixListener::bind(&path).unwrap();
    let mut client = UnixStream::connect(&path).unwrap();
    let hello = Hello {
        protocol: Protocol,
        client: Client {
            kind: "test-client".into(),
            version: "1.0.0".into(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: "client-nonce".into(),
        authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000099").unwrap(),
        authorized_client_credential: None,
    };
    client.write_all(&encode_frame(&hello).unwrap()).unwrap();

    serve_next_macos_attach_with_reader(&listener, &reader, "1.0.0").unwrap();

    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix).unwrap();
    let mut response = vec![0_u8; 4 + u32::from_be_bytes(prefix) as usize];
    response[..4].copy_from_slice(&prefix);
    client.read_exact(&mut response[4..]).unwrap();
    let welcome: Welcome = decode_frame(&response).unwrap().unwrap().0;
    assert_eq!(welcome.selected, 1);
    assert_eq!(reader.reads.get(), 1);

    drop(listener);
    std::fs::remove_file(path).unwrap();
}
