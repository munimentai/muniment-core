#![cfg(all(target_os = "macos", feature = "client"))]

use muniment_attach::{handshake_stream_with_peer_reader, ClientError, MacosPeerReader};
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::time::Duration;

struct FakePeerReader(Result<u32, ()>, u32);

impl MacosPeerReader for FakePeerReader {
    fn peer_effective_uid(&self, _socket: i32) -> Result<u32, ()> {
        self.0
    }

    fn local_effective_uid(&self) -> u32 {
        self.1
    }
}

fn rejection_writes_no_frame(reader: FakePeerReader) {
    let (stream, mut server) = UnixStream::pair().unwrap();
    let result = handshake_stream_with_peer_reader(
        stream,
        &reader,
        "1.0.0",
        Duration::from_millis(10),
        Duration::from_millis(10),
        || {},
    );
    assert_eq!(result.unwrap_err(), ClientError::ConnectionClosed);
    server.set_nonblocking(true).unwrap();
    match server.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        result => panic!("peer received protocol traffic: {result:?}"),
    }
}

#[test]
fn uid_mismatch_closes_before_the_first_frame_write() {
    rejection_writes_no_frame(FakePeerReader(Ok(502), 501));
}

#[test]
fn syscall_failure_closes_before_the_first_frame_write() {
    rejection_writes_no_frame(FakePeerReader(Err(()), 501));
}
