use muniment_core::attach::{
    verify_windows_attach_peer_with_reader, WindowsAttachPeerReader, WindowsPeerError,
    WindowsPeerReadError,
};
use std::cell::Cell;

struct FakePeerReader {
    peer_sid: Result<Vec<u8>, WindowsPeerReadError>,
    local_sid: Result<Vec<u8>, WindowsPeerReadError>,
    peer_reads: Cell<usize>,
    local_reads: Cell<usize>,
}

impl WindowsAttachPeerReader for FakePeerReader {
    fn connected_peer_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
        self.peer_reads.set(self.peer_reads.get() + 1);
        self.peer_sid.clone()
    }

    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
        self.local_reads.set(self.local_reads.get() + 1);
        self.local_sid.clone()
    }
}

fn reader(
    peer_sid: Result<Vec<u8>, WindowsPeerReadError>,
    local_sid: Result<Vec<u8>, WindowsPeerReadError>,
) -> FakePeerReader {
    FakePeerReader {
        peer_sid,
        local_sid,
        peer_reads: Cell::new(0),
        local_reads: Cell::new(0),
    }
}

#[test]
fn accepts_an_exact_sid_match() {
    let reader = reader(Ok(vec![1, 2, 3, 4]), Ok(vec![1, 2, 3, 4]));

    assert_eq!(verify_windows_attach_peer_with_reader(&reader), Ok(()));
    assert_eq!(reader.peer_reads.get(), 1);
    assert_eq!(reader.local_reads.get(), 1);
}

#[test]
fn rejects_a_sid_mismatch() {
    let reader = reader(Ok(vec![1, 2, 3, 4]), Ok(vec![1, 2, 3, 5]));

    assert_eq!(
        verify_windows_attach_peer_with_reader(&reader),
        Err(WindowsPeerError::WrongOwner)
    );
}

#[test]
fn rejects_a_sid_length_mismatch() {
    let reader = reader(Ok(vec![1, 2, 3]), Ok(vec![1, 2, 3, 0]));

    assert_eq!(
        verify_windows_attach_peer_with_reader(&reader),
        Err(WindowsPeerError::WrongOwner)
    );
}

#[test]
fn maps_a_peer_sid_read_failure_to_unavailable_identity() {
    let reader = reader(Err(WindowsPeerReadError), Ok(vec![1, 2, 3, 4]));

    assert_eq!(
        verify_windows_attach_peer_with_reader(&reader),
        Err(WindowsPeerError::IdentityUnavailable)
    );
    assert_eq!(reader.peer_reads.get(), 1);
    assert_eq!(reader.local_reads.get(), 0);
}

#[test]
fn maps_a_local_sid_read_failure_to_unavailable_identity() {
    let reader = reader(Ok(vec![1, 2, 3, 4]), Err(WindowsPeerReadError));

    assert_eq!(
        verify_windows_attach_peer_with_reader(&reader),
        Err(WindowsPeerError::IdentityUnavailable)
    );
    assert_eq!(reader.peer_reads.get(), 1);
    assert_eq!(reader.local_reads.get(), 1);
}
