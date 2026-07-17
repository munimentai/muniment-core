#![cfg(target_os = "linux")]

use muniment_core::browser_control::{
    AuthorizationError, BrowserControlAcceptError, BrowserControlBindError, BrowserControlListener,
    BrowserControlProcessAuthorizer,
};
use std::cell::RefCell;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};

struct RecordingAuthorizer {
    calls: RefCell<Vec<(SocketAddr, SocketAddr, PathBuf)>>,
    result: Result<(), AuthorizationError>,
}

impl BrowserControlProcessAuthorizer for RecordingAuthorizer {
    fn authorize(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        expected_executable: &Path,
    ) -> Result<(), AuthorizationError> {
        self.calls
            .borrow_mut()
            .push((local, peer, expected_executable.to_owned()));
        self.result
    }
}

#[test]
fn accepts_a_real_loopback_stream_only_after_authorization() {
    let expected = PathBuf::from("/desktop/selected-browser");
    let listener = BrowserControlListener::bind("127.0.0.1:0", &expected).unwrap();
    let injected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(injected.local_addr().unwrap()).unwrap();
    let authorizer = RecordingAuthorizer {
        calls: RefCell::new(Vec::new()),
        result: Ok(()),
    };

    let accepted = listener.accept_with(&injected, &authorizer).unwrap();
    let calls = authorizer.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, client.peer_addr().unwrap());
    assert_eq!(calls[0].1, client.local_addr().unwrap());
    assert_eq!(calls[0].2, expected);
    assert_eq!(accepted.local_addr().unwrap(), calls[0].0);
}

#[test]
fn drops_an_unauthorized_accepted_peer() {
    let listener = BrowserControlListener::bind("127.0.0.1:0", "/secret/browser").unwrap();
    let injected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(injected.local_addr().unwrap()).unwrap();
    let authorizer = RecordingAuthorizer {
        calls: RefCell::new(Vec::new()),
        result: Err(AuthorizationError::ExecutableVerificationFailed),
    };

    assert!(matches!(
        listener.accept_with(&injected, &authorizer),
        Err(BrowserControlAcceptError::Unauthorized)
    ));
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    assert_eq!(client.peek(&mut [0]).unwrap(), 0);
}

#[test]
fn rejects_invalid_bind_configuration_before_listening() {
    for address in [
        "0.0.0.0:0",
        "[::]:0",
        "localhost:0",
        "192.0.2.1:0",
        "127.0.0.1:12345",
        "127.0.0.1",
        "127.0.0.1:not-a-port",
    ] {
        assert_eq!(
            BrowserControlListener::bind(address, "/browser").err(),
            Some(BrowserControlBindError::InvalidConfiguration),
            "{address}"
        );
    }
}

#[test]
fn public_errors_are_bounded_and_redacted() {
    let secrets = [
        "127.0.0.1:42424",
        "987654321",
        "/secret/selected-browser",
        "pairing-token",
    ];
    for rendered in [
        format!(
            "{:?}: {}",
            BrowserControlBindError::InvalidConfiguration,
            BrowserControlBindError::InvalidConfiguration
        ),
        format!(
            "{:?}: {}",
            BrowserControlAcceptError::Unauthorized,
            BrowserControlAcceptError::Unauthorized
        ),
    ] {
        assert!(rendered.len() < 100);
        for secret in secrets {
            assert!(!rendered.contains(secret));
        }
    }
}
