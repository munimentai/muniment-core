#![cfg(target_os = "linux")]

use muniment_core::browser_control::{
    AuthorizationError, BrowserControlAcceptError, BrowserControlBindError, BrowserControlListener,
    BrowserControlProcessAuthorizer, WebSocketHandshakeConfig, WebSocketHandshakeError,
};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

fn handshake_config(bytes: usize, headers: usize, timeout: Duration) -> WebSocketHandshakeConfig {
    WebSocketHandshakeConfig::new(
        "/browser",
        "chrome-extension://allowed",
        bytes,
        headers,
        timeout,
    )
    .unwrap()
}

fn valid_request() -> &'static str {
    "GET /browser HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: chrome-extension://allowed\r\n\r\n"
}

fn websocket_exchange(
    request_parts: &[&[u8]],
    config: &WebSocketHandshakeConfig,
) -> (Result<TcpStream, WebSocketHandshakeError>, Vec<u8>) {
    let listener = BrowserControlListener::bind("127.0.0.1:0", "/browser-bin").unwrap();
    let injected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(injected.local_addr().unwrap()).unwrap();
    for part in request_parts {
        client.write_all(part).unwrap();
    }
    let authorizer = RecordingAuthorizer {
        calls: RefCell::new(Vec::new()),
        result: Ok(()),
    };
    let result = listener.accept_websocket_with(&injected, &authorizer, config);
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    (result, response)
}

#[test]
fn completes_fragmented_handshake_with_rfc_accept_key() {
    let request = valid_request().as_bytes();
    let (result, response) = websocket_exchange(
        &[&request[..7], &request[7..41], &request[41..]],
        &handshake_config(1024, 16, Duration::from_secs(1)),
    );
    let stream = result.unwrap();
    assert_eq!(stream.read_timeout().unwrap(), None);
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
}

#[test]
fn accepts_bracketed_ipv6_hosts_with_optional_numeric_ports() {
    for host in ["[::1]", "[2001:db8::1]:443"] {
        let request = valid_request().replace("127.0.0.1:1234", host);
        let (result, response) = websocket_exchange(
            &[request.as_bytes()],
            &handshake_config(1024, 16, Duration::from_secs(1)),
        );
        assert!(result.is_ok(), "{host}");
        assert!(response.starts_with(b"HTTP/1.1 101"), "{host}");
    }
}

#[test]
fn authorization_happens_before_handshake_read() {
    struct SendingAuthorizer(RefCell<TcpStream>);
    impl BrowserControlProcessAuthorizer for SendingAuthorizer {
        fn authorize(
            &self,
            _: SocketAddr,
            _: SocketAddr,
            _: &Path,
        ) -> Result<(), AuthorizationError> {
            self.0
                .borrow_mut()
                .write_all(valid_request().as_bytes())
                .unwrap();
            Ok(())
        }
    }
    let listener = BrowserControlListener::bind("127.0.0.1:0", "/browser-bin").unwrap();
    let injected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(injected.local_addr().unwrap()).unwrap();
    let authorizer = SendingAuthorizer(RefCell::new(client));
    assert!(listener
        .accept_websocket_with(
            &injected,
            &authorizer,
            &handshake_config(1024, 16, Duration::from_millis(100)),
        )
        .is_ok());
}

#[test]
fn rejects_malformed_duplicate_wrong_policy_and_bounded_requests() {
    let cases = [
        (
            valid_request().replace("Host:", "Broken-Header\r\nHost:"),
            WebSocketHandshakeError::Malformed,
        ),
        (
            valid_request().replace("Host:", "Host: duplicate\r\nHost:"),
            WebSocketHandshakeError::Malformed,
        ),
        (
            valid_request().replace("/browser", "/wrong"),
            WebSocketHandshakeError::PolicyRejected,
        ),
        (
            valid_request().replace("chrome-extension://allowed", "https://wrong"),
            WebSocketHandshakeError::PolicyRejected,
        ),
        (
            valid_request().replace("Version: 13", "Version: 12"),
            WebSocketHandshakeError::PolicyRejected,
        ),
        (
            valid_request().replace("dGhlIHNhbXBsZSBub25jZQ==", "c2hvcnQ="),
            WebSocketHandshakeError::PolicyRejected,
        ),
        (
            valid_request().replace("127.0.0.1:1234", "example.com?query"),
            WebSocketHandshakeError::Malformed,
        ),
        (
            valid_request().replace("127.0.0.1:1234", "example.com#fragment"),
            WebSocketHandshakeError::Malformed,
        ),
        (
            valid_request().replace("127.0.0.1:1234", "[::1]trailing"),
            WebSocketHandshakeError::Malformed,
        ),
        (
            valid_request().replace("127.0.0.1:1234", "example.com:not-a-port"),
            WebSocketHandshakeError::Malformed,
        ),
    ];
    for (request, expected) in cases {
        let (result, response) = websocket_exchange(
            &[request.as_bytes()],
            &handshake_config(1024, 16, Duration::from_millis(100)),
        );
        assert_eq!(result.err(), Some(expected));
        assert!(!response.starts_with(b"HTTP/1.1 101"));
    }

    let (result, _) = websocket_exchange(
        &[valid_request().as_bytes()],
        &handshake_config(40, 16, Duration::from_millis(100)),
    );
    assert_eq!(
        result.err(),
        Some(WebSocketHandshakeError::HeaderBytesExceeded)
    );
    let (result, _) = websocket_exchange(
        &[valid_request().as_bytes()],
        &handshake_config(1024, 2, Duration::from_millis(100)),
    );
    assert_eq!(
        result.err(),
        Some(WebSocketHandshakeError::HeaderCountExceeded)
    );
}

#[test]
fn rejects_incomplete_and_timed_out_handshakes() {
    let (result, _) = websocket_exchange(
        &[b"GET /browser HTTP/1.1\r\n"],
        &handshake_config(1024, 16, Duration::from_millis(20)),
    );
    assert_eq!(result.err(), Some(WebSocketHandshakeError::Timeout));

    let listener = BrowserControlListener::bind("127.0.0.1:0", "/browser-bin").unwrap();
    let injected = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(injected.local_addr().unwrap()).unwrap();
    client.write_all(b"GET /browser HTTP/1.1\r\n").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let authorizer = RecordingAuthorizer {
        calls: RefCell::new(Vec::new()),
        result: Ok(()),
    };
    assert_eq!(
        listener
            .accept_websocket_with(
                &injected,
                &authorizer,
                &handshake_config(1024, 16, Duration::from_secs(1))
            )
            .err(),
        Some(WebSocketHandshakeError::Incomplete)
    );
}
