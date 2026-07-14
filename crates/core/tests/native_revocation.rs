use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_core::auth::{
    revoke_current_native_session, sign_out_native_session, InstallationRecord,
    NativeCredentialStore, NativeCredentials, NativeRevocationError, NativeRevocationRequest,
    NativeRevocationResponse, RevocationTransport, TokenSet, UreqRevocationTransport,
};
use uuid::Uuid;

struct MemoryStore(Mutex<Option<NativeCredentials>>);

impl NativeCredentialStore for MemoryStore {
    fn load_installation(
        &self,
    ) -> Result<Option<InstallationRecord>, muniment_core::auth::NativeTokenError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|c| c.installation.clone()))
    }

    fn save_credentials(
        &self,
        value: &NativeCredentials,
    ) -> Result<(), muniment_core::auth::NativeTokenError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn load_credentials(
        &self,
    ) -> Result<Option<NativeCredentials>, muniment_core::auth::NativeTokenError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn clear_session(&self) -> Result<(), muniment_core::auth::NativeTokenError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

fn store() -> MemoryStore {
    MemoryStore(Mutex::new(Some(NativeCredentials {
        installation: InstallationRecord {
            private_key: [1; 32],
            device_id: Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
            registration_token: "registration-secret".into(),
            device_challenge: "challenge-secret".into(),
            registration_expires_at: 600,
        },
        tokens: TokenSet {
            access_token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            refresh_token: Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into()),
            expires_at: Some(1_900),
            subject: Some("user".into()),
        },
        refresh_expires_at: 86_400,
    })))
}

struct Server {
    base_url: String,
    request: Arc<Mutex<Option<String>>>,
}

impl Server {
    fn spawn(status: u16, body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let request = Arc::new(Mutex::new(None));
        let captured = request.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            *captured.lock().unwrap() = Some(read_request(&mut stream));
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        Self { base_url, request }
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream.read(&mut buffer).unwrap();
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(headers_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|value| value.parse().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= headers_end + 4 + content_length {
                break;
            }
        }
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn posts_exact_current_session_contract() {
    let server = Server::spawn(200, r#"{"ok":true}"#);
    revoke_current_native_session(
        &store(),
        &UreqRevocationTransport::new(Duration::from_secs(2)),
        &server.base_url,
    )
    .unwrap();

    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with("POST /v1/auth/native/revoke HTTP/1.1\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"));
    assert!(request.ends_with(
        r#"{"scope":"current","refresh_token":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}"#
    ));
}

#[test]
fn rejects_server_errors_and_malformed_success_envelopes() {
    let server = Server::spawn(503, r#"{"error":{"code":"temporarily_unavailable"}}"#);
    assert_eq!(
        revoke_current_native_session(
            &store(),
            &UreqRevocationTransport::new(Duration::from_secs(2)),
            &server.base_url,
        )
        .unwrap_err(),
        NativeRevocationError::HttpStatus(503)
    );

    for body in [r#"{"ok":false}"#, r#"{"ok":true,"extra":1}"#] {
        let server = Server::spawn(200, body);
        assert!(matches!(
            revoke_current_native_session(
                &store(),
                &UreqRevocationTransport::new(Duration::from_secs(2)),
                &server.base_url,
            ),
            Err(NativeRevocationError::MalformedResponse(_))
        ));
    }
}

#[test]
fn reports_network_failure_without_mutating_credentials() {
    let store = store();
    assert!(matches!(
        revoke_current_native_session(
            &store,
            &UreqRevocationTransport::new(Duration::from_millis(50)),
            "http://127.0.0.1:1",
        ),
        Err(NativeRevocationError::Transport(_))
    ));
    assert_eq!(
        store
            .load_credentials()
            .unwrap()
            .unwrap()
            .tokens
            .refresh_token
            .as_deref(),
        Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    );
}

struct OrderedStore {
    credentials: Mutex<Option<NativeCredentials>>,
    installation: InstallationRecord,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl NativeCredentialStore for OrderedStore {
    fn load_installation(
        &self,
    ) -> Result<Option<InstallationRecord>, muniment_core::auth::NativeTokenError> {
        Ok(Some(self.installation.clone()))
    }

    fn save_credentials(
        &self,
        value: &NativeCredentials,
    ) -> Result<(), muniment_core::auth::NativeTokenError> {
        *self.credentials.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn load_credentials(
        &self,
    ) -> Result<Option<NativeCredentials>, muniment_core::auth::NativeTokenError> {
        Ok(self.credentials.lock().unwrap().clone())
    }

    fn clear_session(&self) -> Result<(), muniment_core::auth::NativeTokenError> {
        self.events.lock().unwrap().push("clear");
        *self.credentials.lock().unwrap() = None;
        Ok(())
    }
}

struct OrderedTransport {
    events: Arc<Mutex<Vec<&'static str>>>,
    result: Result<(), NativeRevocationError>,
}

impl RevocationTransport for OrderedTransport {
    fn revoke(
        &self,
        _url: &str,
        _request: &NativeRevocationRequest,
    ) -> Result<NativeRevocationResponse, NativeRevocationError> {
        self.events.lock().unwrap().push("revoke");
        self.result.clone()?;
        serde_json::from_str(r#"{"ok":true}"#)
            .map_err(|error| NativeRevocationError::MalformedResponse(error.to_string()))
    }
}

fn ordered_store(events: Arc<Mutex<Vec<&'static str>>>) -> OrderedStore {
    let credentials = store().load_credentials().unwrap().unwrap();
    OrderedStore {
        installation: credentials.installation.clone(),
        credentials: Mutex::new(Some(credentials)),
        events,
    }
}

#[test]
fn sign_out_attempts_revocation_before_clearing_locally() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let store = ordered_store(events.clone());
    let transport = OrderedTransport {
        events: events.clone(),
        result: Ok(()),
    };

    sign_out_native_session(&store, &transport, "https://api.muniment.ai").unwrap();

    assert_eq!(*events.lock().unwrap(), ["revoke", "clear"]);
    assert!(store.load_credentials().unwrap().is_none());
    assert_eq!(
        store.load_installation().unwrap().unwrap().device_id,
        store.installation.device_id
    );
}

#[test]
fn sign_out_clears_and_preserves_installation_when_revocation_fails() {
    for failure in [
        NativeRevocationError::Transport("offline".into()),
        NativeRevocationError::HttpStatus(503),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = ordered_store(events.clone());
        let installation = store.installation.clone();
        let transport = OrderedTransport {
            events: events.clone(),
            result: Err(failure),
        };

        sign_out_native_session(&store, &transport, "https://api.muniment.ai").unwrap();

        assert_eq!(*events.lock().unwrap(), ["revoke", "clear"]);
        assert!(store.load_credentials().unwrap().is_none());
        assert_eq!(
            store.load_installation().unwrap().unwrap().device_id,
            installation.device_id
        );
    }
}
