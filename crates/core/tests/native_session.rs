use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_core::auth::{
    inspect_native_session, InstallationRecord, NativeCredentialStore, NativeCredentials,
    NativeSessionError, TokenSet, UreqSessionTransport,
};
use uuid::Uuid;

const DEVICE_ID: &str = "10000000-0000-4000-8000-000000000001";

#[derive(Default)]
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
}

fn store() -> MemoryStore {
    MemoryStore(Mutex::new(Some(NativeCredentials {
        installation: InstallationRecord {
            private_key: [1; 32],
            device_id: Uuid::parse_str(DEVICE_ID).unwrap(),
            registration_token: "registration-secret".into(),
            device_challenge: "challenge-secret".into(),
            registration_expires_at: 600,
        },
        tokens: TokenSet {
            access_token: "access-secret".into(),
            refresh_token: Some("refresh-secret".into()),
            expires_at: Some(1_900),
            subject: Some("user".into()),
        },
        refresh_expires_at: 86_400,
    })))
}

fn success() -> String {
    format!(
        r#"{{"session":{{"org_id":"20000000-0000-4000-8000-000000000002","user_id":"30000000-0000-4000-8000-000000000003","role":"owner","device_id":"{DEVICE_ID}","client_role":"desktop"}},"entitlement_snapshot":{{"payload":{{"version":7,"groups":["staff"]}},"signature":"signature-secret","algorithm":"hmac-sha256"}}}}"#
    )
}

struct Server {
    base_url: String,
    request: Arc<Mutex<Option<String>>>,
}

impl Server {
    fn spawn(status: u16, body: String) -> Self {
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
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn exact_authenticated_get_decodes_typed_contract() {
    let server = Server::spawn(200, success());
    let result = inspect_native_session(
        &store(),
        &UreqSessionTransport::new(Duration::from_secs(2)),
        &server.base_url,
    )
    .unwrap();
    assert_eq!(
        result.session.user_id,
        Uuid::parse_str("30000000-0000-4000-8000-000000000003").unwrap()
    );
    assert_eq!(result.entitlement_snapshot.payload["version"], 7);
    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with("GET /v1/auth/native/session HTTP/1.1\r\n"));
    assert_eq!(
        request
            .to_ascii_lowercase()
            .matches("authorization:")
            .count(),
        1
    );
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer access-secret\r\n"));
}

#[test]
fn signed_out_and_bad_configuration_make_no_request() {
    let server = Server::spawn(200, success());
    assert_eq!(
        inspect_native_session(
            &MemoryStore::default(),
            &UreqSessionTransport::new(Duration::from_secs(1)),
            &server.base_url
        )
        .unwrap_err(),
        NativeSessionError::CredentialsMissing
    );
    assert!(server.request.lock().unwrap().is_none());
    assert!(matches!(
        inspect_native_session(
            &store(),
            &UreqSessionTransport::new(Duration::from_secs(1)),
            "http://example.com"
        ),
        Err(NativeSessionError::Config(_))
    ));
}

#[test]
fn rejects_wrong_device_role_algorithm_and_schema_without_mutation() {
    let cases = [
        success().replace(DEVICE_ID, "10000000-0000-4000-8000-000000000009"),
        success().replace("\"client_role\":\"desktop\"", "\"client_role\":\"mobile\""),
        success().replace("\"role\":\"owner\"", "\"role\":\"superuser\""),
        success().replace("hmac-sha256", "ed25519"),
        success().replace(
            "\"client_role\":\"desktop\"",
            "\"client_role\":\"desktop\",\"extra\":true",
        ),
    ];
    for body in cases {
        let server = Server::spawn(200, body);
        let store = store();
        assert!(matches!(
            inspect_native_session(
                &store,
                &UreqSessionTransport::new(Duration::from_secs(2)),
                &server.base_url
            ),
            Err(NativeSessionError::MalformedResponse(_))
        ));
        assert_eq!(
            store
                .load_credentials()
                .unwrap()
                .unwrap()
                .tokens
                .access_token,
            "access-secret"
        );
    }
}

#[test]
fn failures_and_debug_output_redact_all_secrets() {
    for (status, body) in [
        (401, "response-secret".into()),
        (200, "signature-secret invalid".into()),
    ] {
        let server = Server::spawn(status, body);
        let error = inspect_native_session(
            &store(),
            &UreqSessionTransport::new(Duration::from_secs(2)),
            &server.base_url,
        )
        .unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("response-secret"));
        assert!(!rendered.contains("signature-secret"));
    }
    let session: muniment_core::auth::NativeSession = serde_json::from_str(&success()).unwrap();
    let rendered = format!("{session:?}");
    assert!(!rendered.contains("signature-secret"));
    assert!(matches!(
        inspect_native_session(
            &store(),
            &UreqSessionTransport::new(Duration::from_millis(50)),
            "http://127.0.0.1:1"
        ),
        Err(NativeSessionError::Transport(_))
    ));
}
