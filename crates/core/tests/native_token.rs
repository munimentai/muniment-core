use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use muniment_core::auth::{
    exchange_native_code, InstallationRecord, NativeAuthorizationCode, NativeCredentialStore,
    NativeCredentials, NativeTokenError, UreqTokenTransport,
};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct MemoryStore {
    installation: Mutex<Option<InstallationRecord>>,
    credentials: Mutex<Option<NativeCredentials>>,
    fail_save: bool,
}

impl NativeCredentialStore for MemoryStore {
    fn load_installation(&self) -> Result<Option<InstallationRecord>, NativeTokenError> {
        Ok(self.installation.lock().unwrap().clone())
    }
    fn save_credentials(&self, value: &NativeCredentials) -> Result<(), NativeTokenError> {
        if self.fail_save {
            return Err(NativeTokenError::Persistence(
                "secret persistence detail".into(),
            ));
        }
        *self.credentials.lock().unwrap() = Some(value.clone());
        *self.installation.lock().unwrap() = Some(value.installation.clone());
        Ok(())
    }
    fn load_credentials(&self) -> Result<Option<NativeCredentials>, NativeTokenError> {
        Ok(self.credentials.lock().unwrap().clone())
    }
}

struct Server {
    base_url: String,
    request: Arc<Mutex<Option<(String, String)>>>,
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

fn read_request(stream: &mut TcpStream) -> (String, String) {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream.read(&mut buffer).unwrap();
        bytes.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&bytes);
        let Some(split) = text.find("\r\n\r\n") else {
            continue;
        };
        let length = text[..split]
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if bytes.len() >= split + 4 + length {
            return (
                String::from_utf8(bytes[..split].to_vec()).unwrap(),
                String::from_utf8(bytes[split + 4..split + 4 + length].to_vec()).unwrap(),
            );
        }
    }
}

fn installation() -> InstallationRecord {
    InstallationRecord {
        private_key: [7; 32],
        device_id: "10000000-0000-4000-8000-000000000001".parse().unwrap(),
        registration_token: String::new(),
        device_challenge: URL_SAFE_NO_PAD.encode([8; 32]),
        registration_expires_at: 0,
    }
}

fn code() -> NativeAuthorizationCode {
    NativeAuthorizationCode {
        authorization_code: URL_SAFE_NO_PAD.encode([9; 32]),
        code_verifier: URL_SAFE_NO_PAD.encode([10; 32]),
        device_id: installation().device_id,
        redirect_uri: "http://127.0.0.1:49152/callback".into(),
    }
}

fn success(challenge: &str) -> String {
    format!(
        r#"{{"access_token":"access-secret","token_type":"Bearer","expires_in":900,"refresh_token":"refresh-secret","refresh_expires_in":86400,"session":{{"org_id":"20000000-0000-4000-8000-000000000002","user_id":"30000000-0000-4000-8000-000000000003","role":"user","device_id":"10000000-0000-4000-8000-000000000001","client_role":"desktop"}},"entitlement_snapshot":{{"payload":{{"version":1}},"signature":"snapshot-secret","algorithm":"hmac-sha256"}},"device_challenge":"{challenge}"}}"#
    )
}

fn success_json() -> serde_json::Value {
    serde_json::from_str(&success(&URL_SAFE_NO_PAD.encode([11; 32]))).unwrap()
}

fn store(fail_save: bool) -> MemoryStore {
    MemoryStore {
        installation: Mutex::new(Some(installation())),
        credentials: Mutex::new(None),
        fail_save,
    }
}

#[test]
fn exact_exchange_is_bound_signed_and_persisted_coherently() {
    let server = Server::spawn(200, success(&URL_SAFE_NO_PAD.encode([11; 32])));
    let store = store(false);
    let result = exchange_native_code(
        &store,
        &UreqTokenTransport::new(Duration::from_secs(2)),
        &server.base_url,
        code(),
        1_000,
        [12; 16],
    )
    .unwrap();
    assert_eq!(result.tokens.expires_at, Some(1_900));
    assert_eq!(result.refresh_expires_at, 87_400);
    assert_eq!(
        store
            .load_credentials()
            .unwrap()
            .unwrap()
            .installation
            .device_challenge,
        URL_SAFE_NO_PAD.encode([11; 32])
    );

    let (head, body) = server.request.lock().unwrap().clone().unwrap();
    assert!(head.starts_with("POST /v1/auth/native/token HTTP/1.1"));
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 7);
    assert_eq!(json["grant_type"], "authorization_code");
    assert_eq!(json["code"], URL_SAFE_NO_PAD.encode([9; 32]));
    assert_eq!(json["code_verifier"], URL_SAFE_NO_PAD.encode([10; 32]));
    assert_eq!(json["redirect_uri"], "http://127.0.0.1:49152/callback");
    assert_eq!(json["device_id"], installation().device_id.to_string());

    let object = json.as_object().unwrap();
    let unsigned = object
        .iter()
        .filter(|(k, _)| k.as_str() != "device_proof")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<serde_json::Map<_, _>>();
    let hash = Sha256::digest(serde_json::to_vec(&unsigned).unwrap());
    let proof = object["device_proof"].as_object().unwrap();
    let transcript = format!(
        "MUNIMENT-NATIVE-V1\nPOST\n/v1/auth/native/token\n{}\n{}\n{}\n{}",
        hex(&hash),
        proof["challenge"].as_str().unwrap(),
        proof["issued_at"].as_str().unwrap(),
        proof["jti"].as_str().unwrap()
    );
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(proof["signature"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    SigningKey::from_bytes(&installation().private_key)
        .verifying_key()
        .verify(transcript.as_bytes(), &signature)
        .unwrap();
}

#[test]
fn malformed_or_missing_response_data_publishes_nothing() {
    let mut missing_refresh_token = success_json();
    missing_refresh_token
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    let mut invalid_access_lifetime = success_json();
    invalid_access_lifetime["expires_in"] = 0.into();
    let mut malformed_access_lifetime = success_json();
    malformed_access_lifetime["expires_in"] = "900".into();
    let mut invalid_refresh_lifetime = success_json();
    invalid_refresh_lifetime["refresh_expires_in"] = 0.into();

    for body in [
        success("not-base64"),
        success(&installation().device_challenge),
        success(&URL_SAFE_NO_PAD.encode([11; 32]))
            .trim_end_matches('}')
            .to_string()
            + ",\"extra\":true}",
        missing_refresh_token.to_string(),
        invalid_access_lifetime.to_string(),
        malformed_access_lifetime.to_string(),
        invalid_refresh_lifetime.to_string(),
    ] {
        let server = Server::spawn(200, body);
        let store = store(false);
        let error = exchange_native_code(
            &store,
            &UreqTokenTransport::new(Duration::from_secs(2)),
            &server.base_url,
            code(),
            1_000,
            [1; 16],
        )
        .unwrap_err();
        assert!(matches!(error, NativeTokenError::MalformedResponse(_)));
        assert!(store.load_credentials().unwrap().is_none());
        assert_eq!(
            store.load_installation().unwrap().unwrap().device_challenge,
            installation().device_challenge
        );
    }
}

#[test]
fn http_transport_and_persistence_failures_are_redacted_and_never_partially_publish() {
    let rejected = Server::spawn(
        400,
        r#"{"error_description":"server-description-secret"}"#.into(),
    );
    let store_ok = store(false);
    let error = exchange_native_code(
        &store_ok,
        &UreqTokenTransport::new(Duration::from_secs(2)),
        &rejected.base_url,
        code(),
        1_000,
        [1; 16],
    )
    .unwrap_err();
    assert_eq!(error, NativeTokenError::HttpStatus(400));
    assert!(!format!("{error:?} {error}").contains("server-description-secret"));

    let error = exchange_native_code(
        &store(false),
        &UreqTokenTransport::new(Duration::from_millis(100)),
        "http://127.0.0.1:1",
        code(),
        1_000,
        [1; 16],
    )
    .unwrap_err();
    assert!(matches!(error, NativeTokenError::Transport(_)));

    let server = Server::spawn(200, success(&URL_SAFE_NO_PAD.encode([11; 32])));
    let failing = store(true);
    let error = exchange_native_code(
        &failing,
        &UreqTokenTransport::new(Duration::from_secs(2)),
        &server.base_url,
        code(),
        1_000,
        [1; 16],
    )
    .unwrap_err();
    assert!(matches!(error, NativeTokenError::Persistence(_)));
    assert!(failing.load_credentials().unwrap().is_none());
    assert_eq!(
        failing
            .load_installation()
            .unwrap()
            .unwrap()
            .device_challenge,
        installation().device_challenge
    );
    let rendered = format!("{error:?} {error} {:?}", code());
    for secret in [
        "access-secret",
        "refresh-secret",
        "snapshot-secret",
        "secret persistence detail",
        &URL_SAFE_NO_PAD.encode([9; 32]),
        &URL_SAFE_NO_PAD.encode([10; 32]),
    ] {
        assert!(!rendered.contains(secret));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
