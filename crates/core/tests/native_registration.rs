use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use muniment_core::auth::{
    register_installation, InstallationRecord, InstallationStore, NativeDeviceRegistrationResponse,
    NativeRegistrationError, UreqRegistrationTransport,
};

#[derive(Default)]
struct MemoryStore {
    value: Mutex<Option<InstallationRecord>>,
    fail_save: bool,
}

impl InstallationStore for MemoryStore {
    fn save(&self, value: &InstallationRecord) -> Result<(), NativeRegistrationError> {
        if self.fail_save {
            return Err(NativeRegistrationError::Persistence("mock failure".into()));
        }
        *self.value.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError> {
        Ok(self.value.lock().unwrap().clone())
    }
}

struct MockServer {
    base_url: String,
    hits: Arc<AtomicUsize>,
    request: Arc<Mutex<Option<(String, String)>>>,
}

impl MockServer {
    fn spawn(status: u16, body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let request = Arc::new(Mutex::new(None));
        let thread_hits = hits.clone();
        let thread_request = request.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let (head, request_body) = read_request(&mut stream);
                thread_hits.fetch_add(1, Ordering::SeqCst);
                *thread_request.lock().unwrap() = Some((head, request_body));
                let reason = if status == 201 { "Created" } else { "Error" };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        Self {
            base_url,
            hits,
            request,
        }
    }
}

fn read_request(stream: &mut TcpStream) -> (String, String) {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
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
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if bytes.len() >= split + 4 + length {
            let head = String::from_utf8(bytes[..split].to_vec()).unwrap();
            let body = String::from_utf8(bytes[split + 4..split + 4 + length].to_vec()).unwrap();
            return (head, body);
        }
    }
}

const SUCCESS: &str = r#"{
  "device_id":"7d444840-9dc0-11d1-b245-5ffdce74fad2",
  "registration_token":"registration-secret",
  "device_challenge":"challenge-secret",
  "expires_in":600
}"#;

#[test]
fn sends_exact_contract_and_persists_then_reuses_installation() {
    let server = MockServer::spawn(201, SUCCESS);
    let store = MemoryStore::default();
    let transport = UreqRegistrationTransport::new(Duration::from_secs(2));

    let first = register_installation(&store, &transport, &server.base_url, 1_000).unwrap();
    assert_eq!(first.registration_expires_at, 1_600);
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);

    let (head, body) = server.request.lock().unwrap().clone().unwrap();
    assert!(head.starts_with("POST /v1/auth/native/devices HTTP/1.1"));
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["client_id"], "muniment-desktop");
    assert_eq!(json["client_role"], "desktop");
    assert_eq!(json["platform"], "desktop");
    assert_eq!(json.as_object().unwrap().len(), 4);
    let public_key = json["installation_public_key"].as_str().unwrap();
    assert!(!public_key.contains('='));
    assert_eq!(URL_SAFE_NO_PAD.decode(public_key).unwrap().len(), 32);

    let reused = register_installation(&store, &transport, "not even a URL", 9_999).unwrap();
    assert_eq!(reused.device_id, first.device_id);
    assert_eq!(reused.private_key, first.private_key);
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_and_non_success_responses_are_typed_and_secret_free() {
    let transport = UreqRegistrationTransport::new(Duration::from_secs(2));
    let malformed = MockServer::spawn(201, r#"{"registration_token":"do-not-leak"}"#);
    let error = register_installation(&MemoryStore::default(), &transport, &malformed.base_url, 0)
        .unwrap_err();
    assert!(matches!(
        error,
        NativeRegistrationError::MalformedResponse(_)
    ));
    assert!(!error.to_string().contains("do-not-leak"));

    let rejected = MockServer::spawn(503, r#"{"detail":"server secret"}"#);
    let error = register_installation(&MemoryStore::default(), &transport, &rejected.base_url, 0)
        .unwrap_err();
    assert_eq!(error, NativeRegistrationError::HttpStatus(503));
    assert!(!error.to_string().contains("server secret"));
}

#[test]
fn unavailable_and_persistence_failures_are_typed() {
    let transport = UreqRegistrationTransport::new(Duration::from_millis(100));
    let error = register_installation(&MemoryStore::default(), &transport, "http://127.0.0.1:1", 0)
        .unwrap_err();
    assert!(matches!(error, NativeRegistrationError::Transport(_)));

    let server = MockServer::spawn(201, SUCCESS);
    let store = MemoryStore {
        value: Mutex::new(None),
        fail_save: true,
    };
    let error = register_installation(&store, &transport, &server.base_url, 0).unwrap_err();
    assert!(matches!(error, NativeRegistrationError::Persistence(_)));
    assert!(store.load().unwrap().is_none());
}

#[test]
fn secret_bearing_debug_output_is_redacted() {
    let response = NativeDeviceRegistrationResponse {
        device_id: "7d444840-9dc0-11d1-b245-5ffdce74fad2".parse().unwrap(),
        registration_token: "response-registration-secret".into(),
        device_challenge: "response-challenge-secret".into(),
        expires_in: 600,
    };
    let response_debug = format!("{response:?}");
    assert!(!response_debug.contains("response-registration-secret"));
    assert!(!response_debug.contains("response-challenge-secret"));

    let server = MockServer::spawn(201, SUCCESS);
    let record = register_installation(
        &MemoryStore::default(),
        &UreqRegistrationTransport::new(Duration::from_secs(2)),
        &server.base_url,
        0,
    )
    .unwrap();
    let debug = format!("{record:?}");
    assert!(!debug.contains("registration-secret"));
    assert!(!debug.contains("challenge-secret"));
    assert!(!debug.contains(&URL_SAFE_NO_PAD.encode(record.private_key)));
    assert!(debug.contains("<redacted>"));
}
