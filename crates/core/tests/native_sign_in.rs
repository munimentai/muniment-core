use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use muniment_core::auth::{
    run_native_sign_in, AuthorizationTransport, InstallationRecord, InstallationStore,
    NativeAuthorizationError, NativeAuthorizationRequest, NativeAuthorizationResponse,
    NativeCredentialStore, NativeCredentials, NativeDeviceRegistrationRequest,
    NativeDeviceRegistrationResponse, NativeRegistrationError, NativeSignInError, NativeTokenError,
    RegistrationTransport, UreqTokenTransport,
};

#[derive(Default)]
struct Store {
    installation: Mutex<Option<InstallationRecord>>,
    credentials: Mutex<Option<NativeCredentials>>,
    fail_credentials: bool,
}

impl InstallationStore for Store {
    fn save(&self, value: &InstallationRecord) -> Result<(), NativeRegistrationError> {
        *self.installation.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError> {
        Ok(self.installation.lock().unwrap().clone())
    }
}

impl NativeCredentialStore for Store {
    fn load_installation(&self) -> Result<Option<InstallationRecord>, NativeTokenError> {
        Ok(self.installation.lock().unwrap().clone())
    }

    fn save_credentials(&self, value: &NativeCredentials) -> Result<(), NativeTokenError> {
        if self.fail_credentials {
            return Err(NativeTokenError::Persistence("fake secret detail".into()));
        }
        *self.installation.lock().unwrap() = Some(value.installation.clone());
        *self.credentials.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn load_credentials(&self) -> Result<Option<NativeCredentials>, NativeTokenError> {
        Ok(self.credentials.lock().unwrap().clone())
    }
}

struct Registration(Arc<AtomicUsize>);

impl RegistrationTransport for Registration {
    fn register(
        &self,
        _: &str,
        _: &NativeDeviceRegistrationRequest,
    ) -> Result<NativeDeviceRegistrationResponse, NativeRegistrationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(NativeDeviceRegistrationResponse {
            device_id: "10000000-0000-4000-8000-000000000001".parse().unwrap(),
            registration_token: URL_SAFE_NO_PAD.encode([2; 32]),
            device_challenge: URL_SAFE_NO_PAD.encode([3; 32]),
            expires_in: 600,
        })
    }
}

#[derive(Clone)]
struct Attempt {
    redirect_uri: String,
    state: String,
}

struct Authorization(Arc<Mutex<Option<Attempt>>>);

impl AuthorizationTransport for Authorization {
    fn authorize(
        &self,
        _: &str,
        request: &NativeAuthorizationRequest,
    ) -> Result<NativeAuthorizationResponse, NativeAuthorizationError> {
        *self.0.lock().unwrap() = Some(Attempt {
            redirect_uri: request.redirect_uri.clone(),
            state: request.state.clone(),
        });
        Ok(NativeAuthorizationResponse {
            authorization_url: "https://login.muniment.ai/continue/opaque".into(),
            device_challenge: URL_SAFE_NO_PAD.encode([4; 32]),
        })
    }
}

fn callback(attempt: &Attempt, query: String) {
    let url = url::Url::parse(&attempt.redirect_uri).unwrap();
    let mut stream = TcpStream::connect((url.host_str().unwrap(), url.port().unwrap())).unwrap();
    write!(
        stream,
        "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        url.path(),
        query
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
}

struct TokenServer {
    base_url: String,
    request: Arc<Mutex<Option<serde_json::Value>>>,
}

impl TokenServer {
    fn spawn(status: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let request = Arc::new(Mutex::new(None));
        let captured_request = request.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let read = stream.read(&mut buffer).unwrap();
                bytes.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&bytes);
                let Some(split) = text.find("\r\n\r\n") else {
                    continue;
                };
                let content_length = text[..split]
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= split + 4 + content_length {
                    let body = &bytes[split + 4..split + 4 + content_length];
                    *captured_request.lock().unwrap() = Some(serde_json::from_slice(body).unwrap());
                    break;
                }
            }
            let body = if status == 200 {
                token_response()
            } else {
                r#"{"detail":"server secret"}"#.into()
            };
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        Self { base_url, request }
    }
}

fn token_response() -> String {
    format!(
        r#"{{"access_token":"access-secret","token_type":"Bearer","expires_in":900,"refresh_token":"refresh-secret","refresh_expires_in":86400,"session":{{"org_id":"20000000-0000-4000-8000-000000000002","user_id":"30000000-0000-4000-8000-000000000003","role":"user","device_id":"10000000-0000-4000-8000-000000000001","client_role":"desktop"}},"entitlement_snapshot":{{"payload":{{"version":1}},"signature":"snapshot-secret","algorithm":"hmac-sha256"}},"device_challenge":"{}"}}"#,
        URL_SAFE_NO_PAD.encode([5; 32])
    )
}

fn installation(expires_at: u64) -> InstallationRecord {
    InstallationRecord {
        private_key: [1; 32],
        device_id: "10000000-0000-4000-8000-000000000001".parse().unwrap(),
        registration_token: URL_SAFE_NO_PAD.encode([2; 32]),
        device_challenge: URL_SAFE_NO_PAD.encode([3; 32]),
        registration_expires_at: expires_at,
    }
}

fn run(
    store: &Store,
    registration_hits: Arc<AtomicUsize>,
    status: u16,
    deny: bool,
) -> Result<muniment_core::auth::AuthStatus, NativeSignInError> {
    run_with_clock(
        store,
        registration_hits,
        status,
        deny,
        Arc::new(AtomicU64::new(1_000)),
        1_000,
    )
    .0
}

fn run_with_clock(
    store: &Store,
    registration_hits: Arc<AtomicUsize>,
    status: u16,
    deny: bool,
    clock: Arc<AtomicU64>,
    exchange_time: u64,
) -> (
    Result<muniment_core::auth::AuthStatus, NativeSignInError>,
    TokenServer,
) {
    let server = TokenServer::spawn(status);
    let attempt = Arc::new(Mutex::new(None));
    let authorization = Authorization(attempt.clone());
    let browser_clock = clock.clone();
    let browser = move |_: &str| {
        browser_clock.store(exchange_time, Ordering::SeqCst);
        let attempt = attempt.lock().unwrap().clone().unwrap();
        std::thread::spawn(move || {
            let query = if deny {
                format!("error=access_denied&state={}", attempt.state)
            } else {
                format!(
                    "code={}&state={}",
                    URL_SAFE_NO_PAD.encode([9; 32]),
                    attempt.state
                )
            };
            callback(&attempt, query);
        });
        Ok(())
    };
    let result = run_native_sign_in(
        store,
        &Registration(registration_hits),
        &authorization,
        &UreqTokenTransport::new(Duration::from_secs(2)),
        &browser,
        &server.base_url,
        &|| clock.load(Ordering::SeqCst),
        Duration::from_secs(2),
    );
    (result, server)
}

#[test]
fn first_run_registers_signs_in_and_returns_secret_free_status() {
    let store = Store::default();
    let hits = Arc::new(AtomicUsize::new(0));
    let status = run(&store, hits.clone(), 200, false).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(status.signed_in);
    assert_eq!(
        status.subject.as_deref(),
        Some("30000000-0000-4000-8000-000000000003")
    );
    assert_eq!(status.expires_at, Some(1_900));
    assert!(store.credentials.lock().unwrap().is_some());
}

#[test]
fn reuses_usable_installation_without_registration() {
    let store = Store {
        installation: Mutex::new(Some(installation(1_600))),
        ..Store::default()
    };
    let hits = Arc::new(AtomicUsize::new(0));
    run(&store, hits.clone(), 200, false).unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn exchange_uses_time_sampled_after_browser_authorization() {
    let store = Store::default();
    let (status, server) = run_with_clock(
        &store,
        Arc::new(AtomicUsize::new(0)),
        200,
        false,
        Arc::new(AtomicU64::new(1_000)),
        1_300,
    );

    assert_eq!(status.unwrap().expires_at, Some(2_200));
    assert_eq!(
        server.request.lock().unwrap().as_ref().unwrap()["device_proof"]["issued_at"],
        "1970-01-01T00:21:40Z"
    );
    assert_eq!(
        store
            .credentials
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .tokens
            .expires_at,
        Some(2_200)
    );
}

#[test]
fn cancellation_exchange_and_persistence_failures_are_safe() {
    for (store, status, deny, expected) in [
        (
            Store::default(),
            200,
            true,
            NativeSignInError::Authorization,
        ),
        (
            Store::default(),
            503,
            false,
            NativeSignInError::TokenExchange,
        ),
        (
            Store {
                fail_credentials: true,
                ..Store::default()
            },
            200,
            false,
            NativeSignInError::TokenExchange,
        ),
    ] {
        let error = run(&store, Arc::new(AtomicUsize::new(0)), status, deny).unwrap_err();
        assert_eq!(error, expected);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("secret"));
        assert!(store.credentials.lock().unwrap().is_none());
    }
}
