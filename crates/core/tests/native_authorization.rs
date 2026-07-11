use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use muniment_core::auth::{
    run_native_browser_authorization, AuthorizationTransport, BrowserOpenError, InstallationRecord,
    InstallationStore, NativeAuthorizationError, NativeAuthorizationRequest,
    NativeAuthorizationResponse, NativeBrowserAuthorizationError, NativeRegistrationError,
    PkcePair,
};

#[derive(Default)]
struct MemoryStore(Mutex<Option<InstallationRecord>>);

impl InstallationStore for MemoryStore {
    fn save(&self, value: &InstallationRecord) -> Result<(), NativeRegistrationError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Clone, Debug)]
struct Attempt {
    redirect_uri: String,
    challenge: String,
    state: String,
}

struct FakeTransport(Arc<Mutex<Option<Attempt>>>);

impl AuthorizationTransport for FakeTransport {
    fn authorize(
        &self,
        url: &str,
        request: &NativeAuthorizationRequest,
    ) -> Result<NativeAuthorizationResponse, NativeAuthorizationError> {
        assert_eq!(url, "https://api.muniment.ai/v1/auth/native/authorize");
        *self.0.lock().unwrap() = Some(Attempt {
            redirect_uri: request.redirect_uri.clone(),
            challenge: request.code_challenge.clone(),
            state: request.state.clone(),
        });
        Ok(NativeAuthorizationResponse {
            authorization_url: "https://login.muniment.ai/continue/opaque".into(),
            device_challenge: URL_SAFE_NO_PAD.encode([4; 32]),
        })
    }
}

fn store() -> MemoryStore {
    MemoryStore(Mutex::new(Some(InstallationRecord {
        private_key: [1; 32],
        device_id: "10000000-0000-4000-8000-000000000001".parse().unwrap(),
        registration_token: URL_SAFE_NO_PAD.encode([2; 32]),
        device_challenge: URL_SAFE_NO_PAD.encode([3; 32]),
        registration_expires_at: 2_000,
    })))
}

fn callback(url: &str, query: &str) {
    let parsed = url::Url::parse(url).unwrap();
    let mut stream =
        TcpStream::connect((parsed.host_str().unwrap(), parsed.port().unwrap())).unwrap();
    write!(
        stream,
        "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        parsed.path(),
        query
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
}

#[test]
fn round_trip_uses_one_attempt_and_returns_exchange_material_redacted() {
    let attempt = Arc::new(Mutex::new(None));
    let opened = Arc::new(Mutex::new(None));
    let transport = FakeTransport(attempt.clone());
    let browser = {
        let attempt = attempt.clone();
        let opened = opened.clone();
        move |url: &str| {
            *opened.lock().unwrap() = Some(url.to_string());
            let sent = attempt.lock().unwrap().clone().unwrap();
            std::thread::spawn(move || {
                callback(
                    &sent.redirect_uri,
                    &format!("code=code-secret&state={}", sent.state),
                );
            });
            Ok(())
        }
    };
    let result = run_native_browser_authorization(
        &store(),
        &transport,
        &browser,
        "https://api.muniment.ai",
        None,
        1_000,
        Duration::from_secs(2),
    )
    .unwrap();

    let sent = attempt.lock().unwrap().clone().unwrap();
    assert_eq!(
        PkcePair::from_verifier(result.code_verifier.clone()).challenge,
        sent.challenge
    );
    assert_eq!(result.authorization_code, "code-secret");
    assert_eq!(
        opened.lock().unwrap().as_deref(),
        Some("https://login.muniment.ai/continue/opaque")
    );
    let debug = format!("{result:?}");
    assert!(!debug.contains("code-secret"));
    assert!(!debug.contains(&result.code_verifier));
    assert!(!debug.contains("10000000-0000-4000-8000-000000000001"));
}

fn callback_failure(
    query: impl FnOnce(&Attempt) -> String + Send,
) -> NativeBrowserAuthorizationError {
    let attempt = Arc::new(Mutex::new(None));
    let transport = FakeTransport(attempt.clone());
    let query = Mutex::new(Some(query));
    let browser = move |_: &str| {
        let sent = attempt.lock().unwrap().clone().unwrap();
        let query = query.lock().unwrap().take().unwrap()(&sent);
        std::thread::spawn(move || callback(&sent.redirect_uri, &query));
        Ok(())
    };
    run_native_browser_authorization(
        &store(),
        &transport,
        &browser,
        "https://api.muniment.ai",
        None,
        1_000,
        Duration::from_secs(2),
    )
    .unwrap_err()
}

#[test]
fn rejects_state_mismatch_and_provider_denial_without_secret_errors() {
    assert_eq!(
        callback_failure(|_| "code=secret-code&state=forged".into()),
        NativeBrowserAuthorizationError::StateMismatch
    );
    let denied = callback_failure(|attempt| {
        format!(
            "error=access_denied&error_description=token-secret&state={}",
            attempt.state
        )
    });
    assert_eq!(denied, NativeBrowserAuthorizationError::ProviderDenied);
    assert!(!format!("{denied:?} {denied}").contains("token-secret"));
}

#[test]
fn timeout_and_browser_failure_are_bounded() {
    let attempt = Arc::new(Mutex::new(None));
    let transport = FakeTransport(attempt);
    let no_callback = |_: &str| Ok(());
    let error = run_native_browser_authorization(
        &store(),
        &transport,
        &no_callback,
        "https://api.muniment.ai",
        None,
        1_000,
        Duration::from_millis(50),
    )
    .unwrap_err();
    assert_eq!(error, NativeBrowserAuthorizationError::Timeout);

    let attempt = Arc::new(Mutex::new(None));
    let transport = FakeTransport(attempt);
    let fails = |_: &str| Err(BrowserOpenError);
    let error = run_native_browser_authorization(
        &store(),
        &transport,
        &fails,
        "https://api.muniment.ai",
        None,
        1_000,
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(error, NativeBrowserAuthorizationError::BrowserOpen);
}
