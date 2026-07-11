//! Installation-bound start of Muniment's native browser authorization.

use std::fmt;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::native_registration::{InstallationStore, CLIENT_ID, CLIENT_ROLE};
use super::{random_state, AuthError, PkcePair, RedirectCatcher};

const AUTHORIZATION_PATH: &str = "/v1/auth/native/authorize";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuthorizationInput {
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: String,
    pub org_id: Option<Uuid>,
}

#[derive(Clone, Serialize)]
pub struct NativeDeviceProof {
    pub challenge: String,
    pub issued_at: String,
    pub jti: String,
    pub signature: String,
}

impl fmt::Debug for NativeDeviceProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDeviceProof")
            .field("challenge", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("jti", &self.jti)
            .field("signature", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Serialize)]
pub struct NativeAuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub device_id: Uuid,
    pub client_role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<Uuid>,
    pub registration_token: String,
    pub device_proof: NativeDeviceProof,
}

impl fmt::Debug for NativeAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeAuthorizationRequest")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("response_type", &self.response_type)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("state", &self.state)
            .field("device_id", &self.device_id)
            .field("client_role", &self.client_role)
            .field("org_id", &self.org_id)
            .field("registration_token", &"<redacted>")
            .field("device_proof", &self.device_proof)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAuthorizationResponse {
    pub authorization_url: String,
    pub device_challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuthorizationResult {
    pub authorization_url: String,
    pub device_id: Uuid,
}

/// Values retained by the app for the later native token exchange.
pub struct NativeAuthorizationCode {
    pub authorization_code: String,
    pub code_verifier: String,
    pub device_id: Uuid,
    pub redirect_uri: String,
}

impl fmt::Debug for NativeAuthorizationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeAuthorizationCode")
            .field("authorization_code", &"<redacted>")
            .field("code_verifier", &"<redacted>")
            .field("device_id", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserOpenError;

impl fmt::Display for BrowserOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not open the system browser")
    }
}

impl std::error::Error for BrowserOpenError {}

pub trait BrowserOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), BrowserOpenError>;
}

impl<F> BrowserOpener for F
where
    F: Fn(&str) -> Result<(), BrowserOpenError> + Send + Sync,
{
    fn open(&self, url: &str) -> Result<(), BrowserOpenError> {
        self(url)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeBrowserAuthorizationError {
    Authorization(NativeAuthorizationError),
    BrowserOpen,
    StateMismatch,
    ProviderDenied,
    Timeout,
    Callback,
}

impl fmt::Display for NativeBrowserAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => error.fmt(f),
            Self::BrowserOpen => write!(f, "could not open the system browser"),
            Self::StateMismatch => write!(f, "sign-in rejected: state mismatch"),
            Self::ProviderDenied => write!(f, "sign-in was not completed by the provider"),
            Self::Timeout => write!(f, "timed out waiting for the browser sign-in"),
            Self::Callback => write!(f, "the browser callback was invalid"),
        }
    }
}

impl std::error::Error for NativeBrowserAuthorizationError {}

/// Start native authorization and complete its external-browser loopback leg.
pub fn run_native_browser_authorization(
    store: &dyn InstallationStore,
    transport: &dyn AuthorizationTransport,
    browser: &dyn BrowserOpener,
    base_url: &str,
    org_id: Option<Uuid>,
    now_unix_seconds: u64,
    timeout: Duration,
) -> Result<NativeAuthorizationCode, NativeBrowserAuthorizationError> {
    // Bind first so the exact live redirect URI is sent to the server and no
    // callback can race listener setup.
    let catcher = RedirectCatcher::bind().map_err(map_callback_error)?;
    let pkce = PkcePair::generate().map_err(map_callback_error)?;
    let state = random_state().map_err(map_callback_error)?;
    let mut proof_jti = [0_u8; 16];
    getrandom::fill(&mut proof_jti).map_err(|_| NativeBrowserAuthorizationError::Callback)?;

    let authorization = begin_native_authorization(
        store,
        transport,
        base_url,
        NativeAuthorizationInput {
            redirect_uri: catcher.redirect_uri(),
            code_challenge: pkce.challenge,
            state: state.clone(),
            org_id,
        },
        now_unix_seconds,
        proof_jti,
    )
    .map_err(NativeBrowserAuthorizationError::Authorization)?;

    browser
        .open(&authorization.authorization_url)
        .map_err(|_| NativeBrowserAuthorizationError::BrowserOpen)?;
    let redirect_uri = catcher.redirect_uri();
    let authorization_code = catcher
        .wait_for_callback(&state, timeout)
        .map_err(map_callback_error)?;
    Ok(NativeAuthorizationCode {
        authorization_code,
        code_verifier: pkce.verifier,
        device_id: authorization.device_id,
        redirect_uri,
    })
}

fn map_callback_error(error: AuthError) -> NativeBrowserAuthorizationError {
    match error {
        AuthError::StateMismatch => NativeBrowserAuthorizationError::StateMismatch,
        AuthError::Denied(_) => NativeBrowserAuthorizationError::ProviderDenied,
        AuthError::Timeout => NativeBrowserAuthorizationError::Timeout,
        _ => NativeBrowserAuthorizationError::Callback,
    }
}

pub trait AuthorizationTransport: Send + Sync {
    fn authorize(
        &self,
        url: &str,
        request: &NativeAuthorizationRequest,
    ) -> Result<NativeAuthorizationResponse, NativeAuthorizationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeAuthorizationError {
    Config(String),
    InstallationMissing,
    RegistrationExpired,
    Transport(String),
    HttpStatus(u16),
    MalformedResponse(String),
    Persistence(String),
}

impl fmt::Display for NativeAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => {
                write!(f, "native authorization configuration error: {message}")
            }
            Self::InstallationMissing => write!(f, "native installation is not registered"),
            Self::RegistrationExpired => write!(f, "native installation registration has expired"),
            Self::Transport(message) => write!(f, "native authorization unavailable: {message}"),
            Self::HttpStatus(status) => {
                write!(f, "native authorization rejected with HTTP {status}")
            }
            Self::MalformedResponse(message) => {
                write!(f, "malformed native authorization response: {message}")
            }
            Self::Persistence(message) => write!(f, "installation persistence failed: {message}"),
        }
    }
}

impl std::error::Error for NativeAuthorizationError {}

pub struct UreqAuthorizationTransport {
    timeout: Duration,
}

impl UreqAuthorizationTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl AuthorizationTransport for UreqAuthorizationTransport {
    fn authorize(
        &self,
        url: &str,
        request: &NativeAuthorizationRequest,
    ) -> Result<NativeAuthorizationResponse, NativeAuthorizationError> {
        let response = ureq::post(url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_json(request)
            .map_err(|error| match error {
                ureq::Error::Status(status, _) => NativeAuthorizationError::HttpStatus(status),
                ureq::Error::Transport(_) => {
                    NativeAuthorizationError::Transport("request failed".into())
                }
            })?;
        if response.status() != 200 {
            return Err(NativeAuthorizationError::HttpStatus(response.status()));
        }
        response.into_json().map_err(|_| {
            NativeAuthorizationError::MalformedResponse(
                "response was not valid contract JSON".into(),
            )
        })
    }
}

pub fn begin_native_authorization(
    store: &dyn InstallationStore,
    transport: &dyn AuthorizationTransport,
    base_url: &str,
    input: NativeAuthorizationInput,
    now_unix_seconds: u64,
    proof_jti: [u8; 16],
) -> Result<NativeAuthorizationResult, NativeAuthorizationError> {
    let mut installation = store
        .load()
        .map_err(|_| NativeAuthorizationError::Persistence("load failed".into()))?
        .ok_or(NativeAuthorizationError::InstallationMissing)?;
    if installation.registration_token.is_empty()
        || installation.device_challenge.is_empty()
        || installation.registration_expires_at <= now_unix_seconds
    {
        return Err(NativeAuthorizationError::RegistrationExpired);
    }
    validate_base_url(base_url)?;
    validate_input(&input)?;

    let timestamp = i64::try_from(now_unix_seconds).map_err(|_| {
        NativeAuthorizationError::Config("clock is outside the supported range".into())
    })?;
    let issued_at = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .ok_or_else(|| {
            NativeAuthorizationError::Config("clock is outside the supported range".into())
        })?
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let jti = URL_SAFE_NO_PAD.encode(proof_jti);
    let mut request = NativeAuthorizationRequest {
        client_id: CLIENT_ID.into(),
        redirect_uri: input.redirect_uri,
        response_type: "code".into(),
        code_challenge: input.code_challenge,
        code_challenge_method: "S256".into(),
        state: input.state,
        device_id: installation.device_id,
        client_role: CLIENT_ROLE.into(),
        org_id: input.org_id,
        registration_token: installation.registration_token.clone(),
        device_proof: NativeDeviceProof {
            challenge: installation.device_challenge.clone(),
            issued_at,
            jti,
            signature: String::new(),
        },
    };
    let body = serde_json::to_value(&request)
        .map_err(|_| NativeAuthorizationError::Config("request could not be encoded".into()))?;
    let object = body
        .as_object()
        .expect("authorization request serializes as an object");
    let unsigned = object
        .iter()
        .filter(|(key, _)| key.as_str() != "device_proof")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    let canonical = serde_json::to_vec(&unsigned).expect("JSON values serialize");
    let body_hash = Sha256::digest(canonical);
    let transcript = format!(
        "MUNIMENT-NATIVE-V1\nPOST\n{AUTHORIZATION_PATH}\n{}\n{}\n{}\n{}",
        hex_lower(&body_hash),
        request.device_proof.challenge,
        request.device_proof.issued_at,
        request.device_proof.jti
    );
    let signature = SigningKey::from_bytes(&installation.private_key).sign(transcript.as_bytes());
    request.device_proof.signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let url = format!("{}{AUTHORIZATION_PATH}", base_url.trim_end_matches('/'));
    let response = transport.authorize(&url, &request)?;
    validate_continuation(&response.authorization_url)?;
    let next_challenge = URL_SAFE_NO_PAD.decode(&response.device_challenge);
    if next_challenge
        .as_ref()
        .map_or(true, |value| value.len() != 32)
        || next_challenge
            .as_ref()
            .is_ok_and(|value| URL_SAFE_NO_PAD.encode(value) != response.device_challenge)
    {
        return Err(NativeAuthorizationError::MalformedResponse(
            "device challenge was not canonical contract data".into(),
        ));
    }
    installation.device_challenge = response.device_challenge;
    installation.registration_token.clear();
    installation.registration_expires_at = 0;
    store
        .save(&installation)
        .map_err(|_| NativeAuthorizationError::Persistence("save failed".into()))?;
    Ok(NativeAuthorizationResult {
        authorization_url: response.authorization_url,
        device_id: installation.device_id,
    })
}

fn validate_input(input: &NativeAuthorizationInput) -> Result<(), NativeAuthorizationError> {
    let redirect = url::Url::parse(&input.redirect_uri)
        .map_err(|_| NativeAuthorizationError::Config("redirect URI is invalid".into()))?;
    let loopback = redirect.scheme() == "http"
        && matches!(redirect.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if !loopback
        || input.code_challenge.len() != 43
        || URL_SAFE_NO_PAD
            .decode(&input.code_challenge)
            .map_or(true, |v| v.len() != 32)
        || input.state.is_empty()
        || input.state.len() > 1024
        || input.state.chars().any(char::is_control)
    {
        return Err(NativeAuthorizationError::Config(
            "native authorization input is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_base_url(value: &str) -> Result<(), NativeAuthorizationError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| NativeAuthorizationError::Config("base URL is invalid".into()))?;
    let loopback = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    let bare_origin = parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none();
    if (parsed.scheme() == "https" || loopback) && bare_origin {
        Ok(())
    } else {
        Err(NativeAuthorizationError::Config(
            "base URL must use HTTPS (HTTP is allowed only on loopback)".into(),
        ))
    }
}

fn validate_continuation(value: &str) -> Result<(), NativeAuthorizationError> {
    let parsed = url::Url::parse(value).map_err(|_| {
        NativeAuthorizationError::MalformedResponse("authorization URL is invalid".into())
    })?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(NativeAuthorizationError::MalformedResponse(
            "authorization URL is unsafe".into(),
        ));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::{Signature, Verifier};

    use super::*;
    use crate::auth::{InstallationRecord, NativeRegistrationError};

    #[derive(Default)]
    struct MemoryStore(Mutex<Option<InstallationRecord>>);

    impl InstallationStore for MemoryStore {
        fn save(&self, installation: &InstallationRecord) -> Result<(), NativeRegistrationError> {
            *self.0.lock().unwrap() = Some(installation.clone());
            Ok(())
        }

        fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    struct CaptureTransport {
        calls: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
        response: NativeAuthorizationResponse,
    }

    impl AuthorizationTransport for CaptureTransport {
        fn authorize(
            &self,
            url: &str,
            request: &NativeAuthorizationRequest,
        ) -> Result<NativeAuthorizationResponse, NativeAuthorizationError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.into(), serde_json::to_value(request).unwrap()));
            Ok(NativeAuthorizationResponse {
                authorization_url: self.response.authorization_url.clone(),
                device_challenge: self.response.device_challenge.clone(),
            })
        }
    }

    fn fixture(expires_at: u64) -> InstallationRecord {
        InstallationRecord {
            private_key: [7; 32],
            device_id: "10000000-0000-4000-8000-000000000001".parse().unwrap(),
            registration_token: URL_SAFE_NO_PAD.encode([8; 32]),
            device_challenge: URL_SAFE_NO_PAD.encode([9; 32]),
            registration_expires_at: expires_at,
        }
    }

    fn input() -> NativeAuthorizationInput {
        NativeAuthorizationInput {
            redirect_uri: "http://127.0.0.1:49152/callback".into(),
            code_challenge: URL_SAFE_NO_PAD.encode([10; 32]),
            state: "fixed-state".into(),
            org_id: None,
        }
    }

    #[test]
    fn builds_and_signs_the_exact_live_contract_then_rotates_registration_material() {
        let store = MemoryStore(Mutex::new(Some(fixture(2_000))));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = CaptureTransport {
            calls: calls.clone(),
            response: NativeAuthorizationResponse {
                authorization_url: "https://api.muniment.ai/v1/auth/native/authorize/opaque".into(),
                device_challenge: URL_SAFE_NO_PAD.encode([11; 32]),
            },
        };
        let result = begin_native_authorization(
            &store,
            &transport,
            "https://api.muniment.ai/",
            input(),
            1_000,
            [12; 16],
        )
        .unwrap();
        assert_eq!(
            result.authorization_url,
            "https://api.muniment.ai/v1/auth/native/authorize/opaque"
        );

        let calls = calls.lock().unwrap();
        assert_eq!(
            calls[0].0,
            "https://api.muniment.ai/v1/auth/native/authorize"
        );
        let body = calls[0].1.as_object().unwrap();
        assert_eq!(body.len(), 10);
        assert_eq!(body["client_id"], "muniment-desktop");
        assert_eq!(body["client_role"], "desktop");
        assert_eq!(body["response_type"], "code");
        assert_eq!(body["code_challenge_method"], "S256");
        let proof = body["device_proof"].as_object().unwrap();
        assert_eq!(proof["issued_at"], "1970-01-01T00:16:40Z");
        assert_eq!(proof["jti"], URL_SAFE_NO_PAD.encode([12; 16]));

        let unsigned = body
            .iter()
            .filter(|(key, _)| key.as_str() != "device_proof")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<serde_json::Map<_, _>>();
        let hash = Sha256::digest(serde_json::to_vec(&unsigned).unwrap());
        let transcript = format!(
            "MUNIMENT-NATIVE-V1\nPOST\n/v1/auth/native/authorize\n{}\n{}\n{}\n{}",
            hex_lower(&hash),
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
        SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .verify(transcript.as_bytes(), &signature)
            .unwrap();

        let saved = store.load().unwrap().unwrap();
        assert!(saved.registration_token.is_empty());
        assert_eq!(saved.registration_expires_at, 0);
        assert_eq!(saved.device_challenge, URL_SAFE_NO_PAD.encode([11; 32]));
    }

    #[test]
    fn expired_registration_is_rejected_before_transport() {
        let store = MemoryStore(Mutex::new(Some(fixture(1_000))));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = CaptureTransport {
            calls: calls.clone(),
            response: NativeAuthorizationResponse {
                authorization_url: "https://example.com/opaque".into(),
                device_challenge: URL_SAFE_NO_PAD.encode([1; 32]),
            },
        };
        let error = begin_native_authorization(
            &store,
            &transport,
            "https://api.muniment.ai",
            input(),
            1_000,
            [0; 16],
        )
        .unwrap_err();
        assert_eq!(error, NativeAuthorizationError::RegistrationExpired);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn rejects_unknown_response_fields_and_unsafe_continuations_without_leaking_secrets() {
        assert!(serde_json::from_str::<NativeAuthorizationResponse>(r#"{"authorization_url":"https://example.com/x","device_challenge":"secret","extra":true}"#).is_err());
        let request = NativeAuthorizationRequest {
            client_id: CLIENT_ID.into(),
            redirect_uri: "http://127.0.0.1/callback".into(),
            response_type: "code".into(),
            code_challenge: "pkce-correlation-value".into(),
            code_challenge_method: "S256".into(),
            state: "state".into(),
            device_id: Uuid::nil(),
            client_role: CLIENT_ROLE.into(),
            org_id: None,
            registration_token: "registration-secret".into(),
            device_proof: NativeDeviceProof {
                challenge: "challenge-secret".into(),
                issued_at: "now".into(),
                jti: "jti".into(),
                signature: "signature-secret".into(),
            },
        };
        let debug = format!("{request:?}");
        for secret in [
            "registration-secret",
            "challenge-secret",
            "signature-secret",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(matches!(
            validate_continuation("http://example.com/x"),
            Err(NativeAuthorizationError::MalformedResponse(_))
        ));
        assert!(matches!(
            validate_continuation("https://user:pass@example.com/x"),
            Err(NativeAuthorizationError::MalformedResponse(_))
        ));
    }
}
