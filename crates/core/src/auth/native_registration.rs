//! Installation registration for Muniment's native authentication contract.

use std::fmt;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CLIENT_ID: &str = "muniment-desktop";
pub const CLIENT_ROLE: &str = "desktop";
pub const PLATFORM: &str = "desktop";
const REGISTRATION_PATH: &str = "/v1/auth/native/devices";
const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(30);
const MIN_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Registration retries can wait for at most five minutes across one sign-in attempt.
pub const MAX_REGISTRATION_RETRY_WAIT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeDeviceRegistrationRequest {
    pub client_id: String,
    pub client_role: String,
    pub platform: String,
    pub installation_public_key: String,
}

#[derive(Clone, Deserialize)]
pub struct NativeDeviceRegistrationResponse {
    pub device_id: Uuid,
    pub registration_token: String,
    pub device_challenge: String,
    pub expires_in: u64,
}

impl fmt::Debug for NativeDeviceRegistrationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDeviceRegistrationResponse")
            .field("device_id", &self.device_id)
            .field("registration_token", &"<redacted>")
            .field("device_challenge", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// One coherent keychain record. The signing key is the raw 32-byte Ed25519 seed.
#[derive(Clone, Serialize, Deserialize)]
pub struct InstallationRecord {
    pub private_key: [u8; 32],
    pub device_id: Uuid,
    pub registration_token: String,
    pub device_challenge: String,
    pub registration_expires_at: u64,
}

impl fmt::Debug for InstallationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallationRecord")
            .field("private_key", &"<redacted>")
            .field("device_id", &self.device_id)
            .field("registration_token", &"<redacted>")
            .field("device_challenge", &"<redacted>")
            .field("registration_expires_at", &self.registration_expires_at)
            .finish()
    }
}

pub trait InstallationStore: Send + Sync {
    fn save(&self, installation: &InstallationRecord) -> Result<(), NativeRegistrationError>;
    fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError>;
}

/// Injectable boundary used by the core; tests provide a loopback implementation.
pub trait RegistrationTransport: Send + Sync {
    fn register(
        &self,
        url: &str,
        request: &NativeDeviceRegistrationRequest,
    ) -> Result<NativeDeviceRegistrationResponse, NativeRegistrationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeRegistrationError {
    Config(String),
    Transport(String),
    HttpStatus(u16),
    RateLimited(Duration),
    MalformedResponse(String),
    Persistence(String),
    KeyGeneration,
}

impl fmt::Display for NativeRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => {
                write!(f, "native registration configuration error: {message}")
            }
            Self::Transport(message) => write!(f, "native registration unavailable: {message}"),
            Self::HttpStatus(status) => {
                write!(f, "native registration rejected with HTTP {status}")
            }
            Self::RateLimited(_) => write!(f, "native registration rate limit persisted"),
            Self::MalformedResponse(message) => {
                write!(f, "malformed native registration response: {message}")
            }
            Self::Persistence(message) => write!(f, "installation persistence failed: {message}"),
            Self::KeyGeneration => write!(f, "installation key generation failed"),
        }
    }
}

impl std::error::Error for NativeRegistrationError {}

pub struct UreqRegistrationTransport {
    timeout: Duration,
}

impl UreqRegistrationTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl RegistrationTransport for UreqRegistrationTransport {
    fn register(
        &self,
        url: &str,
        request: &NativeDeviceRegistrationRequest,
    ) -> Result<NativeDeviceRegistrationResponse, NativeRegistrationError> {
        let response = ureq::post(url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_json(request)
            .map_err(|error| match error {
                ureq::Error::Status(429, response) => NativeRegistrationError::RateLimited(
                    retry_delay(response.header("Retry-After")),
                ),
                ureq::Error::Status(status, _) => NativeRegistrationError::HttpStatus(status),
                ureq::Error::Transport(_) => {
                    NativeRegistrationError::Transport("request failed".into())
                }
            })?;
        response.into_json().map_err(|_| {
            NativeRegistrationError::MalformedResponse(
                "response was not valid contract JSON".into(),
            )
        })
    }
}

fn retry_delay(header: Option<&str>) -> Duration {
    let seconds = header
        .and_then(|value| value.trim().parse::<u64>().ok())
        .or_else(|| {
            let retry_at = chrono::DateTime::parse_from_rfc2822(header?).ok()?;
            let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
            let seconds = retry_at.signed_duration_since(now).num_seconds();
            u64::try_from(seconds.max(0)).ok()
        });
    Duration::from_secs(seconds.unwrap_or(DEFAULT_RETRY_DELAY.as_secs()))
        .clamp(MIN_RETRY_DELAY, MAX_REGISTRATION_RETRY_WAIT)
}

/// Return a usable persisted installation, registering when it is missing or expired.
pub fn register_installation(
    store: &dyn InstallationStore,
    transport: &dyn RegistrationTransport,
    base_url: &str,
    now_unix_seconds: u64,
) -> Result<InstallationRecord, NativeRegistrationError> {
    register_installation_with_retry(store, transport, base_url, now_unix_seconds, &|delay| {
        std::thread::sleep(delay)
    })
}

/// Register an installation and report each rate-limit wait before it starts.
pub fn register_installation_with_retry(
    store: &dyn InstallationStore,
    transport: &dyn RegistrationTransport,
    base_url: &str,
    now_unix_seconds: u64,
    wait: &dyn Fn(Duration),
) -> Result<InstallationRecord, NativeRegistrationError> {
    if let Some(existing) = store.load()? {
        if !existing.registration_token.is_empty()
            && !existing.device_challenge.is_empty()
            && existing.registration_expires_at > now_unix_seconds
        {
            return Ok(existing);
        }
    }
    validate_base_url(base_url)?;

    let mut private_key = [0u8; 32];
    getrandom::fill(&mut private_key).map_err(|_| NativeRegistrationError::KeyGeneration)?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let request = NativeDeviceRegistrationRequest {
        client_id: CLIENT_ID.into(),
        client_role: CLIENT_ROLE.into(),
        platform: PLATFORM.into(),
        installation_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
    };
    let url = format!("{}{}", base_url.trim_end_matches('/'), REGISTRATION_PATH);
    let mut total_wait = Duration::ZERO;
    let response = loop {
        match transport.register(&url, &request) {
            Ok(response) => break response,
            Err(NativeRegistrationError::RateLimited(delay)) => {
                if total_wait >= MAX_REGISTRATION_RETRY_WAIT {
                    return Err(NativeRegistrationError::RateLimited(delay));
                }
                let delay = delay
                    .clamp(MIN_RETRY_DELAY, MAX_REGISTRATION_RETRY_WAIT)
                    .min(MAX_REGISTRATION_RETRY_WAIT - total_wait);
                wait(delay);
                total_wait += delay;
            }
            Err(error) => return Err(error),
        }
    };
    if response.expires_in != 600 {
        return Err(NativeRegistrationError::MalformedResponse(
            "registration expiry did not match the contract".into(),
        ));
    }
    let installation = InstallationRecord {
        private_key,
        device_id: response.device_id,
        registration_token: response.registration_token,
        device_challenge: response.device_challenge,
        registration_expires_at: now_unix_seconds.saturating_add(response.expires_in),
    };
    store.save(&installation)?;
    Ok(installation)
}

fn validate_base_url(base_url: &str) -> Result<(), NativeRegistrationError> {
    let parsed = url::Url::parse(base_url)
        .map_err(|_| NativeRegistrationError::Config("base URL is invalid".into()))?;
    let secure = parsed.scheme() == "https";
    let loopback = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if secure || loopback {
        Ok(())
    } else {
        Err(NativeRegistrationError::Config(
            "base URL must use HTTPS (HTTP is allowed only on loopback)".into(),
        ))
    }
}
