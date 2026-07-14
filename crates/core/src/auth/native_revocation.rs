//! Best-effort revocation of the current installation-bound native session.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::native_token::NativeCredentialStore;

const REVOCATION_PATH: &str = "/v1/auth/native/revoke";

#[derive(Clone, Serialize)]
pub struct NativeRevocationRequest {
    scope: NativeRevocationScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip)]
    authorization: String,
}

impl NativeRevocationRequest {
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
}

impl fmt::Debug for NativeRevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeRevocationRequest")
            .field("scope", &self.scope)
            .field("refresh_token", &"<redacted>")
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum NativeRevocationScope {
    Current,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRevocationResponse {
    ok: bool,
}

pub trait RevocationTransport: Send + Sync {
    fn revoke(
        &self,
        url: &str,
        request: &NativeRevocationRequest,
    ) -> Result<NativeRevocationResponse, NativeRevocationError>;
}

#[derive(Clone, PartialEq, Eq)]
pub enum NativeRevocationError {
    Config(String),
    CredentialsMissing,
    Persistence(String),
    Transport(String),
    HttpStatus(u16),
    MalformedResponse(String),
}

impl fmt::Debug for NativeRevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("Config(<redacted>)"),
            Self::CredentialsMissing => f.write_str("CredentialsMissing"),
            Self::Persistence(_) => f.write_str("Persistence(<redacted>)"),
            Self::Transport(_) => f.write_str("Transport(<redacted>)"),
            Self::HttpStatus(status) => f.debug_tuple("HttpStatus").field(status).finish(),
            Self::MalformedResponse(_) => f.write_str("MalformedResponse(<redacted>)"),
        }
    }
}

impl fmt::Display for NativeRevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("native revocation configuration error"),
            Self::CredentialsMissing => f.write_str("native session is signed out"),
            Self::Persistence(_) => f.write_str("native credential persistence failed"),
            Self::Transport(_) => f.write_str("native session revocation unavailable"),
            Self::HttpStatus(status) => {
                write!(f, "native session revocation rejected with HTTP {status}")
            }
            Self::MalformedResponse(_) => f.write_str("malformed native revocation response"),
        }
    }
}

impl std::error::Error for NativeRevocationError {}

pub struct UreqRevocationTransport {
    timeout: Duration,
}

impl UreqRevocationTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl RevocationTransport for UreqRevocationTransport {
    fn revoke(
        &self,
        url: &str,
        request: &NativeRevocationRequest,
    ) -> Result<NativeRevocationResponse, NativeRevocationError> {
        let response = ureq::post(url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .set("Authorization", request.authorization())
            .send_json(request)
            .map_err(|error| match error {
                ureq::Error::Status(status, _) => NativeRevocationError::HttpStatus(status),
                ureq::Error::Transport(_) => {
                    NativeRevocationError::Transport("request failed".into())
                }
            })?;
        if response.status() != 200 {
            return Err(NativeRevocationError::HttpStatus(response.status()));
        }
        let response: NativeRevocationResponse = response.into_json().map_err(|_| {
            NativeRevocationError::MalformedResponse("response was not valid contract JSON".into())
        })?;
        if !response.ok {
            return Err(NativeRevocationError::MalformedResponse(
                "response did not confirm revocation".into(),
            ));
        }
        Ok(response)
    }
}

pub fn revoke_current_native_session(
    store: &dyn NativeCredentialStore,
    transport: &dyn RevocationTransport,
    base_url: &str,
) -> Result<(), NativeRevocationError> {
    validate_base_url(base_url)?;
    let credentials = store
        .load_credentials()
        .map_err(|_| NativeRevocationError::Persistence("load failed".into()))?
        .ok_or(NativeRevocationError::CredentialsMissing)?;
    let refresh_token = credentials
        .tokens
        .refresh_token
        .filter(|token| !token.is_empty());
    if credentials.tokens.access_token.is_empty() {
        return Err(NativeRevocationError::CredentialsMissing);
    }
    let request = NativeRevocationRequest {
        scope: NativeRevocationScope::Current,
        refresh_token,
        authorization: format!("Bearer {}", credentials.tokens.access_token),
    };
    transport.revoke(
        &format!("{}{REVOCATION_PATH}", base_url.trim_end_matches('/')),
        &request,
    )?;
    Ok(())
}

/// Best-effort server revocation followed by the authoritative local clear.
///
/// Revocation errors are deliberately ignored so sign-out remains available
/// while offline. Persistence errors from the local clear are still returned.
pub fn sign_out_native_session(
    store: &dyn NativeCredentialStore,
    transport: &dyn RevocationTransport,
    base_url: &str,
) -> Result<(), super::native_token::NativeTokenError> {
    let _ = revoke_current_native_session(store, transport, base_url);
    store.clear_session()
}

fn validate_base_url(base_url: &str) -> Result<(), NativeRevocationError> {
    let parsed = url::Url::parse(base_url)
        .map_err(|_| NativeRevocationError::Config("invalid API base URL".into()))?;
    let loopback_http = parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if (parsed.scheme() != "https" && !loopback_http)
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(NativeRevocationError::Config(
            "API base URL must be HTTPS or loopback HTTP".into(),
        ));
    }
    Ok(())
}
