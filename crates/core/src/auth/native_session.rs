//! Authoritative inspection of an installation-bound native session.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use uuid::Uuid;

use super::native_registration::CLIENT_ROLE;
use super::native_token::NativeCredentialStore;

const SESSION_PATH: &str = "/v1/auth/native/session";

#[derive(Clone)]
pub struct NativeSessionRequest {
    authorization: String,
}

impl NativeSessionRequest {
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
}

impl fmt::Debug for NativeSessionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeSessionRequest")
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeSessionRole {
    User,
    Admin,
    Owner,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntitlementSnapshotAlgorithm {
    HmacSha256,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEntitlementSnapshot {
    pub payload: serde_json::Value,
    pub signature: String,
    pub algorithm: EntitlementSnapshotAlgorithm,
}

impl fmt::Debug for NativeEntitlementSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeEntitlementSnapshot")
            .field("payload", &self.payload)
            .field("signature", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSessionIdentity {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: NativeSessionRole,
    pub device_id: Uuid,
    pub client_role: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSession {
    pub session: NativeSessionIdentity,
    pub entitlement_snapshot: NativeEntitlementSnapshot,
}

pub trait SessionTransport: Send + Sync {
    fn inspect(
        &self,
        url: &str,
        request: &NativeSessionRequest,
    ) -> Result<NativeSession, NativeSessionError>;
}

#[derive(Clone, PartialEq, Eq)]
pub enum NativeSessionError {
    Config(String),
    CredentialsMissing,
    Persistence(String),
    Transport(String),
    HttpStatus(u16),
    MalformedResponse(String),
}

impl fmt::Debug for NativeSessionError {
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

impl fmt::Display for NativeSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("native session configuration error"),
            Self::CredentialsMissing => f.write_str("native session is signed out"),
            Self::Persistence(_) => f.write_str("native credential persistence failed"),
            Self::Transport(_) => f.write_str("native session inspection unavailable"),
            Self::HttpStatus(status) => {
                write!(f, "native session inspection rejected with HTTP {status}")
            }
            Self::MalformedResponse(_) => f.write_str("malformed native session response"),
        }
    }
}

impl std::error::Error for NativeSessionError {}

pub struct UreqSessionTransport {
    timeout: Duration,
}

impl UreqSessionTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl SessionTransport for UreqSessionTransport {
    fn inspect(
        &self,
        url: &str,
        request: &NativeSessionRequest,
    ) -> Result<NativeSession, NativeSessionError> {
        let response = ureq::get(url)
            .timeout(self.timeout)
            .set("Authorization", request.authorization())
            .call()
            .map_err(|error| match error {
                ureq::Error::Status(status, _) => NativeSessionError::HttpStatus(status),
                ureq::Error::Transport(_) => NativeSessionError::Transport("request failed".into()),
            })?;
        if response.status() != 200 {
            return Err(NativeSessionError::HttpStatus(response.status()));
        }
        response.into_json().map_err(|_| {
            NativeSessionError::MalformedResponse("response was not valid contract JSON".into())
        })
    }
}

pub fn inspect_native_session(
    store: &dyn NativeCredentialStore,
    transport: &dyn SessionTransport,
    base_url: &str,
) -> Result<NativeSession, NativeSessionError> {
    validate_base_url(base_url)?;
    let credentials = store
        .load_credentials()
        .map_err(|_| NativeSessionError::Persistence("load failed".into()))?
        .ok_or(NativeSessionError::CredentialsMissing)?;
    if credentials.tokens.access_token.is_empty() {
        return Err(NativeSessionError::CredentialsMissing);
    }
    let expected_device_id = credentials.installation.device_id;
    let request = NativeSessionRequest {
        authorization: format!("Bearer {}", credentials.tokens.access_token),
    };
    let response = transport.inspect(
        &format!("{}{SESSION_PATH}", base_url.trim_end_matches('/')),
        &request,
    )?;
    validate_response(&response, expected_device_id)?;
    Ok(response)
}

fn validate_response(
    response: &NativeSession,
    expected_device_id: Uuid,
) -> Result<(), NativeSessionError> {
    if response.session.device_id != expected_device_id
        || response.session.client_role != CLIENT_ROLE
        || response.entitlement_snapshot.signature.is_empty()
        || !response.entitlement_snapshot.payload.is_object()
    {
        return Err(NativeSessionError::MalformedResponse(
            "session metadata did not match the contract".into(),
        ));
    }
    Ok(())
}

fn validate_base_url(value: &str) -> Result<(), NativeSessionError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| NativeSessionError::Config("base URL is invalid".into()))?;
    let loopback = parsed.scheme() == "http"
        && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    let bare = parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none();
    if (parsed.scheme() == "https" || loopback) && bare {
        Ok(())
    } else {
        Err(NativeSessionError::Config(
            "base URL must use HTTPS (HTTP is allowed only on loopback)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_debug_is_redacted() {
        let request = NativeSessionRequest {
            authorization: "Bearer access-secret".into(),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("access-secret"));
        assert!(!rendered.contains("Bearer"));
        assert!(rendered.contains("<redacted>"));
    }
}
