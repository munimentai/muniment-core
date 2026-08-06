//! Authoritative inspection of an installation-bound native session.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::native_registration::CLIENT_ROLE;
use super::native_token::{
    refresh_native_credentials, NativeCredentialStore, NativeCredentials, NativeTokenError,
    TokenTransport, UreqTokenTransport,
};
use super::AuthStatus;

const SESSION_PATH: &str = "/v1/auth/native/session";
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const REFRESH_SKEW: Duration = Duration::from_secs(60);

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeSessionRole {
    User,
    Admin,
    Owner,
}

/// The strictly typed, display-only portion of the signed entitlement payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEntitlementPayload {
    #[serde(rename = "version")]
    pub snapshot_version: u64,
    #[serde(default)]
    pub user_display_name: Option<String>,
    #[serde(default)]
    pub organization_display_name: Option<String>,
    pub groups: Vec<NativeEntitlementGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEntitlementGroup {
    pub name: String,
    pub models: Vec<String>,
    pub connections: Vec<String>,
    pub capabilities: Vec<String>,
}

/// Safe webview projection. The signed envelope and native credentials have no
/// fields in this type and therefore cannot be serialized through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntitlementSnapshotView {
    pub snapshot_version: u64,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: NativeSessionRole,
    pub user_display_name: Option<String>,
    pub organization_display_name: Option<String>,
    pub groups: Vec<NativeEntitlementGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntitlementSnapshotAlgorithm {
    HmacSha256,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEntitlementSnapshot {
    pub payload: NativeEntitlementPayload,
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

/// Result of validating the production native session. Credentials remain in
/// native Rust code; Tauri commands may return only the status or the safe
/// entitlement projection.
pub struct FreshNativeSession {
    pub status: AuthStatus,
    pub entitlement_snapshot: Option<EntitlementSnapshotView>,
    credentials: Option<NativeCredentials>,
}

impl FreshNativeSession {
    pub fn credentials(&self) -> Option<&NativeCredentials> {
        self.credentials.as_ref()
    }

    pub fn into_credentials(self) -> Option<NativeCredentials> {
        self.credentials
    }
}

impl fmt::Debug for FreshNativeSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FreshNativeSession")
            .field("status", &self.status)
            .field("entitlement_snapshot", &self.entitlement_snapshot)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum FreshNativeSessionError {
    Credentials,
    Randomness,
    TokenRefresh,
    SessionInspection,
}

impl fmt::Debug for FreshNativeSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for FreshNativeSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credentials => f.write_str("native credential persistence failed"),
            Self::Randomness => {
                f.write_str("native session refresh could not create a secure proof")
            }
            Self::TokenRefresh => f.write_str("native session refresh failed"),
            Self::SessionInspection => f.write_str("native session validation failed"),
        }
    }
}

impl std::error::Error for FreshNativeSessionError {}

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

/// Read the coherent native record without network access.
pub fn native_status(
    store: &dyn NativeCredentialStore,
    now_unix_seconds: u64,
) -> Result<AuthStatus, FreshNativeSessionError> {
    let credentials = store
        .load_credentials()
        .map_err(|_| FreshNativeSessionError::Credentials)?;
    Ok(status_from_credentials(
        credentials.as_ref(),
        now_unix_seconds,
    ))
}

/// Compose the production transports and return a fresh native session.
pub fn ensure_native_session(
    store: &dyn NativeCredentialStore,
    base_url: &str,
    now_unix_seconds: u64,
) -> Result<FreshNativeSession, FreshNativeSessionError> {
    ensure_fresh_native_session(
        store,
        &UreqTokenTransport::new(NETWORK_TIMEOUT),
        &UreqSessionTransport::new(NETWORK_TIMEOUT),
        base_url,
        now_unix_seconds,
        REFRESH_SKEW,
    )
}

/// Refresh a near-expiry native access credential, atomically persist any
/// rotation, and validate the authoritative server-side native session.
pub fn ensure_fresh_native_session(
    store: &dyn NativeCredentialStore,
    token_transport: &dyn TokenTransport,
    session_transport: &dyn SessionTransport,
    base_url: &str,
    now_unix_seconds: u64,
    refresh_skew: Duration,
) -> Result<FreshNativeSession, FreshNativeSessionError> {
    let Some(mut credentials) = store
        .load_credentials()
        .map_err(|_| FreshNativeSessionError::Credentials)?
    else {
        return Ok(signed_out());
    };

    let refresh_at = now_unix_seconds.saturating_add(refresh_skew.as_secs());
    if credentials
        .tokens
        .expires_at
        .is_none_or(|expiry| expiry <= refresh_at)
    {
        if now_unix_seconds >= credentials.refresh_expires_at
            || credentials
                .tokens
                .refresh_token
                .as_ref()
                .is_none_or(String::is_empty)
        {
            return Ok(signed_out());
        }
        let mut proof_jti = [0_u8; 16];
        getrandom::fill(&mut proof_jti).map_err(|_| FreshNativeSessionError::Randomness)?;
        credentials = match refresh_native_credentials(
            store,
            token_transport,
            base_url,
            now_unix_seconds,
            proof_jti,
        ) {
            Ok(credentials) => credentials,
            Err(NativeTokenError::CredentialsMissing | NativeTokenError::RefreshExpired) => {
                return Ok(signed_out())
            }
            Err(_) => return Err(FreshNativeSessionError::TokenRefresh),
        };
    }

    let session = inspect_native_session(store, session_transport, base_url)
        .map_err(|_| FreshNativeSessionError::SessionInspection)?;
    let status = AuthStatus {
        signed_in: true,
        subject: Some(session.session.user_id.to_string()),
        expires_at: credentials.tokens.expires_at,
    };
    let payload = session.entitlement_snapshot.payload;
    Ok(FreshNativeSession {
        status,
        entitlement_snapshot: Some(EntitlementSnapshotView {
            snapshot_version: payload.snapshot_version,
            org_id: session.session.org_id,
            user_id: session.session.user_id,
            role: session.session.role,
            user_display_name: payload.user_display_name,
            organization_display_name: payload.organization_display_name,
            groups: payload.groups,
        }),
        credentials: Some(credentials),
    })
}

fn status_from_credentials(
    credentials: Option<&NativeCredentials>,
    now_unix_seconds: u64,
) -> AuthStatus {
    match credentials {
        Some(credentials)
            if !credentials.tokens.access_token.is_empty()
                && now_unix_seconds < credentials.refresh_expires_at =>
        {
            AuthStatus {
                signed_in: true,
                subject: credentials.tokens.subject.clone(),
                expires_at: credentials.tokens.expires_at,
            }
        }
        _ => AuthStatus {
            signed_in: false,
            subject: None,
            expires_at: None,
        },
    }
}

fn signed_out() -> FreshNativeSession {
    FreshNativeSession {
        status: AuthStatus {
            signed_in: false,
            subject: None,
            expires_at: None,
        },
        entitlement_snapshot: None,
        credentials: None,
    }
}

fn validate_response(
    response: &NativeSession,
    expected_device_id: Uuid,
) -> Result<(), NativeSessionError> {
    if response.session.device_id != expected_device_id
        || response.session.client_role != CLIENT_ROLE
        || response.entitlement_snapshot.signature.is_empty()
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
