//! Installation-bound native authorization-code exchange.

use std::fmt;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::native_authorization::{NativeAuthorizationCode, NativeDeviceProof};
use super::native_registration::{InstallationRecord, CLIENT_ID, CLIENT_ROLE};
use super::TokenSet;

const TOKEN_PATH: &str = "/v1/auth/native/token";

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum NativeTokenRequest {
    AuthorizationCode(NativeAuthorizationCodeTokenRequest),
    RefreshToken(NativeRefreshTokenRequest),
}

#[derive(Clone, Serialize)]
pub struct NativeAuthorizationCodeTokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
    pub device_id: Uuid,
    pub device_proof: NativeDeviceProof,
}

#[derive(Clone, Serialize)]
pub struct NativeRefreshTokenRequest {
    pub grant_type: String,
    pub refresh_token: String,
    pub client_id: String,
    pub device_id: Uuid,
    pub device_proof: NativeDeviceProof,
}

impl fmt::Debug for NativeTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorizationCode(request) => f
                .debug_struct("NativeAuthorizationCodeTokenRequest")
                .field("grant_type", &request.grant_type)
                .field("code", &"<redacted>")
                .field("redirect_uri", &request.redirect_uri)
                .field("client_id", &request.client_id)
                .field("code_verifier", &"<redacted>")
                .field("device_id", &request.device_id)
                .field("device_proof", &request.device_proof)
                .finish(),
            Self::RefreshToken(request) => f
                .debug_struct("NativeRefreshTokenRequest")
                .field("grant_type", &request.grant_type)
                .field("refresh_token", &"<redacted>")
                .field("client_id", &request.client_id)
                .field("device_id", &request.device_id)
                .field("device_proof", &request.device_proof)
                .finish(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    refresh_expires_in: u64,
    session: NativeTokenSession,
    entitlement_snapshot: SignedEntitlementSnapshot,
    device_challenge: String,
}

impl fmt::Debug for NativeTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeTokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &"<redacted>")
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("device_challenge", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeTokenSession {
    org_id: Uuid,
    user_id: Uuid,
    role: NativeRole,
    device_id: Uuid,
    client_role: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum NativeRole {
    User,
    Admin,
    Owner,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEntitlementSnapshot {
    payload: serde_json::Value,
    signature: String,
    algorithm: SnapshotAlgorithm,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SnapshotAlgorithm {
    HmacSha256,
}

/// One atomically published native credential state.
#[derive(Clone)]
pub struct NativeCredentials {
    pub installation: InstallationRecord,
    pub tokens: TokenSet,
    pub refresh_expires_at: u64,
}

impl fmt::Debug for NativeCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeCredentials")
            .field("installation", &self.installation)
            .field("tokens", &self.tokens)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// Persistence boundary implemented as one coherent write by platform code.
pub trait NativeCredentialStore: Send + Sync {
    fn load_installation(&self) -> Result<Option<InstallationRecord>, NativeTokenError>;
    fn save_credentials(&self, credentials: &NativeCredentials) -> Result<(), NativeTokenError>;
    fn load_credentials(&self) -> Result<Option<NativeCredentials>, NativeTokenError>;
}

pub trait TokenTransport: Send + Sync {
    fn exchange(
        &self,
        url: &str,
        request: &NativeTokenRequest,
    ) -> Result<NativeTokenResponse, NativeTokenError>;
}

#[derive(Clone, PartialEq, Eq)]
pub enum NativeTokenError {
    Config(String),
    InstallationMissing,
    CredentialsMissing,
    RefreshExpired,
    DeviceMismatch,
    Transport(String),
    HttpStatus(u16),
    MalformedResponse(String),
    Persistence(String),
}

impl fmt::Debug for NativeTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("Config(<redacted>)"),
            Self::InstallationMissing => f.write_str("InstallationMissing"),
            Self::CredentialsMissing => f.write_str("CredentialsMissing"),
            Self::RefreshExpired => f.write_str("RefreshExpired"),
            Self::DeviceMismatch => f.write_str("DeviceMismatch"),
            Self::Transport(_) => f.write_str("Transport(<redacted>)"),
            Self::HttpStatus(status) => f.debug_tuple("HttpStatus").field(status).finish(),
            Self::MalformedResponse(_) => f.write_str("MalformedResponse(<redacted>)"),
            Self::Persistence(_) => f.write_str("Persistence(<redacted>)"),
        }
    }
}

impl fmt::Display for NativeTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => write!(f, "native token configuration error"),
            Self::InstallationMissing => write!(f, "native installation is not registered"),
            Self::CredentialsMissing => write!(f, "native session is signed out"),
            Self::RefreshExpired => write!(f, "native refresh credential has expired"),
            Self::DeviceMismatch => write!(
                f,
                "native authorization device does not match the installation"
            ),
            Self::Transport(_) => write!(f, "native token exchange unavailable"),
            Self::HttpStatus(s) => write!(f, "native token exchange rejected with HTTP {s}"),
            Self::MalformedResponse(_) => write!(f, "malformed native token response"),
            Self::Persistence(_) => write!(f, "native credential persistence failed"),
        }
    }
}
impl std::error::Error for NativeTokenError {}

pub struct UreqTokenTransport {
    timeout: Duration,
}
impl UreqTokenTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl TokenTransport for UreqTokenTransport {
    fn exchange(
        &self,
        url: &str,
        request: &NativeTokenRequest,
    ) -> Result<NativeTokenResponse, NativeTokenError> {
        let response = ureq::post(url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_json(request)
            .map_err(|error| match error {
                ureq::Error::Status(status, _) => NativeTokenError::HttpStatus(status),
                ureq::Error::Transport(_) => NativeTokenError::Transport("request failed".into()),
            })?;
        if response.status() != 200 {
            return Err(NativeTokenError::HttpStatus(response.status()));
        }
        response.into_json().map_err(|_| {
            NativeTokenError::MalformedResponse("response was not valid contract JSON".into())
        })
    }
}

pub fn exchange_native_code(
    store: &dyn NativeCredentialStore,
    transport: &dyn TokenTransport,
    base_url: &str,
    code: NativeAuthorizationCode,
    now_unix_seconds: u64,
    proof_jti: [u8; 16],
) -> Result<NativeCredentials, NativeTokenError> {
    validate_base_url(base_url)?;
    validate_code(&code)?;
    let installation = store
        .load_installation()
        .map_err(|_| NativeTokenError::Persistence("load failed".into()))?
        .ok_or(NativeTokenError::InstallationMissing)?;
    if installation.device_id != code.device_id {
        return Err(NativeTokenError::DeviceMismatch);
    }
    validate_challenge(&installation.device_challenge, None)?;

    let issued_at = issued_at(now_unix_seconds)?;
    let unsigned = NativeAuthorizationCodeTokenRequest {
        grant_type: "authorization_code".into(),
        code: code.authorization_code,
        redirect_uri: code.redirect_uri,
        client_id: CLIENT_ID.into(),
        code_verifier: code.code_verifier,
        device_id: code.device_id,
        device_proof: make_proof(&installation, issued_at, proof_jti),
    };
    let mut request = NativeTokenRequest::AuthorizationCode(unsigned);
    sign_request(&mut request, &installation)?;

    exchange_and_save(
        store,
        transport,
        base_url,
        installation,
        request,
        now_unix_seconds,
    )
}

pub fn refresh_native_credentials(
    store: &dyn NativeCredentialStore,
    transport: &dyn TokenTransport,
    base_url: &str,
    now_unix_seconds: u64,
    proof_jti: [u8; 16],
) -> Result<NativeCredentials, NativeTokenError> {
    validate_base_url(base_url)?;
    let credentials = store
        .load_credentials()
        .map_err(|_| NativeTokenError::Persistence("load failed".into()))?
        .ok_or(NativeTokenError::CredentialsMissing)?;
    if now_unix_seconds >= credentials.refresh_expires_at {
        return Err(NativeTokenError::RefreshExpired);
    }
    validate_challenge(&credentials.installation.device_challenge, None)?;
    let refresh_token = credentials
        .tokens
        .refresh_token
        .filter(|token| !token.is_empty())
        .ok_or(NativeTokenError::CredentialsMissing)?;
    let issued_at = issued_at(now_unix_seconds)?;
    let installation = credentials.installation;
    let mut request = NativeTokenRequest::RefreshToken(NativeRefreshTokenRequest {
        grant_type: "refresh_token".into(),
        refresh_token,
        client_id: CLIENT_ID.into(),
        device_id: installation.device_id,
        device_proof: make_proof(&installation, issued_at, proof_jti),
    });
    sign_request(&mut request, &installation)?;
    exchange_and_save(
        store,
        transport,
        base_url,
        installation,
        request,
        now_unix_seconds,
    )
}

fn make_proof(
    installation: &InstallationRecord,
    issued_at: String,
    proof_jti: [u8; 16],
) -> NativeDeviceProof {
    NativeDeviceProof {
        challenge: installation.device_challenge.clone(),
        issued_at,
        jti: URL_SAFE_NO_PAD.encode(proof_jti),
        signature: String::new(),
    }
}

fn sign_request(
    request: &mut NativeTokenRequest,
    installation: &InstallationRecord,
) -> Result<(), NativeTokenError> {
    let body = serde_json::to_value(&*request)
        .map_err(|_| NativeTokenError::Config("request could not be encoded".into()))?;
    let unsigned = body
        .as_object()
        .expect("token request is an object")
        .iter()
        .filter(|(key, _)| key.as_str() != "device_proof")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    let hash = Sha256::digest(serde_json::to_vec(&unsigned).expect("JSON values serialize"));
    let transcript = format!(
        "MUNIMENT-NATIVE-V1\nPOST\n{TOKEN_PATH}\n{}\n{}\n{}\n{}",
        hex_lower(&hash),
        proof(request).challenge,
        proof(request).issued_at,
        proof(request).jti
    );
    proof_mut(request).signature = URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&installation.private_key)
            .sign(transcript.as_bytes())
            .to_bytes(),
    );
    Ok(())
}

fn proof(request: &NativeTokenRequest) -> &NativeDeviceProof {
    match request {
        NativeTokenRequest::AuthorizationCode(r) => &r.device_proof,
        NativeTokenRequest::RefreshToken(r) => &r.device_proof,
    }
}

fn proof_mut(request: &mut NativeTokenRequest) -> &mut NativeDeviceProof {
    match request {
        NativeTokenRequest::AuthorizationCode(r) => &mut r.device_proof,
        NativeTokenRequest::RefreshToken(r) => &mut r.device_proof,
    }
}

fn exchange_and_save(
    store: &dyn NativeCredentialStore,
    transport: &dyn TokenTransport,
    base_url: &str,
    mut installation: InstallationRecord,
    request: NativeTokenRequest,
    now_unix_seconds: u64,
) -> Result<NativeCredentials, NativeTokenError> {
    let response = transport.exchange(
        &format!("{}{TOKEN_PATH}", base_url.trim_end_matches('/')),
        &request,
    )?;
    validate_response(&response, &installation)?;
    let expires_at = now_unix_seconds
        .checked_add(response.expires_in)
        .ok_or_else(|| NativeTokenError::MalformedResponse("token expiry overflowed".into()))?;
    let refresh_expires_at = now_unix_seconds
        .checked_add(response.refresh_expires_in)
        .ok_or_else(|| NativeTokenError::MalformedResponse("refresh expiry overflowed".into()))?;
    installation.device_challenge = response.device_challenge;
    let credentials = NativeCredentials {
        installation,
        tokens: TokenSet {
            access_token: response.access_token,
            refresh_token: Some(response.refresh_token),
            expires_at: Some(expires_at),
            subject: Some(response.session.user_id.to_string()),
        },
        refresh_expires_at,
    };
    store
        .save_credentials(&credentials)
        .map_err(|_| NativeTokenError::Persistence("save failed".into()))?;
    Ok(credentials)
}

fn issued_at(now_unix_seconds: u64) -> Result<String, NativeTokenError> {
    DateTime::<Utc>::from_timestamp(
        i64::try_from(now_unix_seconds)
            .map_err(|_| NativeTokenError::Config("clock is outside the supported range".into()))?,
        0,
    )
    .ok_or_else(|| NativeTokenError::Config("clock is outside the supported range".into()))
    .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn validate_response(
    r: &NativeTokenResponse,
    installation: &InstallationRecord,
) -> Result<(), NativeTokenError> {
    if r.access_token.is_empty()
        || r.refresh_token.is_empty()
        || r.token_type != "Bearer"
        || r.expires_in != 900
        || r.refresh_expires_in == 0
        || r.refresh_expires_in > 86400
        || r.session.device_id != installation.device_id
        || r.session.client_role != CLIENT_ROLE
        || r.entitlement_snapshot.signature.is_empty()
        || !r.entitlement_snapshot.payload.is_object()
    {
        return Err(NativeTokenError::MalformedResponse(
            "token metadata did not match the contract".into(),
        ));
    }
    let _ = (
        &r.session.org_id,
        &r.session.role,
        &r.entitlement_snapshot.algorithm,
    );
    validate_challenge(&r.device_challenge, Some(&installation.device_challenge))
}

fn validate_challenge(value: &str, previous: Option<&str>) -> Result<(), NativeTokenError> {
    let decoded = URL_SAFE_NO_PAD.decode(value);
    if decoded.as_ref().map_or(true, |v| v.len() != 32)
        || decoded
            .as_ref()
            .is_ok_and(|v| URL_SAFE_NO_PAD.encode(v) != value)
        || previous == Some(value)
    {
        return Err(NativeTokenError::MalformedResponse(
            "device challenge was not new canonical contract data".into(),
        ));
    }
    Ok(())
}

fn validate_code(code: &NativeAuthorizationCode) -> Result<(), NativeTokenError> {
    let redirect = url::Url::parse(&code.redirect_uri)
        .map_err(|_| NativeTokenError::Config("authorization context is invalid".into()))?;
    let loopback = redirect.scheme() == "http"
        && matches!(redirect.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    let valid_secret = |v: &str, min: usize, max: usize| {
        v.len() >= min
            && v.len() <= max
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
    };
    if !loopback
        || !valid_secret(&code.authorization_code, 43, 43)
        || !valid_secret(&code.code_verifier, 43, 128)
    {
        return Err(NativeTokenError::Config(
            "authorization context is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_base_url(value: &str) -> Result<(), NativeTokenError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| NativeTokenError::Config("base URL is invalid".into()))?;
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
        Err(NativeTokenError::Config(
            "base URL must use HTTPS (HTTP is allowed only on loopback)".into(),
        ))
    }
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
    use super::*;

    #[test]
    fn refresh_contract_debug_redacts_request_and_response_secrets() {
        let installation = InstallationRecord {
            private_key: [1; 32],
            device_id: Uuid::nil(),
            registration_token: String::new(),
            device_challenge: "challenge-secret".into(),
            registration_expires_at: 0,
        };
        let request = NativeTokenRequest::RefreshToken(NativeRefreshTokenRequest {
            grant_type: "refresh_token".into(),
            refresh_token: "refresh-request-secret".into(),
            client_id: CLIENT_ID.into(),
            device_id: installation.device_id,
            device_proof: make_proof(&installation, "1970-01-01T00:00:00Z".into(), [1; 16]),
        });
        let response: NativeTokenResponse = serde_json::from_str(
            r#"{"access_token":"access-response-secret","token_type":"Bearer","expires_in":900,"refresh_token":"refresh-response-secret","refresh_expires_in":86400,"session":{"org_id":"20000000-0000-4000-8000-000000000002","user_id":"30000000-0000-4000-8000-000000000003","role":"user","device_id":"00000000-0000-0000-0000-000000000000","client_role":"desktop"},"entitlement_snapshot":{"payload":{"version":1},"signature":"snapshot-secret","algorithm":"hmac-sha256"},"device_challenge":"rotated-challenge-secret"}"#,
        )
        .unwrap();
        let rendered = format!("{request:?} {response:?}");
        for secret in [
            "refresh-request-secret",
            "challenge-secret",
            "access-response-secret",
            "refresh-response-secret",
            "snapshot-secret",
            "rotated-challenge-secret",
        ] {
            assert!(!rendered.contains(secret));
        }
    }
}
