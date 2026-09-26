//! Desktop half of Municloud QR pairing. The QR payload is the server `qr` object.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::atomic_file;

pub const CONTRACT_VERSION: &str = "muniment.remote-control-pairing/1";
pub const CHALLENGE_PATH: &str = "/v1/remote-control/pairing/challenges";
pub const PAIRING_PATH: &str = "/v1/remote-control/pairing";
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const REPLACEMENT_INTERVAL: Duration = Duration::from_secs(10);
pub const PAIR_FILE_NAME: &str = "remote-control-pair.json";

const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
const KEY_LENGTH: usize = 43;

#[derive(Clone)]
pub struct PairingHttpRequest {
    authorization: String,
}

impl fmt::Debug for PairingHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingHttpRequest")
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingQr {
    pub contract_version: String,
    pub desktop_device_id: Uuid,
    pub desktop_public_key: String,
    pub challenge: String,
}

impl fmt::Debug for PairingQr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingQr")
            .field("contract_version", &self.contract_version)
            .field("desktop_device_id", &self.desktop_device_id)
            .field("desktop_public_key", &"<redacted>")
            .field("challenge", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingChallengeResponse {
    pub contract_version: String,
    pub expires_at: DateTime<Utc>,
    pub qr: PairingQr,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayPair {
    pub pair_id: Uuid,
    pub desktop_device_id: Uuid,
    pub mobile_device_id: Uuid,
    pub desktop_public_key: String,
    pub mobile_public_key: String,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for RelayPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayPair")
            .field("pair_id", &self.pair_id)
            .field("desktop_device_id", &self.desktop_device_id)
            .field("mobile_device_id", &self.mobile_device_id)
            .field("desktop_public_key", &"<redacted>")
            .field("mobile_public_key", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingStatusResponse {
    pub contract_version: String,
    #[serde(deserialize_with = "required_pair")]
    pub pair: Option<RelayPair>,
}

fn required_pair<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RelayPair>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRevokeResponse {
    pub contract_version: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingChallengeView {
    pub expires_at: DateTime<Utc>,
    pub qr_svg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedPhone {
    pub pair_id: Uuid,
    pub mobile_device_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingStatusView {
    pub pair: Option<AuthorizedPhone>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRevokeView {
    pub revoked: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub enum PairingError {
    Config(String),
    CredentialsMissing,
    Transport(String),
    HttpStatus(u16),
    MalformedResponse(String),
}

impl fmt::Debug for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("Config(<redacted>)"),
            Self::CredentialsMissing => f.write_str("CredentialsMissing"),
            Self::Transport(_) => f.write_str("Transport(<redacted>)"),
            Self::HttpStatus(status) => f.debug_tuple("HttpStatus").field(status).finish(),
            Self::MalformedResponse(_) => f.write_str("MalformedResponse(<redacted>)"),
        }
    }
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("pairing configuration error"),
            Self::CredentialsMissing => f.write_str("pairing requires a credential"),
            Self::Transport(_) => f.write_str("pairing unavailable"),
            Self::HttpStatus(409) => f.write_str("A phone is already paired."),
            Self::HttpStatus(429) => f.write_str("Wait ten seconds before replacing the code."),
            Self::HttpStatus(_) => f.write_str("The pairing request failed."),
            Self::MalformedResponse(_) => f.write_str("malformed pairing response"),
        }
    }
}

impl std::error::Error for PairingError {}

pub trait PairingTransport: Send + Sync {
    fn challenge(
        &self,
        url: &str,
        request: &PairingHttpRequest,
        body: &serde_json::Value,
    ) -> Result<PairingChallengeResponse, PairingError>;

    fn status(
        &self,
        url: &str,
        request: &PairingHttpRequest,
    ) -> Result<PairingStatusResponse, PairingError>;

    fn revoke(
        &self,
        url: &str,
        request: &PairingHttpRequest,
        body: &serde_json::Value,
    ) -> Result<PairingRevokeResponse, PairingError>;
}

pub struct UreqPairingTransport {
    timeout: Duration,
}

impl UreqPairingTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl PairingTransport for UreqPairingTransport {
    fn challenge(
        &self,
        url: &str,
        request: &PairingHttpRequest,
        body: &serde_json::Value,
    ) -> Result<PairingChallengeResponse, PairingError> {
        let response = super::native_http::request("POST", CHALLENGE_PATH, || {
            ureq::post(url)
                .timeout(self.timeout)
                .set("Content-Type", "application/json")
                .set("Authorization", &request.authorization)
                .send_json(body)
                .map_err(Box::new)
        })
        .map_err(map_http)?;
        if response.status() != 201 {
            return Err(PairingError::HttpStatus(response.status()));
        }
        parse_json(response)
    }

    fn status(
        &self,
        url: &str,
        request: &PairingHttpRequest,
    ) -> Result<PairingStatusResponse, PairingError> {
        let response = super::native_http::request("GET", PAIRING_PATH, || {
            ureq::get(url)
                .timeout(self.timeout)
                .set("Authorization", &request.authorization)
                .call()
                .map_err(Box::new)
        })
        .map_err(map_http)?;
        if response.status() != 200 {
            return Err(PairingError::HttpStatus(response.status()));
        }
        parse_json(response)
    }

    fn revoke(
        &self,
        url: &str,
        request: &PairingHttpRequest,
        body: &serde_json::Value,
    ) -> Result<PairingRevokeResponse, PairingError> {
        let response = super::native_http::request("DELETE", PAIRING_PATH, || {
            ureq::request("DELETE", url)
                .timeout(self.timeout)
                .set("Content-Type", "application/json")
                .set("Authorization", &request.authorization)
                .send_json(body)
                .map_err(Box::new)
        })
        .map_err(map_http)?;
        if response.status() != 200 {
            return Err(PairingError::HttpStatus(response.status()));
        }
        parse_json(response)
    }
}

fn map_http(error: Box<super::native_http::Error>) -> PairingError {
    match *error {
        super::native_http::Error::Status(status, _) => PairingError::HttpStatus(status),
        super::native_http::Error::Transport(_) => PairingError::Transport("request failed".into()),
    }
}

fn parse_json<T: serde::de::DeserializeOwned>(response: ureq::Response) -> Result<T, PairingError> {
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| PairingError::Transport("response read failed".into()))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(PairingError::MalformedResponse(
            "response exceeded the size limit".into(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&body);
    let result = T::deserialize(&mut deserializer)
        .map_err(|_| PairingError::MalformedResponse("response was not contract JSON".into()))?;
    deserializer
        .end()
        .map_err(|_| PairingError::MalformedResponse("response contained trailing data".into()))?;
    Ok(result)
}

pub fn create_pairing_challenge(
    transport: &dyn PairingTransport,
    base_url: &str,
    access_token: &str,
) -> Result<PairingChallengeView, PairingError> {
    let request = authorized_request(base_url, access_token)?;
    let body = serde_json::json!({ "contract_version": CONTRACT_VERSION });
    let response = transport.challenge(
        &format!("{}{CHALLENGE_PATH}", base_url.trim_end_matches('/')),
        &request,
        &body,
    )?;
    challenge_view(response)
}

pub fn read_pairing(
    transport: &dyn PairingTransport,
    base_url: &str,
    access_token: &str,
    store_path: &Path,
) -> Result<PairingStatusView, PairingError> {
    let request = authorized_request(base_url, access_token)?;
    let response = transport.status(
        &format!("{}{PAIRING_PATH}", base_url.trim_end_matches('/')),
        &request,
    )?;
    if response.contract_version != CONTRACT_VERSION {
        return Err(PairingError::MalformedResponse(
            "unsupported pairing contract".into(),
        ));
    }
    match response.pair {
        Some(pair) => {
            validate_pair(&pair)?;
            save_stored_pair(store_path, &pair)?;
            Ok(PairingStatusView {
                pair: Some(authorized_phone(&pair)),
            })
        }
        None => {
            clear_stored_pair(store_path)?;
            Ok(PairingStatusView { pair: None })
        }
    }
}

pub fn revoke_pairing(
    transport: &dyn PairingTransport,
    base_url: &str,
    access_token: &str,
    pair_id: Uuid,
    store_path: &Path,
) -> Result<PairingRevokeView, PairingError> {
    let request = authorized_request(base_url, access_token)?;
    let body = serde_json::json!({
        "contract_version": CONTRACT_VERSION,
        "pair_id": pair_id,
    });
    let response = transport.revoke(
        &format!("{}{PAIRING_PATH}", base_url.trim_end_matches('/')),
        &request,
        &body,
    )?;
    if response.contract_version != CONTRACT_VERSION || !response.revoked {
        return Err(PairingError::MalformedResponse(
            "revocation was not confirmed".into(),
        ));
    }
    if load_stored_pair(store_path)?.is_some_and(|stored| stored.pair_id == pair_id) {
        clear_stored_pair(store_path)?;
    }
    Ok(PairingRevokeView { revoked: true })
}

pub fn qr_json(qr: &PairingQr) -> Result<String, PairingError> {
    validate_qr(qr)?;
    let payload = serde_json::to_string(qr)
        .map_err(|_| PairingError::MalformedResponse("qr object could not be encoded".into()))?;
    if payload_has_forbidden_material(&payload) {
        return Err(PairingError::MalformedResponse(
            "qr object contained forbidden material".into(),
        ));
    }
    Ok(payload)
}

pub fn qr_svg(payload: &str) -> Result<String, PairingError> {
    let code = QrCode::new(payload.as_bytes())
        .map_err(|_| PairingError::MalformedResponse("qr object could not be encoded".into()))?;
    let width = code.width();
    let mut path = String::new();
    for y in 0..width {
        for x in 0..width {
            if code[(x, y)] == qrcode::Color::Dark {
                path.push_str(&format!("M{},{}h1v1h-1z", x + 4, y + 4));
            }
        }
    }
    let width = width + 8;
    Ok(format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {width}" shape-rendering="crispEdges" role="img" aria-label="Pairing code"><rect width="{width}" height="{width}" fill="white"/><path fill="black" d="{path}"/></svg>"#
    ))
}

pub fn challenge_expired(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now >= expires_at
}

pub fn load_stored_pair(path: &Path) -> Result<Option<RelayPair>, PairingError> {
    match fs::read(path) {
        Ok(bytes) => {
            let pair: RelayPair = serde_json::from_slice(&bytes)
                .map_err(|_| PairingError::MalformedResponse("stored pair is unreadable".into()))?;
            validate_pair(&pair)?;
            Ok(Some(pair))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PairingError::Transport("stored pair is unavailable".into())),
    }
}

fn challenge_view(
    response: PairingChallengeResponse,
) -> Result<PairingChallengeView, PairingError> {
    if response.contract_version != CONTRACT_VERSION {
        return Err(PairingError::MalformedResponse(
            "unsupported pairing contract".into(),
        ));
    }
    let payload = qr_json(&response.qr)?;
    Ok(PairingChallengeView {
        expires_at: response.expires_at,
        qr_svg: qr_svg(&payload)?,
    })
}

fn authorized_phone(pair: &RelayPair) -> AuthorizedPhone {
    AuthorizedPhone {
        pair_id: pair.pair_id,
        mobile_device_id: pair.mobile_device_id,
        created_at: pair.created_at,
    }
}

fn authorized_request(
    base_url: &str,
    access_token: &str,
) -> Result<PairingHttpRequest, PairingError> {
    validate_base_url(base_url)?;
    if access_token.is_empty() {
        return Err(PairingError::CredentialsMissing);
    }
    Ok(PairingHttpRequest {
        authorization: format!("Bearer {access_token}"),
    })
}

fn validate_qr(qr: &PairingQr) -> Result<(), PairingError> {
    if qr.contract_version != CONTRACT_VERSION {
        return Err(PairingError::MalformedResponse(
            "unsupported pairing contract".into(),
        ));
    }
    validate_key(&qr.desktop_public_key)?;
    validate_key(&qr.challenge)?;
    Ok(())
}

fn validate_pair(pair: &RelayPair) -> Result<(), PairingError> {
    validate_key(&pair.desktop_public_key)?;
    validate_key(&pair.mobile_public_key)?;
    Ok(())
}

fn validate_key(value: &str) -> Result<(), PairingError> {
    let valid = value.len() == KEY_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(PairingError::MalformedResponse(
            "pairing key was not contract material".into(),
        ))
    }
}

fn payload_has_forbidden_material(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("access_token")
        || lower.contains("refresh_token")
        || lower.contains("private_key")
        || lower.contains("api_key")
}

fn save_stored_pair(path: &Path, pair: &RelayPair) -> Result<(), PairingError> {
    validate_pair(pair)?;
    let parent = path
        .parent()
        .ok_or_else(|| PairingError::Config("pair store path is invalid".into()))?;
    fs::create_dir_all(parent)
        .map_err(|_| PairingError::Transport("pair store is unavailable".into()))?;
    let bytes = serde_json::to_vec(pair)
        .map_err(|_| PairingError::MalformedResponse("pair could not be stored".into()))?;
    let temporary = path.with_extension("json.tmp");
    write_secret_file(&temporary, &bytes).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        PairingError::Transport("pair store is unavailable".into())
    })?;
    atomic_file::replace(&temporary, path).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        PairingError::Transport("pair store is unavailable".into())
    })
}

fn clear_stored_pair(path: &Path) -> Result<(), PairingError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PairingError::Transport("pair store is unavailable".into())),
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn validate_base_url(value: &str) -> Result<(), PairingError> {
    let parsed =
        url::Url::parse(value).map_err(|_| PairingError::Config("base URL is invalid".into()))?;
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
        Err(PairingError::Config(
            "base URL must use HTTPS (HTTP is allowed only on loopback)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_at_the_deadline_removes_the_code() {
        let deadline = DateTime::parse_from_rfc3339("2026-01-01T00:02:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(!challenge_expired(
            deadline,
            deadline - chrono::TimeDelta::seconds(1)
        ));
        assert!(challenge_expired(deadline, deadline));
        assert!(challenge_expired(
            deadline,
            deadline + chrono::TimeDelta::seconds(1)
        ));
    }
}
