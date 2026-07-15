//! Strict, secret-free listing of a user's native installations.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

const DEVICES_PATH: &str = "/v1/auth/native/devices";
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Clone)]
pub struct NativeDeviceListRequest {
    authorization: String,
}

impl NativeDeviceListRequest {
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
}

impl fmt::Debug for NativeDeviceListRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDeviceListRequest")
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeDevicePlatform {
    Ios,
    Android,
    Desktop,
}

/// Server-derived display metadata for one native installation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDevice {
    pub device_id: Uuid,
    pub client_id: String,
    pub client_role: String,
    pub platform: NativeDevicePlatform,
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_active_at: DateTime<Utc>,
    pub current: bool,
}

fn deserialize_required_nullable<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDeviceList {
    pub devices: Vec<NativeDevice>,
}

pub trait NativeDeviceListTransport: Send + Sync {
    fn list(
        &self,
        url: &str,
        request: &NativeDeviceListRequest,
    ) -> Result<NativeDeviceList, NativeDeviceListError>;
}

#[derive(Clone, PartialEq, Eq)]
pub enum NativeDeviceListError {
    Config(String),
    CredentialsMissing,
    Transport(String),
    HttpStatus(u16),
    MalformedResponse(String),
}

impl fmt::Debug for NativeDeviceListError {
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

impl fmt::Display for NativeDeviceListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(_) => f.write_str("native device list configuration error"),
            Self::CredentialsMissing => f.write_str("native device list requires a credential"),
            Self::Transport(_) => f.write_str("native device list unavailable"),
            Self::HttpStatus(status) => write!(f, "native device list rejected with HTTP {status}"),
            Self::MalformedResponse(_) => f.write_str("malformed native device list response"),
        }
    }
}

impl std::error::Error for NativeDeviceListError {}

pub struct UreqNativeDeviceListTransport {
    timeout: Duration,
}

impl UreqNativeDeviceListTransport {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl NativeDeviceListTransport for UreqNativeDeviceListTransport {
    fn list(
        &self,
        url: &str,
        request: &NativeDeviceListRequest,
    ) -> Result<NativeDeviceList, NativeDeviceListError> {
        let response = ureq::get(url)
            .timeout(self.timeout)
            .set("Authorization", request.authorization())
            .call()
            .map_err(|error| match error {
                ureq::Error::Status(status, _) => NativeDeviceListError::HttpStatus(status),
                ureq::Error::Transport(_) => {
                    NativeDeviceListError::Transport("request failed".into())
                }
            })?;
        if response.status() != 200 {
            return Err(NativeDeviceListError::HttpStatus(response.status()));
        }

        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| NativeDeviceListError::Transport("response read failed".into()))?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(NativeDeviceListError::MalformedResponse(
                "response exceeded the size limit".into(),
            ));
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&body);
        let result = NativeDeviceList::deserialize(&mut deserializer).map_err(|_| {
            NativeDeviceListError::MalformedResponse("response was not contract JSON".into())
        })?;
        deserializer.end().map_err(|_| {
            NativeDeviceListError::MalformedResponse("response contained trailing data".into())
        })?;
        if result.devices.len() > 100 {
            return Err(NativeDeviceListError::MalformedResponse(
                "response exceeded the device limit".into(),
            ));
        }
        Ok(result)
    }
}

pub fn list_native_devices(
    transport: &dyn NativeDeviceListTransport,
    base_url: &str,
    access_token: &str,
) -> Result<NativeDeviceList, NativeDeviceListError> {
    validate_base_url(base_url)?;
    if access_token.is_empty() {
        return Err(NativeDeviceListError::CredentialsMissing);
    }
    let request = NativeDeviceListRequest {
        authorization: format!("Bearer {access_token}"),
    };
    transport.list(
        &format!("{}{DEVICES_PATH}", base_url.trim_end_matches('/')),
        &request,
    )
}

fn validate_base_url(value: &str) -> Result<(), NativeDeviceListError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| NativeDeviceListError::Config("base URL is invalid".into()))?;
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
        Err(NativeDeviceListError::Config(
            "base URL must use HTTPS (HTTP is allowed only on loopback)".into(),
        ))
    }
}
