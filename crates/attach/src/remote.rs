//! Values of the remote attach route: scopes, the runtime identity, pairing
//! links and device credentials.
//!
//! A remote client reaches a runtime over TLS. It trusts exactly the
//! certificate whose SHA-256 the pairing link names, redeems the link's
//! one-time secret once, and then authenticates with the device credential the
//! runtime issued for it.

use std::collections::BTreeSet;
use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::Id;

/// Reads threads, runs, artifacts, records and settings.
pub const SCOPE_THREAD_READ: &str = "thread.read";
/// Starts and steers runs and changes threads, companies and records.
pub const SCOPE_RUN_WRITE: &str = "run.write";
/// Pairs and revokes devices, changes model accounts and requests updates.
pub const SCOPE_RUNTIME_ADMIN: &str = "runtime.admin";
/// Every scope a remote device can hold.
pub const REMOTE_SCOPES: [&str; 3] = [SCOPE_THREAD_READ, SCOPE_RUN_WRITE, SCOPE_RUNTIME_ADMIN];

/// The scopes a pairing link grants when its creator names none. Pairing
/// management stays out unless the creator delegates it.
pub fn default_pairing_scopes() -> BTreeSet<String> {
    BTreeSet::from([SCOPE_THREAD_READ.to_owned(), SCOPE_RUN_WRITE.to_owned()])
}

/// The URI scheme of a pairing link.
pub const PAIRING_LINK_SCHEME: &str = "muniment";
/// Hex characters in a pairing secret: 128 random bits.
pub const PAIRING_SECRET_HEX_LENGTH: usize = 32;
/// Hex characters in a device secret: 256 random bits.
pub const DEVICE_SECRET_HEX_LENGTH: usize = 64;
/// The most endpoints one pairing link carries.
pub const MAX_PAIRING_ENDPOINTS: usize = 8;
/// The longest display name a runtime or device carries.
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;
const MAX_ENDPOINT_LENGTH: usize = 261;
const MAX_LINK_LENGTH: usize = 4096;

/// Whether `value` is lowercase hex of exactly `length` characters.
pub fn is_lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a runtime or device display name is short, printable and not blank.
pub fn is_valid_display_name(name: &str) -> bool {
    !name.trim().is_empty()
        && !name.chars().any(char::is_control)
        && name.chars().take(MAX_DISPLAY_NAME_CHARS + 1).count() <= MAX_DISPLAY_NAME_CHARS
}

/// Whether `endpoint` is `host:port` with an IP literal (IPv6 in brackets) or
/// a DNS name and a nonzero port.
pub fn is_valid_endpoint(endpoint: &str) -> bool {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LENGTH {
        return false;
    }
    if let Ok(address) = endpoint.parse::<std::net::SocketAddr>() {
        return address.port() != 0;
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    let port_valid = !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0);
    let host_valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    port_valid && host_valid
}

/// The SHA-256 of a runtime's certificate in DER form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    pub fn of_certificate(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses 64 hex characters, in either case, with or without colons.
    pub fn parse(text: &str) -> Option<Self> {
        let hex: Vec<u8> = text.bytes().filter(|byte| *byte != b':').collect();
        if hex.len() != 64 || !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in hex.chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).ok()?;
            bytes[index] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// Lowercase hex without separators.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CertificateFingerprint({})", self.to_hex())
    }
}

impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for CertificateFingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CertificateFingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| de::Error::custom("invalid certificate fingerprint"))
    }
}

/// How a runtime is installed, which names the updater that applies a
/// requested version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    Desktop,
    Server,
    Container,
}

impl InstallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Server => "server",
            Self::Container => "container",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "desktop" => Some(Self::Desktop),
            "server" => Some(Self::Server),
            "container" => Some(Self::Container),
            _ => None,
        }
    }
}

/// What a runtime says about itself in `welcome` and `runtime.info`. An
/// install kind a later version adds reads as `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeInfo {
    pub runtime_id: String,
    pub runtime_name: String,
    pub runtime_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_kind: Option<InstallKind>,
}

impl RuntimeInfo {
    /// Builds the value from its wire fields, or `None` when a field is
    /// missing or out of bounds.
    pub fn from_fields(
        runtime_id: Option<String>,
        runtime_name: Option<String>,
        runtime_version: Option<String>,
        install_kind: Option<&serde_json::Value>,
    ) -> Option<Self> {
        let runtime_id = runtime_id.filter(|id| Id::new(id.as_str()).is_ok())?;
        let runtime_name = runtime_name.filter(|name| is_valid_display_name(name))?;
        let runtime_version = runtime_version
            .filter(|version| !version.is_empty() && version.len() <= MAX_DISPLAY_NAME_CHARS)?;
        Some(Self {
            runtime_id,
            runtime_name,
            runtime_version,
            install_kind: install_kind
                .and_then(serde_json::Value::as_str)
                .and_then(InstallKind::from_wire),
        })
    }
}

impl<'de> Deserialize<'de> for RuntimeInfo {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            runtime_id: Option<String>,
            runtime_name: Option<String>,
            runtime_version: Option<String>,
            #[serde(default)]
            install_kind: Option<serde_json::Value>,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::from_fields(
            fields.runtime_id,
            fields.runtime_name,
            fields.runtime_version,
            fields.install_kind.as_ref(),
        )
        .ok_or_else(|| de::Error::custom("invalid runtime info"))
    }
}

/// The credential a runtime issues to a paired device: an id and a 256-bit
/// secret in hex. The runtime keeps only the secret's SHA-256.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredential {
    pub device_id: Id,
    pub secret: String,
}

impl fmt::Debug for DeviceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceCredential")
            .field("device_id", &self.device_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// A one-time pairing link:
/// `muniment://pair?v=1&id=<runtime id>&name=<name>&fp=<sha256>&host=<host:port>...#<secret>`.
///
/// The secret travels in the fragment, so a page or proxy that sees the rest
/// of the link never receives it.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingLink {
    pub runtime_id: Id,
    pub runtime_name: String,
    pub endpoints: Vec<String>,
    pub fingerprint: CertificateFingerprint,
    pub secret: String,
}

/// Why a pairing link did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingLinkError {
    NotALink,
    UnsupportedVersion,
    MissingField,
    InvalidField,
}

impl fmt::Display for PairingLinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotALink => "the text is not a Muniment pairing link",
            Self::UnsupportedVersion => "the pairing link needs a newer client",
            Self::MissingField => "the pairing link is missing a field",
            Self::InvalidField => "the pairing link has an invalid field",
        })
    }
}

impl std::error::Error for PairingLinkError {}

impl PairingLink {
    pub fn to_uri(&self) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("v", "1")
            .append_pair("id", self.runtime_id.as_str())
            .append_pair("name", &self.runtime_name)
            .append_pair("fp", &self.fingerprint.to_hex());
        for endpoint in &self.endpoints {
            query.append_pair("host", endpoint);
        }
        format!(
            "{PAIRING_LINK_SCHEME}://pair?{}#{}",
            query.finish(),
            self.secret
        )
    }

    /// Parses and checks a link. Query fields a later version adds are ignored.
    pub fn parse(text: &str) -> Result<Self, PairingLinkError> {
        if text.len() > MAX_LINK_LENGTH {
            return Err(PairingLinkError::NotALink);
        }
        let url = url::Url::parse(text.trim()).map_err(|_| PairingLinkError::NotALink)?;
        if url.scheme() != PAIRING_LINK_SCHEME
            || url.host_str() != Some("pair")
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(PairingLinkError::NotALink);
        }
        let (mut version, mut id, mut name, mut fingerprint) = (None, None, None, None);
        let mut endpoints = Vec::new();
        for (key, value) in url.query_pairs() {
            let slot = match key.as_ref() {
                "v" => &mut version,
                "id" => &mut id,
                "name" => &mut name,
                "fp" => &mut fingerprint,
                "host" => {
                    if endpoints.len() == MAX_PAIRING_ENDPOINTS || !is_valid_endpoint(&value) {
                        return Err(PairingLinkError::InvalidField);
                    }
                    endpoints.push(value.into_owned());
                    continue;
                }
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(PairingLinkError::InvalidField);
            }
        }
        match version.as_deref() {
            Some("1") => {}
            Some(_) => return Err(PairingLinkError::UnsupportedVersion),
            None => return Err(PairingLinkError::MissingField),
        }
        let (Some(id), Some(name), Some(fingerprint), Some(secret)) =
            (id, name, fingerprint, url.fragment())
        else {
            return Err(PairingLinkError::MissingField);
        };
        if endpoints.is_empty() {
            return Err(PairingLinkError::MissingField);
        }
        if !is_lowercase_hex(secret, PAIRING_SECRET_HEX_LENGTH) || !is_valid_display_name(&name) {
            return Err(PairingLinkError::InvalidField);
        }
        Ok(Self {
            runtime_id: Id::new(id).map_err(|_| PairingLinkError::InvalidField)?,
            runtime_name: name,
            endpoints,
            fingerprint: CertificateFingerprint::parse(&fingerprint)
                .ok_or(PairingLinkError::InvalidField)?,
            secret: secret.to_owned(),
        })
    }
}

impl fmt::Debug for PairingLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingLink")
            .field("runtime_id", &self.runtime_id)
            .field("runtime_name", &self.runtime_name)
            .field("endpoints", &self.endpoints)
            .field("fingerprint", &self.fingerprint)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> PairingLink {
        PairingLink {
            runtime_id: Id::new("018f0000-0000-7000-8000-000000000042").unwrap(),
            runtime_name: "Build box & co".into(),
            endpoints: vec![
                "192.0.2.20:7443".into(),
                "[fd7a:115c::1]:7443".into(),
                "runtime.example.net:7443".into(),
            ],
            fingerprint: CertificateFingerprint::of_certificate(b"certificate"),
            secret: "ab".repeat(16),
        }
    }

    #[test]
    fn a_link_round_trips_with_the_secret_in_the_fragment() {
        let uri = link().to_uri();
        let (before, fragment) = uri.split_once('#').unwrap();
        assert_eq!(fragment, "ab".repeat(16));
        assert!(!before.contains(&"ab".repeat(16)));
        assert_eq!(PairingLink::parse(&uri).unwrap(), link());
        assert!(!format!("{:?}", link()).contains(&"ab".repeat(16)));
    }

    #[test]
    fn a_malformed_link_is_refused() {
        let uri = link().to_uri();
        let cases = [
            (
                uri.replace("muniment://", "https://"),
                PairingLinkError::NotALink,
            ),
            (
                uri.replace("v=1", "v=2"),
                PairingLinkError::UnsupportedVersion,
            ),
            (
                uri.split('#').next().unwrap().to_owned(),
                PairingLinkError::MissingField,
            ),
            (
                format!("{}#{}", uri.split('#').next().unwrap(), "AB".repeat(16)),
                PairingLinkError::InvalidField,
            ),
            (
                format!("{}#{}", uri.split('#').next().unwrap(), "ab".repeat(15)),
                PairingLinkError::InvalidField,
            ),
            (uri.replace("fp=", "fp=00"), PairingLinkError::InvalidField),
            (
                uri.replace("host=192.0.2.20%3A7443", "host=192.0.2.20%3A0"),
                PairingLinkError::InvalidField,
            ),
            (
                uri.replace("&v=1", "&v=1&v=1").replace("?v=1", "?v=1&v=1"),
                PairingLinkError::InvalidField,
            ),
            ("not a link".to_owned(), PairingLinkError::NotALink),
        ];
        for (text, expected) in cases {
            assert_eq!(PairingLink::parse(&text), Err(expected), "{text}");
        }
        let no_hosts = format!(
            "muniment://pair?v=1&id=018f0000-0000-7000-8000-000000000042&name=x&fp={}#{}",
            "00".repeat(32),
            "ab".repeat(16)
        );
        assert_eq!(
            PairingLink::parse(&no_hosts),
            Err(PairingLinkError::MissingField)
        );
    }

    #[test]
    fn endpoints_and_names_are_bounded() {
        for valid in ["127.0.0.1:1", "[::1]:7443", "host-1.lan:65535"] {
            assert!(is_valid_endpoint(valid), "{valid}");
        }
        for invalid in [
            "127.0.0.1",
            "host:0",
            ":80",
            "-bad.lan:1",
            "a b:1",
            "host:99999",
        ] {
            assert!(!is_valid_endpoint(invalid), "{invalid}");
        }
        assert!(is_valid_display_name("Laptop"));
        assert!(!is_valid_display_name(" "));
        assert!(!is_valid_display_name("a\nb"));
        assert!(!is_valid_display_name(&"x".repeat(81)));
    }

    #[test]
    fn fingerprints_parse_with_or_without_colons() {
        let fingerprint = CertificateFingerprint::of_certificate(b"der");
        let colons = fingerprint
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(CertificateFingerprint::parse(&colons), Some(fingerprint));
        assert_eq!(
            CertificateFingerprint::parse(&fingerprint.to_hex()),
            Some(fingerprint)
        );
        assert_eq!(CertificateFingerprint::parse("abcd"), None);
    }

    #[test]
    fn runtime_info_ignores_an_unknown_install_kind() {
        let info: RuntimeInfo = serde_json::from_value(serde_json::json!({
            "runtime_id": "018f0000-0000-7000-8000-000000000042",
            "runtime_name": "Box",
            "runtime_version": "1.2.3",
            "install_kind": "appliance",
        }))
        .unwrap();
        assert_eq!(info.install_kind, None);
        assert!(serde_json::from_value::<RuntimeInfo>(serde_json::json!({
            "runtime_id": "not-a-uuid",
            "runtime_name": "Box",
            "runtime_version": "1.2.3",
        }))
        .is_err());
    }
}
