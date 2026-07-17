use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{ErrorAction, Protocol, ProtocolError, VersionRange};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    pub kind: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Hello {
    pub protocol: Protocol,
    pub client: Client,
    pub supported: VersionRange,
    pub client_nonce: String,
}

impl<'de> Deserialize<'de> for Hello {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct HelloFields {
            protocol: Protocol,
            client: Client,
            supported: VersionRange,
            client_nonce: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }

        const ENVELOPE_FIELDS: &[&str] = &[
            "request_id",
            "operation",
            "capability",
            "idempotency_key",
            "ok",
            "error",
            "subscription_id",
            "event",
            "run_id",
            "run_seq",
            "body",
        ];

        let fields = HelloFields::deserialize(deserializer)?;
        if fields
            .extra
            .keys()
            .any(|field| ENVELOPE_FIELDS.contains(&field.as_str()))
        {
            return Err(de::Error::custom(
                "hello contains non-handshake envelope fields",
            ));
        }

        Ok(Self {
            protocol: fields.protocol,
            client: fields.client,
            supported: fields.supported,
            client_nonce: fields.client_nonce,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authorization {
    PairingRequired,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Welcome {
    pub selected: u32,
    pub desktop_version: String,
    pub server_nonce: String,
    pub authorization: Authorization,
    pub approval_challenge: String,
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Welcome")
            .field("selected", &self.selected)
            .field("desktop_version", &self.desktop_version)
            .field("server_nonce", &self.server_nonce)
            .field("authorization", &self.authorization)
            .field("approval_challenge", &"[REDACTED]")
            .finish()
    }
}

/// The connection-bound grant emitted after desktop approval.
///
/// `expires_at` is the number of whole seconds remaining when this message is
/// emitted, rather than an absolute or monotonic timestamp. Monotonic clock
/// values are deliberately local to the authorization policy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorized {
    pub capability: String,
    pub expires_at: u64,
    pub idle_timeout_seconds: u64,
    pub workspace_scopes: BTreeMap<String, BTreeSet<String>>,
}

impl fmt::Debug for Authorized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorized")
            .field("capability", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("workspace_scopes", &self.workspace_scopes)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FirstMessage {
    Hello(Hello),
    Other(serde_json::Value),
}

#[derive(Debug, Clone, PartialEq)]
pub enum NegotiationError {
    HelloRequired,
    InvalidRange,
    Incompatible(ProtocolError),
}

pub fn negotiate_version(
    client: VersionRange,
    desktop: VersionRange,
) -> Result<u32, ProtocolError> {
    let min = client.min.max(desktop.min);
    let max = client.max.min(desktop.max);
    if client.min <= client.max && desktop.min <= desktop.max && min <= max {
        return Ok(max);
    }
    let action = if client.max < desktop.min {
        ErrorAction::UpgradeCompanion
    } else {
        ErrorAction::UpgradeDesktop
    };
    Err(ProtocolError::protocol_incompatible(desktop, action))
}

/// Validates that the first decoded message is a hello and selects its version.
pub fn negotiate_first(
    message: FirstMessage,
    desktop: VersionRange,
) -> Result<u32, NegotiationError> {
    let FirstMessage::Hello(hello) = message else {
        return Err(NegotiationError::HelloRequired);
    };
    if hello.supported.min > hello.supported.max || desktop.min > desktop.max {
        return Err(NegotiationError::InvalidRange);
    }
    negotiate_version(hello.supported, desktop).map_err(NegotiationError::Incompatible)
}

pub fn welcome(
    selected: u32,
    desktop_version: impl Into<String>,
    server_nonce: impl Into<String>,
    approval_challenge: impl Into<String>,
) -> Welcome {
    Welcome {
        selected,
        desktop_version: desktop_version.into(),
        server_nonce: server_nonce.into(),
        authorization: Authorization::PairingRequired,
        approval_challenge: approval_challenge.into(),
    }
}

pub fn authorized(
    capability: impl Into<String>,
    expires_at: u64,
    idle_timeout_seconds: u64,
    workspace_scopes: BTreeMap<String, BTreeSet<String>>,
) -> Authorized {
    Authorized {
        capability: capability.into(),
        expires_at,
        idle_timeout_seconds,
        workspace_scopes,
    }
}
