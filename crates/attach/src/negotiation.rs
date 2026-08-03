use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{ErrorAction, Id, Protocol, ProtocolError, VersionRange};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    pub kind: String,
    pub version: String,
}

#[derive(Clone, PartialEq, Serialize)]
pub struct Hello {
    pub protocol: Protocol,
    pub client: Client,
    pub supported: VersionRange,
    pub client_nonce: String,
    pub authorized_client_id: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_client_credential: Option<String>,
}

impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hello")
            .field("protocol", &self.protocol)
            .field("client", &self.client)
            .field("supported", &self.supported)
            .field("client_nonce", &"[REDACTED]")
            .finish()
    }
}

impl<'de> Deserialize<'de> for Hello {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct HelloFields {
            protocol: Protocol,
            client: Client,
            supported: VersionRange,
            client_nonce: String,
            authorized_client_id: Id,
            #[serde(default)]
            authorized_client_credential: Option<String>,
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
            authorized_client_id: fields.authorized_client_id,
            authorized_client_credential: fields.authorized_client_credential,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authorization {
    PairingRequired,
    Authorized,
}

#[derive(Clone, PartialEq, Serialize)]
pub struct Welcome {
    pub selected: u32,
    pub desktop_version: String,
    pub server_nonce: String,
    pub authorization: Authorization,
    pub approval_challenge: String,
}

impl<'de> Deserialize<'de> for Welcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct WelcomeFields {
            selected: u32,
            desktop_version: String,
            server_nonce: String,
            authorization: Authorization,
            approval_challenge: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }

        const CONFLICTING_FIELDS: &[&str] = &[
            "protocol",
            "client",
            "supported",
            "client_nonce",
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
            "expires_at",
            "idle_timeout_seconds",
            "workspace_scopes",
        ];

        let fields = WelcomeFields::deserialize(deserializer)?;
        reject_conflicting_fields::<D::Error>(&fields.extra, CONFLICTING_FIELDS, "welcome")?;
        Ok(Self {
            selected: fields.selected,
            desktop_version: fields.desktop_version,
            server_nonce: fields.server_nonce,
            authorization: fields.authorization,
            approval_challenge: fields.approval_challenge,
        })
    }
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Welcome")
            .field("selected", &self.selected)
            .field("desktop_version", &self.desktop_version)
            .field("server_nonce", &"[REDACTED]")
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
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Authorized {
    pub profile_id: String,
    pub capability: String,
    pub expires_at: u64,
    pub idle_timeout_seconds: u64,
    pub workspace_scopes: BTreeMap<String, BTreeSet<String>>,
    pub authorized_client_credential: String,
}

impl<'de> Deserialize<'de> for Authorized {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct AuthorizedFields {
            profile_id: String,
            capability: String,
            expires_at: u64,
            idle_timeout_seconds: u64,
            workspace_scopes: BTreeMap<String, BTreeSet<String>>,
            authorized_client_credential: String,
            #[serde(flatten)]
            extra: BTreeMap<String, serde_json::Value>,
        }

        const CONFLICTING_FIELDS: &[&str] = &[
            "protocol",
            "client",
            "supported",
            "client_nonce",
            "selected",
            "desktop_version",
            "server_nonce",
            "authorization",
            "approval_challenge",
            "request_id",
            "operation",
            "idempotency_key",
            "ok",
            "error",
            "subscription_id",
            "event",
            "run_id",
            "run_seq",
            "body",
        ];

        let fields = AuthorizedFields::deserialize(deserializer)?;
        reject_conflicting_fields::<D::Error>(&fields.extra, CONFLICTING_FIELDS, "authorized")?;
        Ok(Self {
            profile_id: fields.profile_id,
            capability: fields.capability,
            expires_at: fields.expires_at,
            idle_timeout_seconds: fields.idle_timeout_seconds,
            workspace_scopes: fields.workspace_scopes,
            authorized_client_credential: fields.authorized_client_credential,
        })
    }
}

fn reject_conflicting_fields<E: de::Error>(
    extra: &BTreeMap<String, serde_json::Value>,
    conflicting: &[&str],
    message: &str,
) -> Result<(), E> {
    if extra
        .keys()
        .any(|field| conflicting.contains(&field.as_str()))
    {
        return Err(E::custom(format_args!(
            "{message} contains conflicting handshake or envelope fields"
        )));
    }
    Ok(())
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

pub fn reconnect_welcome(
    selected: u32,
    desktop_version: impl Into<String>,
    server_nonce: impl Into<String>,
    approval_challenge: impl Into<String>,
) -> Welcome {
    Welcome {
        selected,
        desktop_version: desktop_version.into(),
        server_nonce: server_nonce.into(),
        authorization: Authorization::Authorized,
        approval_challenge: approval_challenge.into(),
    }
}

pub fn authorized(
    profile_id: impl Into<String>,
    capability: impl Into<String>,
    expires_at: u64,
    idle_timeout_seconds: u64,
    workspace_scopes: BTreeMap<String, BTreeSet<String>>,
) -> Authorized {
    authorized_with_client_credential(
        profile_id,
        capability,
        expires_at,
        idle_timeout_seconds,
        workspace_scopes,
        "00".repeat(32),
    )
}

pub fn authorized_with_client_credential(
    profile_id: impl Into<String>,
    capability: impl Into<String>,
    expires_at: u64,
    idle_timeout_seconds: u64,
    workspace_scopes: BTreeMap<String, BTreeSet<String>>,
    authorized_client_credential: impl Into<String>,
) -> Authorized {
    Authorized {
        profile_id: profile_id.into(),
        capability: capability.into(),
        expires_at,
        idle_timeout_seconds,
        workspace_scopes,
        authorized_client_credential: authorized_client_credential.into(),
    }
}
