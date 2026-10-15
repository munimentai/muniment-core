use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    DeviceCredential, ErrorAction, Id, Protocol, ProtocolError, RuntimeInfo, VersionRange,
};

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
    /// A pairing secret a remote client redeems once for a device credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<PairingRedemption>,
}

/// The one-time secret from a pairing link, with the device name and the
/// scopes the client asks for. Requested scopes narrow the link's scopes and
/// never widen them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRedemption {
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<BTreeSet<String>>,
}

impl fmt::Debug for PairingRedemption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingRedemption")
            .field("secret", &"[REDACTED]")
            .field("device_name", &self.device_name)
            .field("scopes", &self.scopes)
            .finish()
    }
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
            #[serde(default)]
            pairing: Option<PairingRedemption>,
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
            pairing: fields.pairing,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_nonce: Option<String>,
    /// The runtime's id, name, version and install kind, as flat optional
    /// fields. The remote route always sends them.
    #[serde(flatten)]
    pub runtime: Option<RuntimeInfo>,
}

impl Welcome {
    pub fn with_handoff_nonce(mut self, handoff_nonce: impl Into<String>) -> Self {
        self.handoff_nonce = Some(handoff_nonce.into());
        self
    }
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
            #[serde(default)]
            handoff_nonce: Option<String>,
            #[serde(default)]
            runtime_id: Option<String>,
            #[serde(default)]
            runtime_name: Option<String>,
            #[serde(default)]
            runtime_version: Option<String>,
            #[serde(default)]
            install_kind: Option<serde_json::Value>,
            #[serde(default)]
            form_factor: Option<serde_json::Value>,
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
            handoff_nonce: fields.handoff_nonce,
            runtime: RuntimeInfo::from_fields(
                fields.runtime_id,
                fields.runtime_name,
                fields.runtime_version,
                fields.install_kind.as_ref(),
                fields.form_factor.as_ref(),
            ),
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
            .field("handoff_nonce", &"[REDACTED]")
            .field("runtime", &self.runtime)
            .finish()
    }
}

/// The connection-bound grant for an admitted remote client. It carries the
/// desktop client grant's fields, the device's scopes, and, right after a
/// pairing redemption, the device credential the client keeps.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClientAuthorizedGrant {
    pub profile_id: String,
    pub capability: String,
    pub expires_at: u64,
    pub idle_timeout_seconds: u64,
    pub workspace_scopes: BTreeMap<String, BTreeSet<String>>,
    pub scopes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_credential: Option<DeviceCredential>,
}

impl fmt::Debug for RemoteClientAuthorizedGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteClientAuthorizedGrant")
            .field("capability", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("workspace_scopes", &self.workspace_scopes)
            .field("scopes", &self.scopes)
            .field("device_credential", &self.device_credential)
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
            "handoff_nonce",
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

/// A connection-bound grant for an authorized local peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAuthorizedGrant {
    pub capability: String,
    pub expires_at: u64,
    pub idle_timeout_seconds: u64,
}

impl Serialize for PeerAuthorizedGrant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct PeerAuthorizedGrantFields<'a> {
            profile_id: &'static str,
            capability: &'a str,
            expires_at: u64,
            idle_timeout_seconds: u64,
            workspace_scopes: BTreeMap<String, BTreeSet<String>>,
        }

        PeerAuthorizedGrantFields {
            profile_id: "",
            capability: &self.capability,
            expires_at: self.expires_at,
            idle_timeout_seconds: self.idle_timeout_seconds,
            workspace_scopes: BTreeMap::new(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PeerAuthorizedGrant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PeerAuthorizedGrantFields {
            profile_id: String,
            capability: String,
            expires_at: u64,
            idle_timeout_seconds: u64,
            workspace_scopes: BTreeMap<String, BTreeSet<String>>,
        }

        let fields = PeerAuthorizedGrantFields::deserialize(deserializer)?;
        if !fields.profile_id.is_empty() || !fields.workspace_scopes.is_empty() {
            return Err(de::Error::custom("peer grant contains workspace authority"));
        }
        Ok(Self {
            capability: fields.capability,
            expires_at: fields.expires_at,
            idle_timeout_seconds: fields.idle_timeout_seconds,
        })
    }
}

/// A connection-bound grant for an admitted desktop client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DesktopClientAuthorizedGrant {
    pub profile_id: String,
    pub capability: String,
    pub expires_at: u64,
    pub idle_timeout_seconds: u64,
    pub workspace_scopes: BTreeMap<String, BTreeSet<String>>,
}

impl<'de> Deserialize<'de> for DesktopClientAuthorizedGrant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct DesktopClientAuthorizedGrantFields {
            profile_id: String,
            capability: String,
            expires_at: u64,
            idle_timeout_seconds: u64,
            workspace_scopes: BTreeMap<String, BTreeSet<String>>,
        }

        let fields = DesktopClientAuthorizedGrantFields::deserialize(deserializer)?;
        if fields.profile_id.is_empty() {
            return Err(de::Error::custom(
                "desktop client grant has an empty profile",
            ));
        }
        Ok(Self {
            profile_id: fields.profile_id,
            capability: fields.capability,
            expires_at: fields.expires_at,
            idle_timeout_seconds: fields.idle_timeout_seconds,
            workspace_scopes: fields.workspace_scopes,
        })
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
        handoff_nonce: None,
        runtime: None,
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
        handoff_nonce: None,
        runtime: None,
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
