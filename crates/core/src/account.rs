//! Account session, device, and entitlement values that attach and runs carry.
//!
//! The host signs in, lists devices, pairs phones and reads entitlements. The
//! core only moves these values between the host and attach clients, so none
//! of them carries a credential store or a network call.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

/// Tokens held after a successful sign-in. Serialized as one JSON blob into
/// the platform keychain, never onto disk or into logs (the manual
/// `Debug` impl redacts token material; keep it that way).
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds when the access token expires (derived from
    /// `expires_in` at exchange time).
    pub expires_at: Option<u64>,
    /// OIDC subject (`sub` claim of the id_token), kept so `auth_status`
    /// can answer without a network round-trip.
    pub subject: Option<String>,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("subject", &self.subject)
            .finish()
    }
}

/// What `auth_status` reports to the webview: signed-in state only, no
/// token material.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AuthStatus {
    pub signed_in: bool,
    pub subject: Option<String>,
    pub expires_at: Option<u64>,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeSessionRole {
    User,
    Admin,
    Owner,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NativeEntitlementGrant {
    pub id: String,
    pub principal_type: String,
    pub principal_id: Option<String>,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub action: String,
    pub effect: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Safe webview projection. The signed envelope and native credentials have no
/// fields in this type and therefore cannot be serialized through it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementSnapshotView {
    pub snapshot_version: u64,
    pub org_id: String,
    pub user_id: String,
    pub role: NativeSessionRole,
    pub user_display_name: Option<String>,
    pub organization_display_name: Option<String>,
    pub capabilities: Vec<String>,
    pub grants: Vec<NativeEntitlementGrant>,
}

pub type PairId = Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingChallengeView {
    pub expires_at: DateTime<Utc>,
    pub qr_svg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedPhone {
    pub pair_id: PairId,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_token_material() {
        let tokens = TokenSet {
            access_token: "top-secret-access".into(),
            refresh_token: Some("top-secret-refresh".into()),
            expires_at: Some(1_800_000_000),
            subject: Some("user-123".into()),
        };
        let rendered = format!("{tokens:?}");
        assert!(!rendered.contains("top-secret"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("user-123")); // subject is not a secret
    }

    #[test]
    fn a_device_needs_its_revocation_field_even_when_null() {
        let device = serde_json::json!({
            "device_id": "018f2c3e-0000-7000-8000-000000000001",
            "client_id": "desktop",
            "client_role": "desktop",
            "platform": "desktop",
            "created_at": "2026-07-11T12:00:00Z",
            "revoked_at": null,
            "last_active_at": "2026-07-11T12:00:00Z",
            "current": true,
        });
        assert!(serde_json::from_value::<NativeDevice>(device.clone()).is_ok());
        let mut missing = device;
        missing.as_object_mut().unwrap().remove("revoked_at");
        assert!(serde_json::from_value::<NativeDevice>(missing).is_err());
    }
}
