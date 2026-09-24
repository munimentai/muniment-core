//! Platform-neutral companion credential store model and validation.

use super::{bounded_claim, Id, ProtocolError};
use serde_json::Value;
use std::collections::HashMap;

/// The companion credential store file name.
pub const COMPANION_CREDENTIAL_FILE_NAME: &str = "attach-client-credentials.json";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredential {
    pub credential: String,
    pub claimed_kind: String,
    pub claimed_version: String,
    #[serde(deserialize_with = "deserialize_approval_time")]
    pub approved_at: Option<String>,
    /// The signed-in account, or local mode, that approved this companion. A record
    /// without a subject needs a fresh visible approval before it reconnects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

fn deserialize_approval_time<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Option<String> as serde::Deserialize>::deserialize(deserializer)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientCredentialStore {
    version: u32,
    companions: HashMap<String, ClientCredential>,
}

impl ClientCredentialStore {
    pub(super) fn new(companions: HashMap<String, ClientCredential>) -> Self {
        Self {
            version: 1,
            companions,
        }
    }
}

pub(super) fn decode_client_credentials(
    value: Value,
) -> Result<HashMap<String, ClientCredential>, ProtocolError> {
    let credentials = if value.get("version").is_some() {
        let store: ClientCredentialStore =
            serde_json::from_value(value).map_err(|_| ProtocolError::persistence_failed())?;
        if store.version != 1 {
            return Err(ProtocolError::persistence_failed());
        }
        store.companions
    } else {
        let legacy: HashMap<String, String> =
            serde_json::from_value(value).map_err(|_| ProtocolError::persistence_failed())?;
        legacy
            .into_iter()
            .map(|(identity, credential)| {
                (
                    identity,
                    ClientCredential {
                        credential,
                        claimed_kind: "unknown".into(),
                        claimed_version: "unknown".into(),
                        approved_at: None,
                        subject: None,
                    },
                )
            })
            .collect()
    };
    if credentials_are_valid(&credentials) {
        Ok(credentials)
    } else {
        Err(ProtocolError::persistence_failed())
    }
}

fn credentials_are_valid(credentials: &HashMap<String, ClientCredential>) -> bool {
    credentials.iter().all(|(identity, entry)| {
        Id::new(identity).is_ok()
            && entry.credential.len() == 64
            && entry
                .credential
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && entry.claimed_kind == bounded_claim(&entry.claimed_kind)
            && entry.claimed_version == bounded_claim(&entry.claimed_version)
            && entry.approved_at.as_ref().is_none_or(|approved_at| {
                chrono::DateTime::parse_from_rfc3339(approved_at)
                    .map(|time| time.offset().local_minus_utc() == 0)
                    .unwrap_or(false)
            })
            && entry
                .subject
                .as_deref()
                .is_none_or(super::is_valid_approval_subject)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: &str = "018f0000-0000-7000-8000-000000000001";

    fn credential() -> ClientCredential {
        ClientCredential {
            credential: "ab".repeat(32),
            claimed_kind: "cli".into(),
            claimed_version: "1.2.3".into(),
            approved_at: Some("2026-08-04T12:00:00Z".into()),
            subject: Some("account:org:user".into()),
        }
    }

    fn store(entry: ClientCredential) -> HashMap<String, ClientCredential> {
        HashMap::from([(IDENTITY.into(), entry)])
    }

    #[test]
    fn decodes_version_one() {
        let value = serde_json::json!({
            "version": 1,
            "companions": {IDENTITY: credential()},
        });
        let decoded = decode_client_credentials(value).unwrap();
        assert_eq!(decoded[IDENTITY].claimed_kind, "cli");
    }

    #[test]
    fn decodes_a_record_written_without_a_subject() {
        let mut entry = serde_json::to_value(credential()).unwrap();
        entry.as_object_mut().unwrap().remove("subject");
        let value = serde_json::json!({"version": 1, "companions": {IDENTITY: entry}});
        let decoded = decode_client_credentials(value).unwrap();
        assert_eq!(decoded[IDENTITY].subject, None);
    }

    #[test]
    fn rejects_an_invalid_subject() {
        for subject in ["", "account:\n", &"x".repeat(257)] {
            let mut entry = credential();
            entry.subject = Some(subject.into());
            assert!(!credentials_are_valid(&store(entry)));
        }
    }

    #[test]
    fn decodes_legacy_store_with_unknown_claims() {
        let value = serde_json::json!({IDENTITY: "ab".repeat(32)});
        let decoded = decode_client_credentials(value).unwrap();
        assert_eq!(decoded[IDENTITY].claimed_kind, "unknown");
        assert_eq!(decoded[IDENTITY].claimed_version, "unknown");
        assert_eq!(decoded[IDENTITY].approved_at, None);
        assert_eq!(decoded[IDENTITY].subject, None);
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let value = serde_json::json!({"version": 2, "companions": {}});
        assert!(decode_client_credentials(value).is_err());
    }

    #[test]
    fn rejects_an_invalid_identity() {
        let credentials = HashMap::from([("invalid".into(), credential())]);
        assert!(!credentials_are_valid(&credentials));
    }

    #[test]
    fn rejects_an_invalid_credential_length() {
        let mut entry = credential();
        entry.credential.pop();
        assert!(!credentials_are_valid(&store(entry)));
    }

    #[test]
    fn rejects_a_non_hex_credential() {
        let mut entry = credential();
        entry.credential.replace_range(..1, "g");
        assert!(!credentials_are_valid(&store(entry)));
    }

    #[test]
    fn rejects_an_invalid_claimed_kind() {
        let mut entry = credential();
        entry.claimed_kind.clear();
        assert!(!credentials_are_valid(&store(entry)));
    }

    #[test]
    fn rejects_an_invalid_claimed_version() {
        let mut entry = credential();
        entry.claimed_version = "x".repeat(81);
        assert!(!credentials_are_valid(&store(entry)));
    }

    #[test]
    fn rejects_an_invalid_approval_time() {
        let mut entry = credential();
        entry.approved_at = Some("not-a-time".into());
        assert!(!credentials_are_valid(&store(entry)));
    }

    #[test]
    fn rejects_a_non_utc_approval_time() {
        let mut entry = credential();
        entry.approved_at = Some("2026-08-04T12:00:00+01:00".into());
        assert!(!credentials_are_valid(&store(entry)));
    }

    #[test]
    fn accepts_an_empty_store() {
        assert!(credentials_are_valid(&HashMap::new()));
    }
}
