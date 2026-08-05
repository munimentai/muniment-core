use super::{Id, ProtocolError};
use serde_json::Value;
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredential {
    pub credential: String,
    pub claimed_kind: String,
    pub claimed_version: String,
    #[serde(deserialize_with = "deserialize_approval_time")]
    pub approved_at: Option<String>,
}

fn deserialize_approval_time<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Option<String> as serde::Deserialize>::deserialize(deserializer)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ClientCredentialStore {
    version: u32,
    companions: HashMap<String, ClientCredential>,
}

pub fn bounded_claim(claim: &str) -> String {
    const MAX_CLAIM_LENGTH: usize = 80;
    if claim.chars().any(char::is_control)
        || claim.trim().is_empty()
        || claim.chars().take(MAX_CLAIM_LENGTH + 1).count() > MAX_CLAIM_LENGTH
    {
        "unknown".into()
    } else {
        claim.into()
    }
}

pub fn load_client_credentials(
    path: &Path,
) -> Result<HashMap<String, ClientCredential>, ProtocolError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(_) => return Err(ProtocolError::persistence_failed()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| ProtocolError::persistence_failed())?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(ProtocolError::persistence_failed());
    }
    let value: Value =
        serde_json::from_reader(file).map_err(|_| ProtocolError::persistence_failed())?;
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
                    },
                )
            })
            .collect()
    };
    if credentials.iter().any(|(identity, entry)| {
        Id::new(identity).is_err()
            || entry.credential.len() != 64
            || !entry
                .credential
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || entry.claimed_kind != bounded_claim(&entry.claimed_kind)
            || entry.claimed_version != bounded_claim(&entry.claimed_version)
            || entry.approved_at.as_ref().is_some_and(|approved_at| {
                chrono::DateTime::parse_from_rfc3339(approved_at)
                    .map(|time| time.offset().local_minus_utc() != 0)
                    .unwrap_or(true)
            })
    }) {
        return Err(ProtocolError::persistence_failed());
    }
    Ok(credentials)
}

pub fn save_client_credentials(
    path: &Path,
    credentials: &HashMap<String, ClientCredential>,
) -> Result<(), ProtocolError> {
    let parent = path
        .parent()
        .ok_or_else(ProtocolError::persistence_failed)?;
    std::fs::create_dir_all(parent).map_err(|_| ProtocolError::persistence_failed())?;
    let temporary = parent.join(format!(".attach-client-credentials-{}.tmp", Uuid::now_v7()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let file = options
            .open(&temporary)
            .map_err(|_| ProtocolError::persistence_failed())?;
        serde_json::to_writer(
            &file,
            &ClientCredentialStore {
                version: 1,
                companions: credentials.clone(),
            },
        )
        .map_err(|_| ProtocolError::persistence_failed())?;
        file.sync_all()
            .map_err(|_| ProtocolError::persistence_failed())?;
        std::fs::rename(&temporary, path).map_err(|_| ProtocolError::persistence_failed())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "muniment-core-credential-{name}-{}",
            Uuid::now_v7()
        ))
    }

    fn credential() -> (String, ClientCredential) {
        (
            "018f0000-0000-7000-8000-000000000001".into(),
            ClientCredential {
                credential: "ab".repeat(32),
                claimed_kind: "cli".into(),
                claimed_version: "1.2.3".into(),
                approved_at: Some("2026-08-04T12:00:00Z".into()),
            },
        )
    }

    #[test]
    fn missing_file_loads_an_empty_store() {
        assert!(load_client_credentials(&path("missing"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn legacy_file_loads_with_unknown_claims() {
        let path = path("legacy");
        let (identity, entry) = credential();
        let legacy = HashMap::from([(identity, entry.credential)]);
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = load_client_credentials(&path).unwrap();
        let entry = loaded.values().next().unwrap();
        assert_eq!(entry.claimed_kind, "unknown");
        assert_eq!(entry.claimed_version, "unknown");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn version_one_round_trips() {
        let path = path("round-trip");
        let credentials = HashMap::from([credential()]);
        save_client_credentials(&path, &credentials).unwrap();
        let loaded = load_client_credentials(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        let entry = loaded.values().next().unwrap();
        assert_eq!(entry.credential, "ab".repeat(32));
        assert_eq!(entry.claimed_kind, "cli");
        assert_eq!(entry.claimed_version, "1.2.3");
        assert_eq!(entry.approved_at.as_deref(), Some("2026-08-04T12:00:00Z"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_group_or_other_permissions() {
        let path = path("mode");
        save_client_credentials(&path, &HashMap::from([credential()])).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_client_credentials(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let path = path("version");
        let value = serde_json::json!({"version": 2, "companions": {}});
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_client_credentials(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bounds_claims() {
        assert_eq!(bounded_claim(&"x".repeat(80)), "x".repeat(80));
        for claim in ["", "   ", "cli\nspoof", &"x".repeat(81)] {
            assert_eq!(bounded_claim(claim), "unknown");
        }
    }
}
