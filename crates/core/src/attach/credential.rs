use super::{decode_client_credentials, ClientCredential, ClientCredentialStore, ProtocolError};
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use uuid::Uuid;

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
    let value = serde_json::from_reader(file).map_err(|_| ProtocolError::persistence_failed())?;
    decode_client_credentials(value)
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
        serde_json::to_writer(&file, &ClientCredentialStore::new(credentials.clone()))
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
}
