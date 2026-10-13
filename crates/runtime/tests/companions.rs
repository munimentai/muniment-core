#![cfg(target_os = "linux")]

use muniment_core::attach::{
    load_client_credentials, save_client_credentials, ClientCredential, ErrorCode,
    COMPANION_CREDENTIAL_FILE_NAME,
};
use muniment_runtime_core::{list_companions, open_companion_registry, revoke_companion};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct ConfigDirectory(PathBuf);

impl ConfigDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-runtime-companions-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn credential_path(&self) -> PathBuf {
        self.0.join(COMPANION_CREDENTIAL_FILE_NAME)
    }
}

impl Drop for ConfigDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn credential(kind: &str, version: &str, secret: &str) -> ClientCredential {
    ClientCredential {
        credential: secret.repeat(32),
        claimed_kind: kind.into(),
        claimed_version: version.into(),
        approved_at: Some("2026-08-12T00:00:00Z".into()),
        subject: None,
    }
}

#[test]
fn lists_and_revokes_companions_over_one_registry() {
    let config = ConfigDirectory::new();
    let first = "018f0000-0000-7000-8000-000000000001";
    let second = "018f0000-0000-7000-8000-000000000002";
    let staged = HashMap::from([
        (second.into(), credential("desktop", "2.0.0", "cd")),
        (first.into(), credential("cli", "1.0.0", "ab")),
    ]);
    save_client_credentials(&config.credential_path(), &staged).unwrap();

    let registry = open_companion_registry(&config.0).unwrap();
    let companions = list_companions(&registry).unwrap();

    assert_eq!(companions.len(), 2);
    assert_eq!(companions[0].identity, first);
    assert_eq!(companions[0].claimed_kind, "cli");
    assert_eq!(companions[0].claimed_version, "1.0.0");
    assert_eq!(
        companions[0].approved_at.as_deref(),
        Some("2026-08-12T00:00:00Z")
    );
    assert_eq!(companions[1].identity, second);

    revoke_companion(&registry, first).unwrap();

    assert_eq!(
        list_companions(&registry).unwrap(),
        vec![companions[1].clone()]
    );
    let persisted = load_client_credentials(&config.credential_path()).unwrap();
    assert_eq!(persisted.len(), 1);
    assert!(persisted.contains_key(second));
    assert!(!persisted.contains_key(first));
}

#[test]
fn unknown_identity_is_unauthorized_and_does_not_change_the_file() {
    let config = ConfigDirectory::new();
    let identity = "018f0000-0000-7000-8000-000000000001";
    save_client_credentials(
        &config.credential_path(),
        &HashMap::from([(identity.into(), credential("cli", "1.0.0", "ab"))]),
    )
    .unwrap();
    let before = fs::read(config.credential_path()).unwrap();
    let registry = open_companion_registry(&config.0).unwrap();

    let error = revoke_companion(&registry, "018f0000-0000-7000-8000-000000000099").unwrap_err();

    assert_eq!(error.code(), ErrorCode::Unauthorized);
    assert_eq!(fs::read(config.credential_path()).unwrap(), before);
    assert_eq!(list_companions(&registry).unwrap().len(), 1);
}
