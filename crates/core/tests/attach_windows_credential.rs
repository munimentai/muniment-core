#![cfg(target_os = "windows")]

use muniment_core::attach::{load_client_credentials, save_client_credentials, ClientCredential};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

fn directory(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-windows-credential-{name}-{}",
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
            subject: None,
        },
    )
}

#[test]
fn save_then_load_round_trips() {
    let directory = directory("round-trip");
    let path = directory.join("attach-client-credentials.json");
    let credentials = HashMap::from([credential()]);

    save_client_credentials(&path, &HashMap::new()).unwrap();
    save_client_credentials(&path, &credentials).unwrap();
    let loaded = load_client_credentials(&path).unwrap();

    assert_eq!(loaded.len(), 1);
    let entry = loaded.values().next().unwrap();
    assert_eq!(entry.credential, "ab".repeat(32));
    assert_eq!(entry.claimed_kind, "cli");
    assert_eq!(entry.claimed_version, "1.2.3");
    assert_eq!(entry.approved_at.as_deref(), Some("2026-08-04T12:00:00Z"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_file_loads_an_empty_store() {
    let directory = directory("missing");
    let path = directory.join("attach-client-credentials.json");

    assert!(load_client_credentials(&path).unwrap().is_empty());
}

#[test]
fn malformed_store_body_is_rejected() {
    let directory = directory("malformed");
    let path = directory.join("attach-client-credentials.json");
    save_client_credentials(&path, &HashMap::new()).unwrap();
    std::fs::write(&path, b"{").unwrap();

    assert!(load_client_credentials(&path).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}
