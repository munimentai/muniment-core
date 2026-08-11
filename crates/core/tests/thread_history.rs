#![cfg(feature = "keyring")]

use std::collections::BTreeMap;
use std::time::Duration;

use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::thread_history::{chat_thread_open_page, ThreadHistoryError};
use serde_json::{json, Value};
use uuid::Uuid;

fn journal_file() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-thread-history-{}.sqlite3",
        Uuid::new_v4()
    ))
}

fn started_event(run_id: &str, actor_id: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-08T00:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
        },
        provenance: Provenance {
            source: "test".into(),
            source_version: "1".into(),
            actor_id: Some(actor_id.into()),
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

#[test]
fn open_page_uses_the_webview_contract() {
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    let path = journal_file();
    let mut journal = RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let thread_id = journal
        .append_new_run("workspace", &started_event(&run_id, "owner"))
        .unwrap();

    let page = chat_thread_open_page(
        &mut journal,
        None,
        Some("owner"),
        std::path::Path::new("."),
        &thread_id,
        10,
        None,
    )
    .unwrap();
    let value = serde_json::to_value(page).unwrap();
    let entry = &value["entries"][0];

    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["entries", "nextCursor"]
    );
    assert_eq!(
        entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "appliedDiffs",
            "attachments",
            "phase",
            "prompt",
            "recalls",
            "resumable",
            "runId",
            "text",
            "toolActivity"
        ]
    );
    assert_eq!(value["nextCursor"], Value::Null);
    assert_eq!(entry["runId"], run_id);
    assert!(entry.get("pendingPermission").is_none());

    drop(journal);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn open_page_rejects_a_thread_owned_by_another_subject() {
    let path = journal_file();
    let mut journal = RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let thread_id = journal
        .append_new_run("workspace", &started_event(&run_id, "other"))
        .unwrap();

    assert_eq!(
        chat_thread_open_page(
            &mut journal,
            None,
            Some("owner"),
            std::path::Path::new("."),
            &thread_id,
            10,
            None,
        )
        .err(),
        Some(ThreadHistoryError::ThreadNotOwned)
    );

    drop(journal);
    std::fs::remove_file(path).unwrap();
}
