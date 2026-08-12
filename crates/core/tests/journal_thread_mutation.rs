use chrono::{DateTime, Utc};
use muniment_core::journal::thread_mutation::{
    append_thread_delete, append_thread_delete_now, append_thread_rename, append_thread_rename_now,
    ThreadMutationError,
};
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

const RECORDED_AT: &str = "2026-08-06T12:34:56Z";

fn provenance(actor_id: Option<&str>) -> Provenance {
    Provenance {
        source: "desktop-test".into(),
        source_version: "42".into(),
        actor_id: actor_id.map(str::to_owned),
        device_id: Some("device-1".into()),
        rpc_request_id: Some("request-1".into()),
        capability_versions: None,
        extra: BTreeMap::new(),
    }
}

fn run_started(actor_id: Option<&str>) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: Uuid::now_v7().to_string(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-06T12:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
        },
        provenance: provenance(actor_id),
        extra: BTreeMap::new(),
    }
}

fn journal_with_thread(actor_id: Option<&str>) -> (PathBuf, RunJournal, String) {
    let path = std::env::temp_dir().join(format!(
        "muniment-journal-thread-mutation-{}.sqlite3",
        Uuid::new_v4()
    ));
    let mut journal = RunJournal::open(&path).unwrap();
    let thread_id = journal
        .append_new_run("workspace-a", &run_started(actor_id))
        .unwrap();
    (path, journal, thread_id)
}

fn stored_thread_event(path: &PathBuf, thread_id: &str) -> (String, u64, String, String) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT event_type, thread_seq, recorded_at, envelope_json
             FROM thread_events WHERE thread_id=?1 ORDER BY thread_seq DESC LIMIT 1",
            [thread_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

#[test]
fn appends_rename_with_caller_fields() {
    let (path, mut journal, thread_id) = journal_with_thread(Some("owner"));
    let caller_provenance = provenance(Some("owner"));

    append_thread_rename(
        &mut journal,
        Some("owner"),
        &thread_id,
        "  New title  ",
        RECORDED_AT,
        &caller_provenance,
    )
    .unwrap();

    let event = stored_thread_event(&path, &thread_id);
    assert_eq!(event.0, "thread.title.renamed");
    assert_eq!(event.1, 2);
    assert_eq!(event.2, RECORDED_AT);
    let envelope: serde_json::Value = serde_json::from_str(&event.3).unwrap();
    assert_eq!(envelope["payload_json"], json!({"title": "New title"}));
    assert_eq!(
        serde_json::from_value::<Provenance>(envelope["provenance"].clone()).unwrap(),
        caller_provenance
    );
}

#[test]
fn appends_delete_with_caller_fields() {
    let (path, mut journal, thread_id) = journal_with_thread(Some("owner"));
    let caller_provenance = provenance(Some("owner"));

    append_thread_delete(
        &mut journal,
        Some("owner"),
        &thread_id,
        RECORDED_AT,
        &caller_provenance,
    )
    .unwrap();

    let event = stored_thread_event(&path, &thread_id);
    assert_eq!(event.0, "thread.deleted");
    assert_eq!(event.1, 2);
    assert_eq!(event.2, RECORDED_AT);
    let envelope: serde_json::Value = serde_json::from_str(&event.3).unwrap();
    assert_eq!(envelope["payload_json"], json!({}));
    assert_eq!(
        serde_json::from_value::<Provenance>(envelope["provenance"].clone()).unwrap(),
        caller_provenance
    );
}

#[test]
fn rename_now_stores_a_generated_utc_rfc3339_timestamp() {
    let (path, mut journal, thread_id) = journal_with_thread(Some("owner"));
    let before = Utc::now();

    append_thread_rename_now(
        &mut journal,
        Some("owner"),
        &thread_id,
        "New title",
        &provenance(Some("owner")),
    )
    .unwrap();
    let after = Utc::now();

    let recorded_at = stored_thread_event(&path, &thread_id).2;
    let parsed = DateTime::parse_from_rfc3339(&recorded_at).unwrap();
    assert_eq!(parsed.offset().local_minus_utc(), 0);
    assert!(recorded_at.ends_with('Z'));
    assert!(parsed >= before && parsed <= after);
}

#[test]
fn delete_now_stores_a_generated_utc_rfc3339_timestamp() {
    let (path, mut journal, thread_id) = journal_with_thread(Some("owner"));
    let before = Utc::now();

    append_thread_delete_now(
        &mut journal,
        Some("owner"),
        &thread_id,
        &provenance(Some("owner")),
    )
    .unwrap();
    let after = Utc::now();

    let recorded_at = stored_thread_event(&path, &thread_id).2;
    let parsed = DateTime::parse_from_rfc3339(&recorded_at).unwrap();
    assert_eq!(parsed.offset().local_minus_utc(), 0);
    assert!(recorded_at.ends_with('Z'));
    assert!(parsed >= before && parsed <= after);
}

#[test]
fn rejects_rename_by_non_owner() {
    let (_path, mut journal, thread_id) = journal_with_thread(Some("owner"));

    assert!(matches!(
        append_thread_rename(
            &mut journal,
            Some("other"),
            &thread_id,
            "New title",
            RECORDED_AT,
            &provenance(Some("other")),
        ),
        Err(ThreadMutationError::NotOwned)
    ));
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 1);
}

#[test]
fn rejects_delete_by_non_owner() {
    let (_path, mut journal, thread_id) = journal_with_thread(Some("owner"));

    assert!(matches!(
        append_thread_delete(
            &mut journal,
            Some("other"),
            &thread_id,
            RECORDED_AT,
            &provenance(Some("other")),
        ),
        Err(ThreadMutationError::NotOwned)
    ));
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 1);
}

#[test]
fn permits_mutations_when_the_first_run_has_no_recorded_subject() {
    let (_path, mut journal, thread_id) = journal_with_thread(None);
    let caller_provenance = provenance(Some("subject"));

    append_thread_rename(
        &mut journal,
        Some("subject"),
        &thread_id,
        "New title",
        RECORDED_AT,
        &caller_provenance,
    )
    .unwrap();
    append_thread_delete(
        &mut journal,
        Some("subject"),
        &thread_id,
        RECORDED_AT,
        &caller_provenance,
    )
    .unwrap();

    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 3);
}
