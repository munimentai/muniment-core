use chrono::{Duration, TimeZone, Utc};
use muniment_core::cas::LocalCas;
use muniment_core::journal::retention::{apply_retention, RetentionPolicy};
use muniment_core::journal::{CasReference, EventEnvelope, EventPayload, Provenance, RunJournal};
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

fn paths() -> (PathBuf, PathBuf) {
    let id = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("muniment-retention-{}-{id}", std::process::id()));
    (base.with_extension("sqlite3"), base.with_extension("cas"))
}

fn event(run: u64, seq: u64, event_type: &str, recorded_at: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: format!("0190b100-0000-7000-8000-{run:06}{seq:06}"),
        run_id: format!("0190b000-0000-7000-8000-{run:012}"),
        run_seq: seq,
        event_type: event_type.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: recorded_at.into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
        },
        provenance: Provenance {
            source: "test".into(),
            source_version: "1".into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

fn append_run(journal: &mut RunJournal, run: u64, status: &str, at: &str) -> String {
    let started = event(run, 1, "run.started", at);
    let run_id = started.run_id.clone();
    journal
        .append_batch(0, &[started, event(run, 2, status, at)])
        .unwrap();
    run_id
}

fn policy() -> RetentionPolicy {
    RetentionPolicy {
        max_age: Duration::days(30),
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap()
}

#[test]
fn deletes_only_expired_completed_cancelled_and_failed_runs() {
    let (db, _) = paths();
    let mut journal = RunJournal::open(&db).unwrap();
    let completed = append_run(&mut journal, 1, "run.completed", "2026-05-01T00:00:00Z");
    let cancelled = append_run(&mut journal, 2, "run.cancelled", "2026-05-01T00:00:00Z");
    let failed = append_run(&mut journal, 3, "run.failed", "2026-05-01T00:00:00Z");
    let fresh = append_run(&mut journal, 4, "run.completed", "2026-07-01T00:00:00Z");
    let active = event(5, 1, "run.started", "2026-05-01T00:00:00Z");
    let active_id = active.run_id.clone();
    journal.append(0, &active).unwrap();
    let attention = append_run(
        &mut journal,
        6,
        "run.needs_attention",
        "2026-05-01T00:00:00Z",
    );

    let outcome = apply_retention(&mut journal, None, &policy(), now()).unwrap();

    assert_eq!(outcome.deleted_run_ids, [completed, cancelled, failed]);
    assert!(journal.events(&fresh).unwrap().len() == 2);
    assert!(journal.events(&active_id).unwrap().len() == 1);
    assert!(journal.events(&attention).unwrap().len() == 2);
    let _ = fs::remove_file(db);
}

#[test]
fn skips_runs_that_fail_reduction_or_timestamp_parsing() {
    let (db, _) = paths();
    let mut journal = RunJournal::open(&db).unwrap();
    let invalid_reduction = append_run(&mut journal, 1, "run.started", "2026-05-01T00:00:00Z");
    let bad_time = append_run(&mut journal, 2, "run.completed", "2026-05-01T00:00:00Z");

    let raw = Connection::open(&db).unwrap();
    let stored = raw
        .query_row(
            "SELECT envelope_json FROM events WHERE run_id=?1 AND run_seq=2",
            [&bad_time],
            |row| row.get::<_, String>(0),
        )
        .unwrap()
        .replace("2026-05-01T00:00:00Z", "not-a-timestamp");
    raw.execute(
        "UPDATE events SET recorded_at=?1, envelope_json=?2 WHERE run_id=?3 AND run_seq=2",
        ("not-a-timestamp", stored, &bad_time),
    )
    .unwrap();
    drop(raw);

    let outcome = apply_retention(&mut journal, None, &policy(), now()).unwrap();
    assert!(outcome.deleted_run_ids.is_empty());
    assert_eq!(journal.events(&invalid_reduction).unwrap().len(), 2);
    assert_eq!(journal.events(&bad_time).unwrap().len(), 2);
    let _ = fs::remove_file(db);
}

#[test]
fn skips_full_event_reads_for_fresh_and_nonterminal_runs() {
    let (db, _) = paths();
    let mut journal = RunJournal::open(&db).unwrap();
    let fresh = append_run(&mut journal, 1, "run.completed", "2026-07-01T00:00:00Z");
    let active = event(2, 1, "run.started", "2026-05-01T00:00:00Z");
    let active_id = active.run_id.clone();
    journal.append(0, &active).unwrap();

    let raw = Connection::open(&db).unwrap();
    for run_id in [&fresh, &active_id] {
        raw.execute(
            "UPDATE events SET envelope_json='invalid' WHERE run_id=?1",
            [run_id],
        )
        .unwrap();
    }
    drop(raw);

    let outcome = apply_retention(&mut journal, None, &policy(), now()).unwrap();
    assert!(outcome.deleted_run_ids.is_empty());
    let run_ids = journal.run_ids().unwrap();
    assert_eq!(run_ids.len(), 2);
    assert!(run_ids.contains(&fresh));
    assert!(run_ids.contains(&active_id));
    let _ = fs::remove_file(db);
}

#[test]
fn keeps_expired_run_that_reduces_to_a_kept_status() {
    let (db, _) = paths();
    let mut journal = RunJournal::open(&db).unwrap();
    let old = "2026-05-01T00:00:00Z";
    journal
        .append_batch(
            0,
            &[
                event(1, 1, "run.started", old),
                event(1, 2, "run.completed", old),
                event(1, 3, "run.needs_attention", old),
            ],
        )
        .unwrap();
    let run_id = event(1, 1, "run.started", old).run_id;

    let outcome = apply_retention(&mut journal, None, &policy(), now()).unwrap();

    assert!(outcome.deleted_run_ids.is_empty());
    assert_eq!(journal.events(&run_id).unwrap().len(), 3);
    let _ = fs::remove_file(db);
}

#[test]
fn collects_deleted_only_objects_and_preserves_surviving_references() {
    let (db, cas_root) = paths();
    let store = LocalCas::open(&cas_root).unwrap();
    let deleted_only = store.put(b"deleted only").unwrap();
    let shared = store.put(b"shared").unwrap();
    let mut journal = RunJournal::open(&db).unwrap();

    let old = "2026-05-01T00:00:00Z";
    let mut old_reference = event(1, 2, "artifact.recorded", old);
    old_reference.payload = cas_payload(&deleted_only);
    let mut old_shared = event(1, 3, "artifact.recorded", old);
    old_shared.payload = cas_payload(&shared);
    journal
        .append_batch(
            0,
            &[
                event(1, 1, "run.started", old),
                old_reference,
                old_shared,
                event(1, 4, "run.completed", old),
            ],
        )
        .unwrap();

    let mut surviving_reference = event(2, 2, "artifact.recorded", old);
    surviving_reference.payload = cas_payload(&shared);
    journal
        .append_batch(0, &[event(2, 1, "run.started", old), surviving_reference])
        .unwrap();

    let outcome = apply_retention(&mut journal, Some(&store), &policy(), now()).unwrap();
    assert_eq!(
        outcome.collected_hashes,
        std::slice::from_ref(&deleted_only)
    );
    assert!(!store.has(&deleted_only).unwrap());
    assert!(store.has(&shared).unwrap());
    drop(store);
    let _ = fs::remove_file(db);
    let _ = fs::remove_dir_all(cas_root);
}

fn cas_payload(hash: &muniment_core::cas::ContentHash) -> EventPayload {
    EventPayload::Cas {
        payload_cas: CasReference {
            sha256: hash.to_string(),
            media_type: "application/octet-stream".into(),
            byte_length: 1,
        },
    }
}
