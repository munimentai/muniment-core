use chrono::{SecondsFormat, TimeZone, Utc};
use muniment_core::cas::LocalCas;
use muniment_core::journal::{
    reducer::{reduce, RunStatus},
    CasReference, Conflict, EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
};
use rusqlite::Connection;
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DB: AtomicU64 = AtomicU64::new(0);
struct TestDb(PathBuf);
impl TestDb {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "muniment-journal-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }
}
impl AsRef<Path> for TestDb {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", self.0.display(), suffix));
        }
    }
}

const RUN: &str = "0190a100-0000-7000-8000-000000000001";
fn event(seq: u64) -> EventEnvelope {
    EventEnvelope {
        event_id: format!("0190a100-0000-7000-8000-{seq:012}"),
        run_id: RUN.into(),
        run_seq: seq,
        event_type: "future.event".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-07-10T12:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({"seq": seq}),
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
        extra: BTreeMap::from([("future_field".into(), json!({"preserved": true}))]),
    }
}

fn event_for(run_id: &str, event_id: &str, seq: u64, event_type: &str) -> EventEnvelope {
    let mut event = event(seq);
    event.run_id = run_id.into();
    event.event_id = event_id.into();
    event.event_type = event_type.into();
    event
}

fn cas_payload(hash: &str) -> EventPayload {
    EventPayload::Cas {
        payload_cas: CasReference {
            sha256: hash.into(),
            media_type: "application/json".into(),
            byte_length: 1,
        },
    }
}

#[test]
fn first_and_ordered_batch_append_survive_reopen() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(1)).unwrap();
    journal.append_batch(1, &[event(2), event(3)]).unwrap();
    drop(journal);
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let found = journal.events(RUN).unwrap();
    assert_eq!(
        found.iter().map(|e| e.run_seq).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(found[0].extra["future_field"], json!({"preserved": true}));
}

#[test]
fn durable_run_index_reopens_in_first_recorded_order() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(1)).unwrap();

    let second_run = "0190a100-0000-7000-8000-000000000002";
    let mut second = event(1);
    second.event_id = "0190a100-0000-7000-8000-000000000099".into();
    second.run_id = second_run.into();
    second.recorded_at = "2026-07-10T12:00:01Z".into();
    journal.append(0, &second).unwrap();
    drop(journal);

    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    assert_eq!(journal.run_ids().unwrap(), [RUN, second_run]);
    let replayed = journal.events(RUN).unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].run_id, RUN);
    assert_eq!(replayed[0].run_seq, 1);
}

#[test]
fn recorded_at_requires_canonical_whole_second_format() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();

    let mut noncanonical = event(1);
    noncanonical.recorded_at = "2026-07-11T12:00:00.000Z".into();
    assert!(matches!(
        journal.append(0, &noncanonical),
        Err(JournalError::InvalidEnvelope(_))
    ));

    let mut canonical = event(1);
    canonical.recorded_at = Utc
        .with_ymd_and_hms(2026, 7, 11, 12, 0, 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::AutoSi, true);
    assert_eq!(canonical.recorded_at, "2026-07-11T12:00:00Z");
    journal.append(0, &canonical).unwrap();
    drop(journal);

    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let found = journal.events(RUN).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].event_id, canonical.event_id);
    assert_eq!(found[0].recorded_at, canonical.recorded_at);
}

#[test]
fn conflicts_and_invalid_batches_change_no_rows() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(1)).unwrap();
    let mut stale = event(1);
    stale.event_id = "0190a100-0000-7000-8000-000000000098".into();
    assert!(matches!(
        journal.append(0, &stale),
        Err(JournalError::Conflict(Conflict::StaleSequence { .. }))
    ));
    assert!(matches!(
        journal.append_batch(1, &[event(2), event(4)]),
        Err(JournalError::InvalidEnvelope(_))
    ));
    let mut reused = event(2);
    reused.run_seq = 1;
    assert!(matches!(
        journal.append(1, &reused),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(journal.events(RUN).unwrap().len(), 1);
}

#[test]
fn duplicate_is_idempotent_but_changed_duplicate_conflicts_atomically() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_batch(0, &[event(1), event(2)]).unwrap();
    journal.append_batch(0, &[event(1), event(2)]).unwrap();
    let mut changed = event(2);
    changed.event_type = "changed".into();
    assert!(matches!(
        journal.append_batch(0, &[event(1), changed]),
        Err(JournalError::Conflict(Conflict::EventId { .. }))
    ));
    assert_eq!(journal.events(RUN).unwrap()[1].event_type, "future.event");
}

#[test]
fn open_detects_invalid_sequence_and_schema_version() {
    let db = TestDb::new();
    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute(
        "INSERT INTO events VALUES(?1,?2,2,'bad',1,1,'2026-07-10T12:00:00Z',?3)",
        (
            "0190a100-0000-7000-8000-000000000099",
            RUN,
            serde_json::to_string(&event(2)).unwrap(),
        ),
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Corrupt(_))
    ));

    let db2 = TestDb::new();
    RunJournal::open(db2.as_ref()).unwrap();
    let raw = Connection::open(db2.as_ref()).unwrap();
    raw.pragma_update(None, "user_version", 99).unwrap();
    drop(raw);
    assert!(matches!(
        RunJournal::open(db2.as_ref()),
        Err(JournalError::Corrupt(_))
    ));
}

#[test]
fn delete_run_returns_cas_hashes_and_preserves_shared_references_and_other_runs() {
    const OTHER_RUN: &str = "0190a100-0000-7000-8000-000000000002";
    const SHARED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DELETED_ONLY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();

    let inline = event_for(
        RUN,
        "0190a100-0000-7000-8000-000000000011",
        1,
        "run.started",
    );
    let mut shared = event_for(
        RUN,
        "0190a100-0000-7000-8000-000000000012",
        2,
        "future.event",
    );
    shared.payload = cas_payload(SHARED);
    let mut deleted_only = event_for(
        RUN,
        "0190a100-0000-7000-8000-000000000013",
        3,
        "future.event",
    );
    deleted_only.payload = cas_payload(DELETED_ONLY);
    journal
        .append_batch(0, &[inline, shared, deleted_only])
        .unwrap();

    let mut other_start = event_for(
        OTHER_RUN,
        "0190a100-0000-7000-8000-000000000021",
        1,
        "run.started",
    );
    other_start.payload = cas_payload(SHARED);
    let other_next = event_for(
        OTHER_RUN,
        "0190a100-0000-7000-8000-000000000022",
        2,
        "future.event",
    );
    journal.append_batch(0, &[other_start, other_next]).unwrap();

    assert_eq!(
        journal.delete_run(RUN).unwrap(),
        HashSet::from([SHARED.parse().unwrap(), DELETED_ONLY.parse().unwrap()])
    );
    assert_eq!(journal.run_ids().unwrap(), [OTHER_RUN]);
    assert!(journal.events(RUN).unwrap().is_empty());
    assert_eq!(
        journal.referenced_hashes().unwrap(),
        HashSet::from([SHARED.parse().unwrap()])
    );
    let untouched = journal.events(OTHER_RUN).unwrap();
    assert_eq!(
        untouched
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(reduce(&untouched).unwrap().status, RunStatus::Active);
}

#[test]
fn collection_after_run_deletion_preserves_objects_referenced_by_other_runs() {
    const OTHER_RUN: &str = "0190a100-0000-7000-8000-000000000002";
    let db = TestDb::new();
    let cas_root = db.0.with_extension("cas");
    let store = LocalCas::open(&cas_root).unwrap();
    let shared = store.put(b"shared").unwrap();
    let deleted_only = store.put(b"deleted only").unwrap();
    let orphan = store.put(b"orphan").unwrap();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();

    let mut first_shared = event_for(
        RUN,
        "0190a100-0000-7000-8000-000000000031",
        1,
        "future.event",
    );
    first_shared.payload = cas_payload(shared.as_str());
    let mut first_only = event_for(
        RUN,
        "0190a100-0000-7000-8000-000000000032",
        2,
        "future.event",
    );
    first_only.payload = cas_payload(deleted_only.as_str());
    journal
        .append_batch(0, &[first_shared, first_only])
        .unwrap();

    let mut other_shared = event_for(
        OTHER_RUN,
        "0190a100-0000-7000-8000-000000000033",
        1,
        "future.event",
    );
    other_shared.payload = cas_payload(shared.as_str());
    journal.append(0, &other_shared).unwrap();

    assert_eq!(
        store
            .collect_unreferenced(&journal.referenced_hashes().unwrap())
            .unwrap(),
        HashSet::from([orphan])
    );
    store.verify(&shared).unwrap();
    store.verify(&deleted_only).unwrap();

    journal.delete_run(RUN).unwrap();
    let keep = journal.referenced_hashes().unwrap();
    assert_eq!(
        store.collect_unreferenced(&keep).unwrap(),
        HashSet::from([deleted_only.clone()])
    );
    assert!(!store.has(&deleted_only).unwrap());
    assert!(store.has(&shared).unwrap());
    store.verify(&shared).unwrap();
    drop(store);
    fs::remove_dir_all(cas_root).unwrap();
}

#[test]
fn delete_unknown_run_is_a_no_op() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(1)).unwrap();

    assert!(journal
        .delete_run("0190a100-0000-7000-8000-000000000099")
        .unwrap()
        .is_empty());
    assert_eq!(journal.events(RUN).unwrap()[0].event_id, event(1).event_id);
}

#[test]
fn failed_delete_leaves_the_run_untouched() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_batch(0, &[event(1), event(2)]).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER reject_delete BEFORE DELETE ON events
         BEGIN SELECT RAISE(ABORT, 'reject delete'); END;",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        journal.delete_run(RUN),
        Err(JournalError::Sqlite(_))
    ));
    assert_eq!(
        journal
            .events(RUN)
            .unwrap()
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}
