use chrono::{SecondsFormat, TimeZone, Utc};
use muniment_core::journal::{
    Conflict, EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
};
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeMap;
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

#[test]
fn first_and_ordered_batch_append_survive_reopen() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(1)).unwrap();
    journal.append_batch(1, &[event(2), event(3)]).unwrap();
    drop(journal);
    let journal = RunJournal::open(db.as_ref()).unwrap();
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

    let journal = RunJournal::open(db.as_ref()).unwrap();
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

    let journal = RunJournal::open(db.as_ref()).unwrap();
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
