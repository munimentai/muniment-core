use chrono::{SecondsFormat, TimeZone, Utc};
use muniment_core::cas::LocalCas;
use muniment_core::journal::{
    reducer::{reduce, RunStatus},
    CasReference, Conflict, EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
    MAX_THREAD_TITLE_CHARS,
};
use rusqlite::Connection;
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::{Uuid, Version};

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

fn test_provenance() -> Provenance {
    Provenance {
        source: "desktop".into(),
        source_version: "1".into(),
        actor_id: Some("profile-a".into()),
        device_id: Some("device-a".into()),
        rpc_request_id: None,
        capability_versions: None,
        extra: BTreeMap::new(),
    }
}

fn thread_id(db: &TestDb) -> String {
    Connection::open(db.as_ref())
        .unwrap()
        .query_row(
            "SELECT thread_id FROM run_threads WHERE run_id=?1",
            [RUN],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn pending_permission_projection_is_bounded_and_hostile_inputs_are_invalid() {
    let cases = [
        EventPayload::Inline {
            payload_json: json!({
                "gate_id": "g", "kind": "select", "title": "Unsupported",
                "options": ["private option"]
            }),
        },
        EventPayload::Inline {
            payload_json: json!({
                "gate_id": "code-gate", "kind": "code_diff", "effect_id": "effect-1",
                "code_diff_id": "diff-1", "diff_sha256": "aa", "write_plan_sha256": "bb"
            }),
        },
        EventPayload::Inline {
            payload_json: json!({
                "gate_id": "g", "kind": "confirm", "title": "x".repeat(1_025),
                "message": "private"
            }),
        },
        cas_payload(&"ab".repeat(32)),
    ];
    let mut events = Vec::new();
    for (index, payload) in cases.into_iter().enumerate() {
        let seq = index as u64 + 1;
        let mut pending = event(seq);
        pending.event_type = "permission.requested".into();
        pending.payload = payload;
        events.push(pending);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let page = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 16 * 1024)
        .unwrap();
    assert_eq!(page.events.len(), 4);
    assert!(page.events.iter().all(|event| {
        event
            .pending_permission
            .as_ref()
            .is_some_and(|projection| !projection.valid)
    }));
    assert!(format!("{:?}", page.events).len() < 2_000);
}

#[test]
fn reopening_pre_projection_journal_backfills_valid_and_hostile_permissions() {
    let db = TestDb::new();
    let mut valid = event(1);
    valid.event_type = "permission.requested".into();
    valid.payload = EventPayload::Inline {
        payload_json: json!({
            "gate_id": "old-gate", "kind": "confirm", "title": "Allow old request?",
            "private": "do not project"
        }),
    };
    let mut hostile = event(2);
    hostile.event_type = "permission.requested".into();
    hostile.payload = EventPayload::Inline {
        payload_json: json!({
            "gate_id": "hostile-gate", "kind": "confirm", "title": "Hostile",
            "message": {"secret": "not text"}, "command": "private command"
        }),
    };
    let mut oversized = event(3);
    oversized.event_type = "permission.requested".into();
    oversized.payload = EventPayload::Inline {
        payload_json: json!({
            "gate_id": "oversized-private-gate", "kind": "confirm", "title": "Hostile",
            "message": "oversized-private-context", "private": "x".repeat(1_000_000)
        }),
    };
    {
        let mut journal = RunJournal::open(&db).unwrap();
        journal
            .append_batch(0, &[valid, hostile, oversized])
            .unwrap();
        journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    }
    let connection = Connection::open(&db).unwrap();
    connection
        .execute_batch("DROP TABLE permission_pending_projection")
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);

    let mut journal = RunJournal::open(&db).unwrap();
    let page = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 16 * 1024)
        .unwrap();
    let valid = page.events[0].pending_permission.as_ref().unwrap();
    assert!(valid.valid);
    assert_eq!(valid.gate_id, "old-gate");
    assert_eq!(valid.kind, "confirm");
    assert_eq!(valid.title, "Allow old request?");
    assert_eq!(valid.message, None);
    let hostile = page.events[1].pending_permission.as_ref().unwrap();
    assert!(!hostile.valid);
    assert_eq!(hostile.gate_id, "");
    assert_eq!(hostile.kind, "");
    assert_eq!(hostile.title, "");
    assert_eq!(hostile.message, None);
    let oversized = page.events[2].pending_permission.as_ref().unwrap();
    assert!(!oversized.valid);
    assert_eq!(oversized.gate_id, "");
    assert_eq!(oversized.kind, "");
    assert_eq!(oversized.title, "");
    assert_eq!(oversized.message, None);
    let projected = format!("{oversized:?}");
    assert!(projected.len() < 200);
    assert!(!projected.contains("oversized-private"));
}

#[test]
fn commit_subscription_registration_cannot_miss_a_racing_commit() {
    let db = TestDb::new();
    let mut subscriber = RunJournal::open(&db).unwrap();
    let mut writer = RunJournal::open(&db).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = barrier.clone();
    let handle = thread::spawn(move || {
        writer_barrier.wait();
        writer.append(0, &event(1)).unwrap();
    });

    barrier.wait();
    let receiver = subscriber.subscribe_commits(RUN).unwrap();
    let high_water = receiver.committed_high_water;
    handle.join().unwrap();

    if high_water == 0 {
        assert_eq!(receiver.try_recv().unwrap().run_seq, 1);
    } else {
        assert_eq!(high_water, 1);
        assert!(receiver.try_recv().is_err());
    }
}

#[test]
fn batch_commit_publishes_only_its_final_high_water() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(&db).unwrap();
    let receiver = journal.subscribe_commits(RUN).unwrap();

    let batch = [event(1), event(2), event(3)];
    journal.append_batch(0, &batch).unwrap();
    assert_eq!(receiver.try_recv().unwrap().run_seq, 3);
    assert!(receiver.try_recv().is_err());

    journal.append_batch(0, &batch).unwrap();
    assert!(
        receiver.try_recv().is_err(),
        "an exact retry emitted a hint"
    );
}

#[test]
fn commit_hints_cross_file_backed_journal_handles() {
    let db = TestDb::new();
    let mut subscriber = RunJournal::open(&db).unwrap();
    let mut writer = RunJournal::open(&db).unwrap();
    let receiver = subscriber.subscribe_commits(RUN).unwrap();
    let high_water = receiver.committed_high_water;
    assert_eq!(high_water, 0);

    writer.append_new_run("workspace-a", &event(1)).unwrap();
    assert_eq!(receiver.try_recv().unwrap().run_seq, 1);
}

#[test]
fn full_and_dropped_commit_subscribers_do_not_affect_appends() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(&db).unwrap();
    let slow = journal.subscribe_commits(RUN).unwrap();
    let dropped = journal.subscribe_commits(RUN).unwrap();
    drop(dropped);

    for seq in 1..=65 {
        journal.append(seq - 1, &event(seq)).unwrap();
    }
    assert_eq!(journal.events(RUN).unwrap().len(), 65);
    for expected in 1..=64 {
        assert_eq!(slow.try_recv().unwrap().run_seq, expected);
    }
    assert!(
        slow.try_recv().is_err(),
        "the bounded queue accepted overflow"
    );

    journal.append(65, &event(66)).unwrap();
    assert_eq!(slow.try_recv().unwrap().run_seq, 66);
}

#[test]
fn projection_late_pages_use_keyset_index_and_storage_stays_linear() {
    const DELTAS: u64 = 10_000;
    let db = TestDb::new();
    let mut journal = RunJournal::open(&db).unwrap();
    let mut events = Vec::with_capacity(DELTAS as usize + 1);
    let mut started = event(1);
    started.event_type = "run.started".into();
    events.push(started);
    for seq in 2..=DELTAS + 1 {
        let mut delta = event(seq);
        delta.event_type = "model.stream.delta".into();
        delta.payload = EventPayload::Inline {
            payload_json: json!({"text": "x"}),
        };
        events.push(delta);
    }
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    // A late page is addressed by ordinal rather than skipping all earlier rows.
    let late = journal
        .projected_thread_entries("workspace-1", RUN, DELTAS + 1, (DELTAS as i64 / 64) - 4, 3)
        .unwrap();
    assert_eq!(late.len(), 3);
    drop(journal);

    let connection = Connection::open(&db).unwrap();
    let stored_text: u64 = connection
        .query_row(
            "SELECT COALESCE(SUM(length(text)),0) FROM thread_projection_versions WHERE run_id=?1",
            [RUN],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        stored_text <= DELTAS * 64,
        "projection text grew beyond its fixed chunk amplification: {stored_text}"
    );

    let plan = connection
        .prepare(
            "EXPLAIN QUERY PLAN SELECT run_seq,kind,text FROM thread_projection_versions \
             INDEXED BY thread_projection_versions_page WHERE run_id=?1 AND ordinal>=?2 \
             AND valid_from_seq<=?3 AND (valid_until_seq IS NULL OR valid_until_seq>?3) \
             ORDER BY ordinal LIMIT ?4",
        )
        .unwrap()
        .query_map(rusqlite::params![RUN, 150_u64, DELTAS + 1, 3_u64], |row| {
            row.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(plan.contains("thread_projection_versions_page"), "{plan}");
    assert!(plan.contains("ordinal>?"), "{plan}");
    assert!(!plan.contains("SCAN"), "{plan}");
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
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
fn event_pages_are_bounded_ordered_and_cursor_is_run_bound() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append_batch(0, &[event(1), event(2), event(3)])
        .unwrap();
    let first = journal.event_page(RUN, 2, None).unwrap();
    assert_eq!(
        first
            .events
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    let cursor = first.next_cursor.unwrap();
    let second = journal.event_page(RUN, 2, Some(&cursor)).unwrap();
    assert_eq!(
        second
            .events
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        [3]
    );
    assert!(second.next_cursor.is_none());
    assert!(matches!(
        journal.event_page(RUN, 1, Some("forged")),
        Err(muniment_core::journal::RunEventPageError::InvalidCursor)
    ));
    assert!(matches!(
        journal.event_page("0190a100-0000-7000-8000-000000000099", 1, Some(&cursor)),
        Err(muniment_core::journal::RunEventPageError::InvalidCursor)
    ));
    assert!(matches!(
        journal.event_page("0190a100-0000-7000-8000-000000000099", 1, None),
        Err(muniment_core::journal::RunEventPageError::NotFoundOrInaccessible)
    ));
}

#[test]
fn workspace_event_pages_hide_runs_owned_by_another_workspace() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append(0, &event(1)).unwrap();
    journal.bind_run_workspace(RUN, "workspace-a").unwrap();

    assert!(matches!(
        journal.workspace_event_page("workspace-b", RUN, 1, None),
        Err(muniment_core::journal::RunEventPageError::NotFoundOrInaccessible)
    ));
    assert!(matches!(
        journal.workspace_event_page(
            "workspace-b",
            "0190a100-0000-7000-8000-000000000099",
            1,
            None
        ),
        Err(muniment_core::journal::RunEventPageError::NotFoundOrInaccessible)
    ));
    assert_eq!(
        journal
            .workspace_event_page("workspace-a", RUN, 1, None)
            .unwrap()
            .events
            .len(),
        1
    );
}

#[test]
fn run_workspace_creation_and_deletion_are_lifecycle_safe() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    assert!(journal.bind_run_workspace(RUN, "workspace-a").is_err());
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    assert!(journal
        .run_belongs_to_workspace(RUN, "workspace-a")
        .unwrap());
    journal.delete_run(RUN).unwrap();
    assert!(!journal
        .run_belongs_to_workspace(RUN, "workspace-a")
        .unwrap());
    journal.append_new_run("workspace-b", &event(1)).unwrap();
    assert!(journal
        .run_belongs_to_workspace(RUN, "workspace-b")
        .unwrap());
}

#[test]
fn account_actor_provenance_is_not_treated_as_workspace_evidence() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let mut first = event(1);
    first.provenance.actor_id = Some("workspace-a".into());
    journal.append(0, &first).unwrap();
    drop(journal);
    let journal = RunJournal::open(db.as_ref()).unwrap();
    assert!(!journal
        .run_belongs_to_workspace(RUN, "workspace-a")
        .unwrap());
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
fn fresh_and_shipped_v1_journals_migrate_to_head_idempotently() {
    let db = TestDb::new();
    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='events_run_order'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    raw.execute(
        "INSERT INTO thread_projection_entries(run_id,ordinal,run_seq,kind,text) \
         VALUES(?1,0,1,'user','hello')",
        [RUN],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 1).unwrap();
    drop(raw);

    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM thread_projection_versions WHERE run_id=?1",
            [RUN],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn populated_v3_journal_drops_duplicate_event_index_and_keeps_events_indexed() {
    let db = TestDb::new();
    {
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        journal
            .append_batch(0, &[event(1), event(2), event(3)])
            .unwrap();
    }
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute(
        "CREATE INDEX events_run_order ON events(run_id, run_seq)",
        [],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 3).unwrap();
    drop(raw);

    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    assert_eq!(
        journal
            .events(RUN)
            .unwrap()
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    drop(journal);

    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='events_run_order'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let plan = raw
        .prepare(
            "EXPLAIN QUERY PLAN \
             SELECT envelope_json FROM events WHERE run_id=?1 ORDER BY run_seq",
        )
        .unwrap()
        .query_map([RUN], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(plan.contains("SEARCH events USING INDEX"), "{plan}");
    assert!(!plan.contains("SCAN events"), "{plan}");
}

#[test]
fn populated_v2_journal_backfills_distinct_threads_with_workspace_scope() {
    let db = TestDb::new();
    let other_run = "0190a100-0000-7000-8000-000000000002";
    {
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        journal.append_new_run("workspace-a", &event(1)).unwrap();
        journal
            .append_new_run(
                "workspace-b",
                &event_for(
                    other_run,
                    "0190a100-0000-7000-8000-000000000102",
                    1,
                    "future.event",
                ),
            )
            .unwrap();
    }
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch("DROP TABLE run_threads; DROP TABLE thread_events;")
        .unwrap();
    raw.pragma_update(None, "user_version", 2).unwrap();
    drop(raw);

    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(DISTINCT thread_id) FROM run_threads",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM thread_events te JOIN run_threads rt \
             ON rt.thread_id=te.thread_id WHERE te.thread_seq=1 \
             AND te.event_type='thread.created' AND rt.thread_run_ordinal=1 \
             AND json_extract(te.envelope_json,'$.payload_json.migration_backfill')=1 \
             AND json_extract(te.envelope_json,'$.payload_json.workspace') \
                 IN ('workspace-a','workspace-b')",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
}

#[test]
fn populated_v2_journal_backfills_run_without_workspace_scope() {
    let db = TestDb::new();
    {
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        journal.append(0, &event(1)).unwrap();
    }
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM run_workspaces WHERE run_id=?1",
            [RUN],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    raw.execute_batch("DROP TABLE run_threads; DROP TABLE thread_events;")
        .unwrap();
    raw.pragma_update(None, "user_version", 2).unwrap();
    drop(raw);

    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    let (thread_id, ordinal): (String, i64) = raw
        .query_row(
            "SELECT thread_id,thread_run_ordinal FROM run_threads WHERE run_id=?1",
            [RUN],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        Uuid::parse_str(&thread_id).unwrap().get_version(),
        Some(Version::SortRand)
    );
    assert_eq!(ordinal, 1);
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM thread_events WHERE thread_id=?1 \
             AND thread_seq=1 AND event_type='thread.created' \
             AND json_extract(envelope_json,'$.payload_json.migration_backfill')=1 \
             AND json_type(envelope_json,'$.payload_json.workspace')='null'",
            [&thread_id],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn schema_v3_requires_each_thread_table() {
    for statements in [
        "DROP TABLE run_threads;",
        "DROP TABLE thread_events;",
        "DROP TABLE run_threads; DROP TABLE thread_events;",
    ] {
        let db = TestDb::new();
        RunJournal::open(db.as_ref()).unwrap();
        let raw = Connection::open(db.as_ref()).unwrap();
        raw.execute_batch(statements).unwrap();
        drop(raw);
        assert!(matches!(
            RunJournal::open(db.as_ref()),
            Err(JournalError::Corrupt(_))
        ));
    }
}

#[test]
fn schema_v3_rejects_four_named_objects_with_a_missing_column_as_corrupt() {
    let db = TestDb::new();
    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch(
        "DROP INDEX run_threads_thread_run;
         DROP TABLE run_threads;
         CREATE TABLE run_threads(
           run_id TEXT PRIMARY KEY NOT NULL,
           thread_id TEXT NOT NULL
         ) STRICT;
         CREATE INDEX run_threads_thread_run ON run_threads(thread_id);",
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Corrupt(_))
    ));
}

#[test]
fn schema_v3_rejects_thread_identity_invariant_violations() {
    for mutation in [
        "DELETE FROM run_threads",
        "DELETE FROM thread_events",
        "UPDATE thread_events SET thread_seq=2, \
         envelope_json=json_replace(envelope_json,'$.thread_seq',2)",
    ] {
        let db = TestDb::new();
        {
            let mut journal = RunJournal::open(db.as_ref()).unwrap();
            journal.append_new_run("workspace-a", &event(1)).unwrap();
        }
        let raw = Connection::open(db.as_ref()).unwrap();
        raw.execute_batch(mutation).unwrap();
        drop(raw);
        assert!(matches!(
            RunJournal::open(db.as_ref()),
            Err(JournalError::Corrupt(_))
        ));
    }

    let db = TestDb::new();
    let other_run = "0190a100-0000-7000-8000-000000000002";
    {
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        journal.append_new_run("workspace-a", &event(1)).unwrap();
        journal
            .append_new_run(
                "workspace-a",
                &event_for(
                    other_run,
                    "0190a100-0000-7000-8000-000000000102",
                    1,
                    "future.event",
                ),
            )
            .unwrap();
    }
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute("DELETE FROM events WHERE run_id=?1", [other_run])
        .unwrap();
    raw.execute("DELETE FROM run_threads WHERE run_id=?1", [other_run])
        .unwrap();
    drop(raw);
    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Corrupt(_))
    ));
}

#[test]
fn schema_v3_rejects_duplicate_run_ordinals_within_a_thread() {
    let db = TestDb::new();
    let other_run = "0190a100-0000-7000-8000-000000000002";
    {
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        journal.append_new_run("workspace-a", &event(1)).unwrap();
        journal
            .append_new_run(
                "workspace-a",
                &event_for(
                    other_run,
                    "0190a100-0000-7000-8000-000000000102",
                    1,
                    "future.event",
                ),
            )
            .unwrap();
    }
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch(
        "ALTER TABLE run_threads RENAME TO old_run_threads;
         CREATE TABLE run_threads(
           run_id TEXT PRIMARY KEY NOT NULL,
           thread_id TEXT NOT NULL,
           thread_run_ordinal INTEGER NOT NULL CHECK(thread_run_ordinal > 0)
         ) STRICT;
         INSERT INTO run_threads
           SELECT run_id,thread_id,thread_run_ordinal FROM old_run_threads
           WHERE run_id='0190a100-0000-7000-8000-000000000001';
         INSERT INTO run_threads
           SELECT run_id,
             (SELECT thread_id FROM run_threads
              WHERE run_id='0190a100-0000-7000-8000-000000000001'),
             1
           FROM old_run_threads
           WHERE run_id='0190a100-0000-7000-8000-000000000002';
         DROP TABLE old_run_threads;
         CREATE INDEX run_threads_thread_run
           ON run_threads(thread_id,thread_run_ordinal);",
    )
    .unwrap();
    drop(raw);

    match RunJournal::open(db.as_ref()) {
        Err(JournalError::Corrupt(message)) => {
            assert_eq!(
                message,
                "thread run ordinals must be unique within each thread"
            )
        }
        Err(error) => panic!("{error}"),
        Ok(_) => panic!("journal with duplicate thread run ordinals opened"),
    }
}

#[test]
fn deleting_a_run_leaves_a_valid_thread_ordinal_gap() {
    let db = TestDb::new();
    let second_run = "0190a100-0000-7000-8000-000000000002";
    let third_run = "0190a100-0000-7000-8000-000000000003";
    {
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        let thread_id = journal.append_new_run("workspace-a", &event(1)).unwrap();
        journal
            .append_new_run_in_thread(
                "workspace-a",
                &thread_id,
                &event_for(
                    second_run,
                    "0190a100-0000-7000-8000-000000000102",
                    1,
                    "future.event",
                ),
            )
            .unwrap();
        journal
            .append_new_run_in_thread(
                "workspace-a",
                &thread_id,
                &event_for(
                    third_run,
                    "0190a100-0000-7000-8000-000000000103",
                    1,
                    "future.event",
                ),
            )
            .unwrap();
        journal.delete_run(second_run).unwrap();
    }

    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    let ordinals = raw
        .prepare("SELECT thread_run_ordinal FROM run_threads ORDER BY thread_run_ordinal")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(ordinals, [1, 3]);
}

#[test]
fn new_run_in_thread_uses_next_ordinal_and_mirrors_run_creation() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let stamped_thread = journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    assert_eq!(stamped_thread, thread_id);
    let other_run = "0190a100-0000-7000-8000-000000000002";
    let mut first = event_for(
        other_run,
        "0190a100-0000-7000-8000-000000000102",
        1,
        "user.prompt.submitted",
    );
    first.payload = EventPayload::Inline {
        payload_json: json!({"prompt": "second prompt"}),
    };

    journal
        .append_new_run_in_thread("workspace-a", &thread_id, &first)
        .unwrap();

    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM events e \
             JOIN run_workspaces rw ON rw.run_id=e.run_id \
             JOIN run_threads rt ON rt.run_id=e.run_id \
             WHERE e.run_id=?1 AND e.run_seq=1 AND rw.workspace='workspace-a' \
             AND rt.thread_id=?2 AND rt.thread_run_ordinal=2",
            (other_run, &thread_id),
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM thread_projection_entries WHERE run_id=?1",
            [other_run],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn run_less_thread_validates_and_accepts_its_first_run() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let mut provenance = test_provenance();
    provenance
        .extra
        .insert("attach_profile".into(), json!("profile-a"));
    let thread_id = journal
        .create_thread("workspace-a", "2026-07-10T12:00:00Z", provenance.clone())
        .unwrap();

    drop(journal);
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let mut first_run = event_for(
        "0190a100-0000-7000-8000-000000000002",
        "0190a100-0000-7000-8000-000000000102",
        1,
        "user.prompt.submitted",
    );
    first_run.provenance = provenance;
    journal
        .append_new_run_in_thread("workspace-a", &thread_id, &first_run)
        .unwrap();

    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT thread_run_ordinal FROM run_threads WHERE thread_id=?1",
            [&thread_id],
            |row| row.get::<_, u64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn new_run_in_thread_rejections_write_nothing() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    let provenance = test_provenance();
    let new_run = || {
        event_for(
            "0190a100-0000-7000-8000-000000000002",
            "0190a100-0000-7000-8000-000000000102",
            1,
            "future.event",
        )
    };

    for (workspace, selected_thread) in [
        ("workspace-a", "0190a100-0000-7000-8000-000000000099"),
        ("workspace-b", thread_id.as_str()),
    ] {
        assert!(matches!(
            journal.append_new_run_in_thread(workspace, selected_thread, &new_run()),
            Err(JournalError::InvalidEnvelope(_))
        ));
    }
    assert!(matches!(
        journal.append_new_run_in_thread("workspace-a", &thread_id, &event(1)),
        Err(JournalError::Conflict(Conflict::Sequence {
            run_seq: 1,
            ..
        }))
    ));
    journal
        .append_thread_deleted(1, &thread_id, "2026-07-10T12:00:01Z", &provenance)
        .unwrap();
    assert!(matches!(
        journal.append_new_run_in_thread("workspace-a", &thread_id, &new_run()),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(
        Connection::open(db.as_ref())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );

    let mut invalid_seq = new_run();
    invalid_seq.run_seq = 2;
    assert!(matches!(
        journal.append_new_run_in_thread("workspace-a", &thread_id, &invalid_seq),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert!(matches!(
        journal.append_new_run_in_thread("", &thread_id, &new_run()),
        Err(JournalError::InvalidEnvelope(_))
    ));
}

#[test]
fn new_run_is_stamped_and_deletion_removes_its_empty_thread() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    let thread_id: String = raw
        .query_row(
            "SELECT thread_id FROM run_threads WHERE run_id=?1 \
             AND thread_run_ordinal=1",
            [RUN],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM thread_events WHERE thread_id=?1 \
             AND thread_seq=1 AND event_type='thread.created'",
            [&thread_id],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    drop(raw);

    journal.delete_run(RUN).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT (SELECT COUNT(*) FROM run_threads WHERE run_id=?1) + \
             (SELECT COUNT(*) FROM thread_events WHERE thread_id=?2)",
            (RUN, thread_id),
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn thread_rename_and_delete_append_validated_canonical_events() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    let provenance = test_provenance();
    let at = "2026-07-10T12:00:01Z";

    journal
        .append_thread_title_renamed(1, &thread_id, "  New title  ", at, &provenance)
        .unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    let envelope: String = raw
        .query_row(
            "SELECT envelope_json FROM thread_events WHERE thread_id=?1 AND thread_seq=2",
            [&thread_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        envelope,
        format!(
            "{{\"envelope_version\":1,\"event_id\":\"{}\",\"event_type\":\"thread.title.renamed\",\
             \"event_version\":1,\"payload_json\":{{\"title\":\"New title\"}},\
             \"provenance\":{{\"actor_id\":\"profile-a\",\"device_id\":\"device-a\",\
             \"source\":\"desktop\",\"source_version\":\"1\"}},\"recorded_at\":\"{at}\",\
             \"thread_id\":\"{thread_id}\",\"thread_seq\":2}}",
            serde_json::from_str::<serde_json::Value>(&envelope).unwrap()["event_id"]
                .as_str()
                .unwrap()
        )
    );
    drop(raw);

    journal
        .append_thread_deleted(2, &thread_id, "2026-07-10T12:00:02Z", &provenance)
        .unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM thread_events WHERE thread_id=?1 AND thread_seq=3 \
             AND event_type='thread.deleted' \
             AND json_extract(envelope_json,'$.provenance.actor_id')='profile-a' \
             AND json(envelope_json)=json(envelope_json)",
            [&thread_id],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn last_thread_seq_returns_the_tail_or_zero() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    assert_eq!(
        journal
            .last_thread_seq("0190a100-0000-7000-8000-000000000099")
            .unwrap(),
        0
    );
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 1);
    journal
        .append_thread_title_renamed(
            1,
            &thread_id,
            "New title",
            "2026-07-10T12:00:01Z",
            &test_provenance(),
        )
        .unwrap();
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 2);
}

#[test]
fn thread_title_boundaries_and_conflicts_write_no_events() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    let provenance = test_provenance();
    let at = "2026-07-10T12:00:01Z";
    let over_limit = "é".repeat(MAX_THREAD_TITLE_CHARS + 1);

    for invalid in [" \n\t ", over_limit.as_str()] {
        assert!(matches!(
            journal.append_thread_title_renamed(1, &thread_id, invalid, at, &provenance),
            Err(JournalError::InvalidEnvelope(_))
        ));
    }
    assert!(matches!(
        journal.append_thread_title_renamed(0, &thread_id, "stale", at, &provenance),
        Err(JournalError::Conflict(Conflict::StaleSequence {
            expected: 0,
            actual: 1
        }))
    ));
    assert!(matches!(
        journal.append_thread_deleted(0, "0190a100-0000-7000-8000-000000000099", at, &provenance),
        Err(JournalError::InvalidEnvelope(_))
    ));
    journal
        .append_thread_title_renamed(
            1,
            &thread_id,
            &"é".repeat(MAX_THREAD_TITLE_CHARS),
            at,
            &provenance,
        )
        .unwrap();
    assert_eq!(
        Connection::open(db.as_ref())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM thread_events WHERE thread_id=?1",
                [&thread_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn deleted_thread_rejects_every_append_without_writing() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    let provenance = test_provenance();
    journal
        .append_thread_deleted(1, &thread_id, "2026-07-10T12:00:01Z", &provenance)
        .unwrap();

    assert!(matches!(
        journal.append_thread_title_renamed(
            2,
            &thread_id,
            "too late",
            "2026-07-10T12:00:02Z",
            &provenance
        ),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert!(matches!(
        journal.append_thread_deleted(2, &thread_id, "2026-07-10T12:00:02Z", &provenance),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(
        Connection::open(db.as_ref())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM thread_events WHERE thread_id=?1",
                [&thread_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn validation_rejects_an_event_after_thread_deletion() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    let provenance = test_provenance();
    journal
        .append_thread_title_renamed(1, &thread_id, "title", "2026-07-10T12:00:01Z", &provenance)
        .unwrap();
    journal
        .append_thread_deleted(2, &thread_id, "2026-07-10T12:00:02Z", &provenance)
        .unwrap();
    drop(journal);

    let raw = Connection::open(db.as_ref()).unwrap();
    let renamed: String = raw
        .query_row(
            "SELECT envelope_json FROM thread_events WHERE thread_id=?1 AND thread_seq=2",
            [&thread_id],
            |row| row.get(0),
        )
        .unwrap();
    let event_id = "0190a100-0000-7000-8000-000000000099";
    let later = renamed
        .replace(
            serde_json::from_str::<serde_json::Value>(&renamed).unwrap()["event_id"]
                .as_str()
                .unwrap(),
            event_id,
        )
        .replace("\"thread_seq\":2", "\"thread_seq\":4");
    raw.execute(
        "INSERT INTO thread_events VALUES(?1,?2,4,'thread.title.renamed',1,1,\
         '2026-07-10T12:00:01Z',?3)",
        (&event_id, &thread_id, later),
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Corrupt(_))
    ));
}

#[test]
fn validation_allows_an_unknown_event_before_thread_deletion() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append_new_run("workspace-a", &event(1)).unwrap();
    let thread_id = thread_id(&db);
    let provenance = test_provenance();
    journal
        .append_thread_deleted(1, &thread_id, "2026-07-10T12:00:02Z", &provenance)
        .unwrap();
    drop(journal);

    let raw = Connection::open(db.as_ref()).unwrap();
    let deleted: String = raw
        .query_row(
            "SELECT envelope_json FROM thread_events WHERE thread_id=?1 AND thread_seq=2",
            [&thread_id],
            |row| row.get(0),
        )
        .unwrap();
    let deleted = deleted.replace("\"thread_seq\":2", "\"thread_seq\":3");
    raw.execute(
        "UPDATE thread_events SET thread_seq=3,envelope_json=?1 \
         WHERE thread_id=?2 AND thread_seq=2",
        (&deleted, &thread_id),
    )
    .unwrap();
    let event_id = "0190a100-0000-7000-8000-000000000099";
    let unknown = format!(
        "{{\"envelope_version\":1,\"event_id\":\"{event_id}\",\"event_type\":\"thread.future\",\
         \"event_version\":1,\"payload_json\":{{\"future\":true}},\
         \"provenance\":{{\"actor_id\":\"profile-a\",\"device_id\":\"device-a\",\
         \"source\":\"desktop\",\"source_version\":\"1\"}},\
         \"recorded_at\":\"2026-07-10T12:00:01Z\",\
         \"thread_id\":\"{thread_id}\",\"thread_seq\":2}}"
    );
    raw.execute(
        "INSERT INTO thread_events VALUES(?1,?2,2,'thread.future',1,1,\
         '2026-07-10T12:00:01Z',?3)",
        (&event_id, &thread_id, unknown),
    )
    .unwrap();
    drop(raw);

    RunJournal::open(db.as_ref()).unwrap();
}

#[test]
fn failed_step_three_rolls_back_schema_and_version() {
    let db = TestDb::new();
    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch(
        "DROP TABLE run_threads;
         DROP TABLE thread_events;
         CREATE TABLE thread_events(bad TEXT) STRICT;",
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 2).unwrap();
    drop(raw);

    assert!(RunJournal::open(db.as_ref()).is_err());
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='run_threads'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn newer_schema_version_fails_without_writing() {
    let db = TestDb::new();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute("CREATE TABLE future_table(value TEXT)", [])
        .unwrap();
    raw.pragma_update(None, "user_version", 99).unwrap();
    let before: Vec<String> = raw
        .prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(raw);

    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Corrupt(_))
    ));
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        99
    );
    let after: Vec<String> = raw
        .prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn head_schema_missing_journal_metadata_fails_without_recreating_it() {
    let db = TestDb::new();
    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch("DROP TABLE journal_metadata").unwrap();
    drop(raw);

    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Sqlite(_))
    ));
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' \
             AND name='journal_metadata'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn failed_migration_rolls_back_schema_and_version() {
    let db = TestDb::new();
    RunJournal::open(db.as_ref()).unwrap();
    let raw = Connection::open(db.as_ref()).unwrap();
    raw.execute_batch(
        "DROP TABLE run_workspaces;
         DROP TABLE thread_projection_entries;
         DROP TABLE thread_projection_history;
         DROP TABLE thread_projection_versions;
         DROP TABLE permission_pending_projection;
         DROP TABLE receipt_projection;",
    )
    .unwrap();
    raw.execute(
        "INSERT INTO events VALUES(?1,?2,2,'future.event',1,1,'2026-07-10T12:00:00Z',?3)",
        (
            "0190a100-0000-7000-8000-000000000099",
            RUN,
            serde_json::to_string(&event(2)).unwrap(),
        ),
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 1).unwrap();
    drop(raw);

    assert!(matches!(
        RunJournal::open(db.as_ref()),
        Err(JournalError::Corrupt(_))
    ));
    let raw = Connection::open(db.as_ref()).unwrap();
    assert_eq!(
        raw.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' \
             AND name='thread_projection_versions'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
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
fn catch_up_projects_only_a_bounded_authoritative_completion_receipt() {
    let mut completed = event(1);
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({
            "receipt": {
                "route": "cloud", "cost": "$0.01",
                "capabilities": [{"name": "search", "version": "1"}]
            },
            "private": "must not be projected"
        }),
    };
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append(0, &completed).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let page = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 64 * 1024)
        .unwrap();
    let receipt = page.events[0].receipt.as_ref().unwrap();
    assert_eq!(receipt.route.as_deref(), Some("cloud"));
    assert_eq!(receipt.model, None);
    assert_eq!(receipt.cost.as_deref(), Some("$0.01"));
    assert_eq!(receipt.time, None);
    assert_eq!(receipt.capabilities[0].name, "search");
    assert!(!format!("{receipt:?}").contains("must not be projected"));
}

#[test]
fn catch_up_does_not_project_memory_recall_payloads() {
    let mut recalled = event(1);
    recalled.event_type = "memory.recalled".into();
    recalled.payload = EventPayload::Inline {
        payload_json: json!({
            "files": ["memory/private.md"], "item_cap": 5,
            "character_budget": 4000, "timeout_milliseconds": 200,
            "query": "private query", "thread": "thread-1",
            "source_file_state": "current"
        }),
    };
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append(0, &recalled).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let page = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 64 * 1024)
        .unwrap();
    let projection = &page.events[0];
    assert_eq!(projection.event_type, "memory.recalled");
    assert!(!format!("{projection:?}").contains("private query"));
    assert!(!format!("{projection:?}").contains("memory/private.md"));
}

#[test]
fn completion_receipt_projection_rejects_malformed_and_oversized_values() {
    let payloads = [
        json!({"receipt": {"route": 7}}),
        json!({"receipt": {"route": "x".repeat(1_025)}}),
        json!({"receipt": {"route": "cloud", "secret": "do not leak"}}),
        json!({"receipt": {"capabilities": [{"name": "search", "version": "x".repeat(1_025)}]}}),
    ];
    let events = payloads
        .into_iter()
        .enumerate()
        .map(|(index, payload_json)| {
            let mut completed = event(index as u64 + 1);
            completed.event_type = "run.completed".into();
            completed.payload = EventPayload::Inline { payload_json };
            completed
        })
        .collect::<Vec<_>>();
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let page = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 64 * 1024)
        .unwrap();
    assert!(page.events.iter().all(|event| event.receipt.is_none()));
    assert!(!format!("{:?}", page.events).contains("do not leak"));
}

#[test]
fn receipt_backfill_fails_closed_and_stream_byte_limit_counts_projection() {
    let db = TestDb::new();
    let mut completed = event(1);
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({"receipt": {"route": "cloud", "cost": "$0.01"}}),
    };
    let mut corrupt = event(2);
    corrupt.event_type = "run.completed".into();
    corrupt.payload = EventPayload::Inline {
        payload_json: json!({"receipt": {"route": "cloud", "secret": "historical secret"}}),
    };
    {
        let mut journal = RunJournal::open(&db).unwrap();
        journal.append_batch(0, &[completed, corrupt]).unwrap();
        journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    }
    let connection = Connection::open(&db).unwrap();
    connection
        .execute_batch("DROP TABLE receipt_projection")
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);

    let mut journal = RunJournal::open(&db).unwrap();
    let page = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 64 * 1024)
        .unwrap();
    assert_eq!(
        page.events[0].receipt.as_ref().unwrap().route.as_deref(),
        Some("cloud")
    );
    assert!(page.events[1].receipt.is_none());
    assert!(!format!("{:?}", page.events).contains("historical secret"));

    let too_small = journal
        .workspace_catch_up("workspace-1", RUN, 0, 10, 1)
        .unwrap();
    assert!(too_small.events.is_empty());
    assert!(!too_small.exhausted);
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
