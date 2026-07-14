use muniment_core::journal::compaction::{CompactionError, CompactionFault};
use muniment_core::journal::{CasReference, EventEnvelope, EventPayload, Provenance, RunJournal};
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

struct TestDb(PathBuf);
impl TestDb {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "muniment-compaction-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        )))
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
        if let Some(parent) = self.0.parent() {
            if let Some(name) = self.0.file_name() {
                let prefix = format!(".{}.compact-", name.to_string_lossy());
                if let Ok(entries) = fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        if entry.file_name().to_string_lossy().starts_with(&prefix) {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}

const RUN: &str = "0190a100-0000-7000-8000-000000000001";
const DELETED_RUN: &str = "0190a100-0000-7000-8000-000000000002";
const SECOND_RUN: &str = "0190a100-0000-7000-8000-000000000003";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn event(run_id: &str, seq: u64, padding: usize) -> EventEnvelope {
    EventEnvelope {
        event_id: format!(
            "0190a100-0000-7000-8000-{:012}",
            seq + match run_id {
                RUN => 0,
                DELETED_RUN => 10_000,
                _ => 20_000,
            }
        ),
        run_id: run_id.into(),
        run_seq: seq,
        event_type: "future.event".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-07-10T12:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: if run_id == RUN && seq == 1 {
            EventPayload::Cas {
                payload_cas: CasReference {
                    sha256: HASH.into(),
                    media_type: "application/octet-stream".into(),
                    byte_length: 1,
                },
            }
        } else {
            EventPayload::Inline {
                payload_json: json!({"padding": "x".repeat(padding), "seq": seq}),
            }
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
        extra: BTreeMap::from([("unknown".into(), json!({"preserved": true}))]),
    }
}

fn raw_envelopes(path: &Path) -> Vec<String> {
    let connection = Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("SELECT envelope_json FROM events ORDER BY run_id,run_seq")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn compaction_reduces_churn_and_preserves_the_complete_authoritative_history() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal
        .append_batch(
            0,
            &(1..=3).map(|seq| event(RUN, seq, 32)).collect::<Vec<_>>(),
        )
        .unwrap();
    // Equal timestamps exercise the established first-recorded tie-breaker.
    journal.append(0, &event(SECOND_RUN, 1, 32)).unwrap();
    for seq in 1..=160 {
        journal
            .append(seq - 1, &event(DELETED_RUN, seq, 8_000))
            .unwrap();
    }
    journal.delete_run(DELETED_RUN).unwrap();

    let before_events = journal.events(RUN).unwrap();
    let before_hashes = journal.referenced_hashes().unwrap();
    let before_runs = journal.run_ids().unwrap();
    assert_eq!(before_runs, [RUN, SECOND_RUN]);
    let before_raw = raw_envelopes(db.as_ref());
    let before_version: i64 = Connection::open(db.as_ref())
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let before_size = fs::metadata(db.as_ref()).unwrap().len();

    journal.compact().unwrap();
    let after_size = fs::metadata(db.as_ref()).unwrap().len();
    assert!(
        after_size < before_size,
        "{after_size} was not less than {before_size}"
    );
    assert_eq!(journal.events(RUN).unwrap(), before_events);
    assert_eq!(journal.referenced_hashes().unwrap(), before_hashes);
    assert_eq!(journal.run_ids().unwrap(), before_runs);
    assert_eq!(raw_envelopes(db.as_ref()), before_raw);
    let after_version: i64 = Connection::open(db.as_ref())
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(after_version, before_version);

    drop(journal);
    assert_eq!(
        RunJournal::open(db.as_ref()).unwrap().events(RUN).unwrap(),
        before_events
    );
}

#[test]
fn equal_timestamp_run_order_uses_insertion_order_not_event_id_order() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    let mut first = event(RUN, 1, 0);
    first.event_id = "0190a100-0000-7000-8000-000000000099".into();
    let mut second = event(SECOND_RUN, 1, 0);
    second.event_id = "0190a100-0000-7000-8000-000000000001".into();
    journal.append(0, &first).unwrap();
    journal.append(0, &second).unwrap();

    assert_eq!(journal.run_ids().unwrap(), [RUN, SECOND_RUN]);
    journal.compact().unwrap();
    assert_eq!(journal.run_ids().unwrap(), [RUN, SECOND_RUN]);
}

#[test]
fn open_peer_refreshes_all_reads_after_replacement() {
    let db = TestDb::new();
    let mut compactor = RunJournal::open(db.as_ref()).unwrap();
    compactor.append(0, &event(RUN, 1, 0)).unwrap();

    let equivalent_path =
        db.0.parent()
            .unwrap()
            .join(".")
            .join(db.0.file_name().unwrap());
    let mut peer = RunJournal::open(equivalent_path).unwrap();
    compactor.compact().unwrap();
    let mut appended = event(SECOND_RUN, 1, 0);
    appended.payload = EventPayload::Cas {
        payload_cas: CasReference {
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            media_type: "application/octet-stream".into(),
            byte_length: 2,
        },
    };
    compactor.append(0, &appended).unwrap();

    assert_eq!(peer.events(SECOND_RUN).unwrap().len(), 1);
    assert_eq!(peer.run_ids().unwrap(), [RUN, SECOND_RUN]);
    assert_eq!(
        peer.referenced_hashes().unwrap(),
        compactor.referenced_hashes().unwrap()
    );
}

#[test]
fn stale_peer_compaction_refreshes_before_snapshotting() {
    let db = TestDb::new();
    let mut first = RunJournal::open(db.as_ref()).unwrap();
    first.append(0, &event(RUN, 1, 0)).unwrap();
    let mut stale_peer = RunJournal::open(db.as_ref()).unwrap();

    first.compact().unwrap();
    first.append(1, &event(RUN, 2, 0)).unwrap();
    stale_peer.compact().unwrap();

    assert_eq!(first.events(RUN).unwrap().len(), 2);
    drop(first);
    drop(stale_peer);
    assert_eq!(
        RunJournal::open(db.as_ref())
            .unwrap()
            .events(RUN)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn committed_wal_events_are_included() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(RUN, 1, 32)).unwrap();
    assert!(PathBuf::from(format!("{}-wal", db.0.display())).exists());
    journal.compact().unwrap();
    drop(journal);
    assert_eq!(
        RunJournal::open(db.as_ref())
            .unwrap()
            .events(RUN)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn writer_at_the_close_to_replace_boundary_is_serialized_after_compaction() {
    let db = TestDb::new();
    let mut journal = RunJournal::open(db.as_ref()).unwrap();
    journal.append(0, &event(RUN, 1, 32)).unwrap();
    let mut writer = RunJournal::open(db.as_ref()).unwrap();
    let path = db.0.clone();
    let (start_tx, start_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        start_rx.recv().unwrap();
        writer.append(1, &event(RUN, 2, 32)).unwrap();
        done_tx.send(()).unwrap();
    });

    journal
        .compact_with_close_hook(&mut || {
            start_tx.send(()).unwrap();
            assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        })
        .unwrap();
    worker.join().unwrap();
    drop(journal);
    assert_eq!(
        RunJournal::open(path).unwrap().events(RUN).unwrap().len(),
        2
    );
}

#[test]
fn injected_failures_leave_the_original_reopenable_and_remove_temporary_files() {
    for fault in [
        CompactionFault::BeforeSnapshotCompletion,
        CompactionFault::BeforeReplacement,
        CompactionFault::DuringReplacement,
    ] {
        let db = TestDb::new();
        let mut journal = RunJournal::open(db.as_ref()).unwrap();
        journal
            .append_batch(0, &[event(RUN, 1, 32), event(RUN, 2, 32)])
            .unwrap();
        assert!(
            matches!(journal.compact_with_fault(Some(fault)), Err(CompactionError::Injected(found)) if found == fault)
        );
        // The same journal remains usable: pre-replacement failures must have
        // released exclusive locking, and replacement failures must reopen it.
        assert_eq!(
            RunJournal::open(db.as_ref())
                .unwrap()
                .events(RUN)
                .unwrap()
                .len(),
            2
        );
        journal.append(2, &event(RUN, 3, 32)).unwrap();
        drop(journal);
        assert_eq!(
            RunJournal::open(db.as_ref())
                .unwrap()
                .events(RUN)
                .unwrap()
                .len(),
            3
        );
        let prefix = format!(".{}.compact-", db.0.file_name().unwrap().to_string_lossy());
        assert!(!fs::read_dir(db.0.parent().unwrap())
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix)));
    }
}

#[test]
fn post_replace_sync_failure_refreshes_peers_and_preserves_later_appends() {
    let db = TestDb::new();
    let mut compactor = RunJournal::open(db.as_ref()).unwrap();
    compactor.append(0, &event(RUN, 1, 32)).unwrap();
    let mut peer = RunJournal::open(db.as_ref()).unwrap();

    assert!(matches!(
        compactor.compact_with_fault(Some(CompactionFault::AfterReplacementBeforeDirectorySync)),
        Err(CompactionError::Injected(
            CompactionFault::AfterReplacementBeforeDirectorySync
        ))
    ));

    // Both handles must now follow the replacement, despite compaction
    // reporting that its directory durability could not be confirmed.
    compactor.append(1, &event(RUN, 2, 32)).unwrap();
    assert_eq!(peer.events(RUN).unwrap().len(), 2);
    peer.append(2, &event(RUN, 3, 32)).unwrap();
    assert_eq!(compactor.events(RUN).unwrap().len(), 3);
    drop(compactor);
    drop(peer);
    assert_eq!(
        RunJournal::open(db.as_ref())
            .unwrap()
            .events(RUN)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn post_replace_sync_and_first_reopen_failure_recovers_without_panicking() {
    let db = TestDb::new();
    let mut compactor = RunJournal::open(db.as_ref()).unwrap();
    compactor.append(0, &event(RUN, 1, 32)).unwrap();
    let mut peer = RunJournal::open(db.as_ref()).unwrap();

    assert!(matches!(
        compactor.compact_with_fault(Some(
            CompactionFault::AfterReplacementBeforeDirectorySyncAndReopen
        )),
        Err(CompactionError::Injected(
            CompactionFault::AfterReplacementBeforeDirectorySyncAndReopen
        ))
    ));

    // The failed first reopen leaves this handle disconnected and its local
    // generation stale. Its next operation must retry the open, while peers
    // also observe the published replacement generation.
    compactor.append(1, &event(RUN, 2, 32)).unwrap();
    assert_eq!(peer.events(RUN).unwrap().len(), 2);
    peer.append(2, &event(RUN, 3, 32)).unwrap();
    assert_eq!(compactor.events(RUN).unwrap().len(), 3);
    drop(compactor);
    drop(peer);
    assert_eq!(
        RunJournal::open(db.as_ref())
            .unwrap()
            .events(RUN)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn in_memory_compaction_is_typed_and_non_destructive() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append(0, &event(RUN, 1, 0)).unwrap();
    assert!(matches!(
        journal.compact(),
        Err(CompactionError::UnsupportedInMemory)
    ));
    assert_eq!(journal.events(RUN).unwrap().len(), 1);
}
