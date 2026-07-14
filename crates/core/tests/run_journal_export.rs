use muniment_core::cas::{CasError, LocalCas};
use muniment_core::journal::export::{export_runs, ExportError};
use muniment_core::journal::{CasReference, EventEnvelope, EventPayload, Provenance, RunJournal};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    db: PathBuf,
    cas_root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let id = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("muniment-export-{}-{id}", std::process::id()));
        Self {
            db: base.with_extension("sqlite3"),
            cas_root: base.with_extension("cas"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.db);
        let _ = fs::remove_dir_all(&self.cas_root);
    }
}

fn event(run: u64, seq: u64, payload: EventPayload) -> EventEnvelope {
    EventEnvelope {
        event_id: format!("0190b100-0000-7000-8000-{run:06}{seq:06}"),
        run_id: format!("0190b000-0000-7000-8000-{run:012}"),
        run_seq: seq,
        event_type: "artifact.recorded".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: format!("2026-07-14T00:00:{seq:02}Z"),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload,
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

fn inline(run: u64, seq: u64) -> EventEnvelope {
    event(
        run,
        seq,
        EventPayload::Inline {
            payload_json: json!({"sequence": seq}),
        },
    )
}

fn referenced(run: u64, seq: u64, hash: &str, length: usize) -> EventEnvelope {
    event(
        run,
        seq,
        EventPayload::Cas {
            payload_cas: CasReference {
                sha256: hash.into(),
                media_type: "application/octet-stream".into(),
                byte_length: length as u64,
            },
        },
    )
}

fn records(bytes: &[u8]) -> Vec<(u8, &[u8])> {
    let magic = b"MUNIMENT-JOURNAL-EXPORT\0\x01";
    assert!(bytes.starts_with(magic));
    let mut at = magic.len();
    let mut result = Vec::new();
    while at < bytes.len() {
        let kind = bytes[at];
        let length = u64::from_be_bytes(bytes[at + 1..at + 9].try_into().unwrap()) as usize;
        at += 9;
        result.push((kind, &bytes[at..at + length]));
        at += length;
    }
    result
}

#[test]
fn deterministic_multi_run_export_orders_envelopes_and_deduplicates_large_cas() {
    let fixture = Fixture::new();
    let cas = LocalCas::open(&fixture.cas_root).unwrap();
    let body = vec![0x5a; 3 * 1024 * 1024];
    let hash = cas.put(&body).unwrap();
    cas.put(b"access_token=unrelated-secret").unwrap();
    let mut journal = RunJournal::open(&fixture.db).unwrap();
    journal
        .append_batch(
            0,
            &[inline(2, 1), referenced(2, 2, hash.as_str(), body.len())],
        )
        .unwrap();
    let mut unrelated = inline(3, 1);
    unrelated.payload = EventPayload::Inline {
        payload_json: json!({
            "access_token": "unrelated-journal-secret",
            "installation_key": "credential-shaped-value",
            "native_path": fixture.cas_root.display().to_string(),
        }),
    };
    journal.append(0, &unrelated).unwrap();
    journal
        .append_batch(
            0,
            &[
                referenced(1, 1, hash.as_str(), body.len()),
                referenced(1, 2, hash.as_str(), body.len()),
            ],
        )
        .unwrap();
    let ids = vec![inline(2, 1).run_id, inline(1, 1).run_id];

    let mut first = Vec::new();
    export_runs(&mut journal, &cas, &ids, &mut first).unwrap();
    let mut second = Vec::new();
    export_runs(&mut journal, &cas, &ids, &mut second).unwrap();
    assert_eq!(first, second);

    let records = records(&first);
    let manifest: Value = serde_json::from_slice(records[0].1).unwrap();
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["runs"][0]["run_id"], inline(1, 1).run_id);
    let envelopes: Vec<EventEnvelope> = records
        .iter()
        .filter(|r| r.0 == b'E')
        .map(|r| serde_json::from_slice(r.1).unwrap())
        .collect();
    assert_eq!(
        envelopes
            .iter()
            .map(|e| (&e.run_id, e.run_seq))
            .collect::<Vec<_>>(),
        vec![
            (&inline(1, 1).run_id, 1),
            (&inline(1, 1).run_id, 2),
            (&inline(2, 1).run_id, 1),
            (&inline(2, 1).run_id, 2),
        ]
    );
    let objects: Vec<_> = records.iter().filter(|r| r.0 == b'O').collect();
    assert_eq!(objects.len(), 1);
    assert_eq!(&objects[0].1[64..], body);
    assert!(!first
        .windows(b"unrelated-secret".len())
        .any(|w| w == b"unrelated-secret"));
    assert!(!first
        .windows(b"unrelated-journal-secret".len())
        .any(|w| w == b"unrelated-journal-secret"));
    assert!(!first
        .windows(fixture.cas_root.as_os_str().len())
        .any(|w| w == fixture.cas_root.as_os_str().as_encoded_bytes()));
}

#[test]
fn export_uses_one_sqlite_snapshot_during_concurrent_append() {
    let fixture = Fixture::new();
    let cas = LocalCas::open(&fixture.cas_root).unwrap();
    let mut journal = RunJournal::open(&fixture.db).unwrap();
    let padding = "x".repeat(512 * 1024);
    let first_run: Vec<_> = (1..=32)
        .map(|seq| {
            let mut envelope = inline(1, seq);
            envelope.payload = EventPayload::Inline {
                payload_json: json!({"sequence": seq, "padding": padding}),
            };
            envelope
        })
        .collect();
    journal.append_batch(0, &first_run).unwrap();
    journal.append(0, &inline(2, 1)).unwrap();

    // Reading and parsing the large first run establishes the export snapshot
    // and keeps that read active while this append commits. The second run is
    // queried afterwards, so separate non-transactional queries would include
    // its newly appended envelope.
    let db = fixture.db.clone();
    let concurrent_append = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        let mut concurrent = RunJournal::open(db).unwrap();
        concurrent.append(1, &inline(2, 2)).unwrap();
    });
    let mut bytes = Vec::new();
    export_runs(
        &mut journal,
        &cas,
        &[inline(1, 1).run_id, inline(2, 1).run_id],
        &mut bytes,
    )
    .unwrap();
    concurrent_append.join().unwrap();

    let envelopes: Vec<EventEnvelope> = records(&bytes)
        .iter()
        .filter(|r| r.0 == b'E')
        .map(|r| serde_json::from_slice(r.1).unwrap())
        .collect();
    assert_eq!(
        envelopes
            .iter()
            .filter(|event| event.run_id == inline(2, 1).run_id)
            .count(),
        1
    );
    assert_eq!(journal.events(&inline(2, 1).run_id).unwrap().len(), 2);
}

#[test]
fn missing_runs_corrupt_objects_and_writer_failures_are_typed() {
    let fixture = Fixture::new();
    let cas = LocalCas::open(&fixture.cas_root).unwrap();
    let body = b"original";
    let hash = cas.put(body).unwrap();
    let mut journal = RunJournal::open(&fixture.db).unwrap();
    journal
        .append(0, &referenced(1, 1, hash.as_str(), body.len()))
        .unwrap();
    let missing = inline(9, 1).run_id;
    assert!(
        matches!(export_runs(&mut journal, &cas, std::slice::from_ref(&missing), &mut Vec::new()), Err(ExportError::MissingRun(id)) if id == missing)
    );

    fs::write(object_path(&fixture.cas_root, hash.as_str()), b"tampered").unwrap();
    assert!(matches!(
        export_runs(&mut journal, &cas, &[inline(1, 1).run_id], &mut Vec::new()),
        Err(ExportError::Cas(CasError::Corrupt { .. }))
    ));
    fs::write(object_path(&fixture.cas_root, hash.as_str()), body).unwrap();
    let mut failed = FailingWriter;
    assert!(matches!(
        export_runs(&mut journal, &cas, &[inline(1, 1).run_id], &mut failed),
        Err(ExportError::Writer(_))
    ));
}

struct FailingWriter;
impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("full"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn object_path(root: &Path, hash: &str) -> PathBuf {
    root.join("objects").join(&hash[..2]).join(&hash[2..])
}
