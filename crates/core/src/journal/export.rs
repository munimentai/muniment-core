//! Read-only, deterministic durable-journal export.
//!
//! Version 1 is a framed stream. It begins with `MUNIMENT-JOURNAL-EXPORT\0\x01`,
//! followed by records with a one-byte kind and an eight-byte big-endian length:
//! `M` contains the canonical JSON manifest, `E` contains one stored canonical
//! envelope, and `O` contains a 64-byte lowercase hash followed by the CAS body.
//! Runs, envelopes, and objects are lexically/semantically ordered, making output
//! byte-for-byte deterministic for a fixed journal snapshot and CAS contents.

use super::{EventEnvelope, EventPayload, JournalError, RunJournal};
use crate::cas::{CasError, ContentHash, LocalCas};
use rusqlite::TransactionBehavior;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;

const MAGIC: &[u8] = b"MUNIMENT-JOURNAL-EXPORT\0\x01";
const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum ExportError {
    InvalidSelection(String),
    MissingRun(String),
    Journal(JournalError),
    Cas(CasError),
    Writer(std::io::Error),
    CorruptReference(String),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelection(e) => write!(f, "invalid export selection: {e}"),
            Self::MissingRun(id) => write!(f, "selected run does not exist: {id}"),
            Self::Journal(e) => write!(f, "export journal error: {e}"),
            Self::Cas(e) => write!(f, "export object store error: {e}"),
            Self::Writer(e) => write!(f, "export destination error: {e}"),
            Self::CorruptReference(e) => write!(f, "corrupt exported CAS reference: {e}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<JournalError> for ExportError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<rusqlite::Error> for ExportError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Journal(JournalError::Sqlite(value))
    }
}

#[derive(Serialize)]
struct Manifest<'a> {
    format: &'static str,
    version: u32,
    runs: &'a [ManifestRun],
    objects: &'a [ManifestObject],
}

#[derive(Serialize)]
struct ManifestRun {
    run_id: String,
    envelope_count: u64,
}

#[derive(Serialize)]
struct ManifestObject {
    sha256: String,
    byte_length: u64,
}

struct EnvelopeRow {
    canonical: String,
}

/// Exports exactly `run_ids` through an injected destination writer.
///
/// No paths, installation state, or authentication stores are consulted. The
/// only data reachable here is selected journal envelopes and their direct CAS
/// references.
pub fn export_runs(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_ids: &[String],
    writer: &mut impl Write,
) -> Result<(), ExportError> {
    if run_ids.is_empty() {
        return Err(ExportError::InvalidSelection(
            "at least one run ID is required".into(),
        ));
    }
    let selected: BTreeSet<&str> = run_ids.iter().map(String::as_str).collect();
    if selected.len() != run_ids.len() {
        return Err(ExportError::InvalidSelection(
            "run IDs must be unique".into(),
        ));
    }

    let coordination = journal.coordination.clone();
    let _operation = coordination
        .as_ref()
        .map(|state| state.operation.lock().unwrap());
    journal.refresh_after_compaction()?;
    let tx = journal
        .connection
        .as_mut()
        .expect("journal connection is always present outside compaction")
        .transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut runs = Vec::with_capacity(selected.len());
    let mut envelopes = Vec::new();
    let mut objects = BTreeMap::<String, u64>::new();

    for run_id in selected {
        let mut statement =
            tx.prepare("SELECT envelope_json FROM events WHERE run_id=?1 ORDER BY run_seq ASC")?;
        let rows = statement.query_map([run_id], |row| row.get::<_, String>(0))?;
        let mut count = 0_u64;
        for row in rows {
            let canonical = row?;
            let event: EventEnvelope = serde_json::from_str(&canonical).map_err(|e| {
                ExportError::Journal(JournalError::Corrupt(format!(
                    "invalid stored envelope JSON: {e}"
                )))
            })?;
            if let EventPayload::Cas { payload_cas } = &event.payload {
                let hash = ContentHash::from_str(&payload_cas.sha256)
                    .map_err(|e| ExportError::CorruptReference(e.to_string()))?;
                if let Some(existing) = objects.insert(hash.to_string(), payload_cas.byte_length) {
                    if existing != payload_cas.byte_length {
                        return Err(ExportError::CorruptReference(format!(
                            "{} has conflicting byte lengths",
                            payload_cas.sha256
                        )));
                    }
                }
            }
            if let EventPayload::Attachment { attachment } = &event.payload {
                if let Some(existing) =
                    objects.insert(attachment.sha256().to_string(), attachment.byte_length())
                {
                    if existing != attachment.byte_length() {
                        return Err(ExportError::CorruptReference(format!(
                            "{} has conflicting byte lengths",
                            attachment.sha256()
                        )));
                    }
                }
            }
            envelopes.push(EnvelopeRow { canonical });
            count += 1;
        }
        if count == 0 {
            return Err(ExportError::MissingRun(run_id.to_owned()));
        }
        runs.push(ManifestRun {
            run_id: run_id.to_owned(),
            envelope_count: count,
        });
    }

    // Check existence and length before emitting the manifest. Hash verification
    // remains streaming and is completed before this function can succeed.
    for (hash_text, expected_length) in &objects {
        let hash = ContentHash::from_str(hash_text)
            .map_err(|e| ExportError::CorruptReference(e.to_string()))?;
        let file = cas
            .open_object(&hash)
            .map_err(ExportError::Cas)?
            .ok_or_else(|| ExportError::Cas(CasError::NotFound(hash.clone())))?;
        let actual = file
            .metadata()
            .map_err(|e| ExportError::Cas(CasError::Io(e)))?
            .len();
        if actual != *expected_length {
            return Err(ExportError::CorruptReference(format!(
                "{hash_text} declares {expected_length} bytes but contains {actual}"
            )));
        }
    }
    let manifest_objects: Vec<_> = objects
        .iter()
        .map(|(hash, length)| ManifestObject {
            sha256: hash.clone(),
            byte_length: *length,
        })
        .collect();
    let manifest = Manifest {
        format: "muniment.durable-journal",
        version: 1,
        runs: &runs,
        objects: &manifest_objects,
    };
    let mut manifest_value =
        serde_json::to_value(manifest).map_err(|e| ExportError::CorruptReference(e.to_string()))?;
    sort_json(&mut manifest_value);
    let manifest_bytes = serde_json::to_vec(&manifest_value)
        .map_err(|e| ExportError::CorruptReference(e.to_string()))?;

    writer.write_all(MAGIC).map_err(ExportError::Writer)?;
    write_record(writer, b'M', &manifest_bytes)?;
    for envelope in envelopes {
        write_record(writer, b'E', envelope.canonical.as_bytes())?;
    }
    for (hash, length) in objects {
        let hash = ContentHash::from_str(&hash)
            .map_err(|e| ExportError::CorruptReference(e.to_string()))?;
        write_object(writer, cas, &hash, length)?;
    }
    tx.commit()?;
    Ok(())
}

fn write_record(writer: &mut impl Write, kind: u8, bytes: &[u8]) -> Result<(), ExportError> {
    writer.write_all(&[kind]).map_err(ExportError::Writer)?;
    writer
        .write_all(&(bytes.len() as u64).to_be_bytes())
        .map_err(ExportError::Writer)?;
    writer.write_all(bytes).map_err(ExportError::Writer)
}

fn write_object(
    writer: &mut impl Write,
    cas: &LocalCas,
    hash: &ContentHash,
    length: u64,
) -> Result<(), ExportError> {
    writer.write_all(b"O").map_err(ExportError::Writer)?;
    writer
        .write_all(&(64 + length).to_be_bytes())
        .map_err(ExportError::Writer)?;
    writer
        .write_all(hash.as_str().as_bytes())
        .map_err(ExportError::Writer)?;
    let mut reader = cas
        .open_object(hash)
        .map_err(ExportError::Cas)?
        .ok_or_else(|| ExportError::Cas(CasError::NotFound(hash.clone())))?;
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0_u8; BUFFER_SIZE];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(BUFFER_SIZE as u64)).unwrap();
        let count = reader
            .read(&mut buffer[..wanted])
            .map_err(|e| ExportError::Cas(CasError::Io(e)))?;
        if count == 0 {
            return Err(ExportError::CorruptReference(format!(
                "{hash} was truncated while exporting"
            )));
        }
        hasher.update(&buffer[..count]);
        writer
            .write_all(&buffer[..count])
            .map_err(ExportError::Writer)?;
        remaining -= count as u64;
    }
    let actual = ContentHash::from_str(&format!("{:x}", hasher.finalize()))
        .expect("SHA-256 always produces a canonical hash");
    if actual != *hash {
        return Err(ExportError::Cas(CasError::Corrupt {
            expected: hash.clone(),
            actual,
        }));
    }
    Ok(())
}

fn sort_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let old = std::mem::take(map);
            let mut entries: Vec<_> = old.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, mut value) in entries {
                sort_json(&mut value);
                map.insert(key, value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sort_json),
        _ => {}
    }
}
