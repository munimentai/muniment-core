//! Durable, append-only per-run event journal.

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::Duration;
use uuid::{Uuid, Version};

const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasReference {
    pub sha256: String,
    pub media_type: String,
    pub byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventPayload {
    Inline { payload_json: Value },
    Cas { payload_cas: CasReference },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: String,
    pub source_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_versions: Option<BTreeMap<String, String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub run_id: String,
    pub run_seq: u64,
    pub event_type: String,
    pub event_version: u32,
    pub envelope_version: u32,
    pub recorded_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causation_id: Option<String>,
    #[serde(flatten)]
    pub payload: EventPayload,
    pub provenance: Provenance,
    /// Fields unknown to this reader are retained in the stored canonical envelope.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Conflict {
    StaleSequence { expected: u64, actual: u64 },
    EventId { event_id: String },
    Sequence { run_id: String, run_seq: u64 },
}

#[derive(Debug)]
pub enum JournalError {
    Sqlite(rusqlite::Error),
    InvalidEnvelope(String),
    Conflict(Conflict),
    /// Validation failed. The database is left untouched and must not be appended to.
    Corrupt(String),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "journal SQLite error: {e}"),
            Self::InvalidEnvelope(e) => write!(f, "invalid event envelope: {e}"),
            Self::Conflict(e) => write!(f, "journal append conflict: {e:?}"),
            Self::Corrupt(e) => write!(f, "journal is read-only because validation failed: {e}"),
        }
    }
}

impl std::error::Error for JournalError {}
impl From<rusqlite::Error> for JournalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

pub struct RunJournal {
    connection: Connection,
}

impl RunJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            connection.execute_batch(SCHEMA)?;
            connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        } else if version != SCHEMA_VERSION {
            return Err(JournalError::Corrupt(format!(
                "unsupported schema version {version}"
            )));
        }
        validate_database(&connection)?;
        Ok(Self { connection })
    }

    pub fn append(
        &mut self,
        expected_last_seq: u64,
        event: &EventEnvelope,
    ) -> Result<(), JournalError> {
        self.append_batch(expected_last_seq, std::slice::from_ref(event))
    }

    pub fn append_batch(
        &mut self,
        expected_last_seq: u64,
        events: &[EventEnvelope],
    ) -> Result<(), JournalError> {
        if events.is_empty() {
            return Ok(());
        }
        let run_id = &events[0].run_id;
        for (index, event) in events.iter().enumerate() {
            validate_envelope(event)?;
            let wanted = expected_last_seq + index as u64 + 1;
            if &event.run_id != run_id || event.run_seq != wanted {
                return Err(JournalError::InvalidEnvelope("batch must contain one run with contiguous sequence numbers after expected_last_seq".into()));
            }
        }
        let canonical: Vec<String> = events
            .iter()
            .map(canonical_envelope)
            .collect::<Result<_, _>>()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // A complete retry is successful even if the caller's sequence expectation is now stale.
        let mut all_existing = true;
        for (event, bytes) in events.iter().zip(&canonical) {
            match tx
                .query_row(
                    "SELECT envelope_json FROM events WHERE event_id=?1",
                    [&event.event_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
            {
                Some(stored) if stored == *bytes => {}
                Some(_) => {
                    return Err(JournalError::Conflict(Conflict::EventId {
                        event_id: event.event_id.clone(),
                    }))
                }
                None => all_existing = false,
            }
        }
        if all_existing {
            return Ok(());
        }

        let actual: u64 = tx.query_row(
            "SELECT COALESCE(MAX(run_seq), 0) FROM events WHERE run_id=?1",
            [run_id],
            |r| r.get(0),
        )?;
        if actual != expected_last_seq {
            return Err(JournalError::Conflict(Conflict::StaleSequence {
                expected: expected_last_seq,
                actual,
            }));
        }
        for (event, bytes) in events.iter().zip(canonical) {
            let result = tx.execute(
                "INSERT INTO events(event_id,run_id,run_seq,event_type,event_version,envelope_version,recorded_at,envelope_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![event.event_id,event.run_id,event.run_seq,event.event_type,event.event_version,event.envelope_version,event.recorded_at,bytes]);
            if let Err(rusqlite::Error::SqliteFailure(e, _)) = &result {
                if e.code == rusqlite::ErrorCode::ConstraintViolation {
                    return Err(JournalError::Conflict(Conflict::Sequence {
                        run_id: event.run_id.clone(),
                        run_seq: event.run_seq,
                    }));
                }
            }
            result?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn events(&self, run_id: &str) -> Result<Vec<EventEnvelope>, JournalError> {
        let mut statement = self
            .connection
            .prepare("SELECT envelope_json FROM events WHERE run_id=?1 ORDER BY run_seq")?;
        let rows = statement.query_map([run_id], |r| r.get::<_, String>(0))?;
        rows.map(|row| {
            let raw = row?;
            serde_json::from_str(&raw)
                .map_err(|e| JournalError::Corrupt(format!("invalid stored envelope JSON: {e}")))
        })
        .collect()
    }
}

fn validate_envelope(e: &EventEnvelope) -> Result<(), JournalError> {
    if e.run_seq == 0
        || e.event_version == 0
        || e.envelope_version == 0
        || e.event_type.trim().is_empty()
        || e.provenance.source.trim().is_empty()
        || e.provenance.source_version.trim().is_empty()
    {
        return Err(JournalError::InvalidEnvelope(
            "sequence and versions must be positive and type/provenance must be non-empty".into(),
        ));
    }
    for (name, id) in [("event_id", &e.event_id), ("run_id", &e.run_id)] {
        let id = Uuid::parse_str(id)
            .map_err(|_| JournalError::InvalidEnvelope(format!("{name} must be a UUIDv7")))?;
        if id.get_version() != Some(Version::SortRand) {
            return Err(JournalError::InvalidEnvelope(format!(
                "{name} must be a UUIDv7"
            )));
        }
    }
    validate_time("recorded_at", &e.recorded_at, true)?;
    if let Some(value) = &e.occurred_at {
        validate_time("occurred_at", value, false)?;
    }
    if let EventPayload::Cas { payload_cas: cas } = &e.payload {
        if cas.sha256.len() != 64
            || !cas
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || cas.media_type.trim().is_empty()
        {
            return Err(JournalError::InvalidEnvelope(
                "CAS reference must have a lowercase SHA-256 and media type".into(),
            ));
        }
    }
    Ok(())
}

fn validate_time(name: &str, value: &str, canonical: bool) -> Result<(), JournalError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| JournalError::InvalidEnvelope(format!("{name} must be RFC 3339")))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(JournalError::InvalidEnvelope(format!("{name} must be UTC")));
    }
    if canonical
        && parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
            != value
    {
        return Err(JournalError::InvalidEnvelope(format!(
            "{name} is not canonical UTC RFC 3339"
        )));
    }
    Ok(())
}

fn canonical_envelope(event: &EventEnvelope) -> Result<String, JournalError> {
    let mut value =
        serde_json::to_value(event).map_err(|e| JournalError::InvalidEnvelope(e.to_string()))?;
    sort_json(&mut value);
    serde_json::to_string(&value).map_err(|e| JournalError::InvalidEnvelope(e.to_string()))
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

fn validate_database(connection: &Connection) -> Result<(), JournalError> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        return Err(JournalError::Corrupt(format!(
            "SQLite integrity check: {integrity}"
        )));
    }
    let mut statement = connection.prepare("SELECT event_id,run_id,run_seq,event_type,event_version,envelope_version,recorded_at,envelope_json FROM events ORDER BY run_id,run_seq")?;
    let mut rows = statement.query([])?;
    let mut previous: Option<(String, u64)> = None;
    while let Some(row) = rows.next()? {
        let raw: String = row.get(7)?;
        let event: EventEnvelope = serde_json::from_str(&raw)
            .map_err(|e| JournalError::Corrupt(format!("invalid envelope JSON: {e}")))?;
        validate_envelope(&event).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let canonical =
            canonical_envelope(&event).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        if raw != canonical
            || event.event_id != row.get::<_, String>(0)?
            || event.run_id != row.get::<_, String>(1)?
            || event.run_seq != row.get::<_, u64>(2)?
            || event.event_type != row.get::<_, String>(3)?
            || event.event_version != row.get::<_, u32>(4)?
            || event.envelope_version != row.get::<_, u32>(5)?
            || event.recorded_at != row.get::<_, String>(6)?
        {
            return Err(JournalError::Corrupt(format!(
                "stored envelope/index mismatch for {}",
                event.event_id
            )));
        }
        let expected = previous
            .as_ref()
            .filter(|(id, _)| id == &event.run_id)
            .map_or(1, |(_, seq)| seq + 1);
        if event.run_seq != expected {
            return Err(JournalError::Corrupt(format!(
                "run {} has noncontiguous sequence {}",
                event.run_id, event.run_seq
            )));
        }
        previous = Some((event.run_id, event.run_seq));
    }
    Ok(())
}

const SCHEMA: &str = r#"
BEGIN;
CREATE TABLE events (
 event_id TEXT PRIMARY KEY NOT NULL,
 run_id TEXT NOT NULL,
 run_seq INTEGER NOT NULL CHECK(run_seq > 0),
 event_type TEXT NOT NULL,
 event_version INTEGER NOT NULL CHECK(event_version > 0),
 envelope_version INTEGER NOT NULL CHECK(envelope_version > 0),
 recorded_at TEXT NOT NULL,
 envelope_json TEXT NOT NULL,
 UNIQUE(run_id, run_seq)
) STRICT;
CREATE INDEX events_run_order ON events(run_id, run_seq);
COMMIT;
"#;
