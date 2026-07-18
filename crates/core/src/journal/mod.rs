//! Durable, append-only per-run event journal.

pub mod compaction;
pub mod export;
pub mod reducer;
pub mod retention;
pub mod summaries;

use crate::attachment::ChatAttachment;
use crate::cas::ContentHash;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
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
    Attachment { attachment: ChatAttachment },
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
    pub(crate) connection: Option<Connection>,
    pub(crate) cursor_key: [u8; 32],
    pub(crate) path: Option<PathBuf>,
    pub(crate) coordination: Option<Arc<JournalCoordination>>,
    pub(crate) generation: u64,
}

/// A bounded, sequence-ordered slice of one run. Callers must project these
/// envelopes before crossing the journal boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct RunEventPage {
    pub events: Vec<EventEnvelope>,
    pub next_cursor: Option<String>,
}

/// Sequence bounds and a bounded retained slice captured from one workspace-owned run.
#[derive(Clone, Debug, PartialEq)]
pub struct RunCatchUpPage {
    pub first_available_run_seq: u64,
    pub current_run_seq: u64,
    pub events: Vec<RunEventProjection>,
    pub exhausted: bool,
}

/// The bounded subset of a retained event needed by companion catch-up.
///
/// These fields are stored in dedicated columns, so reading a redacted stream
/// never loads or parses the potentially large raw journal payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunEventProjection {
    pub run_id: String,
    pub run_seq: u64,
    pub event_type: String,
    pub event_version: u32,
    pub recorded_at: String,
}

#[derive(Debug)]
pub enum RunEventPageError {
    InvalidLimit,
    InvalidCursor,
    NotFoundOrInaccessible,
    Journal(JournalError),
}

impl From<JournalError> for RunEventPageError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunEventCursor {
    version: u8,
    run_id: String,
    after_run_seq: u64,
    authenticator: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadProjectionCursor {
    version: u8,
    run_id: String,
    snapshot_seq: u64,
    last_ordinal: i64,
    authenticator: String,
}

pub(crate) struct JournalCoordination {
    pub(crate) operation: Mutex<()>,
    pub(crate) generation: std::sync::atomic::AtomicU64,
}

fn coordination_for(path: &Path) -> Arc<JournalCoordination> {
    static JOURNALS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<JournalCoordination>>>> =
        OnceLock::new();
    let key = normalized_path(path);
    let mut journals = JOURNALS.get_or_init(Default::default).lock().unwrap();
    if let Some(existing) = journals.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    let coordination = Arc::new(JournalCoordination {
        operation: Mutex::new(()),
        generation: std::sync::atomic::AtomicU64::new(0),
    });
    journals.insert(key, Arc::downgrade(&coordination));
    coordination
}

fn normalized_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) {
        if let Ok(parent) = parent.canonicalize() {
            return parent.join(name);
        }
    }
    absolute
        .components()
        .fold(PathBuf::new(), |mut result, part| {
            match part {
                Component::CurDir => {}
                Component::ParentDir if result.file_name().is_some() => {
                    result.pop();
                }
                _ => result.push(part.as_os_str()),
            }
            result
        })
}

impl RunJournal {
    /// Reads retained events after a committed sequence from a single bounded snapshot.
    pub fn workspace_catch_up(
        &mut self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
        limit: usize,
        byte_limit: usize,
    ) -> Result<RunCatchUpPage, RunEventPageError> {
        if !(1..=1_024).contains(&limit) || byte_limit == 0 {
            return Err(RunEventPageError::InvalidLimit);
        }
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()
            .map_err(RunEventPageError::Journal)?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let bounds = connection
            .query_row(
                "SELECT MIN(e.run_seq), MAX(e.run_seq) FROM events e \
                 JOIN run_workspaces w ON w.run_id=e.run_id \
                 WHERE e.run_id=?1 AND w.workspace=?2",
                params![run_id, workspace],
                |row| Ok((row.get::<_, Option<u64>>(0)?, row.get::<_, Option<u64>>(1)?)),
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        let (Some(first), Some(current)) = bounds else {
            return Err(RunEventPageError::NotFoundOrInaccessible);
        };
        if after_run_seq < first.saturating_sub(1) || after_run_seq > current {
            return Err(RunEventPageError::InvalidCursor);
        }
        let mut statement = connection
            .prepare(
                "SELECT run_id,run_seq,event_type,event_version,recorded_at, \
                 length(CAST(run_id AS BLOB))+length(CAST(event_type AS BLOB))+ \
                 length(CAST(recorded_at AS BLOB)) \
                 FROM events WHERE run_id=?1 AND run_seq>?2 \
                 AND run_seq<=?3 ORDER BY run_seq LIMIT ?4",
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        let mut rows = statement
            .query(params![run_id, after_run_seq, current, (limit + 1) as u64])
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        let mut events = Vec::with_capacity(limit);
        let mut retained_bytes = 0usize;
        let mut exhausted = true;
        while let Some(row) = rows
            .next()
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?
        {
            let field_bytes = row.get::<_, usize>(5).map_err(JournalError::from)?;
            if events.len() == limit || field_bytes > byte_limit.saturating_sub(retained_bytes) {
                exhausted = false;
                break;
            }
            events.push(RunEventProjection {
                run_id: row.get(0).map_err(JournalError::from)?,
                run_seq: row.get(1).map_err(JournalError::from)?,
                event_type: row.get(2).map_err(JournalError::from)?,
                event_version: row.get(3).map_err(JournalError::from)?,
                recorded_at: row.get(4).map_err(JournalError::from)?,
            });
            retained_bytes += field_bytes;
        }
        Ok(RunCatchUpPage {
            first_available_run_seq: first,
            current_run_seq: current,
            events,
            exhausted,
        })
    }

    pub fn thread_projection_boundary(
        &self,
        workspace: &str,
        run_id: &str,
        cursor: Option<&str>,
    ) -> Result<(u64, i64), RunEventPageError> {
        if !self
            .run_belongs_to_workspace(run_id, workspace)
            .map_err(RunEventPageError::Journal)?
        {
            return Err(RunEventPageError::NotFoundOrInaccessible);
        }
        if let Some(cursor) = cursor {
            return decode_thread_projection_cursor(cursor, run_id, &self.cursor_key);
        }
        let snapshot = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .query_row(
                "SELECT MAX(run_seq) FROM events WHERE run_id=?1",
                [run_id],
                |row| row.get::<_, Option<u64>>(0),
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?
            .ok_or(RunEventPageError::NotFoundOrInaccessible)?;
        Ok((snapshot, -1))
    }

    pub fn thread_projection_cursor(
        &self,
        run_id: &str,
        snapshot_seq: u64,
        last_ordinal: i64,
    ) -> Result<String, RunEventPageError> {
        encode_thread_projection_cursor(run_id, snapshot_seq, last_ordinal, &self.cursor_key)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref();
        let file_path = (path != Path::new(":memory:") && !path.as_os_str().is_empty())
            .then(|| normalized_path(path));
        let coordination = file_path.as_deref().map(coordination_for);
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
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
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS run_workspaces( \
             run_id TEXT PRIMARY KEY NOT NULL, workspace TEXT NOT NULL); \
             CREATE INDEX IF NOT EXISTS run_workspaces_workspace_run \
             ON run_workspaces(workspace, run_id); \
             CREATE TABLE IF NOT EXISTS thread_projection_entries( \
             run_id TEXT NOT NULL, ordinal INTEGER NOT NULL, run_seq INTEGER NOT NULL, \
             kind TEXT NOT NULL, text TEXT, PRIMARY KEY(run_id, ordinal)); \
             CREATE INDEX IF NOT EXISTS thread_projection_run_order \
             ON thread_projection_entries(run_id, ordinal); \
             CREATE TABLE IF NOT EXISTS thread_projection_history( \
             run_id TEXT NOT NULL, ordinal INTEGER NOT NULL, valid_until_seq INTEGER NOT NULL, \
             run_seq INTEGER NOT NULL, kind TEXT NOT NULL, text TEXT, \
             PRIMARY KEY(run_id, ordinal, valid_until_seq)); \
             CREATE TABLE IF NOT EXISTS thread_projection_versions( \
             run_id TEXT NOT NULL, ordinal INTEGER NOT NULL, valid_from_seq INTEGER NOT NULL, \
             valid_until_seq INTEGER, run_seq INTEGER NOT NULL, kind TEXT NOT NULL, text TEXT, \
             PRIMARY KEY(run_id, ordinal, valid_from_seq)); \
             CREATE INDEX IF NOT EXISTS thread_projection_versions_page \
             ON thread_projection_versions(run_id, ordinal, valid_from_seq, valid_until_seq);",
        )?;
        // Journals created by the first projection implementation have only a
        // current row. Treat that row as the initial version; new writes use
        // interval versions from this point forward.
        connection.execute(
            "INSERT OR IGNORE INTO thread_projection_versions( \
             run_id,ordinal,valid_from_seq,run_seq,kind,text) \
             SELECT run_id,ordinal,run_seq,run_seq,kind,text \
             FROM thread_projection_entries",
            [],
        )?;
        validate_database(&connection)?;
        let cursor_key = load_or_create_cursor_key(&connection)?;
        let generation = coordination.as_ref().map_or(0, |state| {
            state.generation.load(std::sync::atomic::Ordering::Acquire)
        });
        drop(_operation);
        Ok(Self {
            connection: Some(connection),
            cursor_key,
            path: file_path,
            generation,
            coordination,
        })
    }

    pub fn append(
        &mut self,
        expected_last_seq: u64,
        event: &EventEnvelope,
    ) -> Result<(), JournalError> {
        self.append_batch(expected_last_seq, std::slice::from_ref(event))
    }

    /// Atomically creates a run and records its authoritative workspace.
    pub fn append_new_run(
        &mut self,
        workspace: &str,
        event: &EventEnvelope,
    ) -> Result<(), JournalError> {
        if workspace.is_empty() || event.run_seq != 1 {
            return Err(JournalError::InvalidEnvelope(
                "new run workspace and sequence must be valid".into(),
            ));
        }
        validate_envelope(event)?;
        let canonical = canonical_envelope(event)?;
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let tx = self
            .connection
            .as_mut()
            .expect("journal connection is always present outside compaction")
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?1)",
            [&event.run_id],
            |row| row.get(0),
        )?;
        if exists {
            return Err(JournalError::Conflict(Conflict::Sequence {
                run_id: event.run_id.clone(),
                run_seq: 1,
            }));
        }
        tx.execute(
            "INSERT INTO events(event_id,run_id,run_seq,event_type,event_version,envelope_version,recorded_at,envelope_json) VALUES(?1,?2,1,?3,?4,?5,?6,?7)",
            params![event.event_id,event.run_id,event.event_type,event.event_version,event.envelope_version,event.recorded_at,canonical],
        )?;
        update_thread_projection(&tx, event)?;
        tx.execute(
            "INSERT INTO run_workspaces(run_id, workspace) VALUES(?1, ?2)",
            params![event.run_id, workspace],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn append_batch(
        &mut self,
        expected_last_seq: u64,
        events: &[EventEnvelope],
    ) -> Result<(), JournalError> {
        if events.is_empty() {
            return Ok(());
        }
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
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
            .as_mut()
            .expect("journal connection is always present outside compaction")
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
            update_thread_projection(&tx, event)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Records the authorization boundary that owns a run. A run can never be
    /// rebound to another workspace.
    pub fn bind_run_workspace(
        &mut self,
        run_id: &str,
        workspace: &str,
    ) -> Result<(), JournalError> {
        if workspace.is_empty() {
            return Err(JournalError::InvalidEnvelope(
                "workspace must be non-empty".into(),
            ));
        }
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?1)",
            [run_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(JournalError::InvalidEnvelope("run does not exist".into()));
        }
        connection.execute(
            "INSERT INTO run_workspaces(run_id, workspace) VALUES(?1, ?2) \
             ON CONFLICT(run_id) DO UPDATE SET workspace=excluded.workspace \
             WHERE run_workspaces.workspace=excluded.workspace",
            params![run_id, workspace],
        )?;
        let bound: Option<String> = connection
            .query_row(
                "SELECT workspace FROM run_workspaces WHERE run_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()?;
        if bound.as_deref() != Some(workspace) {
            return Err(JournalError::Conflict(Conflict::EventId {
                event_id: run_id.to_owned(),
            }));
        }
        Ok(())
    }

    pub fn workspace_event_page(
        &mut self,
        workspace: &str,
        run_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<RunEventPage, RunEventPageError> {
        let owned: bool = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM run_workspaces WHERE run_id=?1 AND workspace=?2)",
                params![run_id, workspace],
                |row| row.get(0),
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        if !owned {
            return Err(RunEventPageError::NotFoundOrInaccessible);
        }
        self.event_page(run_id, limit, cursor)
    }

    pub fn run_belongs_to_workspace(
        &self,
        run_id: &str,
        workspace: &str,
    ) -> Result<bool, JournalError> {
        self.connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM run_workspaces WHERE run_id=?1 AND workspace=?2)",
                params![run_id, workspace],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn events(&mut self, run_id: &str) -> Result<Vec<EventEnvelope>, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let mut statement = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .prepare("SELECT envelope_json FROM events WHERE run_id=?1 ORDER BY run_seq")?;
        let rows = statement.query_map([run_id], |r| r.get::<_, String>(0))?;
        rows.map(|row| {
            let raw = row?;
            serde_json::from_str(&raw)
                .map_err(|e| JournalError::Corrupt(format!("invalid stored envelope JSON: {e}")))
        })
        .collect()
    }

    /// Reads at most `limit` envelopes without loading the complete run.
    pub fn event_page(
        &mut self,
        run_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<RunEventPage, RunEventPageError> {
        const MAX_PAGE_SIZE: usize = 100;
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(RunEventPageError::InvalidLimit);
        }
        let after = match cursor {
            Some(value) => decode_run_event_cursor(value, run_id, &self.cursor_key)?,
            None => 0,
        };
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()
            .map_err(RunEventPageError::Journal)?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?1)",
                [run_id],
                |row| row.get(0),
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        if !exists {
            return Err(RunEventPageError::NotFoundOrInaccessible);
        }
        if after > 0 {
            let boundary_exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?1 AND run_seq=?2)",
                    params![run_id, after],
                    |row| row.get(0),
                )
                .map_err(JournalError::from)
                .map_err(RunEventPageError::Journal)?;
            if !boundary_exists {
                return Err(RunEventPageError::InvalidCursor);
            }
        }
        let mut statement = connection
            .prepare("SELECT envelope_json FROM events WHERE run_id=?1 AND run_seq>?2 ORDER BY run_seq LIMIT ?3")
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        let rows = statement
            .query_map(params![run_id, after, (limit + 1) as u64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        let mut events = rows
            .map(|row| {
                let raw = row.map_err(JournalError::from)?;
                serde_json::from_str::<EventEnvelope>(&raw).map_err(|error| {
                    JournalError::Corrupt(format!("invalid stored envelope JSON: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(RunEventPageError::Journal)?;
        let has_more = events.len() > limit;
        events.truncate(limit);
        let next_cursor = if has_more {
            events
                .last()
                .map(|event| encode_run_event_cursor(run_id, event.run_seq, &self.cursor_key))
                .transpose()?
        } else {
            None
        };
        Ok(RunEventPage {
            events,
            next_cursor,
        })
    }

    /// Atomically removes a run's events and returns their distinct CAS hashes.
    pub fn delete_run(&mut self, run_id: &str) -> Result<HashSet<ContentHash>, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let tx = self
            .connection
            .as_mut()
            .expect("journal connection is always present outside compaction")
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hashes = referenced_hashes_for_run(&tx, Some(run_id))?;
        tx.execute("DELETE FROM events WHERE run_id=?1", [run_id])?;
        tx.execute(
            "DELETE FROM thread_projection_entries WHERE run_id=?1",
            [run_id],
        )?;
        tx.execute(
            "DELETE FROM thread_projection_history WHERE run_id=?1",
            [run_id],
        )?;
        tx.execute(
            "DELETE FROM thread_projection_versions WHERE run_id=?1",
            [&run_id],
        )?;
        tx.execute("DELETE FROM run_workspaces WHERE run_id=?1", [run_id])?;
        tx.commit()?;
        Ok(hashes)
    }

    /// Distinct CAS hashes referenced by all events currently in the journal.
    pub fn referenced_hashes(&mut self) -> Result<HashSet<ContentHash>, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        referenced_hashes_for_run(
            self.connection
                .as_ref()
                .expect("journal connection is always present outside compaction"),
            None,
        )
    }

    /// Run identities in first-recorded order. Callers still reconstruct all
    /// visible state through `events`; this is only the durable history index.
    pub fn run_ids(&mut self) -> Result<Vec<String>, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let mut statement = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .prepare(
                "SELECT run_id FROM events GROUP BY run_id ORDER BY MIN(recorded_at), MIN(rowid)",
            )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn refresh_after_compaction(&mut self) -> Result<(), JournalError> {
        let Some(coordination) = &self.coordination else {
            return Ok(());
        };
        let generation = coordination
            .generation
            .load(std::sync::atomic::Ordering::Acquire);
        if generation != self.generation || self.connection.is_none() {
            let path = self
                .path
                .as_ref()
                .expect("coordinated journals are file-backed");
            self.connection = Some(open_journal_connection(path)?);
            self.generation = generation;
        }
        Ok(())
    }
}

fn run_event_cursor_mac(key: &[u8; 32], run_id: &str, sequence: u64) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    mac.update(b"muniment-run-event-cursor-v1\0");
    mac.update(run_id.as_bytes());
    mac.update(&[0]);
    mac.update(&sequence.to_be_bytes());
    mac
}

fn thread_projection_cursor_mac(
    key: &[u8; 32],
    run_id: &str,
    snapshot_seq: u64,
    last_ordinal: i64,
) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    mac.update(b"muniment-thread-projection-cursor-v1\0");
    mac.update(run_id.as_bytes());
    mac.update(&[0]);
    mac.update(&snapshot_seq.to_be_bytes());
    mac.update(&last_ordinal.to_be_bytes());
    mac
}

fn encode_thread_projection_cursor(
    run_id: &str,
    snapshot_seq: u64,
    last_ordinal: i64,
    key: &[u8; 32],
) -> Result<String, RunEventPageError> {
    let cursor = ThreadProjectionCursor {
        version: 1,
        run_id: run_id.to_owned(),
        snapshot_seq,
        last_ordinal,
        authenticator: URL_SAFE_NO_PAD.encode(
            thread_projection_cursor_mac(key, run_id, snapshot_seq, last_ordinal)
                .finalize()
                .into_bytes(),
        ),
    };
    serde_json::to_vec(&cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| RunEventPageError::Journal(JournalError::Corrupt(error.to_string())))
}

fn decode_thread_projection_cursor(
    value: &str,
    run_id: &str,
    key: &[u8; 32],
) -> Result<(u64, i64), RunEventPageError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    let cursor: ThreadProjectionCursor =
        serde_json::from_slice(&bytes).map_err(|_| RunEventPageError::InvalidCursor)?;
    if cursor.version != 1 || cursor.run_id != run_id || cursor.snapshot_seq == 0 {
        return Err(RunEventPageError::InvalidCursor);
    }
    let authenticator = URL_SAFE_NO_PAD
        .decode(&cursor.authenticator)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    if cursor.last_ordinal < 0 {
        return Err(RunEventPageError::InvalidCursor);
    }
    thread_projection_cursor_mac(key, run_id, cursor.snapshot_seq, cursor.last_ordinal)
        .verify_slice(&authenticator)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    Ok((cursor.snapshot_seq, cursor.last_ordinal))
}

fn encode_run_event_cursor(
    run_id: &str,
    sequence: u64,
    key: &[u8; 32],
) -> Result<String, RunEventPageError> {
    let cursor = RunEventCursor {
        version: 1,
        run_id: run_id.to_owned(),
        after_run_seq: sequence,
        authenticator: URL_SAFE_NO_PAD.encode(
            run_event_cursor_mac(key, run_id, sequence)
                .finalize()
                .into_bytes(),
        ),
    };
    serde_json::to_vec(&cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| {
            RunEventPageError::Journal(JournalError::Corrupt(format!(
                "could not encode run-event cursor: {error}"
            )))
        })
}

fn decode_run_event_cursor(
    encoded: &str,
    run_id: &str,
    key: &[u8; 32],
) -> Result<u64, RunEventPageError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    let cursor: RunEventCursor =
        serde_json::from_slice(&bytes).map_err(|_| RunEventPageError::InvalidCursor)?;
    let authenticator = URL_SAFE_NO_PAD
        .decode(&cursor.authenticator)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    if cursor.version != 1
        || cursor.run_id != run_id
        || cursor.after_run_seq == 0
        || run_event_cursor_mac(key, run_id, cursor.after_run_seq)
            .verify_slice(&authenticator)
            .is_err()
    {
        return Err(RunEventPageError::InvalidCursor);
    }
    Ok(cursor.after_run_seq)
}

fn load_or_create_cursor_key(connection: &Connection) -> Result<[u8; 32], JournalError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS journal_metadata (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL) STRICT;",
    )?;
    let existing = connection
        .query_row(
            "SELECT value FROM journal_metadata WHERE key='run_summary_cursor_key'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let bytes = match existing {
        Some(bytes) => bytes,
        None => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|error| {
                JournalError::Corrupt(format!("cursor-key randomness failed: {error}"))
            })?;
            connection.execute(
                "INSERT OR IGNORE INTO journal_metadata(key,value) VALUES('run_summary_cursor_key',?1)",
                [&key[..]],
            )?;
            connection.query_row(
                "SELECT value FROM journal_metadata WHERE key='run_summary_cursor_key'",
                [],
                |row| row.get(0),
            )?
        }
    };
    bytes
        .try_into()
        .map_err(|_| JournalError::Corrupt("invalid stored run-summary cursor key".to_owned()))
}

pub(crate) fn open_journal_connection(path: &Path) -> Result<Connection, JournalError> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    Ok(connection)
}

fn referenced_hashes_for_run(
    connection: &Connection,
    run_id: Option<&str>,
) -> Result<HashSet<ContentHash>, JournalError> {
    let (sql, parameters) = match run_id {
        Some(run_id) => (
            "SELECT envelope_json FROM events WHERE run_id=?1",
            vec![run_id],
        ),
        None => ("SELECT envelope_json FROM events", vec![]),
    };
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(parameters), |row| {
        row.get::<_, String>(0)
    })?;
    let mut hashes = HashSet::new();
    for row in rows {
        let raw = row?;
        let event: EventEnvelope = serde_json::from_str(&raw)
            .map_err(|e| JournalError::Corrupt(format!("invalid stored envelope JSON: {e}")))?;
        match event.payload {
            EventPayload::Cas { payload_cas } => {
                hashes.insert(ContentHash::from_str(&payload_cas.sha256).map_err(|error| {
                    JournalError::Corrupt(format!("invalid stored CAS reference: {error}"))
                })?);
            }
            EventPayload::Attachment { attachment } => {
                hashes.insert(attachment.sha256().clone());
            }
            EventPayload::Inline { .. } => {}
        }
    }
    Ok(hashes)
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
CREATE TABLE run_workspaces (
 run_id TEXT PRIMARY KEY NOT NULL,
 workspace TEXT NOT NULL
) STRICT;
CREATE INDEX run_workspaces_workspace_run ON run_workspaces(workspace, run_id);
CREATE TABLE thread_projection_entries (
 run_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 run_seq INTEGER NOT NULL,
 kind TEXT NOT NULL,
 text TEXT,
 PRIMARY KEY(run_id, ordinal)
) STRICT;
CREATE INDEX thread_projection_run_order ON thread_projection_entries(run_id, ordinal);
CREATE TABLE thread_projection_history (
 run_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 valid_until_seq INTEGER NOT NULL,
 run_seq INTEGER NOT NULL,
 kind TEXT NOT NULL,
 text TEXT,
 PRIMARY KEY(run_id, ordinal, valid_until_seq)
) STRICT;
CREATE TABLE thread_projection_versions (
 run_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 valid_from_seq INTEGER NOT NULL,
 valid_until_seq INTEGER,
 run_seq INTEGER NOT NULL,
 kind TEXT NOT NULL,
 text TEXT,
 PRIMARY KEY(run_id, ordinal, valid_from_seq)
) STRICT;
CREATE INDEX thread_projection_versions_page
 ON thread_projection_versions(run_id, ordinal, valid_from_seq, valid_until_seq);
CREATE TABLE journal_metadata (
 key TEXT PRIMARY KEY NOT NULL,
 value BLOB NOT NULL
) STRICT;
COMMIT;
"#;

// Mutable chunks are deliberately small: snapshot versioning can copy at most
// this many bytes per appended byte, so projection storage remains linearly
// bounded even for a stream made up of one-byte deltas.
const PROJECTION_TEXT_CHUNK: usize = 64;

fn update_thread_projection(
    tx: &rusqlite::Transaction<'_>,
    event: &EventEnvelope,
) -> Result<(), JournalError> {
    fn inline_text(event: &EventEnvelope, name: &str) -> Option<String> {
        let EventPayload::Inline { payload_json } = &event.payload else {
            return None;
        };
        payload_json.get(name)?.as_str().map(str::to_owned)
    }
    fn chunks(text: &str) -> Vec<String> {
        if text.is_empty() {
            return vec![String::new()];
        }
        let mut result = Vec::new();
        let mut start = 0;
        while start < text.len() {
            let mut end = (start + PROJECTION_TEXT_CHUNK).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            result.push(text[start..end].to_owned());
            start = end;
        }
        result
    }
    let next_ordinal = || -> Result<i64, rusqlite::Error> {
        tx.query_row(
            "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM thread_projection_entries WHERE run_id=?1",
            [&event.run_id],
            |row| row.get(0),
        )
    };
    let insert_chunks = |kind: &str, text: &str| -> Result<(), JournalError> {
        let first_ordinal = next_ordinal()?;
        for (offset, chunk) in chunks(text).into_iter().enumerate() {
            let ordinal = first_ordinal + offset as i64;
            tx.execute(
                "INSERT INTO thread_projection_entries(run_id,ordinal,run_seq,kind,text) VALUES(?1,?2,?3,?4,?5)",
                params![event.run_id, ordinal, event.run_seq, kind, chunk],
            )?;
            tx.execute(
                "INSERT INTO thread_projection_versions(run_id,ordinal,valid_from_seq,run_seq,kind,text) VALUES(?1,?2,?3,?3,?4,?5)",
                params![event.run_id, ordinal, event.run_seq, kind, chunk],
            )?;
        }
        Ok(())
    };
    let archive = |kind: &str| -> Result<(), JournalError> {
        tx.execute(
            "UPDATE thread_projection_versions SET valid_until_seq=?1 \
             WHERE run_id=?2 AND kind=?3 AND valid_until_seq IS NULL",
            params![event.run_seq, event.run_id, kind],
        )?;
        Ok(())
    };
    match event.event_type.as_str() {
        "user.prompt.submitted" => {
            if let Some(text) = inline_text(event, "prompt") {
                insert_chunks("user_message", &text)?;
            }
        }
        "model.stream.delta" => {
            let Some(mut text) = inline_text(event, "text") else {
                return Ok(());
            };
            let last: Option<(i64, String)> = tx
                .query_row(
                    "SELECT ordinal, COALESCE(text,'') FROM thread_projection_entries WHERE run_id=?1 AND kind='assistant_message' ORDER BY ordinal DESC LIMIT 1",
                    [&event.run_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let had_tail = last.is_some();
            if let Some((ordinal, mut tail)) = last {
                let available = PROJECTION_TEXT_CHUNK.saturating_sub(tail.len());
                let mut take = available.min(text.len());
                while !text.is_char_boundary(take) {
                    take -= 1;
                }
                tail.push_str(&text[..take]);
                tx.execute(
                    "UPDATE thread_projection_versions SET valid_until_seq=?1 \
                     WHERE run_id=?2 AND ordinal=?3 AND valid_until_seq IS NULL",
                    params![event.run_seq, event.run_id, ordinal],
                )?;
                tx.execute(
                    "UPDATE thread_projection_entries SET text=?1 WHERE run_id=?2 AND ordinal=?3",
                    params![tail, event.run_id, ordinal],
                )?;
                tx.execute(
                    "INSERT INTO thread_projection_versions(run_id,ordinal,valid_from_seq,run_seq,kind,text) \
                     VALUES(?1,?2,?3,?3,'assistant_message',?4)",
                    params![event.run_id, ordinal, event.run_seq, tail],
                )?;
                text.drain(..take);
            }
            if !text.is_empty() || !had_tail {
                insert_chunks("assistant_message", &text)?;
            }
        }
        "chat.attachment.ingested" => {
            if let EventPayload::Attachment { attachment } = &event.payload {
                insert_chunks("attachment", attachment.display_name())?;
            }
        }
        "tool.effect.started" => {
            let effect_id = inline_text(event, "effect_id").unwrap_or_default();
            let display = inline_text(event, "display_name");
            let ordinal = next_ordinal()?;
            let kind = format!("tool_running:{effect_id}");
            tx.execute(
                "INSERT INTO thread_projection_entries(run_id,ordinal,run_seq,kind,text) VALUES(?1,?2,?3,?4,?5)",
                params![event.run_id, ordinal, event.run_seq, kind, display],
            )?;
            tx.execute(
                "INSERT INTO thread_projection_versions(run_id,ordinal,valid_from_seq,run_seq,kind,text) \
                 VALUES(?1,?2,?3,?3,?4,?5)",
                params![event.run_id, ordinal, event.run_seq, kind, display],
            )?;
        }
        "tool.effect.completed" | "tool.effect.failed" => {
            if let Some(effect_id) = inline_text(event, "effect_id") {
                let old = format!("tool_running:{effect_id}");
                let new = if event.event_type == "tool.effect.completed" {
                    "tool_completed"
                } else {
                    "tool_failed"
                };
                archive(&old)?;
                tx.execute(
                    "UPDATE thread_projection_entries SET kind=?1 WHERE run_id=?2 AND kind=?3",
                    params![new, event.run_id, old],
                )?;
                tx.execute(
                    "INSERT INTO thread_projection_versions(run_id,ordinal,valid_from_seq,run_seq,kind,text) \
                     SELECT run_id,ordinal,?1,?1,?2,text FROM thread_projection_entries \
                     WHERE run_id=?3 AND kind=?2",
                    params![event.run_seq, new, event.run_id],
                )?;
            }
        }
        "permission.requested" => {
            let title = inline_text(event, "title").unwrap_or_default();
            archive("permission_pending")?;
            tx.execute("DELETE FROM thread_projection_entries WHERE run_id=?1 AND kind='permission_pending'", [&event.run_id])?;
            insert_chunks("permission_pending", &title)?;
        }
        "permission.resolved" => {
            archive("permission_pending")?;
            tx.execute("DELETE FROM thread_projection_entries WHERE run_id=?1 AND kind='permission_pending'", [&event.run_id])?;
        }
        _ => {}
    }
    Ok(())
}
