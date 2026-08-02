//! Durable, append-only per-run event journal.

pub mod compaction;
pub mod content_disclosure;
pub mod export;
pub mod reducer;
pub mod retention;
pub mod summaries;
pub mod thread_summaries;

pub const MAX_MODEL_STREAM_DELTA_BYTES: usize = 65_536;
pub const MAX_THREAD_TITLE_CHARS: usize = summaries::MAX_TITLE_CHARS;

pub fn split_model_stream_delta(text: &str) -> impl Iterator<Item = &str> {
    let mut remaining = text;
    std::iter::from_fn(move || {
        if remaining.is_empty() {
            return None;
        }
        let mut end = remaining.len().min(MAX_MODEL_STREAM_DELTA_BYTES);
        while !remaining.is_char_boundary(end) {
            end -= 1;
        }
        let (slice, rest) = remaining.split_at(end);
        remaining = rest;
        Some(slice)
    })
}

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
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use uuid::{Uuid, Version};

const SCHEMA_VERSION: i64 = 4;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const COMMIT_HINT_CAPACITY: usize = 64;

/// A loss-tolerant wake-up hint. SQLite remains the authoritative event source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalCommitHint {
    pub run_id: String,
    pub run_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunEventType {
    pub run_id: String,
    pub run_seq: u64,
    pub event_type: String,
}

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct ThreadEventEnvelope {
    event_id: String,
    thread_id: String,
    thread_seq: u64,
    event_type: String,
    event_version: u32,
    envelope_version: u32,
    recorded_at: String,
    payload_json: Value,
    provenance: Provenance,
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
    pub(crate) assistant_projection_cache: Option<AssistantProjectionCache>,
}

pub(crate) struct AssistantProjectionCache {
    pub(crate) workspace: String,
    pub(crate) run_id: String,
    pub(crate) snapshot_seq: u64,
    pub(crate) entries: BTreeMap<i64, Option<String>>,
}

/// A bounded, sequence-ordered slice of one run. Callers must project these
/// envelopes before crossing the journal boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct RunEventPage {
    pub events: Vec<EventEnvelope>,
    pub next_cursor: Option<String>,
}

/// A bounded, stamp-ordered slice of a thread's runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadRunPage {
    pub run_ids: Vec<String>,
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
    pub pending_permission: Option<PendingPermissionProjection>,
    pub receipt: Option<ReceiptProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptProjection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<ReceiptCapabilityProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCapabilityProjection {
    pub name: String,
    pub version: String,
}

/// The bounded allow/deny context retained separately from a journal envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPermissionProjection {
    pub gate_id: String,
    pub kind: String,
    pub title: String,
    pub message: Option<String>,
    pub valid: bool,
}

const MAX_PENDING_GATE_ID_BYTES: usize = 256;
const MAX_PENDING_KIND_BYTES: usize = 32;
const MAX_PENDING_TITLE_BYTES: usize = 1_024;
const MAX_PENDING_MESSAGE_BYTES: usize = 4_096;
const MAX_PENDING_BACKFILL_ENVELOPE_BYTES: usize = 16 * 1024;
const MAX_RECEIPT_FIELD_BYTES: usize = 1_024;
const MAX_RECEIPT_CAPABILITIES: usize = 64;
const MAX_RECEIPT_BACKFILL_ENVELOPE_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub enum RunEventPageError {
    InvalidLimit,
    InvalidCursor,
    NotFoundOrInaccessible,
    Journal(JournalError),
}

#[derive(Debug)]
pub enum ThreadRunPageError {
    InvalidLimit,
    InvalidCursor,
    NotFoundOrInaccessible,
    Journal(JournalError),
}

impl From<JournalError> for ThreadRunPageError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
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
struct ThreadRunCursor {
    version: u8,
    thread_id: String,
    after_ordinal: u64,
    authenticator: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadProjectionCursor {
    version: u8,
    thread_id: String,
    workspace: String,
    snapshot_event_id: String,
    last_run_ordinal: i64,
    last_run_seq: u64,
    last_entry_ordinal: i64,
    authenticator: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadProjectionBoundary {
    pub(crate) snapshot_rowid: i64,
    pub(crate) snapshot_event_id: String,
    pub(crate) last_run_ordinal: i64,
    pub(crate) last_run_seq: u64,
    pub(crate) last_entry_ordinal: i64,
}

pub(crate) struct JournalCoordination {
    pub(crate) operation: Mutex<()>,
    pub(crate) generation: std::sync::atomic::AtomicU64,
    subscribers: Mutex<Vec<CommitSubscriber>>,
}

struct CommitSubscriber {
    run_id: String,
    sender: SyncSender<JournalCommitHint>,
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
        subscribers: Mutex::new(Vec::new()),
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

fn publish_commit_hint(coordination: Option<&JournalCoordination>, run_id: &str, run_seq: u64) {
    let Some(coordination) = coordination else {
        return;
    };
    let hint = JournalCommitHint {
        run_id: run_id.to_owned(),
        run_seq,
    };
    coordination
        .subscribers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|subscriber| {
            if subscriber.run_id != run_id {
                return true;
            }
            !matches!(
                subscriber.sender.try_send(hint.clone()),
                Err(TrySendError::Disconnected(_))
            )
        });
}

impl RunJournal {
    /// Registers a bounded commit-hint receiver and returns the run's committed
    /// high-water sequence at the same coordination boundary. Hints may be
    /// dropped under backpressure; consumers recover by reading SQLite after
    /// `high_water`.
    pub fn subscribe_commits(
        &mut self,
        run_id: &str,
    ) -> Result<(u64, Receiver<JournalCommitHint>), JournalError> {
        let coordination = self.coordination.clone().ok_or_else(|| {
            JournalError::InvalidEnvelope(
                "commit subscriptions require a file-backed journal".into(),
            )
        })?;
        let _operation = coordination.operation.lock().unwrap();
        self.refresh_after_compaction()?;
        let high_water = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .query_row(
                "SELECT COALESCE(MAX(run_seq), 0) FROM events WHERE run_id=?1",
                [run_id],
                |row| row.get(0),
            )?;
        let (sender, receiver) = mpsc::sync_channel(COMMIT_HINT_CAPACITY);
        coordination
            .subscribers
            .lock()
            .unwrap()
            .push(CommitSubscriber {
                run_id: run_id.to_owned(),
                sender,
            });
        Ok((high_water, receiver))
    }

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
                "SELECT e.run_id,e.run_seq,e.event_type,e.event_version,e.recorded_at, \
                 length(CAST(e.run_id AS BLOB))+length(CAST(e.event_type AS BLOB))+ \
                 length(CAST(e.recorded_at AS BLOB))+COALESCE(length(CAST(p.gate_id AS BLOB)),0)+ \
                 COALESCE(length(CAST(p.kind AS BLOB)),0)+COALESCE(length(CAST(p.title AS BLOB)),0)+ \
                 COALESCE(length(CAST(p.message AS BLOB)),0)+COALESCE(length(CAST(r.receipt_json AS BLOB)),0), \
                 p.gate_id,p.kind,p.title,p.message,p.valid,r.receipt_json,r.valid \
                 FROM events e LEFT JOIN permission_pending_projection p \
                 ON p.run_id=e.run_id AND p.run_seq=e.run_seq \
                 LEFT JOIN receipt_projection r ON r.run_id=e.run_id AND r.run_seq=e.run_seq \
                 WHERE e.run_id=?1 AND e.run_seq>?2 \
                 AND e.run_seq<=?3 ORDER BY e.run_seq LIMIT ?4",
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
                pending_permission: if row.get::<_, String>(2).map_err(JournalError::from)?
                    == "permission.requested"
                {
                    Some(PendingPermissionProjection {
                        gate_id: row
                            .get::<_, Option<String>>(6)
                            .map_err(JournalError::from)?
                            .unwrap_or_default(),
                        kind: row
                            .get::<_, Option<String>>(7)
                            .map_err(JournalError::from)?
                            .unwrap_or_default(),
                        title: row
                            .get::<_, Option<String>>(8)
                            .map_err(JournalError::from)?
                            .unwrap_or_default(),
                        message: row.get(9).map_err(JournalError::from)?,
                        valid: row
                            .get::<_, Option<bool>>(10)
                            .map_err(JournalError::from)?
                            .unwrap_or(false),
                    })
                } else {
                    None
                },
                receipt: if row.get::<_, String>(2).map_err(JournalError::from)? == "run.completed"
                    && row
                        .get::<_, Option<bool>>(12)
                        .map_err(JournalError::from)?
                        .unwrap_or(false)
                {
                    row.get::<_, Option<String>>(11)
                        .map_err(JournalError::from)?
                        .and_then(|value| serde_json::from_str(&value).ok())
                } else {
                    None
                },
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

    pub fn ledger_thread_projection_boundary(
        &mut self,
        workspace: &str,
        thread_id: &str,
        cursor: Option<&str>,
    ) -> Result<ThreadProjectionBoundary, RunEventPageError> {
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
        let accessible: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM thread_events te \
                 WHERE te.thread_id=?1 \
                 AND NOT EXISTS(SELECT 1 FROM thread_events deleted \
                    WHERE deleted.thread_id=te.thread_id AND deleted.event_type='thread.deleted') \
                 AND EXISTS(SELECT 1 FROM run_threads rt JOIN run_workspaces rw \
                    ON rw.run_id=rt.run_id WHERE rt.thread_id=te.thread_id AND rw.workspace=?2))",
                params![thread_id, workspace],
                |row| row.get(0),
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        if !accessible {
            return Err(RunEventPageError::NotFoundOrInaccessible);
        }
        if let Some(cursor) = cursor {
            let mut boundary =
                decode_thread_projection_cursor(cursor, thread_id, workspace, &self.cursor_key)?;
            boundary.snapshot_rowid = connection
                .query_row(
                    "SELECT e.rowid FROM run_threads rt JOIN events e ON e.run_id=rt.run_id \
                     WHERE rt.thread_id=?1 AND e.event_id=?2",
                    params![thread_id, boundary.snapshot_event_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(JournalError::from)
                .map_err(RunEventPageError::Journal)?
                .ok_or(RunEventPageError::InvalidCursor)?;
            return Ok(boundary);
        }
        let (snapshot_rowid, snapshot_event_id) = connection
            .query_row(
                "SELECT e.rowid,e.event_id FROM run_threads rt JOIN events e ON e.run_id=rt.run_id \
                 WHERE rt.thread_id=?1 ORDER BY e.rowid DESC LIMIT 1",
                [thread_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(JournalError::from)
            .map_err(RunEventPageError::Journal)?;
        Ok(ThreadProjectionBoundary {
            snapshot_rowid,
            snapshot_event_id,
            last_run_ordinal: 0,
            last_run_seq: 0,
            last_entry_ordinal: -1,
        })
    }

    pub fn ledger_thread_projection_cursor(
        &self,
        thread_id: &str,
        workspace: &str,
        boundary: &ThreadProjectionBoundary,
    ) -> Result<String, RunEventPageError> {
        encode_thread_projection_cursor(thread_id, workspace, boundary, &self.cursor_key)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref();
        let file_path = (path != Path::new(":memory:") && !path.as_os_str().is_empty())
            .then(|| normalized_path(path));
        let coordination = file_path.as_deref().map(coordination_for);
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        let mut connection = Connection::open(path)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(JournalError::Corrupt(format!(
                "unsupported schema version {version}"
            )));
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        let mut current_version = version;
        while current_version < SCHEMA_VERSION {
            let migration = MIGRATIONS
                .iter()
                .find(|migration| migration.version == current_version + 1)
                .ok_or_else(|| {
                    JournalError::Corrupt(format!("unsupported schema version {current_version}"))
                })?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            (migration.apply)(&tx)?;
            validate_database(&tx)?;
            tx.pragma_update(None, "user_version", migration.version)?;
            tx.commit()?;
            current_version = migration.version;
        }
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
            assistant_projection_cache: None,
        })
    }

    pub fn append(
        &mut self,
        expected_last_seq: u64,
        event: &EventEnvelope,
    ) -> Result<(), JournalError> {
        self.append_batch(expected_last_seq, std::slice::from_ref(event))
    }

    pub fn append_thread_title_renamed(
        &mut self,
        expected_last_thread_seq: u64,
        thread_id: &str,
        title: &str,
        recorded_at: &str,
        provenance: &Provenance,
    ) -> Result<(), JournalError> {
        let title = title.trim();
        if title.is_empty() || title.chars().count() > MAX_THREAD_TITLE_CHARS {
            return Err(JournalError::InvalidEnvelope(format!(
                "thread title must contain 1 to {MAX_THREAD_TITLE_CHARS} characters"
            )));
        }
        self.append_thread_event(
            expected_last_thread_seq,
            thread_id,
            "thread.title.renamed",
            recorded_at,
            serde_json::json!({ "title": title }),
            provenance,
        )
    }

    pub fn last_thread_seq(&mut self, thread_id: &str) -> Result<u64, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        self.connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .query_row(
                "SELECT COALESCE(MAX(thread_seq), 0) FROM thread_events WHERE thread_id=?1",
                [thread_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn append_thread_deleted(
        &mut self,
        expected_last_thread_seq: u64,
        thread_id: &str,
        recorded_at: &str,
        provenance: &Provenance,
    ) -> Result<(), JournalError> {
        self.append_thread_event(
            expected_last_thread_seq,
            thread_id,
            "thread.deleted",
            recorded_at,
            serde_json::json!({}),
            provenance,
        )
    }

    fn append_thread_event(
        &mut self,
        expected_last_thread_seq: u64,
        thread_id: &str,
        event_type: &str,
        recorded_at: &str,
        payload_json: Value,
        provenance: &Provenance,
    ) -> Result<(), JournalError> {
        let event = ThreadEventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            thread_id: thread_id.to_owned(),
            thread_seq: expected_last_thread_seq
                .checked_add(1)
                .ok_or_else(|| JournalError::InvalidEnvelope("thread sequence overflow".into()))?,
            event_type: event_type.to_owned(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: recorded_at.to_owned(),
            payload_json,
            provenance: provenance.clone(),
        };
        validate_thread_envelope(&event)?;
        let canonical = canonical_thread_envelope(&event)?;
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
        let actual: u64 = tx.query_row(
            "SELECT COALESCE(MAX(thread_seq), 0) FROM thread_events WHERE thread_id=?1",
            [thread_id],
            |row| row.get(0),
        )?;
        if actual != expected_last_thread_seq {
            return Err(JournalError::Conflict(Conflict::StaleSequence {
                expected: expected_last_thread_seq,
                actual,
            }));
        }
        if actual == 0 {
            return Err(JournalError::InvalidEnvelope(
                "thread does not exist".into(),
            ));
        }
        let deleted: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM thread_events \
             WHERE thread_id=?1 AND event_type='thread.deleted')",
            [thread_id],
            |row| row.get(0),
        )?;
        if deleted {
            return Err(JournalError::InvalidEnvelope("thread is deleted".into()));
        }
        tx.execute(
            "INSERT INTO thread_events(event_id,thread_id,thread_seq,event_type,event_version,\
             envelope_version,recorded_at,envelope_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                event.event_id,
                event.thread_id,
                event.thread_seq,
                event.event_type,
                event.event_version,
                event.envelope_version,
                event.recorded_at,
                canonical
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically creates a run and records its authoritative workspace.
    pub fn append_new_run(
        &mut self,
        workspace: &str,
        event: &EventEnvelope,
    ) -> Result<String, JournalError> {
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
        update_permission_pending_projection(&tx, event)?;
        update_receipt_projection(&tx, event)?;
        tx.execute(
            "INSERT INTO run_workspaces(run_id, workspace) VALUES(?1, ?2)",
            params![event.run_id, workspace],
        )?;
        let thread_id = Uuid::now_v7().to_string();
        append_thread_created(&tx, &thread_id, Some(workspace), &event.recorded_at, false)?;
        tx.execute(
            "INSERT INTO run_threads(run_id,thread_id,thread_run_ordinal) VALUES(?1,?2,1)",
            params![event.run_id, thread_id],
        )?;
        tx.commit()?;
        publish_commit_hint(coordination.as_deref(), &event.run_id, event.run_seq);
        Ok(thread_id)
    }

    /// Atomically creates a run in an existing thread at its next ordinal.
    pub fn append_new_run_in_thread(
        &mut self,
        workspace: &str,
        thread_id: &str,
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
        let thread_workspace: Option<Option<String>> = tx
            .query_row(
                "SELECT json_extract(envelope_json,'$.payload_json.workspace') \
                 FROM thread_events WHERE thread_id=?1 AND thread_seq=1 \
                 AND event_type='thread.created'",
                [thread_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(thread_workspace) = thread_workspace else {
            return Err(JournalError::InvalidEnvelope(
                "thread does not exist".into(),
            ));
        };
        let deleted: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM thread_events \
             WHERE thread_id=?1 AND event_type='thread.deleted')",
            [thread_id],
            |row| row.get(0),
        )?;
        if deleted {
            return Err(JournalError::InvalidEnvelope("thread is deleted".into()));
        }
        if thread_workspace.as_deref() != Some(workspace) {
            return Err(JournalError::InvalidEnvelope(
                "thread belongs to another workspace".into(),
            ));
        }
        let next_ordinal: u64 = tx.query_row(
            "SELECT COALESCE(MAX(thread_run_ordinal), 0) + 1 \
             FROM run_threads WHERE thread_id=?1",
            [thread_id],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO events(event_id,run_id,run_seq,event_type,event_version,envelope_version,recorded_at,envelope_json) VALUES(?1,?2,1,?3,?4,?5,?6,?7)",
            params![event.event_id,event.run_id,event.event_type,event.event_version,event.envelope_version,event.recorded_at,canonical],
        )?;
        update_thread_projection(&tx, event)?;
        update_permission_pending_projection(&tx, event)?;
        update_receipt_projection(&tx, event)?;
        tx.execute(
            "INSERT INTO run_workspaces(run_id, workspace) VALUES(?1, ?2)",
            params![event.run_id, workspace],
        )?;
        tx.execute(
            "INSERT INTO run_threads(run_id,thread_id,thread_run_ordinal) VALUES(?1,?2,?3)",
            params![event.run_id, thread_id, next_ordinal],
        )?;
        tx.commit()?;
        publish_commit_hint(coordination.as_deref(), &event.run_id, event.run_seq);
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
        if actual == 0 {
            // Low-level append remains available for import/tests. Production
            // creation uses append_new_run, which records the real scope.
            let thread_id = Uuid::now_v7().to_string();
            append_thread_created(&tx, &thread_id, Some(""), &events[0].recorded_at, false)?;
            tx.execute(
                "INSERT INTO run_threads(run_id,thread_id,thread_run_ordinal) VALUES(?1,?2,1)",
                params![run_id, thread_id],
            )?;
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
            update_permission_pending_projection(&tx, event)?;
            update_receipt_projection(&tx, event)?;
        }
        tx.commit()?;
        publish_commit_hint(
            coordination.as_deref(),
            run_id,
            events.last().expect("non-empty batch").run_seq,
        );
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
            .as_mut()
            .expect("journal connection is always present outside compaction");
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let recorded_at: Option<String> = tx.query_row(
            "SELECT MIN(recorded_at) FROM events WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        let Some(recorded_at) = recorded_at else {
            return Err(JournalError::InvalidEnvelope("run does not exist".into()));
        };
        tx.execute(
            "INSERT INTO run_workspaces(run_id, workspace) VALUES(?1, ?2) \
             ON CONFLICT(run_id) DO UPDATE SET workspace=excluded.workspace \
             WHERE run_workspaces.workspace=excluded.workspace",
            params![run_id, workspace],
        )?;
        let bound: Option<String> = tx
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
        let stamped: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM run_threads WHERE run_id=?1)",
            [run_id],
            |row| row.get(0),
        )?;
        if !stamped {
            let thread_id = Uuid::now_v7().to_string();
            append_thread_created(&tx, &thread_id, Some(workspace), &recorded_at, false)?;
            tx.execute(
                "INSERT INTO run_threads(run_id,thread_id,thread_run_ordinal) VALUES(?1,?2,1)",
                params![run_id, thread_id],
            )?;
        }
        tx.commit()?;
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

    /// Reads run event types in journal order without loading run envelopes.
    pub fn run_event_types(&mut self) -> Result<Vec<RunEventType>, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let mut statement = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .prepare("SELECT run_id,run_seq,event_type FROM events ORDER BY run_id,run_seq")?;
        let rows = statement.query_map([], |row| {
            Ok(RunEventType {
                run_id: row.get(0)?,
                run_seq: row.get(1)?,
                event_type: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Reads at most `limit` stamped run IDs without loading run envelopes.
    pub fn thread_run_ids(
        &mut self,
        thread_id: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ThreadRunPage, ThreadRunPageError> {
        const MAX_PAGE_SIZE: usize = 100;
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(ThreadRunPageError::InvalidLimit);
        }
        let after = match cursor {
            Some(value) => decode_thread_run_cursor(value, thread_id, &self.cursor_key)?,
            None => 0,
        };
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()
            .map_err(ThreadRunPageError::Journal)?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let accessible: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM thread_events te WHERE te.thread_id=?1 \
                 AND NOT EXISTS(SELECT 1 FROM thread_events deleted \
                    WHERE deleted.thread_id=te.thread_id AND deleted.event_type='thread.deleted'))",
                [thread_id],
                |row| row.get(0),
            )
            .map_err(JournalError::from)
            .map_err(ThreadRunPageError::Journal)?;
        if !accessible {
            return Err(ThreadRunPageError::NotFoundOrInaccessible);
        }
        if after > 0 {
            let boundary_exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM run_threads \
                     WHERE thread_id=?1 AND thread_run_ordinal=?2)",
                    params![thread_id, after],
                    |row| row.get(0),
                )
                .map_err(JournalError::from)
                .map_err(ThreadRunPageError::Journal)?;
            if !boundary_exists {
                return Err(ThreadRunPageError::InvalidCursor);
            }
        }
        let mut statement = connection
            .prepare(
                "SELECT run_id,thread_run_ordinal FROM run_threads \
                 WHERE thread_id=?1 AND thread_run_ordinal>?2 \
                 ORDER BY thread_run_ordinal LIMIT ?3",
            )
            .map_err(JournalError::from)
            .map_err(ThreadRunPageError::Journal)?;
        let rows = statement
            .query_map(params![thread_id, after, (limit + 1) as u64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(JournalError::from)
            .map_err(ThreadRunPageError::Journal)?;
        let mut runs = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(JournalError::from)
            .map_err(ThreadRunPageError::Journal)?;
        let has_more = runs.len() > limit;
        runs.truncate(limit);
        let next_cursor = if has_more {
            runs.last()
                .map(|(_, ordinal)| encode_thread_run_cursor(thread_id, *ordinal, &self.cursor_key))
                .transpose()?
        } else {
            None
        };
        Ok(ThreadRunPage {
            run_ids: runs.into_iter().map(|(run_id, _)| run_id).collect(),
            next_cursor,
        })
    }

    /// Reads only the first envelope for one run.
    pub fn first_envelope(&mut self, run_id: &str) -> Result<EventEnvelope, JournalError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let raw = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction")
            .query_row(
                "SELECT envelope_json FROM events WHERE run_id=?1 ORDER BY run_seq LIMIT 1",
                [run_id],
                |row| row.get::<_, String>(0),
            )?;
        serde_json::from_str(&raw).map_err(|error| {
            JournalError::Corrupt(format!("invalid stored envelope JSON: {error}"))
        })
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
            "DELETE FROM permission_pending_projection WHERE run_id=?1",
            [run_id],
        )?;
        tx.execute("DELETE FROM receipt_projection WHERE run_id=?1", [run_id])?;
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
        let thread_id: Option<String> = tx
            .query_row(
                "SELECT thread_id FROM run_threads WHERE run_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute("DELETE FROM run_threads WHERE run_id=?1", [run_id])?;
        if let Some(thread_id) = thread_id {
            tx.execute(
                "DELETE FROM thread_events WHERE thread_id=?1 \
                 AND NOT EXISTS(SELECT 1 FROM run_threads WHERE thread_id=?1)",
                [thread_id],
            )?;
        }
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

fn thread_run_cursor_mac(key: &[u8; 32], thread_id: &str, ordinal: u64) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    mac.update(b"muniment-thread-run-cursor-v1\0");
    mac.update(thread_id.as_bytes());
    mac.update(&[0]);
    mac.update(&ordinal.to_be_bytes());
    mac
}

fn thread_projection_cursor_mac(
    key: &[u8; 32],
    thread_id: &str,
    workspace: &str,
    boundary: &ThreadProjectionBoundary,
) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    mac.update(b"muniment-ledger-thread-projection-cursor-v1\0");
    mac.update(thread_id.as_bytes());
    mac.update(&[0]);
    mac.update(workspace.as_bytes());
    mac.update(&[0]);
    mac.update(boundary.snapshot_event_id.as_bytes());
    mac.update(&[0]);
    mac.update(&boundary.last_run_ordinal.to_be_bytes());
    mac.update(&boundary.last_run_seq.to_be_bytes());
    mac.update(&boundary.last_entry_ordinal.to_be_bytes());
    mac
}

fn encode_thread_projection_cursor(
    thread_id: &str,
    workspace: &str,
    boundary: &ThreadProjectionBoundary,
    key: &[u8; 32],
) -> Result<String, RunEventPageError> {
    let cursor = ThreadProjectionCursor {
        version: 1,
        thread_id: thread_id.to_owned(),
        workspace: workspace.to_owned(),
        snapshot_event_id: boundary.snapshot_event_id.clone(),
        last_run_ordinal: boundary.last_run_ordinal,
        last_run_seq: boundary.last_run_seq,
        last_entry_ordinal: boundary.last_entry_ordinal,
        authenticator: URL_SAFE_NO_PAD.encode(
            thread_projection_cursor_mac(key, thread_id, workspace, boundary)
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
    thread_id: &str,
    workspace: &str,
    key: &[u8; 32],
) -> Result<ThreadProjectionBoundary, RunEventPageError> {
    if value.is_empty() || value.len() > 1024 {
        return Err(RunEventPageError::InvalidCursor);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    let cursor: ThreadProjectionCursor =
        serde_json::from_slice(&bytes).map_err(|_| RunEventPageError::InvalidCursor)?;
    if cursor.version != 1
        || cursor.thread_id != thread_id
        || cursor.workspace != workspace
        || cursor.snapshot_event_id.is_empty()
        || cursor.last_run_ordinal <= 0
        || cursor.last_run_seq == 0
        || cursor.last_entry_ordinal < 0
    {
        return Err(RunEventPageError::InvalidCursor);
    }
    let authenticator = URL_SAFE_NO_PAD
        .decode(&cursor.authenticator)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    let boundary = ThreadProjectionBoundary {
        snapshot_rowid: 0,
        snapshot_event_id: cursor.snapshot_event_id,
        last_run_ordinal: cursor.last_run_ordinal,
        last_run_seq: cursor.last_run_seq,
        last_entry_ordinal: cursor.last_entry_ordinal,
    };
    thread_projection_cursor_mac(key, thread_id, workspace, &boundary)
        .verify_slice(&authenticator)
        .map_err(|_| RunEventPageError::InvalidCursor)?;
    Ok(boundary)
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

fn encode_thread_run_cursor(
    thread_id: &str,
    ordinal: u64,
    key: &[u8; 32],
) -> Result<String, ThreadRunPageError> {
    let cursor = ThreadRunCursor {
        version: 1,
        thread_id: thread_id.to_owned(),
        after_ordinal: ordinal,
        authenticator: URL_SAFE_NO_PAD.encode(
            thread_run_cursor_mac(key, thread_id, ordinal)
                .finalize()
                .into_bytes(),
        ),
    };
    serde_json::to_vec(&cursor)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| {
            ThreadRunPageError::Journal(JournalError::Corrupt(format!(
                "could not encode thread-run cursor: {error}"
            )))
        })
}

fn decode_thread_run_cursor(
    encoded: &str,
    thread_id: &str,
    key: &[u8; 32],
) -> Result<u64, ThreadRunPageError> {
    if encoded.is_empty() || encoded.len() > 512 {
        return Err(ThreadRunPageError::InvalidCursor);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ThreadRunPageError::InvalidCursor)?;
    let cursor: ThreadRunCursor =
        serde_json::from_slice(&bytes).map_err(|_| ThreadRunPageError::InvalidCursor)?;
    let authenticator = URL_SAFE_NO_PAD
        .decode(&cursor.authenticator)
        .map_err(|_| ThreadRunPageError::InvalidCursor)?;
    if cursor.version != 1
        || cursor.thread_id != thread_id
        || cursor.after_ordinal == 0
        || thread_run_cursor_mac(key, thread_id, cursor.after_ordinal)
            .verify_slice(&authenticator)
            .is_err()
    {
        return Err(ThreadRunPageError::InvalidCursor);
    }
    Ok(cursor.after_ordinal)
}

fn load_or_create_cursor_key(connection: &Connection) -> Result<[u8; 32], JournalError> {
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

fn canonical_thread_envelope(event: &ThreadEventEnvelope) -> Result<String, JournalError> {
    let mut value =
        serde_json::to_value(event).map_err(|e| JournalError::InvalidEnvelope(e.to_string()))?;
    sort_json(&mut value);
    serde_json::to_string(&value).map_err(|e| JournalError::InvalidEnvelope(e.to_string()))
}

fn validate_thread_envelope(event: &ThreadEventEnvelope) -> Result<(), JournalError> {
    if event.thread_seq == 0
        || event.event_version != 1
        || event.envelope_version != 1
        || event.provenance.source.trim().is_empty()
        || event.provenance.source_version.trim().is_empty()
    {
        return Err(JournalError::InvalidEnvelope(
            "thread sequence and versions must be valid and provenance must be non-empty".into(),
        ));
    }
    for (name, value) in [
        ("thread event ID", event.event_id.as_str()),
        ("thread ID", event.thread_id.as_str()),
    ] {
        let uuid = Uuid::parse_str(value)
            .map_err(|_| JournalError::InvalidEnvelope(format!("{name} must be a UUIDv7")))?;
        if uuid.get_version() != Some(Version::SortRand) {
            return Err(JournalError::InvalidEnvelope(format!(
                "{name} must be a UUIDv7"
            )));
        }
    }
    validate_time("recorded_at", &event.recorded_at, true)?;
    match event.event_type.as_str() {
        "thread.created" => {
            let valid = event.payload_json.as_object().is_some_and(|payload| {
                payload.len() == 2
                    && payload
                        .get("migration_backfill")
                        .is_some_and(Value::is_boolean)
                    && payload
                        .get("workspace")
                        .is_some_and(|value| value.is_null() || value.is_string())
            });
            if !valid {
                return Err(JournalError::InvalidEnvelope(
                    "thread.created payload is invalid".into(),
                ));
            }
        }
        "thread.title.renamed" => {
            let title = event
                .payload_json
                .as_object()
                .filter(|payload| payload.len() == 1)
                .and_then(|payload| payload.get("title"))
                .and_then(Value::as_str);
            if !title.is_some_and(|title| {
                !title.is_empty()
                    && title == title.trim()
                    && title.chars().count() <= MAX_THREAD_TITLE_CHARS
            }) {
                return Err(JournalError::InvalidEnvelope(
                    "thread.title.renamed payload is invalid".into(),
                ));
            }
        }
        "thread.deleted"
            if event
                .payload_json
                .as_object()
                .is_some_and(|value| value.is_empty()) => {}
        "thread.deleted" => {
            return Err(JournalError::InvalidEnvelope(
                "thread.deleted payload is invalid".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn append_thread_created(
    tx: &rusqlite::Transaction<'_>,
    thread_id: &str,
    workspace: Option<&str>,
    recorded_at: &str,
    migration_backfill: bool,
) -> Result<(), JournalError> {
    let envelope = ThreadEventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        thread_id: thread_id.to_owned(),
        thread_seq: 1,
        event_type: "thread.created".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: recorded_at.to_owned(),
        payload_json: serde_json::json!({
            "migration_backfill": migration_backfill,
            "workspace": workspace,
        }),
        provenance: Provenance {
            source: if migration_backfill {
                "schema-v3-migration"
            } else {
                "run-journal"
            }
            .into(),
            source_version: "1".into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
    };
    validate_thread_envelope(&envelope)?;
    let canonical = canonical_thread_envelope(&envelope)?;
    tx.execute(
        "INSERT INTO thread_events(event_id,thread_id,thread_seq,event_type,event_version,\
         envelope_version,recorded_at,envelope_json) VALUES(?1,?2,1,?3,?4,?5,?6,?7)",
        params![
            envelope.event_id,
            envelope.thread_id,
            envelope.event_type,
            envelope.event_version,
            envelope.envelope_version,
            envelope.recorded_at,
            canonical
        ],
    )?;
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
    let schema_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let thread_schema_objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE \
         (type='table' AND name IN ('thread_events','run_threads')) OR \
         (type='index' AND name IN ('thread_events_thread_order','run_threads_thread_run'))",
        [],
        |row| row.get(0),
    )?;
    if schema_version >= 3 || thread_schema_objects != 0 {
        if thread_schema_objects == 4 {
            match validate_thread_identity(connection) {
                Err(JournalError::Sqlite(error)) => {
                    return Err(JournalError::Corrupt(format!(
                        "malformed thread schema: {error}"
                    )));
                }
                result => result?,
            }
            validate_thread_schema(connection)?;
        } else {
            validate_thread_schema(connection)?;
            validate_thread_identity(connection)?;
        }
    }
    Ok(())
}

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace(" if not exists", "")
}

fn validate_thread_schema(connection: &Connection) -> Result<(), JournalError> {
    for (object_type, name, expected) in [
        ("table", "thread_events", CREATE_THREAD_EVENTS),
        (
            "index",
            "thread_events_thread_order",
            CREATE_THREAD_EVENTS_INDEX,
        ),
        ("table", "run_threads", CREATE_RUN_THREADS),
        ("index", "run_threads_thread_run", CREATE_RUN_THREADS_INDEX),
    ] {
        let actual = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![object_type, name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let expected = normalized_schema_sql(expected);
        if actual.as_deref().map(normalized_schema_sql).as_deref() != Some(expected.as_str()) {
            return Err(JournalError::Corrupt(format!(
                "missing or malformed schema object {name}"
            )));
        }
    }
    Ok(())
}

fn validate_thread_identity(connection: &Connection) -> Result<(), JournalError> {
    let missing_or_duplicate: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT e.run_id FROM events e \
         LEFT JOIN run_threads rt ON rt.run_id=e.run_id GROUP BY e.run_id \
         HAVING COUNT(DISTINCT rt.rowid) != 1)",
        [],
        |row| row.get(0),
    )?;
    if missing_or_duplicate != 0 {
        return Err(JournalError::Corrupt(
            "every run must have exactly one thread stamp".into(),
        ));
    }
    let orphan_stamps: i64 = connection.query_row(
        "SELECT COUNT(*) FROM run_threads rt \
         WHERE NOT EXISTS(SELECT 1 FROM events e WHERE e.run_id=rt.run_id)",
        [],
        |row| row.get(0),
    )?;
    if orphan_stamps != 0 {
        return Err(JournalError::Corrupt(
            "thread stamp references a missing run".into(),
        ));
    }
    let invalid_ordinals: i64 = connection.query_row(
        "SELECT COUNT(*) FROM run_threads WHERE thread_run_ordinal <= 0",
        [],
        |row| row.get(0),
    )?;
    if invalid_ordinals != 0 {
        return Err(JournalError::Corrupt(
            "thread run ordinals must be positive".into(),
        ));
    }
    let duplicate_ordinals: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM run_threads \
         GROUP BY thread_id,thread_run_ordinal HAVING COUNT(*) > 1)",
        [],
        |row| row.get(0),
    )?;
    if duplicate_ordinals != 0 {
        return Err(JournalError::Corrupt(
            "thread run ordinals must be unique within each thread".into(),
        ));
    }
    let mut statement = connection.prepare(
        "SELECT event_id,thread_id,thread_seq,event_type,event_version,envelope_version,\
         recorded_at,envelope_json FROM thread_events ORDER BY thread_id,thread_seq",
    )?;
    let mut rows = statement.query([])?;
    let mut previous: Option<(String, u64)> = None;
    while let Some(row) = rows.next()? {
        let raw: String = row.get(7)?;
        let event: ThreadEventEnvelope = serde_json::from_str(&raw)
            .map_err(|e| JournalError::Corrupt(format!("invalid thread envelope JSON: {e}")))?;
        validate_thread_envelope(&event).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let canonical =
            canonical_thread_envelope(&event).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        if raw != canonical
            || event.event_id != row.get::<_, String>(0)?
            || event.thread_id != row.get::<_, String>(1)?
            || event.thread_seq != row.get::<_, u64>(2)?
            || event.event_type != row.get::<_, String>(3)?
            || event.event_version != row.get::<_, u32>(4)?
            || event.envelope_version != row.get::<_, u32>(5)?
            || event.recorded_at != row.get::<_, String>(6)?
        {
            return Err(JournalError::Corrupt(format!(
                "stored thread envelope/index mismatch for {}",
                event.event_id
            )));
        }
        let expected = previous
            .as_ref()
            .filter(|(id, _)| id == &event.thread_id)
            .map_or(1, |(_, seq)| seq + 1);
        if event.thread_seq != expected
            || (event.thread_seq == 1 && event.event_type != "thread.created")
            || previous.as_ref().is_some_and(|(id, _)| {
                id == &event.thread_id && event.event_type == "thread.created"
            })
        {
            return Err(JournalError::Corrupt(format!(
                "thread {} has invalid sequence or creation event",
                event.thread_id
            )));
        }
        previous = Some((event.thread_id, event.thread_seq));
    }
    let events_after_delete: i64 = connection.query_row(
        "SELECT COUNT(*) FROM thread_events deleted JOIN thread_events later \
         ON later.thread_id=deleted.thread_id AND later.thread_seq>deleted.thread_seq \
         WHERE deleted.event_type='thread.deleted'",
        [],
        |row| row.get(0),
    )?;
    if events_after_delete != 0 {
        return Err(JournalError::Corrupt(
            "thread deletion must be the last event".into(),
        ));
    }
    let unstamped_threads: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT DISTINCT te.thread_id FROM thread_events te \
         WHERE NOT EXISTS(SELECT 1 FROM run_threads rt WHERE rt.thread_id=te.thread_id))",
        [],
        |row| row.get(0),
    )?;
    let stamps_without_threads: i64 = connection.query_row(
        "SELECT COUNT(*) FROM run_threads rt WHERE NOT EXISTS(\
         SELECT 1 FROM thread_events te WHERE te.thread_id=rt.thread_id \
         AND te.thread_seq=1 AND te.event_type='thread.created')",
        [],
        |row| row.get(0),
    )?;
    if unstamped_threads != 0 || stamps_without_threads != 0 {
        return Err(JournalError::Corrupt(
            "thread ledger and run stamps are inconsistent".into(),
        ));
    }
    Ok(())
}

const SCHEMA: &str = r#"
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
CREATE TABLE permission_pending_projection (
 run_id TEXT NOT NULL,
 run_seq INTEGER NOT NULL,
 gate_id TEXT,
 kind TEXT,
 title TEXT,
 message TEXT,
 valid INTEGER NOT NULL,
 PRIMARY KEY(run_id, run_seq)
) STRICT;
CREATE TABLE receipt_projection (
 run_id TEXT NOT NULL, run_seq INTEGER NOT NULL, receipt_json TEXT,
 valid INTEGER NOT NULL, PRIMARY KEY(run_id, run_seq)
) STRICT;
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
"#;

struct Migration {
    version: i64,
    apply: fn(&rusqlite::Transaction<'_>) -> Result<(), JournalError>,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        apply: migrate_to_1,
    },
    Migration {
        version: 2,
        apply: migrate_to_2,
    },
    Migration {
        version: 3,
        apply: migrate_to_3,
    },
    Migration {
        version: 4,
        apply: migrate_to_4,
    },
];

const CREATE_THREAD_EVENTS: &str = "CREATE TABLE IF NOT EXISTS thread_events( \
 event_id TEXT PRIMARY KEY NOT NULL, thread_id TEXT NOT NULL, \
 thread_seq INTEGER NOT NULL CHECK(thread_seq > 0), event_type TEXT NOT NULL, \
 event_version INTEGER NOT NULL CHECK(event_version > 0), \
 envelope_version INTEGER NOT NULL CHECK(envelope_version > 0), \
 recorded_at TEXT NOT NULL, envelope_json TEXT NOT NULL, \
 UNIQUE(thread_id, thread_seq)) STRICT";
const CREATE_THREAD_EVENTS_INDEX: &str = "CREATE INDEX IF NOT EXISTS thread_events_thread_order \
 ON thread_events(thread_id, thread_seq)";
const CREATE_RUN_THREADS: &str = "CREATE TABLE IF NOT EXISTS run_threads( \
 run_id TEXT PRIMARY KEY NOT NULL, thread_id TEXT NOT NULL, \
 thread_run_ordinal INTEGER NOT NULL CHECK(thread_run_ordinal > 0), \
 UNIQUE(thread_id, thread_run_ordinal)) STRICT";
const CREATE_RUN_THREADS_INDEX: &str = "CREATE INDEX IF NOT EXISTS run_threads_thread_run \
 ON run_threads(thread_id, thread_run_ordinal)";
const THREAD_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS thread_events( \
 event_id TEXT PRIMARY KEY NOT NULL, thread_id TEXT NOT NULL, \
 thread_seq INTEGER NOT NULL CHECK(thread_seq > 0), event_type TEXT NOT NULL, \
 event_version INTEGER NOT NULL CHECK(event_version > 0), \
 envelope_version INTEGER NOT NULL CHECK(envelope_version > 0), \
 recorded_at TEXT NOT NULL, envelope_json TEXT NOT NULL, \
 UNIQUE(thread_id, thread_seq)) STRICT; \
 CREATE INDEX IF NOT EXISTS thread_events_thread_order \
 ON thread_events(thread_id, thread_seq); \
 CREATE TABLE IF NOT EXISTS run_threads( \
 run_id TEXT PRIMARY KEY NOT NULL, thread_id TEXT NOT NULL, \
 thread_run_ordinal INTEGER NOT NULL CHECK(thread_run_ordinal > 0), \
 UNIQUE(thread_id, thread_run_ordinal)) STRICT; \
 CREATE INDEX IF NOT EXISTS run_threads_thread_run \
 ON run_threads(thread_id, thread_run_ordinal);";

fn migrate_to_1(tx: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    tx.execute_batch(SCHEMA)?;
    Ok(())
}

fn migrate_to_2(tx: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    tx.execute_batch(
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
         ON thread_projection_versions(run_id, ordinal, valid_from_seq, valid_until_seq); \
         CREATE TABLE IF NOT EXISTS permission_pending_projection( \
         run_id TEXT NOT NULL, run_seq INTEGER NOT NULL, gate_id TEXT, kind TEXT, \
         title TEXT, message TEXT, valid INTEGER NOT NULL, PRIMARY KEY(run_id, run_seq)); \
         CREATE TABLE IF NOT EXISTS receipt_projection( \
         run_id TEXT NOT NULL, run_seq INTEGER NOT NULL, receipt_json TEXT, \
         valid INTEGER NOT NULL, PRIMARY KEY(run_id, run_seq));",
    )?;
    backfill_permission_pending_projection(tx)?;
    backfill_receipt_projection(tx)?;
    // Journals created by the first projection implementation have only a
    // current row. Treat that row as the initial version; new writes use
    // interval versions from this point forward.
    tx.execute(
        "INSERT OR IGNORE INTO thread_projection_versions( \
         run_id,ordinal,valid_from_seq,run_seq,kind,text) \
         SELECT run_id,ordinal,run_seq,run_seq,kind,text \
         FROM thread_projection_entries",
        [],
    )?;
    Ok(())
}

fn migrate_to_3(tx: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    tx.execute_batch(THREAD_SCHEMA)?;
    let runs = {
        let mut statement = tx.prepare(
            "SELECT e.run_id, MIN(e.recorded_at), rw.workspace FROM events e \
             LEFT JOIN run_workspaces rw ON rw.run_id=e.run_id \
             WHERE NOT EXISTS(SELECT 1 FROM run_threads rt WHERE rt.run_id=e.run_id) \
             GROUP BY e.run_id ORDER BY e.run_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (run_id, recorded_at, workspace) in runs {
        let thread_id = Uuid::now_v7().to_string();
        append_thread_created(tx, &thread_id, workspace.as_deref(), &recorded_at, true)?;
        tx.execute(
            "INSERT INTO run_threads(run_id,thread_id,thread_run_ordinal) VALUES(?1,?2,1)",
            params![run_id, thread_id],
        )?;
    }
    Ok(())
}

fn migrate_to_4(tx: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    tx.execute_batch("DROP INDEX IF EXISTS events_run_order")?;
    Ok(())
}

// Mutable chunks are deliberately small: snapshot versioning can copy at most
// this many bytes per appended byte, so projection storage remains linearly
// bounded even for a stream made up of one-byte deltas.
const PROJECTION_TEXT_CHUNK: usize = 64;

fn update_permission_pending_projection(
    tx: &rusqlite::Transaction<'_>,
    event: &EventEnvelope,
) -> Result<(), JournalError> {
    if event.event_type != "permission.requested" {
        return Ok(());
    }
    let fields = match &event.payload {
        EventPayload::Inline { payload_json } => {
            let gate_id = payload_json.get("gate_id").and_then(Value::as_str);
            let kind = payload_json.get("kind").and_then(Value::as_str);
            let title = payload_json.get("title").and_then(Value::as_str);
            let message_value = payload_json.get("message");
            let message = message_value.and_then(Value::as_str);
            match (gate_id, kind, title) {
                (Some(gate_id), Some("confirm"), Some(title))
                    if !gate_id.trim().is_empty()
                        && gate_id.len() <= MAX_PENDING_GATE_ID_BYTES
                        && "confirm".len() <= MAX_PENDING_KIND_BYTES
                        && !title.trim().is_empty()
                        && title.len() <= MAX_PENDING_TITLE_BYTES
                        && (message_value.is_none_or(Value::is_null)
                            || message
                                .is_some_and(|value| value.len() <= MAX_PENDING_MESSAGE_BYTES)) =>
                {
                    Some((gate_id, "confirm", title, message))
                }
                _ => None,
            }
        }
        _ => None,
    };
    if let Some((gate_id, kind, title, message)) = fields {
        tx.execute(
            "INSERT INTO permission_pending_projection(run_id,run_seq,gate_id,kind,title,message,valid) \
             VALUES(?1,?2,?3,?4,?5,?6,1)",
            params![event.run_id, event.run_seq, gate_id, kind, title, message],
        )?;
    } else {
        tx.execute(
            "INSERT INTO permission_pending_projection(run_id,run_seq,valid) VALUES(?1,?2,0)",
            params![event.run_id, event.run_seq],
        )?;
    }
    Ok(())
}

fn update_receipt_projection(
    tx: &rusqlite::Transaction<'_>,
    event: &EventEnvelope,
) -> Result<(), JournalError> {
    if event.event_type != "run.completed" {
        return Ok(());
    }
    let receipt = match &event.payload {
        EventPayload::Inline { payload_json } => payload_json
            .get("receipt")
            .cloned()
            .and_then(|value| serde_json::from_value::<ReceiptProjection>(value).ok())
            .filter(valid_receipt),
        _ => None,
    };
    if let Some(receipt) = receipt {
        let encoded = serde_json::to_string(&receipt)
            .map_err(|error| JournalError::InvalidEnvelope(error.to_string()))?;
        tx.execute(
            "INSERT INTO receipt_projection(run_id,run_seq,receipt_json,valid) VALUES(?1,?2,?3,1)",
            params![event.run_id, event.run_seq, encoded],
        )?;
    } else {
        tx.execute(
            "INSERT INTO receipt_projection(run_id,run_seq,valid) VALUES(?1,?2,0)",
            params![event.run_id, event.run_seq],
        )?;
    }
    Ok(())
}

fn valid_receipt(receipt: &ReceiptProjection) -> bool {
    let valid_optional = |value: &Option<String>| {
        value
            .as_ref()
            .is_none_or(|value| !value.trim().is_empty() && value.len() <= MAX_RECEIPT_FIELD_BYTES)
    };
    valid_optional(&receipt.route)
        && valid_optional(&receipt.model)
        && valid_optional(&receipt.cost)
        && valid_optional(&receipt.time)
        && receipt.capabilities.len() <= MAX_RECEIPT_CAPABILITIES
        && receipt.capabilities.iter().all(|capability| {
            !capability.name.trim().is_empty()
                && capability.name.len() <= MAX_RECEIPT_FIELD_BYTES
                && !capability.version.trim().is_empty()
                && capability.version.len() <= MAX_RECEIPT_FIELD_BYTES
        })
}

fn backfill_receipt_projection(tx: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    let rows = {
        let mut statement = tx.prepare(
            "SELECT run_id,run_seq,CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
             THEN envelope_json END FROM events WHERE event_type='run.completed' \
             AND NOT EXISTS (SELECT 1 FROM receipt_projection r \
             WHERE r.run_id=events.run_id AND r.run_seq=events.run_seq)",
        )?;
        let rows = statement
            .query_map([MAX_RECEIPT_BACKFILL_ENVELOPE_BYTES], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (run_id, run_seq, encoded) in rows {
        if let Some(encoded) = encoded {
            let event = serde_json::from_str::<EventEnvelope>(&encoded)
                .map_err(|error| JournalError::Corrupt(error.to_string()))?;
            update_receipt_projection(tx, &event)?;
        } else {
            tx.execute(
                "INSERT INTO receipt_projection(run_id,run_seq,valid) VALUES(?1,?2,0)",
                params![run_id, run_seq],
            )?;
        }
    }
    Ok(())
}

fn backfill_permission_pending_projection(connection: &Connection) -> Result<(), JournalError> {
    connection.execute(
        "INSERT INTO permission_pending_projection( \
         run_id,run_seq,gate_id,kind,title,message,valid) \
         SELECT run_id,run_seq, \
         CASE WHEN valid THEN gate_id END, CASE WHEN valid THEN kind END, \
         CASE WHEN valid THEN title END, CASE WHEN valid THEN message END, valid \
         FROM ( \
           SELECT run_id,run_seq,gate_id,kind,title,message, \
             bounded AND payload_type='object' \
             AND typeof(gate_id)='text' AND trim(gate_id)<>'' \
             AND length(CAST(gate_id AS BLOB))<=?2 \
             AND kind='confirm' AND length(CAST(kind AS BLOB))<=?3 \
             AND typeof(title)='text' AND trim(title)<>'' \
             AND length(CAST(title AS BLOB))<=?4 \
             AND (message_type IS NULL OR message_type='null' OR (message_type='text' \
               AND length(CAST(message AS BLOB))<=?5)) AS valid \
           FROM ( \
             SELECT run_id,run_seq, \
               length(CAST(envelope_json AS BLOB))<=?1 AS bounded, \
               CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
                 THEN json_type(envelope_json,'$.payload_json') END AS payload_type, \
               CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
                 THEN json_extract(envelope_json,'$.payload_json.gate_id') END AS gate_id, \
               CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
                 THEN json_extract(envelope_json,'$.payload_json.kind') END AS kind, \
               CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
                 THEN json_extract(envelope_json,'$.payload_json.title') END AS title, \
               CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
                 THEN json_extract(envelope_json,'$.payload_json.message') END AS message, \
               CASE WHEN length(CAST(envelope_json AS BLOB))<=?1 \
                 THEN json_type(envelope_json,'$.payload_json.message') END AS message_type \
             FROM events WHERE event_type='permission.requested' \
               AND NOT EXISTS (SELECT 1 FROM permission_pending_projection p \
                 WHERE p.run_id=events.run_id AND p.run_seq=events.run_seq) \
           ) \
         )",
        params![
            MAX_PENDING_BACKFILL_ENVELOPE_BYTES,
            MAX_PENDING_GATE_ID_BYTES,
            MAX_PENDING_KIND_BYTES,
            MAX_PENDING_TITLE_BYTES,
            MAX_PENDING_MESSAGE_BYTES
        ],
    )?;
    Ok(())
}

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
