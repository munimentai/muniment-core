//! Derived, cursor-paginated summaries of journal threads.

use super::summaries::{title_from, MAX_PAGE_SIZE};
use super::{EventEnvelope, JournalError, RunJournal, ThreadEventEnvelope};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadSummary {
    pub thread_id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadSummaryPage {
    pub summaries: Vec<ThreadSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug)]
pub enum ThreadSummaryListError {
    InvalidLimit { limit: usize, max: usize },
    InvalidCursor,
    Journal(JournalError),
}

impl fmt::Display for ThreadSummaryListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { limit, max } => {
                write!(f, "thread-summary limit {limit} is outside 1..={max}")
            }
            Self::InvalidCursor => write!(f, "invalid thread-summary cursor"),
            Self::Journal(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ThreadSummaryListError {}

impl From<JournalError> for ThreadSummaryListError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<rusqlite::Error> for ThreadSummaryListError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Journal(JournalError::Sqlite(value))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadCursor {
    version: u8,
    updated_at: String,
    thread_id: String,
    workspace: Option<String>,
    authenticator: String,
}

impl RunJournal {
    /// Lists non-deleted threads by latest event time, then thread ID.
    ///
    /// A run contributes its last event by `run_seq`.
    pub fn thread_summaries(
        &mut self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ThreadSummaryPage, ThreadSummaryListError> {
        self.thread_summaries_inner(None, limit, cursor)
    }

    /// Lists non-deleted threads with a run owned by `workspace`.
    ///
    /// A run contributes its last event by `run_seq`.
    pub fn workspace_thread_summaries(
        &mut self,
        workspace: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ThreadSummaryPage, ThreadSummaryListError> {
        self.thread_summaries_inner(Some(workspace), limit, cursor)
    }

    fn thread_summaries_inner(
        &mut self,
        workspace: Option<&str>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ThreadSummaryPage, ThreadSummaryListError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(ThreadSummaryListError::InvalidLimit {
                limit,
                max: MAX_PAGE_SIZE,
            });
        }
        let boundary = cursor
            .map(|value| decode_cursor(value, &self.cursor_key, workspace))
            .transpose()?;

        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");

        let summary_rows = "WITH thread_times AS (\
            SELECT te.thread_id, MAX(te.recorded_at) AS updated_at FROM thread_events te \
            GROUP BY te.thread_id), run_times AS (\
            SELECT rt.thread_id, MAX((SELECT e.recorded_at FROM events e \
                WHERE e.run_id=rt.run_id ORDER BY e.run_seq DESC LIMIT 1)) AS updated_at \
            FROM run_threads rt GROUP BY rt.thread_id), summaries AS (\
            SELECT tt.thread_id, MAX(tt.updated_at, COALESCE(rt.updated_at, tt.updated_at)) AS updated_at \
            FROM thread_times tt LEFT JOIN run_times rt ON rt.thread_id=tt.thread_id \
            WHERE NOT EXISTS(SELECT 1 FROM thread_events deleted \
                WHERE deleted.thread_id=tt.thread_id AND deleted.event_type='thread.deleted') \
            AND (?1 IS NULL OR EXISTS(SELECT 1 FROM run_threads scoped \
                JOIN run_workspaces rw ON rw.run_id=scoped.run_id \
                WHERE scoped.thread_id=tt.thread_id AND rw.workspace=?1)))";

        if let Some(boundary) = &boundary {
            let exists: bool = connection.query_row(
                "WITH thread_time AS (\
                    SELECT MAX(recorded_at) AS updated_at FROM thread_events \
                    WHERE thread_id=?2), run_time AS (\
                    SELECT MAX((SELECT e.recorded_at FROM events e \
                        WHERE e.run_id=rt.run_id ORDER BY e.run_seq DESC LIMIT 1)) AS updated_at \
                    FROM run_threads rt WHERE rt.thread_id=?2) \
                 SELECT EXISTS(SELECT 1 FROM thread_time tt CROSS JOIN run_time rt \
                    WHERE MAX(tt.updated_at, COALESCE(rt.updated_at, tt.updated_at))=?3 \
                    AND NOT EXISTS(SELECT 1 FROM thread_events deleted \
                        WHERE deleted.thread_id=?2 AND deleted.event_type='thread.deleted') \
                    AND (?1 IS NULL OR EXISTS(SELECT 1 FROM run_threads scoped \
                        JOIN run_workspaces rw ON rw.run_id=scoped.run_id \
                        WHERE scoped.thread_id=?2 AND rw.workspace=?1)))",
                rusqlite::params![workspace, boundary.thread_id, boundary.updated_at],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(ThreadSummaryListError::InvalidCursor);
            }
        }

        let page_size = limit + 1;
        let mut keys = Vec::with_capacity(page_size);
        if let Some(boundary) = &boundary {
            let sql = format!(
                "{summary_rows} SELECT thread_id, updated_at FROM summaries \
                 WHERE updated_at < ?2 OR (updated_at=?2 AND thread_id>?3) \
                 ORDER BY updated_at DESC, thread_id ASC LIMIT ?4"
            );
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(
                rusqlite::params![
                    workspace,
                    boundary.updated_at,
                    boundary.thread_id,
                    page_size as u64
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            keys.extend(rows.collect::<Result<Vec<_>, _>>()?);
        } else {
            let sql = format!(
                "{summary_rows} SELECT thread_id, updated_at FROM summaries \
                 ORDER BY updated_at DESC, thread_id ASC LIMIT ?2"
            );
            let mut statement = connection.prepare(&sql)?;
            let rows = statement
                .query_map(rusqlite::params![workspace, page_size as u64], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
            keys.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }

        let has_more = keys.len() > limit;
        keys.truncate(limit);
        let mut summaries = Vec::with_capacity(keys.len());
        for (thread_id, updated_at) in keys {
            let renamed = connection
                .query_row(
                    "SELECT envelope_json FROM thread_events \
                     WHERE thread_id=?1 AND event_type='thread.title.renamed' \
                     ORDER BY thread_seq DESC LIMIT 1",
                    [&thread_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|json| serde_json::from_str::<ThreadEventEnvelope>(&json))
                .transpose()
                .map_err(|error| {
                    JournalError::Corrupt(format!("could not read thread title: {error}"))
                })?;
            let title = if let Some(event) = renamed {
                event
                    .payload_json
                    .get("title")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| JournalError::Corrupt("thread title is missing".into()))?
                    .to_owned()
            } else {
                let prompt = connection
                    .query_row(
                        "SELECT e.envelope_json FROM run_threads rt JOIN events e ON e.run_id=rt.run_id \
                         WHERE rt.thread_id=?1 AND e.event_type='user.prompt.submitted' \
                         AND json_type(e.envelope_json, '$.payload_json.prompt')='text' \
                         ORDER BY rt.thread_run_ordinal, e.run_seq LIMIT 1",
                        [&thread_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .map(|json| serde_json::from_str::<EventEnvelope>(&json))
                    .transpose()
                    .map_err(|error| {
                        JournalError::Corrupt(format!("could not read thread prompt: {error}"))
                    })?;
                title_from(prompt.as_slice())
            };
            summaries.push(ThreadSummary {
                thread_id,
                title,
                updated_at,
            });
        }
        let next_cursor = if has_more {
            summaries
                .last()
                .map(|summary| encode_cursor(summary, workspace, &self.cursor_key))
                .transpose()?
        } else {
            None
        };
        Ok(ThreadSummaryPage {
            summaries,
            next_cursor,
        })
    }
}

fn encode_cursor(
    summary: &ThreadSummary,
    workspace: Option<&str>,
    key: &[u8; 32],
) -> Result<String, ThreadSummaryListError> {
    let authenticator =
        cursor_authenticator(key, &summary.updated_at, &summary.thread_id, workspace);
    let cursor = ThreadCursor {
        version: 1,
        updated_at: summary.updated_at.clone(),
        thread_id: summary.thread_id.clone(),
        workspace: workspace.map(str::to_owned),
        authenticator,
    };
    let bytes = serde_json::to_vec(&cursor).map_err(|error| {
        ThreadSummaryListError::Journal(JournalError::Corrupt(format!(
            "could not encode thread-summary cursor: {error}"
        )))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(
    encoded: &str,
    key: &[u8; 32],
    workspace: Option<&str>,
) -> Result<ThreadCursor, ThreadSummaryListError> {
    if encoded.is_empty() || encoded.len() > 512 {
        return Err(ThreadSummaryListError::InvalidCursor);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ThreadSummaryListError::InvalidCursor)?;
    let cursor: ThreadCursor =
        serde_json::from_slice(&bytes).map_err(|_| ThreadSummaryListError::InvalidCursor)?;
    if cursor.workspace.as_deref() != workspace {
        return Err(ThreadSummaryListError::InvalidCursor);
    }
    let authenticator = URL_SAFE_NO_PAD
        .decode(&cursor.authenticator)
        .map_err(|_| ThreadSummaryListError::InvalidCursor)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("SHA-256 HMAC accepts any key length");
    update_cursor_mac(&mut mac, &cursor.updated_at, &cursor.thread_id, workspace);
    if cursor.version != 1 || mac.verify_slice(&authenticator).is_err() {
        return Err(ThreadSummaryListError::InvalidCursor);
    }
    Ok(cursor)
}

fn cursor_authenticator(
    key: &[u8; 32],
    updated_at: &str,
    thread_id: &str,
    workspace: Option<&str>,
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("SHA-256 HMAC accepts any key length");
    update_cursor_mac(&mut mac, updated_at, thread_id, workspace);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn update_cursor_mac(
    mac: &mut Hmac<Sha256>,
    updated_at: &str,
    thread_id: &str,
    workspace: Option<&str>,
) {
    mac.update(b"muniment-thread-summary-cursor-v1\0");
    mac.update(updated_at.as_bytes());
    mac.update(b"\0");
    mac.update(thread_id.as_bytes());
    mac.update(b"\0");
    match workspace {
        Some(workspace) => {
            mac.update(b"workspace\0");
            mac.update(workspace.as_bytes());
        }
        None => mac.update(b"all"),
    }
}
