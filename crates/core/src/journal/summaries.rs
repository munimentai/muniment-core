//! Derived, cursor-paginated summaries of journal runs.

use super::{EventEnvelope, EventPayload, JournalError, RunJournal};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;

/// Maximum number of summaries returned by one call.
pub const MAX_PAGE_SIZE: usize = 100;
/// Maximum title length in Unicode scalar values, including a trailing ellipsis.
pub const MAX_TITLE_CHARS: usize = 80;
/// Title used when a run has no `user.prompt.submitted` event with a string `prompt`.
pub const UNTITLED_RUN_TITLE: &str = "Untitled run";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSummary {
    pub run_id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSummaryPage {
    pub summaries: Vec<RunSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug)]
pub enum RunSummaryListError {
    InvalidLimit { limit: usize, max: usize },
    InvalidCursor,
    Journal(JournalError),
}

impl fmt::Display for RunSummaryListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { limit, max } => {
                write!(f, "run-summary limit {limit} is outside 1..={max}")
            }
            Self::InvalidCursor => write!(f, "invalid run-summary cursor"),
            Self::Journal(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RunSummaryListError {}

impl From<JournalError> for RunSummaryListError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<rusqlite::Error> for RunSummaryListError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Journal(JournalError::Sqlite(value))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    updated_at: String,
    run_id: String,
    authenticator: String,
}

impl RunJournal {
    /// Lists summaries ordered by latest event time descending, then run ID ascending.
    ///
    /// Titles are derived on every read from the first inline
    /// `user.prompt.submitted` event's `prompt` string. Whitespace is collapsed and
    /// titles longer than [`MAX_TITLE_CHARS`] are truncated with an ellipsis. Runs
    /// without such an event use [`UNTITLED_RUN_TITLE`].
    pub fn run_summaries(
        &mut self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<RunSummaryPage, RunSummaryListError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(RunSummaryListError::InvalidLimit {
                limit,
                max: MAX_PAGE_SIZE,
            });
        }
        let boundary = cursor
            .map(|cursor| decode_cursor(cursor, &self.cursor_key))
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

        if let Some(boundary) = &boundary {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?1 GROUP BY run_id HAVING MAX(recorded_at)=?2)",
                rusqlite::params![boundary.run_id, boundary.updated_at],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(RunSummaryListError::InvalidCursor);
            }
        }

        let page_size = limit + 1;
        let mut keys = Vec::with_capacity(page_size);
        if let Some(boundary) = &boundary {
            let mut statement = connection.prepare(
                "SELECT run_id, MAX(recorded_at) AS updated_at FROM events GROUP BY run_id \
                 HAVING updated_at < ?1 OR (updated_at = ?1 AND run_id > ?2) \
                 ORDER BY updated_at DESC, run_id ASC LIMIT ?3",
            )?;
            let rows = statement.query_map(
                rusqlite::params![boundary.updated_at, boundary.run_id, page_size as u64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            keys.extend(rows.collect::<Result<Vec<_>, _>>()?);
        } else {
            let mut statement = connection.prepare(
                "SELECT run_id, MAX(recorded_at) AS updated_at FROM events GROUP BY run_id \
                 ORDER BY updated_at DESC, run_id ASC LIMIT ?1",
            )?;
            let rows = statement.query_map([page_size as u64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            keys.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }

        let has_more = keys.len() > limit;
        keys.truncate(limit);
        let mut summaries = Vec::with_capacity(keys.len());
        for (run_id, updated_at) in keys {
            let mut statement = connection
                .prepare("SELECT envelope_json FROM events WHERE run_id=?1 ORDER BY run_seq")?;
            let rows = statement.query_map([&run_id], |row| row.get::<_, String>(0))?;
            let events = rows
                .map(|row| {
                    serde_json::from_str::<EventEnvelope>(&row?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            summaries.push(RunSummary {
                run_id,
                title: title_from(&events),
                updated_at,
            });
        }
        let next_cursor = if has_more {
            summaries
                .last()
                .map(|summary| encode_cursor(summary, &self.cursor_key))
                .transpose()?
        } else {
            None
        };
        Ok(RunSummaryPage {
            summaries,
            next_cursor,
        })
    }
}

fn title_from(events: &[EventEnvelope]) -> String {
    let prompt = events.iter().find_map(|event| {
        if event.event_type != "user.prompt.submitted" {
            return None;
        }
        let EventPayload::Inline { payload_json } = &event.payload else {
            return None;
        };
        payload_json.get("prompt")?.as_str()
    });
    let normalized = prompt
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return UNTITLED_RUN_TITLE.to_owned();
    }
    if normalized.chars().count() <= MAX_TITLE_CHARS {
        return normalized;
    }
    normalized
        .chars()
        .take(MAX_TITLE_CHARS - 1)
        .chain(std::iter::once('…'))
        .collect()
}

fn encode_cursor(summary: &RunSummary, key: &[u8; 32]) -> Result<String, RunSummaryListError> {
    let authenticator = cursor_authenticator(key, &summary.updated_at, &summary.run_id);
    let cursor = Cursor {
        version: 1,
        updated_at: summary.updated_at.clone(),
        run_id: summary.run_id.clone(),
        authenticator,
    };
    let bytes = serde_json::to_vec(&cursor).map_err(|error| {
        RunSummaryListError::Journal(JournalError::Corrupt(format!(
            "could not encode run-summary cursor: {error}"
        )))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(encoded: &str, key: &[u8; 32]) -> Result<Cursor, RunSummaryListError> {
    if encoded.is_empty() || encoded.len() > 512 {
        return Err(RunSummaryListError::InvalidCursor);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RunSummaryListError::InvalidCursor)?;
    let cursor: Cursor =
        serde_json::from_slice(&bytes).map_err(|_| RunSummaryListError::InvalidCursor)?;
    let authenticator = URL_SAFE_NO_PAD
        .decode(&cursor.authenticator)
        .map_err(|_| RunSummaryListError::InvalidCursor)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("SHA-256 HMAC accepts any key length");
    update_cursor_mac(&mut mac, &cursor.updated_at, &cursor.run_id);
    if cursor.version != 1 || mac.verify_slice(&authenticator).is_err() {
        return Err(RunSummaryListError::InvalidCursor);
    }
    Ok(cursor)
}

fn cursor_authenticator(key: &[u8; 32], updated_at: &str, run_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("SHA-256 HMAC accepts any key length");
    update_cursor_mac(&mut mac, updated_at, run_id);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn update_cursor_mac(mac: &mut Hmac<Sha256>, updated_at: &str, run_id: &str) {
    mac.update(b"muniment-run-summary-cursor-v1\0");
    mac.update(updated_at.as_bytes());
    mac.update(b"\0");
    mac.update(run_id.as_bytes());
}
