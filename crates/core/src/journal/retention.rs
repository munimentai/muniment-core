//! Deterministic retention for completed run history.

use super::reducer::{reduce, RunStatus};
use super::{JournalError, RunJournal};
use crate::cas::{CasError, ContentHash, LocalCas};
use chrono::{DateTime, Duration, Utc};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_age: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionOutcome {
    pub deleted_run_ids: Vec<String>,
    pub collected_hashes: Vec<ContentHash>,
}

#[derive(Debug)]
pub enum RetentionError {
    Journal(JournalError),
    Cas(CasError),
    InvalidPolicy,
}

impl fmt::Display for RetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "retention journal error: {error}"),
            Self::Cas(error) => write!(formatter, "retention object store error: {error}"),
            Self::InvalidPolicy => formatter.write_str("retention max age must not be negative"),
        }
    }
}

impl std::error::Error for RetentionError {}

impl From<JournalError> for RetentionError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<CasError> for RetentionError {
    fn from(error: CasError) -> Self {
        Self::Cas(error)
    }
}

/// Deletes expired terminal runs and sweeps objects unreferenced by survivors.
///
/// Reduction and timestamp failures are deliberately skipped: retention must
/// never turn journal corruption into destructive recovery behavior.
pub fn apply_retention(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    policy: &RetentionPolicy,
    now: DateTime<Utc>,
) -> Result<RetentionOutcome, RetentionError> {
    if policy.max_age < Duration::zero() {
        return Err(RetentionError::InvalidPolicy);
    }
    let cutoff = now
        .checked_sub_signed(policy.max_age)
        .ok_or(RetentionError::InvalidPolicy)?;
    let mut deleted_run_ids = Vec::new();

    let event_types = journal.run_event_types_with_newest_recorded_at()?;
    for run in event_types.chunk_by(|left, right| left.run_id == right.run_id) {
        if !run.iter().any(|event| {
            matches!(
                event.event_type.as_str(),
                "run.completed" | "run.cancelled" | "run.failed"
            )
        }) {
            continue;
        }
        let Some(newest) = run.last() else {
            continue;
        };
        let Ok(recorded_at) = DateTime::parse_from_rfc3339(&newest.newest_recorded_at) else {
            continue;
        };
        if recorded_at.with_timezone(&Utc) >= cutoff {
            continue;
        }
        let events = journal.events(&newest.run_id)?;
        let Some(newest_event) = events.last() else {
            continue;
        };
        let Ok(state) = reduce(&events) else {
            continue;
        };
        if !matches!(
            state.status,
            RunStatus::Completed | RunStatus::Cancelled | RunStatus::Failed { .. }
        ) {
            continue;
        }
        let Ok(recorded_at) = DateTime::parse_from_rfc3339(&newest_event.recorded_at) else {
            continue;
        };
        if recorded_at.with_timezone(&Utc) >= cutoff {
            continue;
        }
        journal.delete_run(&newest.run_id)?;
        deleted_run_ids.push(newest.run_id.clone());
    }

    let mut collected_hashes = if let Some(cas) = cas {
        cas.collect_unreferenced(&journal.referenced_hashes()?)?
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    deleted_run_ids.sort();
    collected_hashes.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    Ok(RetentionOutcome {
        deleted_run_ids,
        collected_hashes,
    })
}
