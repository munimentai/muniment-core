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
    pub deleted_runs: Vec<DeletedRun>,
    pub collected_hashes: Vec<ContentHash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedRun {
    pub run_id: String,
    pub subject: Option<String>,
}

#[derive(Debug)]
pub enum RetentionError {
    Journal(JournalError),
    Cas(CasError),
    BeforeDelete,
    InvalidPolicy,
}

impl fmt::Display for RetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "retention journal error: {error}"),
            Self::Cas(error) => write!(formatter, "retention object store error: {error}"),
            Self::BeforeDelete => formatter.write_str("retention pre-delete action failed"),
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
    apply_retention_with(journal, cas, policy, now, |_| Ok(()))
}

/// Deletes expired terminal runs after a caller-provided pre-delete action.
pub fn apply_retention_with(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    policy: &RetentionPolicy,
    now: DateTime<Utc>,
    mut before_delete: impl FnMut(&DeletedRun) -> Result<(), RetentionError>,
) -> Result<RetentionOutcome, RetentionError> {
    if policy.max_age < Duration::zero() {
        return Err(RetentionError::InvalidPolicy);
    }
    let cutoff = now
        .checked_sub_signed(policy.max_age)
        .ok_or(RetentionError::InvalidPolicy)?;
    let mut deleted_runs = Vec::new();

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
        let subject = events
            .first()
            .and_then(|event| event.provenance.actor_id.clone());
        let deleted_run = DeletedRun {
            run_id: newest.run_id.clone(),
            subject,
        };
        before_delete(&deleted_run)?;
        journal.delete_run(&newest.run_id)?;
        deleted_runs.push(deleted_run);
    }

    let mut collected_hashes = if let Some(cas) = cas {
        cas.collect_unreferenced(&journal.referenced_hashes()?)?
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    deleted_runs.sort_by(|left, right| left.run_id.cmp(&right.run_id));
    collected_hashes.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    Ok(RetentionOutcome {
        deleted_runs,
        collected_hashes,
    })
}

/// Applies retention with the current time as the cutoff reference.
pub fn apply_retention_now(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    max_age_seconds: i64,
) -> Result<RetentionOutcome, RetentionError> {
    let max_age = Duration::try_seconds(max_age_seconds).ok_or(RetentionError::InvalidPolicy)?;
    apply_retention(journal, cas, &RetentionPolicy { max_age }, Utc::now())
}

/// Applies retention with a pre-delete action and the current time.
pub fn apply_retention_now_with(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    max_age_seconds: i64,
    before_delete: impl FnMut(&DeletedRun) -> Result<(), RetentionError>,
) -> Result<RetentionOutcome, RetentionError> {
    let max_age = Duration::try_seconds(max_age_seconds).ok_or(RetentionError::InvalidPolicy)?;
    apply_retention_with(
        journal,
        cas,
        &RetentionPolicy { max_age },
        Utc::now(),
        before_delete,
    )
}
