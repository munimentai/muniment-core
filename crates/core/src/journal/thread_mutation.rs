use crate::thread_ownership::{subject_owns_first_run, ThreadOwnershipError};
use chrono::{SecondsFormat, Utc};

use super::{JournalError, Provenance, RunJournal};

pub fn create_thread_now(
    journal: &mut RunJournal,
    workspace: &str,
    provenance: Provenance,
) -> Result<String, JournalError> {
    journal.create_thread(
        workspace,
        &Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        provenance,
    )
}

#[derive(Debug)]
pub enum ThreadMutationError {
    Ownership(ThreadOwnershipError),
    NotOwned,
    Journal(JournalError),
}

fn check_ownership(
    journal: &mut RunJournal,
    thread_id: &str,
    subject: Option<&str>,
) -> Result<(), ThreadMutationError> {
    if !subject_owns_first_run(journal, thread_id, subject)
        .map_err(ThreadMutationError::Ownership)?
    {
        return Err(ThreadMutationError::NotOwned);
    }
    Ok(())
}

pub fn append_thread_rename(
    journal: &mut RunJournal,
    subject: Option<&str>,
    thread_id: &str,
    title: &str,
    recorded_at: &str,
    provenance: &Provenance,
) -> Result<(), ThreadMutationError> {
    check_ownership(journal, thread_id, subject)?;
    let last_thread_seq = journal
        .last_thread_seq(thread_id)
        .map_err(ThreadMutationError::Journal)?;
    journal
        .append_thread_title_renamed(last_thread_seq, thread_id, title, recorded_at, provenance)
        .map_err(ThreadMutationError::Journal)
}

pub fn append_thread_rename_now(
    journal: &mut RunJournal,
    subject: Option<&str>,
    thread_id: &str,
    title: &str,
    provenance: &Provenance,
) -> Result<(), ThreadMutationError> {
    append_thread_rename(
        journal,
        subject,
        thread_id,
        title,
        &Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        provenance,
    )
}

pub fn append_thread_delete(
    journal: &mut RunJournal,
    subject: Option<&str>,
    thread_id: &str,
    recorded_at: &str,
    provenance: &Provenance,
) -> Result<(), ThreadMutationError> {
    check_ownership(journal, thread_id, subject)?;
    let last_thread_seq = journal
        .last_thread_seq(thread_id)
        .map_err(ThreadMutationError::Journal)?;
    journal
        .append_thread_deleted(last_thread_seq, thread_id, recorded_at, provenance)
        .map_err(ThreadMutationError::Journal)
}

pub fn append_thread_delete_now(
    journal: &mut RunJournal,
    subject: Option<&str>,
    thread_id: &str,
    provenance: &Provenance,
) -> Result<(), ThreadMutationError> {
    append_thread_delete(
        journal,
        subject,
        thread_id,
        &Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        provenance,
    )
}

/// A first-turn name may replace only its own temporary fallback, never a user's name.
pub fn first_thread_needs_name(journal: &mut RunJournal, run_id: &str) -> Option<String> {
    let thread_id = journal.run_thread_id(run_id).ok()??;
    let runs = journal.thread_run_ids(&thread_id, 1, None).ok()?;
    if runs.run_ids.first().map(String::as_str) != Some(run_id) {
        return None;
    }
    let events = journal.thread_events(&thread_id).ok()?;
    if events.iter().any(|event| {
        event.event_type == "thread.deleted"
            || (event.event_type == "thread.title.renamed"
                && event.provenance.source != "thread-name-fallback")
    }) {
        return None;
    }
    Some(thread_id)
}

pub fn save_first_thread_name(
    journal: &mut RunJournal,
    run_id: &str,
    title: &str,
    generated: bool,
) -> Result<bool, JournalError> {
    let Some(thread_id) = first_thread_needs_name(journal, run_id) else {
        return Ok(false);
    };
    let title = title.trim();
    let title = if crate::memory_secret::reject_memory_secret(title).is_err() {
        if generated {
            return Ok(false);
        }
        "New conversation"
    } else {
        title
    };
    if title.is_empty()
        || title.chars().count() > 80
        || title.split_whitespace().count() > 3
        || title.chars().any(char::is_control)
    {
        return Ok(false);
    }
    let mut provenance = journal
        .events(run_id)?
        .first()
        .ok_or_else(|| JournalError::InvalidEnvelope("The thread has no first message.".into()))?
        .provenance
        .clone();
    provenance.source = if generated {
        "thread-name-model"
    } else {
        "thread-name-fallback"
    }
    .into();
    let seq = journal.last_thread_seq(&thread_id)?;
    journal.append_thread_title_renamed(
        seq,
        &thread_id,
        title,
        &Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        &provenance,
    )?;
    Ok(true)
}
