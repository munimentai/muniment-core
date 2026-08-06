use crate::thread_ownership::{subject_owns_first_run, ThreadOwnershipError};

use super::{JournalError, Provenance, RunJournal};

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
