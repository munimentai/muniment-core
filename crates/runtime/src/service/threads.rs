//! Thread and run stream service operations.

use super::runtime_provenance;
use muniment_core::attach::desktop_service_message::RunStreamPage;
use muniment_core::attach::thread_service::ThreadListService;
use muniment_core::attach::ProtocolError;
use muniment_core::chat_profile::ChatProfile;
use muniment_core::journal::retention::{
    apply_retention_now_with, RetentionError, RetentionOutcome,
};
use muniment_core::journal::thread_mutation::{
    append_thread_delete_now, append_thread_rename_now, create_thread_now,
};
use muniment_core::journal::thread_summaries::ThreadSummaryPage;
use muniment_core::owned_threads::chat_thread_summaries_page;
use muniment_core::run_events::{ChatStorage, SharedStorage};
use muniment_core::run_start::ActiveRun;
use muniment_core::thread_history::{
    chat_thread_open_page_without_prompts, load_page_prompts, ChatThreadOpenPage, HistoryRuntime,
};
use muniment_core::thread_ownership::subject_owns_first_run;
use std::path::Path;
use std::sync::Mutex;

fn lock_error(error: impl std::fmt::Display) -> String {
    format!("Conversation history lock failed: {error}")
}

fn journal_error(error: impl std::fmt::Debug) -> String {
    format!("Conversation history journal operation failed: {error:?}")
}

/// Lists the threads owned by one subject.
pub fn thread_summaries(
    storage: SharedStorage,
    subject: Option<String>,
    limit: usize,
    cursor: Option<String>,
) -> Result<ThreadSummaryPage, String> {
    let mut storage = storage.lock().map_err(lock_error)?;
    chat_thread_summaries_page(
        &mut storage.journal,
        subject.as_deref(),
        limit,
        cursor.as_deref(),
    )
    .map_err(journal_error)
}

/// Reports whether one subject owns a thread.
pub fn select_thread(
    storage: SharedStorage,
    subject: Option<String>,
    thread_id: String,
) -> Result<bool, String> {
    let mut storage = storage.lock().map_err(lock_error)?;
    subject_owns_first_run(&mut storage.journal, &thread_id, subject.as_deref())
        .map_err(journal_error)
}

/// Reads one page of a run stream.
pub fn stream_run(
    storage: SharedStorage,
    workspace: String,
    run_id: String,
    after_run_seq: u64,
) -> Result<RunStreamPage, ProtocolError> {
    let mut storage = storage
        .lock()
        .map_err(|_| ProtocolError::persistence_failed())?;
    storage
        .journal
        .stream_run(&workspace, &run_id, after_run_seq)
}

/// Subscribes to commits for one run.
pub fn subscribe_run_commits(
    storage: SharedStorage,
    run_id: String,
) -> Result<Option<muniment_core::journal::CommitSubscription>, ProtocolError> {
    let mut storage = storage
        .lock()
        .map_err(|_| ProtocolError::persistence_failed())?;
    storage.journal.subscribe_run_commits(&run_id)
}

/// Creates one thread for an authorized attach profile.
pub fn create_thread(
    storage: SharedStorage,
    workspace: String,
    attach_profile: String,
) -> Result<String, String> {
    let mut provenance = runtime_provenance();
    provenance
        .extra
        .insert("attach_profile".into(), attach_profile.into());
    let mut storage = storage.lock().map_err(lock_error)?;
    create_thread_now(&mut storage.journal, &workspace, provenance).map_err(journal_error)
}

/// Renames one thread owned by one subject.
pub fn rename_thread(
    storage: SharedStorage,
    subject: Option<String>,
    thread_id: String,
    title: String,
) -> Result<(), String> {
    let mut storage = storage.lock().map_err(lock_error)?;
    append_thread_rename_now(
        &mut storage.journal,
        subject.as_deref(),
        &thread_id,
        &title,
        &runtime_provenance(),
    )
    .map_err(journal_error)
}

/// Deletes one thread owned by one subject.
pub fn delete_thread(
    storage: SharedStorage,
    subject: Option<String>,
    thread_id: String,
) -> Result<(), String> {
    let mut storage = storage.lock().map_err(lock_error)?;
    append_thread_delete_now(
        &mut storage.journal,
        subject.as_deref(),
        &thread_id,
        &runtime_provenance(),
    )
    .map_err(journal_error)
}

/// Deletes terminal runs older than the maximum age.
pub fn apply_retention(
    storage: SharedStorage,
    max_age_seconds: i64,
) -> Result<RetentionOutcome, String> {
    let mut storage = storage.lock().map_err(lock_error)?;
    let ChatStorage { journal, cas } = &mut *storage;
    apply_retention_now_with(journal, Some(cas), max_age_seconds, |deleted_run| {
        if !deleted_run.prompt_stored {
            return Ok(());
        }
        muniment_core::chat_prompt::delete_prompt(
            &deleted_run.run_id,
            deleted_run.subject.as_deref(),
        )
        .map_err(|error| RetentionError::BeforeDeleteWithReason(format!("{error:?}")))
    })
    .map_err(journal_error)
}

/// Opens one thread owned by one subject.
pub fn thread_page(
    profile_directory: impl AsRef<Path>,
    storage: SharedStorage,
    active: &Mutex<Option<ActiveRun>>,
    subject: Option<String>,
    thread_id: String,
    limit: usize,
    cursor: Option<String>,
) -> Result<ChatThreadOpenPage, String> {
    let profile_directory = profile_directory.as_ref();
    let profile = ChatProfile::new(profile_directory);
    let mut page = {
        // Keep ownership stable until the journal snapshot completes.
        let active = active.lock().map_err(lock_error)?;
        let mut storage = storage.lock().map_err(lock_error)?;
        let ChatStorage { journal, cas } = &mut *storage;
        chat_thread_open_page_without_prompts(
            journal,
            Some(cas),
            subject.as_deref(),
            HistoryRuntime {
                session_root: &profile.pi_session_root(),
                active_run_id: active.as_ref().map(|run| run.id.as_str()),
            },
            &thread_id,
            limit,
            cursor.as_deref(),
        )
        .map_err(journal_error)?
    };
    // Each prompt is one keychain read. The journal lock is released first,
    // so a slow keychain never holds up a run's appends.
    load_page_prompts(&mut page, subject.as_deref()).map_err(journal_error)?;
    Ok(page)
}
