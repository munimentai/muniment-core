use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::cas::LocalCas;
use crate::chat_resume::resumable_locator;
use crate::chat_view::{
    chat_attachments, chat_pending_permission, chat_tool_activity, projection_phase,
    ChatAppliedDiff, ChatAttachment, ChatPendingPermission, ChatToolActivity,
};
use crate::code_diff_journal::{load_applied_code_diffs, load_pending_code_diff};
use crate::journal::reducer::{ChatProjector, ProjectedRecall, RunState};
use crate::journal::{EventEnvelope, RunJournal};
use crate::thread_ownership::{subject_owns_first_run, ThreadOwnershipError};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    pub run_id: String,
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_storage_notice: Option<String>,
    pub phase: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
    pub tool_activity: Vec<ChatToolActivity>,
    pub attachments: Vec<ChatAttachment>,
    pub recalls: Vec<ProjectedRecall>,
    pub applied_diffs: Vec<ChatAppliedDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_permission: Option<ChatPendingPermission>,
    pub resumable: bool,
}

/// The runtime supplies ownership and session files for one history snapshot.
pub struct HistoryRuntime<'a> {
    pub session_root: &'a Path,
    pub active_run_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatThreadOpenPage {
    pub entries: Vec<HistoryEntry>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadHistoryError {
    ThreadOwnershipUnavailable(ThreadOwnershipError),
    ThreadNotOwned,
    ThreadRunsUnavailable(String),
    RunEventsUnavailable(String),
    ProjectionUnavailable(String),
    PromptUnavailable(String),
}

pub fn load_prompt(
    run_id: &str,
    subject: Option<&str>,
) -> Result<Option<String>, ThreadHistoryError> {
    crate::chat_prompt::load_prompt(run_id, subject)
        .map_err(|error| ThreadHistoryError::PromptUnavailable(format!("{error:?}")))
}

pub fn project_history_entry(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    run_id: String,
    subject: Option<&str>,
    session_root: &Path,
) -> Result<HistoryEntry, ThreadHistoryError> {
    let mut entry =
        project_history_entry_without_prompt(journal, cas, run_id, subject, session_root, false)?;
    load_entry_prompt(&mut entry, subject)?;
    Ok(entry)
}

/// Projects one run's history entry without its prompt, which lives in the keychain.
fn project_history_entry_without_prompt(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    run_id: String,
    subject: Option<&str>,
    session_root: &Path,
    active: bool,
) -> Result<HistoryEntry, ThreadHistoryError> {
    let events = journal
        .events(&run_id)
        .map_err(|error| ThreadHistoryError::RunEventsUnavailable(error.to_string()))?;
    let project = || {
        let mut projector = ChatProjector::new();
        for event in &events {
            projector.apply(event)?;
        }
        // A live journal can end between an effect start and its outcome.
        // Only a run without a runtime owner uses crash recovery for that gap.
        let live = active.then(|| projector.projection()).transpose()?;
        let (projection, state) = projector.finish()?;
        Ok::<_, crate::journal::reducer::ReduceError>((live.unwrap_or(projection), state))
    };
    let (projection, state) =
        project().map_err(|error| ThreadHistoryError::ProjectionUnavailable(error.to_string()))?;
    let resumable = !active && history_resumable(&events, &state, subject, session_root);
    let code_diff = cas.and_then(|cas| {
        load_pending_code_diff(journal, cas, &run_id, &projection.pending_permission)
    });
    let applied_diffs = match cas {
        Some(cas) => load_applied_code_diffs(journal, cas, &run_id, projection.applied_diffs),
        None => projection
            .applied_diffs
            .into_iter()
            .map(|record| ChatAppliedDiff::from_projected(record, None))
            .collect(),
    };
    Ok(HistoryEntry {
        sent_at: events.first().map(|event| event.recorded_at.clone()),
        prompt: None,
        prompt_storage_notice: projection.prompt_storage_notice,
        phase: projection_phase(&projection.status).into(),
        text: projection.text,
        failure_reason: crate::chat_view::failure_reason(&projection.status),
        receipt: projection.receipt,
        tool_activity: chat_tool_activity(&projection.tool_activity),
        attachments: chat_attachments(&projection.attachments),
        recalls: projection.recalls,
        applied_diffs,
        pending_permission: chat_pending_permission(projection.pending_permission, code_diff),
        resumable,
        run_id,
    })
}

/// Reads the stored prompt of one entry. A refused write leaves no prompt
/// history to read from the keyring.
fn load_entry_prompt(
    entry: &mut HistoryEntry,
    subject: Option<&str>,
) -> Result<(), ThreadHistoryError> {
    if entry.prompt_storage_notice.is_none() {
        entry.prompt = load_prompt(&entry.run_id, subject)?;
    }
    Ok(())
}

/// Reads the stored prompts of a page from
/// [`chat_thread_open_page_without_prompts`]. It needs no journal, so the
/// caller releases the journal before these keychain reads.
pub fn load_page_prompts(
    page: &mut ChatThreadOpenPage,
    subject: Option<&str>,
) -> Result<(), ThreadHistoryError> {
    page.entries
        .iter_mut()
        .try_for_each(|entry| load_entry_prompt(entry, subject))
}

pub fn history_resumable(
    events: &[EventEnvelope],
    state: &RunState,
    subject: Option<&str>,
    session_root: &Path,
) -> bool {
    resumable_locator(events.first(), state, subject, session_root).is_ok()
}

pub fn chat_thread_open_page(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    subject: Option<&str>,
    session_root: &Path,
    thread_id: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<ChatThreadOpenPage, ThreadHistoryError> {
    let mut page = chat_thread_open_page_without_prompts(
        journal,
        cas,
        subject,
        HistoryRuntime {
            session_root,
            active_run_id: None,
        },
        thread_id,
        limit,
        cursor,
    )?;
    load_page_prompts(&mut page, subject)?;
    Ok(page)
}

/// Reads one thread page with every entry's prompt left out.
/// [`load_page_prompts`] fills them after the caller releases the journal.
/// The runtime supplies its owned run ID while it holds the active-run lock.
pub fn chat_thread_open_page_without_prompts(
    journal: &mut RunJournal,
    cas: Option<&LocalCas>,
    subject: Option<&str>,
    runtime: HistoryRuntime<'_>,
    thread_id: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<ChatThreadOpenPage, ThreadHistoryError> {
    if !subject_owns_first_run(journal, thread_id, subject)
        .map_err(ThreadHistoryError::ThreadOwnershipUnavailable)?
    {
        return Err(ThreadHistoryError::ThreadNotOwned);
    }
    let page = journal
        .thread_run_ids(thread_id, limit, cursor)
        .map_err(|error| ThreadHistoryError::ThreadRunsUnavailable(format!("{error:?}")))?;
    let entries = page
        .run_ids
        .into_iter()
        .map(|run_id| {
            let active = runtime.active_run_id == Some(run_id.as_str());
            project_history_entry_without_prompt(
                journal,
                cas,
                run_id,
                subject,
                runtime.session_root,
                active,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ChatThreadOpenPage {
        entries,
        next_cursor: page.next_cursor,
    })
}
