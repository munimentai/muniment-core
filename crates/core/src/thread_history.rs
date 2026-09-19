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
use crate::journal::reducer::{project_chat_with_state, ProjectedRecall, RunState};
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
    let events = journal
        .events(&run_id)
        .map_err(|error| ThreadHistoryError::RunEventsUnavailable(error.to_string()))?;
    let (projection, state) = project_chat_with_state(&events)
        .map_err(|error| ThreadHistoryError::ProjectionUnavailable(error.to_string()))?;
    let resumable = history_resumable(&events, &state, subject, session_root);
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
        // A refused write leaves no prompt history to read from the keyring.
        prompt: if projection.prompt_storage_notice.is_some() {
            None
        } else {
            load_prompt(&run_id, subject)?
        },
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
        .map(|run_id| project_history_entry(journal, cas, run_id, subject, session_root))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ChatThreadOpenPage {
        entries,
        next_cursor: page.next_cursor,
    })
}
