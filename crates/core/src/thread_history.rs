use std::path::Path;

use muniment_code_diff::{CodeDiff, DiffLineKind};
use serde::Serialize;
use serde_json::Value;

use crate::cas::LocalCas;
use crate::chat_resume::resumable_locator;
pub use crate::chat_view::RunDetailKind;
use crate::chat_view::{
    chat_attachments, chat_pending_permission, chat_tool_activity, projection_phase, utf8_prefix,
    ChatAppliedDiff, ChatAttachment, ChatPendingPermission, ChatToolActivity,
};
use crate::code_diff_journal::{
    load_applied_code_diff, load_applied_code_diffs, load_pending_code_diff,
};
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

/// The most bytes one serialized `run.detail` answer carries. A longer tool
/// output answers its start, and a larger diff answers its first lines with
/// `truncated` set.
pub const RUN_DETAIL_MAX_BYTES: usize = 256 * 1024;

/// One body the chat events leave out, read from the journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunDetail {
    ToolOutput {
        text: String,
        /// The whole output's length in UTF-8 bytes.
        bytes: usize,
        truncated: bool,
    },
    CodeDiff {
        diff: CodeDiff,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunDetailError {
    RunUnavailable(String),
    ThreadOwnershipUnavailable(ThreadOwnershipError),
    RunNotOwned,
    ProjectionUnavailable(String),
    NotFound,
}

/// Reads one tool output or one applied diff of a run the subject owns.
pub fn run_detail(
    journal: &mut RunJournal,
    cas: &LocalCas,
    subject: Option<&str>,
    run_id: &str,
    effect_id: &str,
    kind: RunDetailKind,
) -> Result<RunDetail, RunDetailError> {
    let thread_id = journal
        .run_thread_id(run_id)
        .map_err(|error| RunDetailError::RunUnavailable(error.to_string()))?
        .ok_or(RunDetailError::NotFound)?;
    if !subject_owns_first_run(journal, &thread_id, subject)
        .map_err(RunDetailError::ThreadOwnershipUnavailable)?
    {
        return Err(RunDetailError::RunNotOwned);
    }
    let events = journal
        .events(run_id)
        .map_err(|error| RunDetailError::RunUnavailable(error.to_string()))?;
    let mut projector = ChatProjector::new();
    for event in &events {
        projector
            .apply(event)
            .map_err(|error| RunDetailError::ProjectionUnavailable(error.to_string()))?;
    }
    let projection = projector
        .projection()
        .map_err(|error| RunDetailError::ProjectionUnavailable(error.to_string()))?;
    match kind {
        RunDetailKind::ToolOutput => {
            let output = projection
                .tool_activity
                .iter()
                .rev()
                .find(|activity| activity.effect_id == effect_id)
                .and_then(|activity| activity.output.as_deref())
                .ok_or(RunDetailError::NotFound)?;
            let text = bounded_text(output);
            Ok(RunDetail::ToolOutput {
                truncated: text.len() < output.len(),
                text: text.to_owned(),
                bytes: output.len(),
            })
        }
        RunDetailKind::CodeDiff => {
            let record = projection
                .applied_diffs
                .iter()
                .find(|record| record.effect_id == effect_id)
                .ok_or(RunDetailError::NotFound)?;
            let diff = load_applied_code_diff(journal, cas, run_id, record)
                .ok_or(RunDetailError::NotFound)?;
            Ok(RunDetail::CodeDiff {
                diff: bounded_diff(diff),
            })
        }
    }
}

fn json_len(value: &impl Serialize) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// The longest prefix of `text` whose JSON string fits the detail budget.
/// Escapes can make the JSON several times longer than the text.
fn bounded_text(text: &str) -> &str {
    let mut end = text.len().min(RUN_DETAIL_MAX_BYTES);
    loop {
        let prefix = utf8_prefix(text, end);
        let encoded = json_len(&prefix);
        if encoded <= RUN_DETAIL_MAX_BYTES {
            return prefix;
        }
        end = prefix.len() * RUN_DETAIL_MAX_BYTES / encoded;
    }
}

/// Drops lines, hunks and files from the end of `diff` until it fits the
/// detail budget. A shortened hunk keeps counts that match its lines, so the
/// diff still validates.
fn bounded_diff(mut diff: CodeDiff) -> CodeDiff {
    loop {
        let size = json_len(&diff);
        if size <= RUN_DETAIL_MAX_BYTES {
            return diff;
        }
        diff.truncated = true;
        let mut excess = size - RUN_DETAIL_MAX_BYTES;
        while excess > 0 {
            let Some(file) = diff.files.last_mut() else {
                return diff;
            };
            let removed = match file.hunks.last_mut() {
                Some(hunk) => match hunk.lines.pop() {
                    Some(line) => json_len(&line),
                    None => file.hunks.pop().map_or(0, |hunk| json_len(&hunk)),
                },
                None => diff.files.pop().map_or(0, |file| json_len(&file)),
            };
            excess = excess.saturating_sub(removed + 1);
        }
        if let Some(file) = diff.files.last_mut() {
            if file.hunks.last().is_some_and(|hunk| hunk.lines.is_empty()) {
                file.hunks.pop();
            }
            if let Some(hunk) = file.hunks.last_mut() {
                let (old_count, new_count) =
                    hunk.lines
                        .iter()
                        .fold((0, 0), |(old, new), line| match line.kind {
                            DiffLineKind::Context => (old + 1, new + 1),
                            DiffLineKind::Deletion => (old + 1, new),
                            DiffLineKind::Addition => (old, new + 1),
                        });
                hunk.old_count = old_count;
                hunk.new_count = new_count;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_code_diff::{DiffFile, DiffHunk, DiffLine, DiffStatus};

    fn line(kind: DiffLineKind, index: u64) -> DiffLine {
        DiffLine {
            kind,
            old_line_number: (kind != DiffLineKind::Addition).then_some(index),
            new_line_number: (kind != DiffLineKind::Deletion).then_some(index),
            text: format!("line {index} of a long generated file"),
            segments: Vec::new(),
        }
    }

    fn file(path: &str, lines: Vec<DiffLine>) -> DiffFile {
        let old_count = lines
            .iter()
            .filter(|line| line.kind != DiffLineKind::Addition)
            .count() as u64;
        let new_count = lines
            .iter()
            .filter(|line| line.kind != DiffLineKind::Deletion)
            .count() as u64;
        DiffFile {
            old_path: Some(path.into()),
            new_path: Some(path.into()),
            status: DiffStatus::Modified,
            old_mode: None,
            new_mode: None,
            binary: false,
            hunks: vec![DiffHunk {
                old_start: 1,
                old_count,
                new_start: 1,
                new_count,
                header: "@@".into(),
                lines,
            }],
        }
    }

    #[test]
    fn a_large_diff_answers_its_first_lines_within_the_cap() {
        let kinds = [
            DiffLineKind::Context,
            DiffLineKind::Deletion,
            DiffLineKind::Addition,
        ];
        let lines = |count: u64| {
            (0..count)
                .map(|index| line(kinds[index as usize % 3], index + 1))
                .collect::<Vec<_>>()
        };
        let diff = CodeDiff {
            schema_version: 1,
            id: "diff-1".into(),
            files: vec![file("src/a.rs", lines(30)), file("src/b.rs", lines(12_000))],
            truncated: false,
        };
        assert!(json_len(&diff) > RUN_DETAIL_MAX_BYTES);

        let bounded = bounded_diff(diff.clone());
        assert!(json_len(&bounded) <= RUN_DETAIL_MAX_BYTES);
        assert!(bounded.truncated);
        bounded.validate().unwrap();
        assert_eq!(bounded.files[0], diff.files[0]);
        let kept = &bounded.files[1].hunks[0].lines;
        assert!(!kept.is_empty() && kept.len() < 12_000);
        assert_eq!(kept[..], diff.files[1].hunks[0].lines[..kept.len()]);

        let small = CodeDiff {
            files: vec![file("src/a.rs", lines(30))],
            ..diff
        };
        assert_eq!(bounded_diff(small.clone()), small);
    }
}
