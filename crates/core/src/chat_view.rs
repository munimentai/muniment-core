//! Webview chat payloads derived from journal projections.

use std::path::PathBuf;

use muniment_code_diff::{CodeDiff, DiffLineKind, DiffStatus};
use serde::{Deserialize, Serialize};

use crate::journal::reducer::{
    AttentionReason, PermissionGate, PermissionRequest, ProjectedAppliedDiff, ProjectedAttachment,
    RunStatus, ToolActivity, ToolActivityStatus,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedFile {
    pub path: PathBuf,
}

/// The longest tool output a chat event or history entry carries, in UTF-8
/// bytes. A whole state repeats every tool of its run, so the body stays in
/// the journal and `run.detail` answers it on demand.
pub const TOOL_OUTPUT_PREVIEW_BYTES: usize = 1024;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatToolActivity {
    pub text_offset: usize,
    pub effect_id: String,
    pub display_name: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// The start of the output, at most [`TOOL_OUTPUT_PREVIEW_BYTES`] bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// The whole output's length in UTF-8 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<usize>,
    /// Set when `output` holds only the start of the output.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub output_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatPendingPermission {
    pub gate_id: String,
    #[serde(flatten)]
    pub request: PermissionRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<CodeDiff>,
}

/// An applied code diff as a chat event carries it: the record and, while
/// the stored diff verifies, its per-file counts. `run.detail` answers the
/// diff itself.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatAppliedDiff {
    pub effect_id: String,
    pub code_diff_id: String,
    pub diff_sha256: String,
    pub write_plan_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<ChatDiffSummary>,
}

impl ChatAppliedDiff {
    pub fn from_projected(record: ProjectedAppliedDiff, diff: Option<&CodeDiff>) -> Self {
        Self {
            effect_id: record.effect_id,
            code_diff_id: record.code_diff_id,
            diff_sha256: record.diff_sha256,
            write_plan_sha256: record.write_plan_sha256,
            summary: diff.map(ChatDiffSummary::of),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatDiffSummary {
    pub files: Vec<ChatDiffFileSummary>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatDiffFileSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    pub status: DiffStatus,
    pub binary: bool,
    pub additions: usize,
    pub deletions: usize,
}

impl ChatDiffSummary {
    pub fn of(diff: &CodeDiff) -> Self {
        Self {
            files: diff
                .files
                .iter()
                .map(|file| {
                    let (additions, deletions) = file
                        .hunks
                        .iter()
                        .flat_map(|hunk| &hunk.lines)
                        .fold((0, 0), |(additions, deletions), line| match line.kind {
                            DiffLineKind::Addition => (additions + 1, deletions),
                            DiffLineKind::Deletion => (additions, deletions + 1),
                            DiffLineKind::Context => (additions, deletions),
                        });
                    ChatDiffFileSummary {
                        old_path: file.old_path.clone(),
                        new_path: file.new_path.clone(),
                        status: file.status,
                        binary: file.binary,
                        additions,
                        deletions,
                    }
                })
                .collect(),
            truncated: diff.truncated,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatAttachment {
    pub display_name: String,
    pub byte_length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

pub fn chat_attachments(attachments: &[ProjectedAttachment]) -> Vec<ChatAttachment> {
    attachments
        .iter()
        .map(|attachment| ChatAttachment {
            display_name: attachment.display_name.clone(),
            byte_length: attachment.byte_length,
            media_type: attachment.media_type.clone(),
        })
        .collect()
}

pub fn chat_pending_permission(
    gate: Option<PermissionGate>,
    code_diff: Option<CodeDiff>,
) -> Option<ChatPendingPermission> {
    gate.map(|gate| {
        let diff = matches!(&gate.request, PermissionRequest::CodeDiff { .. })
            .then_some(code_diff)
            .flatten();
        ChatPendingPermission {
            gate_id: gate.gate_id,
            request: gate.request,
            diff,
        }
    })
}

pub fn chat_tool_activity(activity: &[ToolActivity]) -> Vec<ChatToolActivity> {
    activity
        .iter()
        .map(|activity| ChatToolActivity {
            text_offset: activity.text_offset,
            effect_id: activity.effect_id.clone(),
            input: activity.input.clone(),
            output: activity
                .output
                .as_deref()
                .map(|output| utf8_prefix(output, TOOL_OUTPUT_PREVIEW_BYTES).to_owned()),
            output_bytes: activity.output.as_ref().map(String::len),
            output_truncated: activity
                .output
                .as_ref()
                .is_some_and(|output| output.len() > TOOL_OUTPUT_PREVIEW_BYTES),
            started_at: activity.started_at.clone(),
            finished_at: activity.finished_at.clone(),
            display_name: activity.display_name.clone(),
            status: match activity.status {
                ToolActivityStatus::Running => "running",
                ToolActivityStatus::Completed => "completed",
                ToolActivityStatus::Failed => "failed",
            }
            .into(),
        })
        .collect()
}

/// What one `run.detail` request reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunDetailKind {
    /// The output a tool returned.
    ToolOutput,
    /// The diff an applied code-diff effect wrote.
    CodeDiff,
}

/// The longest prefix of `text` that fits `max_bytes` and ends on a character
/// boundary.
pub fn utf8_prefix(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Keeps the recorded cause separate from assistant text.
pub fn failure_reason(status: &Option<RunStatus>) -> Option<String> {
    match status {
        Some(RunStatus::Failed { reason }) => reason.clone(),
        Some(RunStatus::NeedsAttention(AttentionReason::Recorded { reason })) => {
            Some(reason.clone())
        }
        Some(RunStatus::NeedsAttention(AttentionReason::UnknownEffectOutcome { .. })) => {
            Some("unknown-effect-outcome".into())
        }
        _ => None,
    }
}

pub fn projection_phase(status: &Option<RunStatus>) -> &'static str {
    match status {
        Some(RunStatus::AcquiringPi { .. }) => "acquiring-pi",
        Some(RunStatus::Streaming) => "streaming",
        Some(RunStatus::Completed) => "complete",
        Some(RunStatus::Cancelled) => "cancelled",
        Some(RunStatus::Failed { .. }) => "failed",
        Some(RunStatus::NeedsAttention(_)) => "interrupted",
        Some(RunStatus::PendingPermission(_)) => "pending-permission",
        _ => "thinking",
    }
}
