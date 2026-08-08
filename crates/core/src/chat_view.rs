//! Webview chat payloads derived from journal projections.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::journal::reducer::{
    PermissionGate, PermissionRequest, ProjectedAttachment, RunStatus, ToolActivity,
    ToolActivityStatus,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedFile {
    pub path: PathBuf,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatToolActivity {
    pub effect_id: String,
    pub display_name: Option<String>,
    pub status: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatPendingPermission {
    pub gate_id: String,
    #[serde(flatten)]
    pub request: PermissionRequest,
}

#[derive(Clone, Serialize)]
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

pub fn chat_pending_permission(gate: Option<PermissionGate>) -> Option<ChatPendingPermission> {
    gate.map(|gate| ChatPendingPermission {
        gate_id: gate.gate_id,
        request: gate.request,
    })
}

pub fn chat_tool_activity(activity: &[ToolActivity]) -> Vec<ChatToolActivity> {
    activity
        .iter()
        .map(|activity| ChatToolActivity {
            effect_id: activity.effect_id.clone(),
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

pub fn projection_phase(status: &Option<RunStatus>) -> &'static str {
    match status {
        Some(RunStatus::Streaming) => "streaming",
        Some(RunStatus::Completed) => "complete",
        Some(RunStatus::Cancelled) => "cancelled",
        Some(RunStatus::Failed { .. }) => "failed",
        Some(RunStatus::NeedsAttention(_)) => "interrupted",
        Some(RunStatus::PendingPermission(_)) => "pending-permission",
        _ => "thinking",
    }
}
