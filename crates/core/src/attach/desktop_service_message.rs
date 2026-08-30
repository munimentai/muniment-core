//! Platform-neutral desktop attach service messages.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompanionProvenance {
    pub profile: String,
    pub companion_kind: String,
    pub companion_version: String,
    pub peer_uid: u32,
    pub peer_pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RunStartAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSubmitRequest {
    pub text: String,
    pub files: Vec<String>,
    pub thread_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct RunSubmitAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub attachments: Vec<crate::chat_view::ChatAttachment>,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunResumeRequest {
    pub run_id: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct RunResumeAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadCreateAccepted {
    pub thread_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationControlRequest {
    pub handoff_nonce: String,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunCancelRequest {
    pub run_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RunCancelAccepted {
    pub run_id: String,
    pub accepted_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionAnswerRequest {
    pub run_id: String,
    pub gate_id: String,
    pub decision: PermissionDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct PermissionAnswerAccepted {
    pub run_id: String,
    pub gate_id: String,
    pub decision: PermissionDecision,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunMessageRequest {
    pub run_id: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RunMessageAccepted {
    pub run_id: String,
    pub accepted_at: String,
}

#[derive(Clone, Debug)]
pub struct RunPermissionAnswerRequest {
    pub run_id: String,
    pub gate_id: String,
    pub answer: crate::permission_gate::ChatPermissionAnswer,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct RunPermissionAnswerAccepted {
    pub run_id: String,
    pub gate_id: String,
    pub answer: crate::permission_gate::ChatPermissionAnswer,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunStreamPage {
    pub run_id: String,
    pub first_available_run_seq: u64,
    pub current_run_seq: u64,
    pub events: Vec<crate::journal::RunEventProjection>,
    pub exhausted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactFetchResult {
    pub total_bytes: u64,
    pub sha256: String,
}
