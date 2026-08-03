//! Pure reconstruction of user-visible run state from journal events.

use super::{EventEnvelope, EventPayload};
use crate::assistant_text::projector::Projector;
use crate::assistant_text::stream::{AssistantText, RunStreamProjector};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedThreadEntry {
    pub ordinal: i64,
    pub run_seq: u64,
    pub kind: String,
    pub text: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StampedThreadEntry {
    pub run_id: String,
    pub snapshot_seq: u64,
    pub run_ordinal: i64,
    pub entry_ordinal: i64,
    pub run_seq: u64,
    pub kind: String,
    pub text: Option<String>,
}

impl super::RunJournal {
    /// Rebuilds the assistant-text stream projection through one stable snapshot.
    pub fn projected_run_stream_text(
        &mut self,
        workspace: &str,
        run_id: &str,
        snapshot_seq: u64,
    ) -> Result<BTreeMap<u64, AssistantText>, super::RunEventPageError> {
        let owned = self
            .run_belongs_to_workspace(run_id, workspace)
            .map_err(super::RunEventPageError::Journal)?;
        if !owned {
            return Err(super::RunEventPageError::NotFoundOrInaccessible);
        }
        let events = self
            .events(run_id)
            .map_err(super::RunEventPageError::Journal)?;
        let mut projector = RunStreamProjector::new(workspace, |path: &std::path::Path| {
            std::fs::canonicalize(path)
        });
        let mut projected = BTreeMap::new();
        let empty_payload = Value::Null;
        for event in events.iter().filter(|event| event.run_seq <= snapshot_seq) {
            let payload = match &event.payload {
                EventPayload::Inline { payload_json } => payload_json,
                EventPayload::Cas { .. } | EventPayload::Attachment { .. } => &empty_payload,
            };
            let emittable = projector
                .push(event.run_seq, &event.event_type, payload)
                .map_err(|_| {
                    super::RunEventPageError::Journal(super::JournalError::Corrupt(
                        "assistant text stream projection failed".into(),
                    ))
                })?;
            projected.extend(
                emittable
                    .into_iter()
                    .map(|event| (event.run_seq, event.assistant_text)),
            );
        }
        Ok(projected)
    }

    pub fn ledger_thread_projection_entries(
        &mut self,
        workspace: &str,
        thread_id: &str,
        boundary: &super::ThreadProjectionBoundary,
        limit: usize,
    ) -> Result<Vec<StampedThreadEntry>, super::RunEventPageError> {
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()
            .map_err(super::RunEventPageError::Journal)?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let accessible: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM thread_events te \
                 WHERE te.thread_id=?1 \
                 AND NOT EXISTS(SELECT 1 FROM thread_events deleted \
                    WHERE deleted.thread_id=te.thread_id AND deleted.event_type='thread.deleted') \
                 AND EXISTS(SELECT 1 FROM run_threads rt JOIN run_workspaces rw \
                    ON rw.run_id=rt.run_id WHERE rt.thread_id=te.thread_id AND rw.workspace=?2))",
                rusqlite::params![thread_id, workspace],
                |row| row.get(0),
            )
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        if !accessible {
            return Err(super::RunEventPageError::NotFoundOrInaccessible);
        }
        let mut statement = connection
            .prepare(
                "WITH run_snapshots AS (\
                    SELECT rt.run_id, rt.thread_run_ordinal, MAX(e.run_seq) AS snapshot_seq \
                    FROM run_threads rt JOIN run_workspaces rw ON rw.run_id=rt.run_id \
                    JOIN events e ON e.run_id=rt.run_id AND e.rowid<=?3 \
                    WHERE rt.thread_id=?1 AND rw.workspace=?2 \
                    GROUP BY rt.run_id, rt.thread_run_ordinal) \
                 SELECT rs.run_id,rs.snapshot_seq,rs.thread_run_ordinal,p.ordinal,p.run_seq,p.kind,p.text \
                 FROM run_snapshots rs JOIN thread_projection_versions p ON p.run_id=rs.run_id \
                 WHERE p.valid_from_seq<=rs.snapshot_seq \
                 AND (p.valid_until_seq IS NULL OR p.valid_until_seq>rs.snapshot_seq) \
                 AND (rs.thread_run_ordinal>?4 OR (rs.thread_run_ordinal=?4 \
                    AND (p.run_seq>?5 OR (p.run_seq=?5 AND p.ordinal>?6)))) \
                 ORDER BY rs.thread_run_ordinal,p.run_seq,p.ordinal LIMIT ?7",
            )
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        let rows = statement
            .query_map(
                rusqlite::params![
                    thread_id,
                    workspace,
                    boundary.snapshot_rowid,
                    boundary.last_run_ordinal,
                    boundary.last_run_seq,
                    boundary.last_entry_ordinal,
                    limit
                ],
                |row| {
                    Ok(StampedThreadEntry {
                        run_id: row.get(0)?,
                        snapshot_seq: row.get(1)?,
                        run_ordinal: row.get(2)?,
                        entry_ordinal: row.get(3)?,
                        run_seq: row.get(4)?,
                        kind: row
                            .get::<_, String>(5)?
                            .split(':')
                            .next()
                            .unwrap_or_default()
                            .to_owned(),
                        text: row.get(6)?,
                    })
                },
            )
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)
    }

    /// Reprojects assistant deltas for one stable run snapshot.
    pub fn projected_assistant_text(
        &mut self,
        workspace: &str,
        run_id: &str,
        snapshot_seq: u64,
        ordinals: &[i64],
    ) -> Result<BTreeMap<i64, Option<String>>, super::RunEventPageError> {
        if let Some(cached) = &self.assistant_projection_cache {
            if cached.workspace == workspace
                && cached.run_id == run_id
                && cached.snapshot_seq == snapshot_seq
            {
                return Ok(ordinals
                    .iter()
                    .filter_map(|ordinal| {
                        cached
                            .entries
                            .get(ordinal)
                            .cloned()
                            .map(|text| (*ordinal, text))
                    })
                    .collect());
            }
        }
        let owned = self
            .run_belongs_to_workspace(run_id, workspace)
            .map_err(super::RunEventPageError::Journal)?;
        if !owned {
            return Err(super::RunEventPageError::NotFoundOrInaccessible);
        }
        let events = self
            .events(run_id)
            .map_err(super::RunEventPageError::Journal)?;
        let mut projector = Projector::new(workspace, |path: &std::path::Path| {
            std::fs::canonicalize(path)
        });
        let mut released = String::new();
        let terminal = events.iter().any(|event| {
            event.run_seq <= snapshot_seq
                && matches!(
                    event.event_type.as_str(),
                    "run.completed" | "run.cancelled" | "run.failed"
                )
        });
        for event in events.iter().filter(|event| {
            event.run_seq <= snapshot_seq && event.event_type == "model.stream.delta"
        }) {
            let EventPayload::Inline { payload_json } = &event.payload else {
                continue;
            };
            let text = payload_json
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let projections = projector
                .push(event.run_seq, text, payload_json)
                .map_err(|_| {
                    super::RunEventPageError::Journal(super::JournalError::Corrupt(
                        "assistant text projection failed".into(),
                    ))
                })?;
            for projection in projections {
                if let Some(text) = projection.text {
                    released.push_str(&text);
                }
            }
        }
        let projections = if terminal {
            projector.finish::<std::io::Error>()
        } else {
            projector.flush::<std::io::Error>()
        }
        .map_err(|_| {
            super::RunEventPageError::Journal(super::JournalError::Corrupt(
                "assistant text projection failed".into(),
            ))
        })?;
        for projection in projections {
            if let Some(text) = projection.text {
                released.push_str(&text);
            }
        }

        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()
            .map_err(super::RunEventPageError::Journal)?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let mut statement = connection
            .prepare(
                "SELECT ordinal,COALESCE(text,'') FROM thread_projection_versions \
                 WHERE run_id=?1 AND kind='assistant_message' AND valid_from_seq<=?2 \
                 AND (valid_until_seq IS NULL OR valid_until_seq>?2) ORDER BY ordinal",
            )
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        let rows = statement
            .query_map(rusqlite::params![run_id, snapshot_seq], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?.len()))
            })
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        let mut released_offset = 0;
        let mut original_offset = 0;
        let mut result = BTreeMap::new();
        for row in rows {
            let (ordinal, original_len) = row
                .map_err(super::JournalError::from)
                .map_err(super::RunEventPageError::Journal)?;
            original_offset += original_len;
            let mut end = original_offset.min(released.len());
            while !released.is_char_boundary(end) {
                end -= 1;
            }
            let text = (end > released_offset).then(|| released[released_offset..end].to_owned());
            result.insert(ordinal, text);
            released_offset = end;
        }
        self.assistant_projection_cache = Some(super::AssistantProjectionCache {
            workspace: workspace.to_owned(),
            run_id: run_id.to_owned(),
            snapshot_seq,
            entries: result,
        });
        let projection = &self.assistant_projection_cache.as_ref().unwrap().entries;
        Ok(ordinals
            .iter()
            .filter_map(|ordinal| {
                projection
                    .get(ordinal)
                    .cloned()
                    .map(|text| (*ordinal, text))
            })
            .collect())
    }

    /// Replays a stable run snapshot one row at a time. This keeps reducer
    /// state across storage boundaries without loading the journal envelopes.
    pub fn projected_thread_entries(
        &mut self,
        workspace: &str,
        run_id: &str,
        snapshot_seq: u64,
        last_ordinal: i64,
        limit: usize,
    ) -> Result<Vec<ProjectedThreadEntry>, super::RunEventPageError> {
        let owned = self
            .run_belongs_to_workspace(run_id, workspace)
            .map_err(super::RunEventPageError::Journal)?;
        if !owned {
            return Err(super::RunEventPageError::NotFoundOrInaccessible);
        }
        let coordination = self.coordination.clone();
        let _operation = coordination
            .as_ref()
            .map(|state| state.operation.lock().unwrap());
        self.refresh_after_compaction()
            .map_err(super::RunEventPageError::Journal)?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is always present outside compaction");
        let mut statement = connection
            .prepare(
                "SELECT ordinal,run_seq,kind,text FROM thread_projection_versions INDEXED BY thread_projection_versions_page \
                 WHERE run_id=?1 AND ordinal>?4 AND valid_from_seq<=?2 \
                 AND (valid_until_seq IS NULL OR valid_until_seq>?2) \
                 ORDER BY ordinal LIMIT ?3",
            )
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        let rows = statement
            .query_map(
                rusqlite::params![run_id, snapshot_seq, limit, last_ordinal],
                |row| {
                    Ok(ProjectedThreadEntry {
                        ordinal: row.get(0)?,
                        run_seq: row.get(1)?,
                        kind: row
                            .get::<_, String>(2)?
                            .split(':')
                            .next()
                            .unwrap_or_default()
                            .to_owned(),
                        text: row.get(3)?,
                    })
                },
            )
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(super::JournalError::from)
            .map_err(super::RunEventPageError::Journal)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGate {
    pub gate_id: String,
    #[serde(flatten)]
    pub request: PermissionRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PermissionRequest {
    Select {
        title: String,
        options: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
    Confirm {
        title: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
    Input {
        title: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        placeholder: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
    Editor {
        title: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefill: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttentionReason {
    UnknownEffectOutcome { effect_id: String },
    Recorded { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStatus {
    Active,
    Streaming,
    PendingPermission(PermissionGate),
    Completed,
    Cancelled,
    Failed { reason: Option<String> },
    NeedsAttention(AttentionReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunState {
    pub run_id: String,
    pub last_seq: u64,
    pub status: RunStatus,
    pub pi_session: Option<PiSessionBinding>,
    pub pending_permission: Option<PermissionGate>,
    pub running_effects: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiSessionBinding {
    pub run_id: String,
    pub locator: String,
}

/// The webview-facing chat projection derived from journal events.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChatProjection {
    pub prompt_accepted: bool,
    pub text: String,
    pub receipt: Option<Value>,
    pub status: Option<RunStatus>,
    pub pending_permission: Option<PermissionGate>,
    pub tool_activity: Vec<ToolActivity>,
    pub attachments: Vec<ProjectedAttachment>,
}

/// Safe attachment metadata for display outside the journal/CAS boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedAttachment {
    pub display_name: String,
    pub byte_length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolActivity {
    pub effect_id: String,
    pub display_name: Option<String>,
    pub status: ToolActivityStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolActivityStatus {
    Running,
    Completed,
    Failed,
}

pub fn project_chat(events: &[EventEnvelope]) -> Result<ChatProjection, ReduceError> {
    project_chat_with_state(events).map(|(chat, _)| chat)
}

pub fn project_chat_with_state(
    events: &[EventEnvelope],
) -> Result<(ChatProjection, RunState), ReduceError> {
    let mut projector = ChatProjector::new();
    for event in events {
        projector.apply(event)?;
    }
    projector.finish()
}

/// Projects a bounded continuation fragment when the reducer state lives before
/// the page boundary. Only independently displayable fields are emitted.
pub fn project_chat_fragment(events: &[EventEnvelope]) -> Result<ChatProjection, ReduceError> {
    let mut chat = ChatProjection::default();
    for event in events {
        match event.event_type.as_str() {
            "chat.attachment.ingested" => {
                let EventPayload::Attachment { attachment } = &event.payload else {
                    return Err(ReduceError::MissingAttachmentPayload {
                        event_type: event.event_type.clone(),
                    });
                };
                chat.attachments.push(ProjectedAttachment {
                    display_name: attachment.display_name().to_owned(),
                    byte_length: attachment.byte_length(),
                    media_type: attachment.media_type().map(str::to_owned),
                });
            }
            "model.stream.delta" => chat.text.push_str(&field(event, "text")?),
            "tool.effect.started" => chat.tool_activity.push(ToolActivity {
                effect_id: field(event, "effect_id")?,
                display_name: optional_field(event, "display_name")?,
                status: ToolActivityStatus::Running,
            }),
            "tool.effect.completed" | "tool.effect.failed" => {
                let effect_id = field(event, "effect_id")?;
                if let Some(activity) = chat
                    .tool_activity
                    .iter_mut()
                    .rev()
                    .find(|activity| activity.effect_id == effect_id)
                {
                    activity.status = if event.event_type == "tool.effect.completed" {
                        ToolActivityStatus::Completed
                    } else {
                        ToolActivityStatus::Failed
                    };
                }
            }
            _ => {}
        }
    }
    Ok(chat)
}

#[derive(Clone, Debug, Default)]
pub struct ChatProjector {
    chat: ChatProjection,
    reducer: RunReducer,
}

impl ChatProjector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, event: &EventEnvelope) -> Result<(), ReduceError> {
        self.reducer.apply(event)?;
        match event.event_type.as_str() {
            "chat.attachment.ingested" => {
                let EventPayload::Attachment { attachment } = &event.payload else {
                    return Err(ReduceError::MissingAttachmentPayload {
                        event_type: event.event_type.clone(),
                    });
                };
                self.chat.attachments.push(ProjectedAttachment {
                    display_name: attachment.display_name().to_owned(),
                    byte_length: attachment.byte_length(),
                    media_type: attachment.media_type().map(str::to_owned),
                });
            }
            "model.prompt.accepted" => self.chat.prompt_accepted = true,
            "model.stream.delta" => self.chat.text.push_str(&field(event, "text")?),
            "tool.effect.started" => self.chat.tool_activity.push(ToolActivity {
                effect_id: field(event, "effect_id")?,
                display_name: optional_field(event, "display_name")?,
                status: ToolActivityStatus::Running,
            }),
            "tool.effect.completed" | "tool.effect.failed" => {
                let effect_id = field(event, "effect_id")?;
                if let Some(activity) = self
                    .chat
                    .tool_activity
                    .iter_mut()
                    .rev()
                    .find(|activity| activity.effect_id == effect_id)
                {
                    activity.status = if event.event_type == "tool.effect.completed" {
                        ToolActivityStatus::Completed
                    } else {
                        ToolActivityStatus::Failed
                    };
                }
            }
            "run.completed" => {
                self.chat.receipt = payload(event)?.get("receipt").cloned();
            }
            _ => {}
        }
        Ok(())
    }

    pub fn projection(&self) -> Result<ChatProjection, ReduceError> {
        let mut chat = self.chat.clone();
        let status = self.reducer.clone().finish()?.status;
        chat.pending_permission = match &status {
            RunStatus::PendingPermission(gate) => Some(gate.clone()),
            _ => None,
        };
        chat.status = Some(status);
        Ok(chat)
    }

    pub fn finish(self) -> Result<(ChatProjection, RunState), ReduceError> {
        let state = self.reducer.finish()?;
        let mut chat = self.chat;
        chat.pending_permission = match &state.status {
            RunStatus::PendingPermission(gate) => Some(gate.clone()),
            _ => None,
        };
        chat.status = Some(state.status.clone());
        Ok((chat, state))
    }
}

impl RunState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            RunStatus::Completed
                | RunStatus::Cancelled
                | RunStatus::Failed { .. }
                | RunStatus::NeedsAttention(_)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReduceError {
    Sequence {
        expected: u64,
        actual: u64,
    },
    RunChanged {
        expected: String,
        actual: String,
    },
    UnsupportedSafetyEvent {
        event_type: String,
        version: u32,
    },
    MissingInlinePayload {
        event_type: String,
    },
    MissingAttachmentPayload {
        event_type: String,
    },
    MissingField {
        event_type: String,
        field: &'static str,
    },
    InvalidTransition {
        event_type: String,
        detail: String,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "run journal reduction failed: {self:?}")
    }
}
impl std::error::Error for ReduceError {}

#[derive(Clone, Debug)]
pub struct RunReducer {
    state: Option<RunState>,
    pending_gate: Option<PermissionGate>,
    open_effects: Vec<String>,
    pi_session: Option<PiSessionBinding>,
}

impl Default for RunReducer {
    fn default() -> Self {
        Self::new()
    }
}

impl RunReducer {
    pub fn new() -> Self {
        Self {
            state: None,
            pending_gate: None,
            open_effects: Vec::new(),
            pi_session: None,
        }
    }

    pub fn apply(&mut self, event: &EventEnvelope) -> Result<(), ReduceError> {
        let expected = self.state.as_ref().map_or(1, |s| s.last_seq + 1);
        if event.run_seq != expected {
            return Err(ReduceError::Sequence {
                expected,
                actual: event.run_seq,
            });
        }
        if let Some(state) = &self.state {
            if state.run_id != event.run_id {
                return Err(ReduceError::RunChanged {
                    expected: state.run_id.clone(),
                    actual: event.run_id.clone(),
                });
            }
        }
        if is_safety_event(&event.event_type)
            && (event.event_version != 1 || !is_known_safety_event(&event.event_type))
        {
            return Err(ReduceError::UnsupportedSafetyEvent {
                event_type: event.event_type.clone(),
                version: event.event_version,
            });
        }

        let terminal = self.state.as_ref().is_some_and(RunState::is_terminal);
        if terminal
            && !matches!(
                event.event_type.as_str(),
                "run.needs_attention" | "run.resumed"
            )
            && is_state_event(&event.event_type)
        {
            return Err(invalid(event, "event follows a terminal run state"));
        }

        match event.event_type.as_str() {
            "run.started" => {
                if self.state.is_some() {
                    return Err(invalid(event, "run may only start once"));
                }
                self.set_status(event, RunStatus::Active);
            }
            "chat.attachment.ingested" => {
                self.require_active(event)?;
                let status = self.state.as_ref().unwrap().status.clone();
                self.set_status(event, status);
            }
            "runtime.pi_session.bound" => {
                self.require_active(event)?;
                if self.pi_session.is_some() {
                    return Err(invalid(event, "Pi session may only be bound once"));
                }
                let binding: PiSessionBinding = serde_json::from_value(payload(event)?.clone())
                    .map_err(|_| invalid(event, "Pi session binding payload is invalid"))?;
                if binding.run_id != event.run_id
                    || binding.locator.is_empty()
                    || binding.locator.contains('/')
                    || binding.locator.contains('\\')
                    || !binding.locator.ends_with(".jsonl")
                {
                    return Err(invalid(event, "Pi session binding payload is invalid"));
                }
                self.pi_session = Some(binding);
                self.set_status(event, RunStatus::Active);
            }
            "model.stream.delta" => self.require_executable(event, RunStatus::Streaming)?,
            "permission.requested" => {
                self.require_active(event)?;
                if self.pending_gate.is_some() {
                    return Err(invalid(event, "a permission gate is already pending"));
                }
                let gate: PermissionGate = serde_json::from_value(payload(event)?.clone())
                    .map_err(|_| invalid(event, "permission request payload is invalid"))?;
                if gate.gate_id.is_empty() {
                    return Err(invalid(event, "permission request gate id is empty"));
                }
                self.pending_gate = Some(gate.clone());
                self.set_status(event, RunStatus::PendingPermission(gate));
            }
            "permission.resolved" => {
                let gate_id = field(event, "gate_id")?;
                match self.pending_gate.take() {
                    Some(g) if g.gate_id == gate_id => self.set_status(event, RunStatus::Active),
                    Some(g) => {
                        self.pending_gate = Some(g);
                        return Err(invalid(event, "resolution does not match the pending gate"));
                    }
                    None => return Err(invalid(event, "no permission gate is pending")),
                }
            }
            "tool.effect.started" => {
                self.require_active(event)?;
                let effect_id = field(event, "effect_id")?;
                if self.open_effects.contains(&effect_id) {
                    return Err(invalid(event, "effect is already open"));
                }
                self.open_effects.push(effect_id);
                self.set_status(event, RunStatus::Active);
            }
            "tool.effect.completed" | "tool.effect.failed" => {
                let effect_id = field(event, "effect_id")?;
                if let Some(index) = self.open_effects.iter().position(|id| id == &effect_id) {
                    self.open_effects.remove(index);
                    self.set_status(event, RunStatus::Active);
                } else {
                    return Err(invalid(event, "effect outcome has no matching start"));
                }
            }
            "run.completed" => self.terminal(event, RunStatus::Completed)?,
            "run.cancelled" => self.terminal(event, RunStatus::Cancelled)?,
            "run.failed" => self.terminal(
                event,
                RunStatus::Failed {
                    reason: optional_field(event, "reason")?,
                },
            )?,
            "run.needs_attention" => {
                self.set_status(
                    event,
                    RunStatus::NeedsAttention(AttentionReason::Recorded {
                        reason: optional_field(event, "reason")?
                            .unwrap_or_else(|| "unspecified".into()),
                    }),
                );
            }
            "run.resumed" => {
                if !matches!(
                    self.state.as_ref().map(|state| &state.status),
                    Some(RunStatus::NeedsAttention(_))
                ) || self.pending_gate.is_some()
                    || !self.open_effects.is_empty()
                    || self.pi_session.is_none()
                {
                    return Err(invalid(event, "run is not safely resumable"));
                }
                self.set_status(event, RunStatus::Active);
            }
            _ => {
                if self.state.is_none() {
                    return Err(invalid(event, "first event must be run.started"));
                }
                self.state.as_mut().unwrap().last_seq = event.run_seq;
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<RunState, ReduceError> {
        let mut state = self
            .state
            .take()
            .ok_or_else(|| ReduceError::InvalidTransition {
                event_type: "end-of-stream".into(),
                detail: "empty journal".into(),
            })?;
        // Open effects retain start order; report the earliest dangling effect deterministically.
        if self.pending_gate.is_none() && !matches!(state.status, RunStatus::NeedsAttention(_)) {
            if let Some(effect_id) = self.open_effects.into_iter().next() {
                state.status =
                    RunStatus::NeedsAttention(AttentionReason::UnknownEffectOutcome { effect_id });
            }
        }
        Ok(state)
    }

    fn require_active(&self, event: &EventEnvelope) -> Result<(), ReduceError> {
        match self.state.as_ref().map(|s| &s.status) {
            Some(RunStatus::Active | RunStatus::Streaming) if self.pending_gate.is_none() => Ok(()),
            _ => Err(invalid(event, "run is not executable")),
        }
    }
    fn require_executable(
        &mut self,
        event: &EventEnvelope,
        status: RunStatus,
    ) -> Result<(), ReduceError> {
        self.require_active(event)?;
        self.set_status(event, status);
        Ok(())
    }
    fn terminal(&mut self, event: &EventEnvelope, status: RunStatus) -> Result<(), ReduceError> {
        self.require_active(event)?;
        if !self.open_effects.is_empty() {
            return Err(invalid(event, "effect outcome is unknown"));
        }
        self.set_status(event, status);
        Ok(())
    }
    fn set_status(&mut self, event: &EventEnvelope, status: RunStatus) {
        self.state = Some(RunState {
            run_id: event.run_id.clone(),
            last_seq: event.run_seq,
            status,
            pi_session: self.pi_session.clone(),
            pending_permission: self.pending_gate.clone(),
            running_effects: self.open_effects.clone(),
        });
    }
}

pub fn reduce(events: &[EventEnvelope]) -> Result<RunState, ReduceError> {
    let mut reducer = RunReducer::new();
    for event in events {
        reducer.apply(event)?;
    }
    reducer.finish()
}

fn payload(event: &EventEnvelope) -> Result<&Value, ReduceError> {
    match &event.payload {
        EventPayload::Inline { payload_json } => Ok(payload_json),
        EventPayload::Cas { .. } | EventPayload::Attachment { .. } => {
            Err(ReduceError::MissingInlinePayload {
                event_type: event.event_type.clone(),
            })
        }
    }
}
fn field(event: &EventEnvelope, name: &'static str) -> Result<String, ReduceError> {
    optional_field(event, name)?.ok_or_else(|| ReduceError::MissingField {
        event_type: event.event_type.clone(),
        field: name,
    })
}
fn optional_field(
    event: &EventEnvelope,
    name: &'static str,
) -> Result<Option<String>, ReduceError> {
    Ok(payload(event)?
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned))
}
fn invalid(event: &EventEnvelope, detail: &str) -> ReduceError {
    ReduceError::InvalidTransition {
        event_type: event.event_type.clone(),
        detail: detail.into(),
    }
}
fn is_safety_event(t: &str) -> bool {
    t.starts_with("chat.attachment.")
        || t.starts_with("permission.")
        || t.starts_with("tool.effect.")
        || t.starts_with("runtime.pi_session.")
}
fn is_known_safety_event(t: &str) -> bool {
    matches!(
        t,
        "chat.attachment.ingested"
            | "permission.requested"
            | "permission.resolved"
            | "tool.effect.started"
            | "tool.effect.completed"
            | "tool.effect.failed"
            | "runtime.pi_session.bound"
            | "run.resumed"
    )
}
fn is_state_event(t: &str) -> bool {
    t.starts_with("chat.attachment.")
        || t.starts_with("run.")
        || t.starts_with("model.")
        || t.starts_with("permission.")
        || t.starts_with("tool.")
        || t.starts_with("runtime.pi_session.")
}
