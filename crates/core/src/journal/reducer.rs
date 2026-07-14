//! Pure reconstruction of user-visible run state from journal events.

use super::{EventEnvelope, EventPayload};
use serde_json::Value;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionGate {
    pub gate_id: String,
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
}

/// The webview-facing chat projection derived from journal events.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChatProjection {
    pub prompt_accepted: bool,
    pub text: String,
    pub receipt: Option<Value>,
    pub status: Option<RunStatus>,
    pub tool_activity: Vec<ToolActivity>,
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
    let mut projector = ChatProjector::new();
    for event in events {
        projector.apply(event)?;
    }
    projector.projection()
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
        chat.status = Some(self.reducer.clone().finish()?.status);
        Ok(chat)
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
            && event.event_type != "run.needs_attention"
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
            "model.stream.delta" => self.require_executable(event, RunStatus::Streaming)?,
            "permission.requested" => {
                self.require_active(event)?;
                if self.pending_gate.is_some() {
                    return Err(invalid(event, "a permission gate is already pending"));
                }
                let gate = PermissionGate {
                    gate_id: field(event, "gate_id")?,
                };
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
                self.pending_gate = None;
                self.open_effects.clear();
                self.set_status(
                    event,
                    RunStatus::NeedsAttention(AttentionReason::Recorded {
                        reason: optional_field(event, "reason")?
                            .unwrap_or_else(|| "unspecified".into()),
                    }),
                );
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
        if let Some(effect_id) = self.open_effects.into_iter().next() {
            state.status =
                RunStatus::NeedsAttention(AttentionReason::UnknownEffectOutcome { effect_id });
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
        EventPayload::Cas { .. } => Err(ReduceError::MissingInlinePayload {
            event_type: event.event_type.clone(),
        }),
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
    t.starts_with("permission.") || t.starts_with("tool.effect.")
}
fn is_known_safety_event(t: &str) -> bool {
    matches!(
        t,
        "permission.requested"
            | "permission.resolved"
            | "tool.effect.started"
            | "tool.effect.completed"
            | "tool.effect.failed"
    )
}
fn is_state_event(t: &str) -> bool {
    t.starts_with("run.")
        || t.starts_with("model.")
        || t.starts_with("permission.")
        || t.starts_with("tool.")
}
