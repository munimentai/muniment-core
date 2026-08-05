use std::path::Path;

use crate::journal::reducer::{reduce, RunState, RunStatus};
use crate::journal::EventEnvelope;
use crate::sidecar::{validate_pi_session, PiSessionLocator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatResumeError {
    InvalidEvents,
    MissingFirstEvent,
    SubjectMismatch,
    StatusNotResumable,
    PendingPermission,
    RunningEffect,
    MissingPiSession,
    InvalidPiSession,
}

pub struct ResumeContext {
    pub events: Vec<EventEnvelope>,
    pub locator: PiSessionLocator,
}

pub fn resumable_context(
    events: &[EventEnvelope],
    subject: Option<&str>,
    session_root: &Path,
) -> Result<ResumeContext, ChatResumeError> {
    let state = reduce(events).map_err(|_| ChatResumeError::InvalidEvents)?;
    let locator = resumable_locator(events.first(), &state, subject, session_root)?;
    Ok(ResumeContext {
        events: events.to_vec(),
        locator,
    })
}

pub fn resumable_locator(
    first_event: Option<&EventEnvelope>,
    state: &RunState,
    subject: Option<&str>,
    session_root: &Path,
) -> Result<PiSessionLocator, ChatResumeError> {
    let first_event = first_event.ok_or(ChatResumeError::MissingFirstEvent)?;
    if matches!(
        first_event.provenance.actor_id.as_deref(),
        Some(owner) if Some(owner) != subject
    ) {
        return Err(ChatResumeError::SubjectMismatch);
    }
    if !matches!(&state.status, RunStatus::NeedsAttention(_)) {
        return Err(ChatResumeError::StatusNotResumable);
    }
    if state.pending_permission.is_some() {
        return Err(ChatResumeError::PendingPermission);
    }
    if !state.running_effects.is_empty() {
        return Err(ChatResumeError::RunningEffect);
    }
    let binding = state
        .pi_session
        .as_ref()
        .ok_or(ChatResumeError::MissingPiSession)?;
    validate_pi_session(session_root, &binding.locator)
        .map(|(locator, _)| locator)
        .map_err(|_| ChatResumeError::InvalidPiSession)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::reducer::{
        AttentionReason, PermissionGate, PermissionRequest, PiSessionBinding,
    };
    use crate::journal::{EventPayload, Provenance};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn event(actor_id: Option<&str>) -> EventEnvelope {
        EventEnvelope {
            event_id: "event".into(),
            run_id: "run".into(),
            run_seq: 1,
            event_type: "run.started".into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: "2026-08-05T00:00:00Z".into(),
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: json!({}),
            },
            provenance: Provenance {
                source: "test".into(),
                source_version: "1".into(),
                actor_id: actor_id.map(str::to_owned),
                device_id: None,
                rpc_request_id: None,
                capability_versions: None,
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        }
    }

    fn state() -> RunState {
        RunState {
            run_id: "run".into(),
            last_seq: 3,
            status: RunStatus::NeedsAttention(AttentionReason::Recorded {
                reason: "interrupted".into(),
            }),
            pi_session: Some(PiSessionBinding {
                run_id: "run".into(),
                locator: "session.jsonl".into(),
            }),
            pending_permission: None,
            running_effects: Vec::new(),
        }
    }

    fn session_root() -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("muniment-chat-resume-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("session.jsonl"), b"{}\n").unwrap();
        root
    }

    #[test]
    fn accepts_resumable_run() {
        let root = session_root();
        assert!(
            resumable_locator(Some(&event(Some("owner"))), &state(), Some("owner"), &root).is_ok()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_missing_first_event() {
        let root = session_root();
        assert_eq!(
            resumable_locator(None, &state(), None, &root),
            Err(ChatResumeError::MissingFirstEvent)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_another_subject() {
        let root = session_root();
        assert_eq!(
            resumable_locator(Some(&event(Some("owner"))), &state(), Some("other"), &root),
            Err(ChatResumeError::SubjectMismatch)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_resumable_status() {
        let root = session_root();
        let mut value = state();
        value.status = RunStatus::Completed;
        assert_eq!(
            resumable_locator(Some(&event(None)), &value, None, &root),
            Err(ChatResumeError::StatusNotResumable)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_pending_permission() {
        let root = session_root();
        let mut value = state();
        value.pending_permission = Some(PermissionGate {
            gate_id: "gate".into(),
            request: PermissionRequest::Confirm {
                title: "Allow?".into(),
                message: "Proceed?".into(),
                timeout: None,
            },
        });
        assert_eq!(
            resumable_locator(Some(&event(None)), &value, None, &root),
            Err(ChatResumeError::PendingPermission)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_running_effect() {
        let root = session_root();
        let mut value = state();
        value.running_effects.push("effect".into());
        assert_eq!(
            resumable_locator(Some(&event(None)), &value, None, &root),
            Err(ChatResumeError::RunningEffect)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_missing_pi_session() {
        let root = session_root();
        let mut value = state();
        value.pi_session = None;
        assert_eq!(
            resumable_locator(Some(&event(None)), &value, None, &root),
            Err(ChatResumeError::MissingPiSession)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_invalid_pi_session() {
        let root = session_root();
        let mut value = state();
        value.pi_session.as_mut().unwrap().locator = "missing.jsonl".into();
        assert_eq!(
            resumable_locator(Some(&event(None)), &value, None, &root),
            Err(ChatResumeError::InvalidPiSession)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_invalid_events() {
        assert!(matches!(
            resumable_context(&[], None, Path::new("missing")),
            Err(ChatResumeError::InvalidEvents)
        ));
    }
}
