use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;

use crate::permission_gate::{ChatPermissionAnswer, PendingPermissionAnswer};
use crate::run_start::ActiveRun;
use crate::sidecar::pi_chat::cancel_command;

const QUEUE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChatDelivery {
    Steer,
    FollowUp,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatQueueRequest {
    pub run_id: String,
    pub delivery: ChatDelivery,
    pub message: String,
}

pub fn queue_message(
    active: &Mutex<Option<ActiveRun>>,
    request: ChatQueueRequest,
) -> Result<(), String> {
    let active = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let run = active
        .as_ref()
        .filter(|run| run.id == request.run_id)
        .ok_or_else(|| "That reply is no longer active.".to_string())?;
    let transport = run
        .transport
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let adapter = run
        .adapter
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    drop(active);
    let (transport, adapter) = transport
        .zip(adapter)
        .ok_or_else(|| "The reply is not ready for messages yet.".to_string())?;
    let result = match request.delivery {
        ChatDelivery::Steer => adapter.steer(&transport, &request.message, QUEUE_TIMEOUT),
        ChatDelivery::FollowUp => adapter.follow_up(&transport, &request.message, QUEUE_TIMEOUT),
    };
    result.map_err(|error| {
        if error == "Pi queued message must not be empty" {
            "Enter a message before sending.".to_string()
        } else {
            "The message could not be queued. Try again.".to_string()
        }
    })
}

pub fn cancel_active_run(
    active_runs: &Mutex<Option<ActiveRun>>,
    run_id: &str,
    workspace: Option<&str>,
) -> Result<(), String> {
    let active = active_runs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let run = active
        .as_ref()
        .filter(|run| run.id == run_id && workspace.is_none_or(|value| value == run.workspace))
        .ok_or_else(|| "That reply is no longer active.".to_string())?;
    let cancelled = Arc::clone(&run.cancelled);
    let transport = run
        .transport
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    drop(active);
    cancelled.store(true, Ordering::SeqCst);
    if let Some(transport) = transport {
        transport
            .call(cancel_command(), Duration::from_secs(2))
            .map_err(|_| "The reply could not be stopped yet. Try again.".to_string())?;
    }
    Ok(())
}

pub fn queue_permission_answer(
    active: &Mutex<Option<ActiveRun>>,
    run_id: String,
    gate_id: String,
    answer: ChatPermissionAnswer,
) -> Result<(), String> {
    let active = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let run = active
        .as_ref()
        .filter(|run| run.id == run_id)
        .ok_or_else(|| "That reply is no longer active.".to_string())?;
    run.permission_answers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push_back(PendingPermissionAnswer {
            gate_id,
            answer,
            resolved: None,
        });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;

    use serde_json::json;

    use super::*;
    use crate::attach::RuntimeActivityRegistry;

    fn inactive_transport_run(
        id: &str,
        workspace: &str,
        runtime_activity: &RuntimeActivityRegistry,
    ) -> ActiveRun {
        ActiveRun {
            id: id.into(),
            workspace: workspace.into(),
            cancelled: Arc::new(AtomicBool::new(false)),
            transport: Arc::new(Mutex::new(None)),
            adapter: Arc::new(Mutex::new(None)),
            permission_answers: Arc::new(Mutex::new(VecDeque::new())),
            _activity: runtime_activity.mark_active_run(),
        }
    }

    #[test]
    fn queue_request_is_closed_and_typed() {
        for value in [
            json!({"runId":"run-1", "delivery":"later", "message":"hello"}),
            json!({"runId":"run-1", "delivery":"steer", "message":"hello", "extra":true}),
        ] {
            assert!(serde_json::from_value::<ChatQueueRequest>(value).is_err());
        }
        assert!(serde_json::from_value::<ChatQueueRequest>(json!({
            "runId":"run-1", "delivery":"followUp", "message":"hello"
        }))
        .is_ok());
    }

    #[test]
    fn queue_rejects_mismatched_and_not_ready_runs_safely() {
        let runtime_activity = RuntimeActivityRegistry::new();
        let active = Mutex::new(Some(inactive_transport_run(
            "run-1",
            "workspace-a",
            &runtime_activity,
        )));
        let request = |run_id: &str| ChatQueueRequest {
            run_id: run_id.into(),
            delivery: ChatDelivery::Steer,
            message: "hello".into(),
        };
        assert_eq!(
            queue_message(&active, request("stale-run")).unwrap_err(),
            "That reply is no longer active."
        );
        assert_eq!(
            queue_message(&active, request("run-1")).unwrap_err(),
            "The reply is not ready for messages yet."
        );
    }

    #[test]
    fn cancel_rejects_a_run_in_another_workspace() {
        let runtime_activity = RuntimeActivityRegistry::new();
        let active = Mutex::new(Some(inactive_transport_run(
            "run-1",
            "workspace-a",
            &runtime_activity,
        )));

        assert_eq!(
            cancel_active_run(&active, "run-1", Some("workspace-b")).unwrap_err(),
            "That reply is no longer active."
        );
        assert!(!active
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .cancelled
            .load(Ordering::SeqCst));
        cancel_active_run(&active, "run-1", Some("workspace-a")).unwrap();
        assert!(active
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .cancelled
            .load(Ordering::SeqCst));
    }

    #[test]
    fn permission_answer_handoff_rejects_stale_runs_and_queues_typed_answers() {
        let runtime_activity = RuntimeActivityRegistry::new();
        let active = Mutex::new(Some(inactive_transport_run(
            "run-1",
            "workspace-a",
            &runtime_activity,
        )));
        assert_eq!(
            queue_permission_answer(
                &active,
                "stale-run".into(),
                "gate-1".into(),
                ChatPermissionAnswer::Confirm(true),
            )
            .unwrap_err(),
            "That reply is no longer active."
        );
        queue_permission_answer(
            &active,
            "run-1".into(),
            "gate-1".into(),
            ChatPermissionAnswer::Select("A".into()),
        )
        .unwrap();
        let active = active.lock().unwrap();
        let queued = active
            .as_ref()
            .unwrap()
            .permission_answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap();
        assert_eq!(queued.gate_id, "gate-1");
        assert!(matches!(queued.answer, ChatPermissionAnswer::Select(value) if value == "A"));
    }
}
