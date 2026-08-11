use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use crate::attach::RuntimeActivityRegistry;
use crate::auth::TokenSet;
use crate::chat_coordinate::coordinate;
use crate::chat_grant::ChatGrant;
use crate::journal::reducer::{reduce, RunState, RunStatus};
use crate::journal::EventEnvelope;
use crate::memory_index::ModelMemoryCapability;
use crate::memory_runtime::ApplicationMemoryRuntime;
use crate::permission_gate::PendingPermissionAnswer;
use crate::pi_execution::PiRuntime;
use crate::pi_launch::PiLaunchBoundaries;
use crate::run_events::{ChatEventSink, SharedStorage};
use crate::run_start::ActiveRun;
use crate::sidecar::pi_chat::PiRunAdapter;
use crate::sidecar::PiRpcTransport;
use crate::sidecar::{validate_pi_session, PiSessionLocator};

const RESUME_PROMPT: &str =
    "Continue the interrupted response from the existing session. Do not repeat completed work.";

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

pub struct ResumeLaunch<S> {
    pub sink: S,
    pub storage: SharedStorage,
    pub runtime: Arc<Mutex<Option<PiRuntime>>>,
    pub runtime_activity: RuntimeActivityRegistry,
    pub memory_runtime: Arc<ApplicationMemoryRuntime>,
    pub active: Arc<Mutex<Option<ActiveRun>>>,
    pub run_id: String,
    pub tokens: TokenSet,
    pub grant: ChatGrant,
    pub cancelled: Arc<AtomicBool>,
    pub transport: Arc<Mutex<Option<Arc<PiRpcTransport>>>>,
    pub adapter: Arc<Mutex<Option<Arc<PiRunAdapter>>>>,
    pub permission_answers: Arc<Mutex<VecDeque<PendingPermissionAnswer>>>,
    pub resume: ResumeContext,
    pub attempt: std::sync::mpsc::Sender<Result<(), String>>,
}

pub fn install_resume_run(
    memory_runtime: &ApplicationMemoryRuntime,
    active: &Mutex<Option<ActiveRun>>,
    run: ActiveRun,
    thread_id: &str,
    minimum_cacheable_prefix_characters: usize,
) -> Result<(), String> {
    let run_id = run.id.clone();
    install_active_run(active, run)?;
    if memory_runtime
        .open_session(
            &run_id,
            thread_id,
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters,
            },
        )
        .is_err()
    {
        clear_active_run(active, &run_id);
        return Err("This reply cannot be resumed.".to_string());
    }
    Ok(())
}

pub fn run_resume<S: ChatEventSink + PiLaunchBoundaries>(launch: ResumeLaunch<S>) {
    coordinate(
        launch.sink,
        launch.storage,
        launch.runtime,
        launch.runtime_activity,
        Arc::clone(&launch.memory_runtime),
        launch.run_id.clone(),
        RESUME_PROMPT.into(),
        launch.tokens.access_token,
        launch.tokens.subject,
        launch.grant,
        launch.cancelled,
        launch.transport,
        launch.adapter,
        launch.permission_answers,
        Some(launch.resume),
        Some(launch.attempt),
        None,
    );
    launch.memory_runtime.close_session(&launch.run_id);
    clear_active_run(&launch.active, &launch.run_id);
}

pub fn install_active_run(active: &Mutex<Option<ActiveRun>>, run: ActiveRun) -> Result<(), String> {
    let mut active = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if active.is_some() {
        return Err("A reply is already in progress.".into());
    }
    *active = Some(run);
    Ok(())
}

pub fn clear_active_run(active: &Mutex<Option<ActiveRun>>, run_id: &str) {
    let mut active = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if active.as_ref().is_some_and(|current| current.id == run_id) {
        *active = None;
    }
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

    fn inactive_run(id: &str, activity: &RuntimeActivityRegistry) -> ActiveRun {
        ActiveRun {
            id: id.into(),
            workspace: "workspace".into(),
            cancelled: Arc::new(AtomicBool::new(false)),
            transport: Arc::new(Mutex::new(None)),
            adapter: Arc::new(Mutex::new(None)),
            permission_answers: Arc::new(Mutex::new(VecDeque::new())),
            _activity: activity.mark_active_run(),
        }
    }

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

    #[test]
    fn active_run_marks_runtime_activity_for_its_lifetime() {
        let activity = RuntimeActivityRegistry::new();
        let active = Mutex::new(None);
        assert!(!activity.snapshot().active_run);

        install_active_run(&active, inactive_run("run-1", &activity)).unwrap();
        assert!(activity.snapshot().active_run);

        clear_active_run(&active, "run-1");
        assert!(!activity.snapshot().active_run);
    }

    #[test]
    fn sequential_active_runs_clear_runtime_activity() {
        let activity = RuntimeActivityRegistry::new();
        let active = Mutex::new(None);

        for run_id in ["run-1", "run-2"] {
            install_active_run(&active, inactive_run(run_id, &activity)).unwrap();
            assert!(activity.snapshot().active_run);
            clear_active_run(&active, run_id);
        }

        assert!(!activity.snapshot().active_run);
    }

    #[test]
    fn concurrent_active_run_installs_allow_exactly_one_run() {
        let active = Arc::new(Mutex::new(None));
        let activity = RuntimeActivityRegistry::new();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let active = Arc::clone(&active);
                let activity = activity.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    install_active_run(&active, inactive_run(&format!("run-{index}"), &activity))
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let errors: Vec<_> = results
            .iter()
            .filter_map(|result| result.as_ref().err().map(String::as_str))
            .collect();
        assert_eq!(errors, ["A reply is already in progress."]);
    }

    #[test]
    fn memory_session_failure_leaves_no_active_run() {
        let root =
            std::env::temp_dir().join(format!("muniment-resume-memory-{}", uuid::Uuid::now_v7()));
        let memory = ApplicationMemoryRuntime::new(root.join("config"), root.join("cache"));
        let activity = RuntimeActivityRegistry::new();
        let active = Mutex::new(None);

        let error = install_resume_run(
            &memory,
            &active,
            inactive_run("run-1", &activity),
            "thread-1",
            8_192,
        )
        .unwrap_err();

        assert_eq!(error, "This reply cannot be resumed.");
        assert!(active.lock().unwrap().is_none());
        assert!(!activity.snapshot().active_run);
        assert!(memory
            .dispatch_tool_call("run-1", "memory-search", br#"{"query":"saffron"}"#)
            .is_err());
        assert!(!root.exists());
    }
}
