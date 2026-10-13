use std::collections::VecDeque;
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use muniment_core::attach::{RuntimeActivityRegistry, SignedWorkspaceApproval};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::permission_gate::ChatPermissionAnswer;
use muniment_core::run_start::ActiveRun;
use muniment_core::run_start::RunAttachBoundaries;
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{
    answer_permission, open_companion_registry, open_profile_storage, run_prompt,
    RuntimeAttachBoundaries, RuntimeChatEventTarget, RuntimeHost,
};

mod common;
use common::{fixture_grant, stage_pi_stub, TemporaryProfile};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

fn inactive_run() -> ActiveRun {
    let runtime_activity = RuntimeActivityRegistry::new();
    ActiveRun {
        id: "run-1".into(),
        workspace: "workspace-a".into(),
        cancelled: Arc::new(AtomicBool::new(false)),
        transport: Arc::new(Mutex::new(None)),
        adapter: Arc::new(Mutex::new(None)),
        permission_answers: Arc::new(Mutex::new(VecDeque::new())),
        _activity: runtime_activity.mark_active_run(),
    }
}

#[test]
fn permission_answer_reports_rejection_and_timeout() {
    let active = Arc::new(Mutex::new(Some(inactive_run())));
    std::thread::scope(|scope| {
        let answer = scope.spawn(|| {
            answer_permission(
                Arc::clone(&active),
                "workspace-a".into(),
                "run-1".into(),
                "gate-1".into(),
                ChatPermissionAnswer::Confirm(true),
                Duration::from_secs(1),
            )
        });
        loop {
            let sender = active
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .permission_answers
                .lock()
                .unwrap()
                .pop_front()
                .and_then(|answer| answer.resolved);
            if let Some(sender) = sender {
                sender.send(None).unwrap();
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(
            answer.join().unwrap().unwrap_err(),
            "The permission answer was rejected."
        );
    });

    assert_eq!(
        answer_permission(
            active,
            "workspace-a".into(),
            "run-1".into(),
            "gate-2".into(),
            ChatPermissionAnswer::Confirm(true),
            Duration::ZERO,
        )
        .unwrap_err(),
        "The permission answer did not commit in time."
    );
}

#[test]
fn a_queued_permission_answer_reaches_a_live_runtime_run() {
    let _environment = ENVIRONMENT.lock().unwrap();
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary_profile = TemporaryProfile::new("permission", true);
    let temporary_root = temporary_profile.root.clone();
    let profile = temporary_profile.profile.clone();
    let config = temporary_profile.config.clone();
    let descriptor = stage_pi_stub(&temporary_root);
    let permission_capture = temporary_root.join("permission.jsonl");
    let steer_capture = temporary_root.join("steer.json");
    std::env::set_var("PI_RESUME_STUB_PERMISSION_CAPTURE", &permission_capture);
    std::env::set_var("PI_RESUME_STUB_STEER_CAPTURE", &steer_capture);

    let run_id = "018f0000-0000-7000-8000-000000000113";
    let storage = open_profile_storage(&profile).unwrap();
    let runtime = Arc::new(Mutex::new(None));
    let runtime_activity = RuntimeActivityRegistry::new();
    let active = Arc::new(Mutex::new(None));
    let boundaries = RuntimeAttachBoundaries::new(
        Arc::clone(&storage),
        Arc::clone(&active),
        profile.clone(),
        config.clone(),
        Arc::clone(&runtime),
        Arc::new(ApplicationMemoryRuntime::new(
            config.clone(),
            profile.join("memory"),
        )),
        runtime_activity.clone(),
        RuntimeHost::default(),
        SignedWorkspaceApproval::default(),
        Arc::new(SessionThread::default()),
        open_companion_registry(&profile).unwrap(),
    );
    let (subscriber, events) = mpsc::channel();
    let committed_seq = std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            run_prompt(
                &RuntimeHost::default(),
                &profile,
                Arc::clone(&storage),
                Arc::clone(&runtime),
                &runtime_activity,
                &config,
                run_id.into(),
                "initial prompt".into(),
                None,
                &muniment_core::session_thread::SessionThread::default(),
                false,
                "token".into(),
                Some("owner".into()),
                Vec::new(),
                fixture_grant(),
                Arc::clone(&active),
                RuntimeChatEventTarget::Subscriber(Some(subscriber)),
                Some(descriptor),
            )
        });
        assert_eq!(
            events.recv_timeout(Duration::from_secs(5)).unwrap().phase,
            "thinking"
        );
        boundaries
            .queue_attach_message(
                "workspace-a",
                run_id,
                muniment_core::active_run::ChatDelivery::Steer,
                "redirect here",
            )
            .unwrap();
        let gate_id = loop {
            let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
            if let Some(permission) = event.pending_permission {
                break permission.gate_id;
            }
        };
        let committed_seq = boundaries
            .queue_attach_permission_answer(
                "workspace-a",
                run_id,
                &gate_id,
                ChatPermissionAnswer::Confirm(true),
            )
            .unwrap()
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        run.join().unwrap().unwrap();
        committed_seq
    });

    let captured = fs::read_to_string(permission_capture).unwrap();
    assert!(captured.contains(r#""type":"extension_ui_response""#));
    assert!(captured.contains(r#""id":"permission-1""#));
    assert!(captured.contains(r#""confirmed":true"#));
    let captured = fs::read_to_string(steer_capture).unwrap();
    assert!(captured.contains(r#""type":"steer""#));
    // The queued text arrives behind the line that says when it was sent.
    assert!(captured.contains(r#""message":"[sent 20"#), "{captured}");
    assert!(captured.contains(r#"\nredirect here""#), "{captured}");

    drop(storage);
    let storage = open_profile_storage(&profile).unwrap();
    let journal_events = storage.lock().unwrap().journal.events(run_id).unwrap();
    let event_types: Vec<_> = journal_events
        .iter()
        .map(|event| event.event_type.as_str())
        .collect();
    let requested = event_types
        .iter()
        .position(|event| *event == "permission.requested")
        .unwrap();
    let resolved = event_types
        .iter()
        .position(|event| *event == "permission.resolved")
        .unwrap();
    let terminal = event_types
        .iter()
        .position(|event| matches!(*event, "run.completed" | "run.failed" | "run.cancelled"))
        .unwrap();
    assert!(requested < resolved && resolved < terminal);
    assert_eq!(journal_events[resolved].run_seq, committed_seq);

    drop(journal_events);
    drop(storage);
    std::env::remove_var("PI_RESUME_STUB_PERMISSION_CAPTURE");
    std::env::remove_var("PI_RESUME_STUB_STEER_CAPTURE");
    std::env::remove_var("MUNIMENT_PI_ROOT");
}
