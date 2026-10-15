use std::fs;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use muniment_core::active_run::ChatDelivery;
use muniment_core::attach::{RuntimeActivityRegistry, SignedWorkspaceApproval};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::run_start::RunAttachBoundaries;
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{
    open_companion_registry, open_profile_storage, run_prompt, RuntimeAttachBoundaries,
    RuntimeChatEventTarget, RuntimeHost,
};

mod common;
use common::{fixture_grant, stage_pi_stub, TemporaryProfile};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

fn queued_message_reaches_a_live_runtime_run(
    test_name: &str,
    run_id: &str,
    delivery: ChatDelivery,
    message: &str,
    command: &str,
) {
    let _environment = ENVIRONMENT.lock().unwrap();
    common::use_test_prompt_store();
    let temporary_profile = TemporaryProfile::new(test_name, true);
    let temporary_root = temporary_profile.root.clone();
    let profile = temporary_profile.profile.clone();
    let config = temporary_profile.config.clone();
    let descriptor = stage_pi_stub(&temporary_root);
    let steer_capture = temporary_root.join("steer.json");
    std::env::set_var("PI_RESUME_STUB_STEER_CAPTURE", &steer_capture);

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
    std::thread::scope(|scope| {
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
            .queue_attach_message("workspace-a", run_id, delivery, message)
            .unwrap();
        let delivered = events
            .iter()
            .take_while(|event| {
                !matches!(event.phase.as_str(), "complete" | "failed" | "cancelled")
            })
            .any(|event| event.text.contains(command));
        assert!(delivered);
        run.join().unwrap().unwrap();
    });

    let captured = fs::read_to_string(steer_capture).unwrap();
    assert!(captured.contains(&format!(r#""type":"{command}""#)));
    // The queued text arrives behind the line that says when it was sent.
    assert!(captured.contains(r#""message":"[sent 20"#), "{captured}");
    assert!(captured.contains(&format!(r#"\n{message}""#)), "{captured}");
    for id in [run_id, "018f0000-0000-7000-8000-000000000999"] {
        assert!(boundaries
            .queue_attach_message("workspace-a", id, ChatDelivery::Steer, "too late")
            .is_err());
    }

    drop(storage);
    let storage = open_profile_storage(&profile).unwrap();
    let journal_events = storage.lock().unwrap().journal.events(run_id).unwrap();
    assert!(matches!(
        journal_events.last().map(|event| event.event_type.as_str()),
        Some("run.completed" | "run.failed" | "run.cancelled")
    ));

    drop(journal_events);
    drop(storage);
    std::env::remove_var("PI_RESUME_STUB_STEER_CAPTURE");
    std::env::remove_var("MUNIMENT_PI_ROOT");
}

#[test]
fn a_queued_steer_reaches_a_live_runtime_run() {
    queued_message_reaches_a_live_runtime_run(
        "steer",
        "018f0000-0000-7000-8000-000000000112",
        ChatDelivery::Steer,
        "redirect here",
        "steer",
    );
}

#[test]
fn a_queued_follow_up_reaches_a_live_runtime_run() {
    queued_message_reaches_a_live_runtime_run(
        "follow-up",
        "018f0000-0000-7000-8000-000000000114",
        ChatDelivery::FollowUp,
        "then do this",
        "follow_up",
    );
}
