use std::fs;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use muniment_core::attach::RuntimeActivityRegistry;
use muniment_runtime_core::{
    cancel_run, open_profile_storage, run_prompt, RuntimeChatEventTarget, RuntimeHost,
};

mod common;
use common::{fixture_grant, stage_pi_stub, TemporaryProfile};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

#[test]
fn cancelling_a_live_run_sends_abort_to_pi() {
    let _environment = ENVIRONMENT.lock().unwrap();
    common::use_test_prompt_store();
    let temporary_profile = TemporaryProfile::new("cancel", true);
    let temporary_root = temporary_profile.root.clone();
    let profile = temporary_profile.profile.clone();
    let config = temporary_profile.config.clone();
    let descriptor = stage_pi_stub(&temporary_root);
    let abort_capture = temporary_root.join("abort.json");
    std::env::set_var("PI_RESUME_STUB_ABORT_CAPTURE", &abort_capture);
    std::env::set_var("PI_RESUME_STUB_MEMORY_QUERY", "hold the run open");

    let run_id = "018f0000-0000-7000-8000-000000000113";
    let storage = open_profile_storage(&profile).unwrap();
    let runtime = Arc::new(Mutex::new(None));
    let runtime_activity = RuntimeActivityRegistry::new();
    let active = Arc::new(Mutex::new(None));
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
        cancel_run(Arc::clone(&active), "workspace-a".into(), run_id.into()).unwrap();
        run.join().unwrap().unwrap();
    });

    let captured = fs::read_to_string(abort_capture).unwrap();
    assert!(captured.contains(r#""type":"abort""#));
    assert_eq!(
        cancel_run(Arc::clone(&active), "workspace-a".into(), run_id.into()),
        Err("That reply is no longer active.".into())
    );
    let journal_events = storage.lock().unwrap().journal.events(run_id).unwrap();
    assert_eq!(journal_events.last().unwrap().event_type, "run.cancelled");

    drop(journal_events);
    drop(storage);
    std::env::remove_var("PI_RESUME_STUB_ABORT_CAPTURE");
    std::env::remove_var("PI_RESUME_STUB_MEMORY_QUERY");
    std::env::remove_var("MUNIMENT_PI_ROOT");
}
