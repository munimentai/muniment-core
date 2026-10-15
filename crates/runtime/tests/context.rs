use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use muniment_core::attach::{RuntimeActivityRegistry, SignedWorkspaceApproval};
use muniment_core::engine::{CompactionPhase, CompactionSettings, ThreadContextSnapshot};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::run_start::{ActiveRun, RunAttachBoundaries};
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{
    open_companion_registry, open_profile_storage, run_prompt, RuntimeAttachBoundaries,
    RuntimeChatEventTarget, RuntimeHost,
};

mod common;
use common::{local_grant, stage_pi_stub, TemporaryProfile};

const RUN_ID: &str = "018f0000-0000-7000-8000-000000000301";

fn settled(
    boundaries: &RuntimeAttachBoundaries,
    thread: &str,
    done: impl Fn(&ThreadContextSnapshot) -> bool,
) -> ThreadContextSnapshot {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let snapshot = boundaries.thread_context_usage("local", thread).unwrap();
        if !snapshot.reading && done(&snapshot) {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "{snapshot:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn reason(error: muniment_core::attach::ProtocolError) -> String {
    match error.details() {
        Some(muniment_core::attach::ErrorDetails::RequestReason { reason }) => reason.clone(),
        _ => panic!("{error:?}"),
    }
}

#[test]
fn a_thread_reports_its_context_and_compacts_through_the_runtime() {
    common::use_test_prompt_store();
    let temporary_profile = TemporaryProfile::new("context", true);
    let temporary_root = temporary_profile.root.clone();
    let profile = temporary_profile.profile.clone();
    let config = temporary_profile.config.clone();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join(muniment_core::local_mode::LOCAL_MODE_MARKER),
        [],
    )
    .unwrap();
    std::env::set_var("MUNIMENT_STATE_DIR", &profile);
    let descriptor = stage_pi_stub(&temporary_root);

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
    )
    .with_pi_artifact(descriptor);

    // Settings round trip through the engine adapter.
    let wanted = CompactionSettings {
        enabled: true,
        reserve_tokens: 8192,
        keep_recent_tokens: 12000,
    };
    assert_eq!(boundaries.save_context_settings(wanted).unwrap(), wanted);
    assert_eq!(boundaries.context_settings().unwrap(), wanted);
    assert_eq!(
        reason(
            boundaries
                .save_context_settings(CompactionSettings {
                    reserve_tokens: 1,
                    ..wanted
                })
                .unwrap_err()
        ),
        "Choose token counts between 4,096 and 131,072."
    );

    run_prompt(
        &RuntimeHost::default(),
        &profile,
        Arc::clone(&storage),
        Arc::clone(&runtime),
        &runtime_activity,
        &config,
        RUN_ID.into(),
        "first prompt".into(),
        None,
        &SessionThread::default(),
        false,
        String::new(),
        None,
        Vec::new(),
        local_grant(),
        Arc::clone(&active),
        RuntimeChatEventTarget::Subscriber(None),
        Some(descriptor),
    )
    .unwrap();
    let thread = storage
        .lock()
        .unwrap()
        .journal
        .run_thread_id(RUN_ID)
        .unwrap()
        .unwrap();

    let usage = settled(&boundaries, &thread, |snapshot| snapshot.usage.is_some())
        .usage
        .unwrap();
    assert_eq!(usage.tokens, Some(60000));
    assert_eq!(usage.context_window, Some(200000));
    assert_eq!(usage.compact_at, Some(200000 - 8192));
    assert!(!usage.estimated);

    // A reply in flight in this thread refuses the compaction.
    *active.lock().unwrap() = Some(ActiveRun {
        id: RUN_ID.into(),
        workspace: "local".into(),
        cancelled: Arc::new(AtomicBool::new(false)),
        transport: Arc::new(Mutex::new(None)),
        adapter: Arc::new(Mutex::new(None)),
        permission_answers: Arc::new(Mutex::new(VecDeque::new())),
        _activity: runtime_activity.mark_active_run(),
    });
    assert_eq!(
        reason(
            boundaries
                .compact_thread("local", &thread, None)
                .unwrap_err()
        ),
        "This thread is replying. Compact it after the reply finishes."
    );
    *active.lock().unwrap() = None;

    let empty = boundaries
        .create_thread(
            "local",
            muniment_core::journal::Provenance {
                source: "test".into(),
                source_version: "1".into(),
                actor_id: None,
                device_id: None,
                rpc_request_id: None,
                capability_versions: None,
                extra: [("attach_profile".to_owned(), "profile-a".into())]
                    .into_iter()
                    .collect(),
            },
        )
        .unwrap();
    assert_eq!(
        reason(
            boundaries
                .compact_thread("local", &empty, None)
                .unwrap_err()
        ),
        "This thread has no conversation to compact yet."
    );
    assert_eq!(settled(&boundaries, &empty, |_| true).usage, None);

    let run_id = boundaries
        .compact_thread("local", &thread, Some("Keep the decisions."))
        .unwrap();
    let snapshot = settled(&boundaries, &thread, |snapshot| {
        snapshot
            .compaction
            .as_ref()
            .is_some_and(|compaction| compaction.state != CompactionPhase::Running)
    });
    let compaction = snapshot.compaction.unwrap();
    assert_eq!(compaction.run_id, run_id);
    assert_eq!(compaction.state, CompactionPhase::Completed);
    assert_eq!(compaction.tokens_before, Some(152400));
    assert_eq!(compaction.estimated_tokens_after, Some(31900));
    assert!(!snapshot.compacting);
    let usage = settled(&boundaries, &thread, |snapshot| {
        snapshot.usage.as_ref().is_some_and(|usage| usage.estimated)
    })
    .usage
    .unwrap();
    assert_eq!(usage.tokens, Some(31900));

    let events = storage.lock().unwrap().journal.events(&run_id).unwrap();
    assert_eq!(events.last().unwrap().event_type, "run.completed");
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .journal
            .run_thread_id(&run_id)
            .unwrap()
            .as_deref(),
        Some(thread.as_str())
    );

    if let Some(mut runtime) = runtime.lock().unwrap().take() {
        let _ = runtime.supervisor.shutdown();
    }
    drop(events);
    drop(storage);
    std::env::remove_var("MUNIMENT_PI_ROOT");
    std::env::remove_var("MUNIMENT_STATE_DIR");
}
