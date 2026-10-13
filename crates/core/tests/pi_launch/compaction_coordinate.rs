use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use super::ChatGrant;
use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::cas::LocalCas;
use muniment_core::chat_coordinate::{coordinate, coordinate_compaction};
use muniment_core::engine::CompactionOutcome;
use muniment_core::journal::{EventPayload, RunJournal};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatStorage};
use muniment_core::run_preparation::{
    prepare_new_run_with_session_thread, prepare_opened_run_with_prompt_storage, SessionThreadStart,
};
use muniment_core::session_thread::SessionThread;
use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_ARTIFACT};

const ARCHIVE: &[u8] = b"muniment-sidecar-test-stub\n";
const ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    byte_size: ARCHIVE.len() as u64,
    sha256: "758b0db8f6304639edfca2b779e886f3006afeb006417e49dd6bce53ff2a65ab",
    ..PI_ARTIFACT
};

struct Boundary(PathBuf);
impl ChatEventSink for Boundary {
    fn provenance(&self) -> (&str, &str) {
        ("test", "1")
    }
    fn deliver(&self, _: ChatEvent) -> Result<(), ()> {
        Ok(())
    }
}
impl PiLaunchBoundaries for Boundary {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
        Ok(self.0.join("sessions"))
    }
    fn memory_agent_extension_path(&self) -> Option<PathBuf> {
        None
    }
    fn pi_artifact(&self) -> PiArtifactDescriptor {
        ARTIFACT
    }
    fn prepare_pi_settings(&self, _: PiArtifactDescriptor, _: &Path) -> Result<(), PiLaunchError> {
        Ok(())
    }
}

fn memory(root: &Path) -> Arc<ApplicationMemoryRuntime> {
    Arc::new(ApplicationMemoryRuntime::new(
        root.join("memory-config"),
        root.join("memory-cache"),
    ))
}

#[test]
fn a_manual_compaction_runs_in_its_thread_and_the_usage_read_answers_its_estimate() {
    let _environment = super::ENVIRONMENT.lock().unwrap();
    let root = std::env::temp_dir().join(format!(
        "muniment-compaction-coordinate-{}",
        uuid::Uuid::new_v4()
    ));
    let revision = root.join("revisions").join(ARTIFACT.version);
    let executable = revision.join(ARTIFACT.executable);
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
    std::fs::create_dir_all(root.join("sessions")).unwrap();
    std::fs::create_dir_all(root.join("state").join("agent")).unwrap();
    std::fs::write(
        root.join("state").join("agent").join("settings.json"),
        r#"{"compaction":{"enabled":true,"reserveTokens":16384}}"#,
    )
    .unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_sidecar-test-stub"), executable).unwrap();
    std::fs::write(revision.join(ARTIFACT.archive), ARCHIVE).unwrap();
    std::fs::write(
        root.join("current"),
        format!("muniment-pi-pointer-v1\n{}\n", ARTIFACT.version),
    )
    .unwrap();
    std::env::set_var("MUNIMENT_PI_ROOT", &root);
    std::env::set_var("MUNIMENT_STATE_DIR", root.join("state"));
    let storage = Arc::new(Mutex::new(ChatStorage {
        journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
        cas: LocalCas::open(&root.join("cas")).unwrap(),
    }));
    let runtime = Arc::new(Mutex::new(None));
    let active = Mutex::new(None);

    // A thread with no saved conversation has no usage and nothing to compact.
    let first = uuid::Uuid::now_v7().to_string();
    let prepared = prepare_new_run_with_session_thread(
        &storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        &first,
        "local",
        Some("owner"),
        Vec::new(),
        None,
        "test",
        "1",
        || Ok(()),
    )
    .unwrap();
    let thread = storage
        .lock()
        .unwrap()
        .journal
        .run_thread_id(&first)
        .unwrap()
        .unwrap();
    assert_eq!(
        muniment_core::pi_execution::thread_context_usage(
            &Boundary(root.clone()),
            &storage,
            &runtime,
            &active,
            &thread,
            Some("owner"),
            || Ok(ChatGrant::local()),
        )
        .unwrap(),
        None
    );
    coordinate(
        Boundary(root.clone()),
        Arc::clone(&storage),
        Arc::clone(&runtime),
        RuntimeActivityRegistry::new(),
        memory(&root),
        first.clone(),
        "Reply briefly.".into(),
        String::new(),
        Some("owner".into()),
        ChatGrant::local(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(VecDeque::new())),
        None,
        None,
        Some(prepared),
    );
    let events = storage.lock().unwrap().journal.events(&first).unwrap();
    assert_eq!(events.last().unwrap().event_type, "run.completed");

    // The process the reply left answers the usage read.
    let usage = muniment_core::pi_execution::thread_context_usage(
        &Boundary(root.clone()),
        &storage,
        &runtime,
        &active,
        &thread,
        Some("owner"),
        || panic!("the reply's process holds the conversation"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(usage.tokens, Some(60000));
    assert_eq!(usage.context_window, Some(200000));
    assert!(!usage.estimated);
    assert!(usage.window_known);
    assert_eq!(usage.provider.as_deref(), Some("stub"));
    assert_eq!(usage.model.as_deref(), Some("stub-model"));
    assert!(usage.auto_compact);
    assert_eq!(usage.compact_at, Some(200000 - 16384));

    let compaction = uuid::Uuid::now_v7().to_string();
    let prepared = prepare_opened_run_with_prompt_storage(
        &storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        &compaction,
        "local",
        Some("owner"),
        Vec::new(),
        None,
        Some(&thread),
        "test",
        "1",
        || Ok(None),
    )
    .unwrap();
    let requests = root.join("requests.jsonl");
    std::env::set_var("PI_RESUME_STUB_REQUESTS", &requests);
    let (outcome, received) = std::sync::mpsc::channel();
    coordinate_compaction(
        Boundary(root.clone()),
        Arc::clone(&storage),
        Arc::clone(&runtime),
        RuntimeActivityRegistry::new(),
        memory(&root),
        compaction.clone(),
        Some("Keep the decisions.".into()),
        String::new(),
        Some("owner".into()),
        ChatGrant::local(),
        Arc::new(AtomicBool::new(false)),
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(VecDeque::new())),
        Some(prepared),
        outcome,
    );
    std::env::remove_var("PI_RESUME_STUB_REQUESTS");
    assert_eq!(
        received.recv().unwrap(),
        Ok(CompactionOutcome {
            tokens_before: 152400,
            estimated_tokens_after: Some(31900),
        })
    );
    let request: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&requests).unwrap().trim()).unwrap();
    assert_eq!(request["type"], "compact");
    assert_eq!(request["customInstructions"], "Keep the decisions.");
    let events = storage.lock().unwrap().journal.events(&compaction).unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        [
            "run.started",
            "runtime.pi_session.bound",
            "tool.effect.started",
            "tool.effect.completed",
            "run.completed"
        ]
    );
    let payload = |index: usize| match &events[index].payload {
        EventPayload::Inline { payload_json } => payload_json.clone(),
        _ => panic!("inline payload"),
    };
    assert_eq!(payload(2)["display_name"], "compact_context");
    assert_eq!(payload(2)["input"], r#"{"reason":"manual"}"#);
    let output = payload(3)["output"].as_str().unwrap().to_owned();
    assert!(output.contains("Context before compaction: 152400 tokens.\nContext after compaction: about 31900 tokens.\n"));

    // Pi counts no tokens until the next reply, so the read answers the estimate.
    let usage = muniment_core::pi_execution::thread_context_usage(
        &Boundary(root.clone()),
        &storage,
        &runtime,
        &active,
        &thread,
        Some("owner"),
        || panic!("the compaction's process holds the conversation"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(usage.tokens, Some(31900));
    assert!(usage.estimated);

    if let Some(mut runtime) = runtime.lock().unwrap().take() {
        runtime.supervisor.shutdown().unwrap();
    };
    std::env::remove_var("MUNIMENT_PI_ROOT");
    std::env::remove_var("MUNIMENT_STATE_DIR");
    drop(storage);
    std::fs::remove_dir_all(root).unwrap();
}
