use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::ChatGrant;
use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::cas::LocalCas;
use muniment_core::chat_coordinate::coordinate;
use muniment_core::journal::RunJournal;
use muniment_core::memory_files::{self, Trust};
use muniment_core::memory_index::ModelMemoryCapability;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatStorage, SharedStorage};
use muniment_core::run_preparation::{prepare_new_run_with_session_thread, SessionThreadStart};
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

const PROMPT: &str = "I am a pediatric nurse and I work night shifts at the clinic.";

/// Runs one reply to its end through the coordinator, as the runtime does,
/// and answers the run id, its thread and the last journal event.
fn reply(
    root: &Path,
    storage: &SharedStorage,
    runtime: &Arc<Mutex<Option<muniment_core::pi_execution::PiRuntime>>>,
    memory: &Arc<ApplicationMemoryRuntime>,
) -> (String, String, String) {
    let run = uuid::Uuid::now_v7().to_string();
    let prepared = prepare_new_run_with_session_thread(
        storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        &run,
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
        .run_thread_id(&run)
        .unwrap()
        .unwrap();
    memory
        .open_session(
            &run,
            &thread,
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: 8192,
            },
        )
        .unwrap();
    coordinate(
        Boundary(root.to_owned()),
        Arc::clone(storage),
        Arc::clone(runtime),
        RuntimeActivityRegistry::new(),
        Arc::clone(memory),
        run.clone(),
        PROMPT.into(),
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
    memory.close_session(&run);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !memory.extraction_idle() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(memory.extraction_idle());
    let last = storage
        .lock()
        .unwrap()
        .journal
        .events(&run)
        .unwrap()
        .last()
        .unwrap()
        .event_type
        .clone();
    (run, thread, last)
}

#[test]
fn only_a_completed_run_without_a_saved_fact_learns_after_it_ends() {
    let _environment = super::ENVIRONMENT.lock().unwrap();
    let root = std::env::temp_dir().join(format!(
        "muniment-memory-extract-coordinate-{}",
        uuid::Uuid::new_v4()
    ));
    let revision = root.join("revisions").join(ARTIFACT.version);
    let executable = revision.join(ARTIFACT.executable);
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
    std::fs::create_dir_all(root.join("sessions")).unwrap();
    std::fs::create_dir_all(root.join("state").join("agent")).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_sidecar-test-stub"), executable).unwrap();
    std::fs::write(revision.join(ARTIFACT.archive), ARCHIVE).unwrap();
    std::fs::write(
        root.join("current"),
        format!("muniment-pi-pointer-v1\n{}\n", ARTIFACT.version),
    )
    .unwrap();
    std::env::set_var("MUNIMENT_PI_ROOT", &root);
    std::env::set_var("MUNIMENT_STATE_DIR", root.join("state"));
    let config = root.join("config");
    let home = root.join("home");
    muniment_core::home::confirm_home(&config, &home).unwrap();

    let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&prompts);
    let memory = Arc::new(
        ApplicationMemoryRuntime::new(config.clone(), root.join("memory-cache"))
            .with_extraction_model(Arc::new(move |_, user| {
                seen.lock().unwrap().push(user.to_owned());
                Ok(serde_json::json!({"actions": [
                    {"op": "add", "title": "Work", "content": "Works night shifts as a pediatric nurse."}
                ]})
                .to_string())
            })),
    );
    let storage = Arc::new(Mutex::new(ChatStorage {
        journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
        cas: LocalCas::open(&root.join("cas")).unwrap(),
    }));
    let runtime = Arc::new(Mutex::new(None));

    // A failed reply and a cancelled reply learn nothing.
    for (reason, terminal) in [("error", "run.failed"), ("aborted", "run.cancelled")] {
        std::env::set_var("PI_RESUME_STUB_STOP_REASON", reason);
        let (_, _, last) = reply(&root, &storage, &runtime, &memory);
        std::env::remove_var("PI_RESUME_STUB_STOP_REASON");
        assert_eq!(last, terminal);
        assert!(memory_files::facts_in(&home).unwrap().is_empty());
    }
    assert!(prompts.lock().unwrap().is_empty());

    // A reply whose model saved a fact through memory-save is not read again.
    std::env::set_var(
        "PI_RESUME_STUB_MEMORY_SAVE",
        r#"{"title":"Shift","content":"Works nights."}"#,
    );
    let (_, _, last) = reply(&root, &storage, &runtime, &memory);
    std::env::remove_var("PI_RESUME_STUB_MEMORY_SAVE");
    assert_eq!(last, "run.completed");
    assert_eq!(memory_files::facts_in(&home).unwrap().len(), 1);
    assert!(prompts.lock().unwrap().is_empty());

    // A completed reply writes what the model proposed as a conversation fact.
    let (run, thread, last) = reply(&root, &storage, &runtime, &memory);
    assert_eq!(last, "run.completed");
    let sent = prompts.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].contains(PROMPT));
    assert!(!sent[0].contains("resumed"), "assistant text stays out");
    let facts = memory_files::facts_in(&home).unwrap();
    let learned = facts.iter().find(|fact| fact.title == "Work").unwrap();
    assert_eq!(learned.trust, Trust::Conversation);
    assert_eq!(
        learned.source,
        format!("extracted thread:{thread} run:{run}")
    );
    assert!(home
        .join(format!("memory/facts/{}.md", learned.id))
        .is_file());

    if let Some(mut runtime) = runtime.lock().unwrap().take() {
        runtime.supervisor.shutdown().unwrap();
    };
    std::env::remove_var("MUNIMENT_PI_ROOT");
    std::env::remove_var("MUNIMENT_STATE_DIR");
    drop(storage);
    std::fs::remove_dir_all(root).unwrap();
}
