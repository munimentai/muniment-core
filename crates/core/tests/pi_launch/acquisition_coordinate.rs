use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::ChatGrant;
use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::chat_coordinate::coordinate;
use muniment_core::chat_profile::ChatProfile;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatStorage};
use muniment_core::run_preparation::{prepare_new_run_with_session_thread, SessionThreadStart};
use muniment_core::session_thread::SessionThread;
use muniment_core::sidecar::pi_install::{
    FsPiLifecycleBoundary, PiArtifactDescriptor, PiLifecycleBoundary, PI_ARTIFACT,
};

const ARCHIVE: &[u8] = b"muniment-sidecar-test-stub\n";
const ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
    byte_size: ARCHIVE.len() as u64,
    sha256: "758b0db8f6304639edfca2b779e886f3006afeb006417e49dd6bce53ff2a65ab",
    ..PI_ARTIFACT
};

#[derive(Clone)]
struct Boundary {
    profile: ChatProfile,
    events: Arc<Mutex<Vec<ChatEvent>>>,
    acquisitions: Arc<AtomicUsize>,
    outcome: &'static str,
}

impl ChatEventSink for Boundary {
    fn provenance(&self) -> (&str, &str) {
        ("test", "1")
    }
    fn deliver(&self, event: ChatEvent) -> Result<(), ()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}

impl PiLaunchBoundaries for Boundary {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
        Ok(self.profile.pi_session_root())
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
    fn acquire_pi(&self, root: &Path, cancelled: &AtomicBool) -> Result<PathBuf, PiLaunchError> {
        assert_eq!(root, self.profile.pi_install_root());
        assert_eq!(
            self.events.lock().unwrap().last().unwrap().phase,
            "acquiring-pi"
        );
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        if self.outcome == "cancelled" {
            cancelled.store(true, Ordering::SeqCst);
        }
        if self.outcome == "publication-failed" {
            let error = FsPiLifecycleBoundary
                .sync_file(&root.join("missing-archive"))
                .unwrap_err();
            return Err(PiLaunchError::Acquisition(
                muniment_core::model_install::ModelInstallError::Publication(error),
            ));
        }
        if self.outcome != "complete" {
            return Err(PiLaunchError::Acquisition(
                muniment_core::model_install::ModelInstallError::Acquisition(
                    muniment_core::sidecar::pi_install::PiInstallError::Download,
                ),
            ));
        }
        let revision = root.join("revisions").join(ARTIFACT.version);
        let executable = revision.join(ARTIFACT.executable);
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::copy(env!("CARGO_BIN_EXE_sidecar-test-stub"), &executable).unwrap();
        std::fs::write(revision.join(ARTIFACT.archive), ARCHIVE).unwrap();
        std::fs::write(
            root.join("current"),
            format!("muniment-pi-pointer-v1\n{}\n", ARTIFACT.version),
        )
        .unwrap();
        Ok(executable)
    }
}

#[test]
fn coordinate_acquires_from_the_profile_once_without_an_environment_root() {
    let _environment = super::ENVIRONMENT.lock().unwrap();
    if std::env::var_os("MUNIMENT_COORDINATE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "acquisition_coordinate::coordinate_acquires_from_the_profile_once_without_an_environment_root",
                "--nocapture",
            ])
            .env("MUNIMENT_COORDINATE_CHILD", "1")
            .env_remove("MUNIMENT_PI_ROOT")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("pi_acquire completed"), "{stderr}");
        assert!(stderr.contains("pi_spawn started"), "{stderr}");
        assert!(stderr.contains("first_event"), "{stderr}");
        let publication = stderr
            .lines()
            .find(|line| {
                line.contains("pi_acquire failed") && line.contains("Publication(PersistenceIo")
            })
            .unwrap_or_else(|| panic!("Missing publication diagnostic: {stderr}"));
        assert!(publication.contains("run_id="), "{publication}");
        assert!(
            publication.contains("step: \"open_sync_file\""),
            "{publication}"
        );
        assert!(publication.contains("kind: NotFound"), "{publication}");
        assert!(publication.contains("os_error: Some("), "{publication}");
        return;
    }
    assert!(std::env::var_os("MUNIMENT_PI_ROOT").is_none());
    for outcome in ["complete", "failed", "publication-failed", "cancelled"] {
        let directory =
            std::env::temp_dir().join(format!("muniment-pi-coordinate-{}", uuid::Uuid::new_v4()));
        let profile = ChatProfile::new(&directory);
        let (journal, cas) = profile.open_storage().unwrap();
        let storage = Arc::new(Mutex::new(ChatStorage { journal, cas }));
        let boundary = Boundary {
            profile,
            events: Arc::new(Mutex::new(Vec::new())),
            acquisitions: Arc::new(AtomicUsize::new(0)),
            outcome,
        };
        assert_eq!(boundary.pi_install_root().unwrap(), directory.join("pi"));
        let runs = if outcome == "complete" { 2 } else { 1 };
        for index in 0..runs {
            boundary.events.lock().unwrap().clear();
            let run_id = uuid::Uuid::now_v7().to_string();
            let prepared = prepare_new_run_with_session_thread(
                &storage,
                SessionThreadStart {
                    tracker: &SessionThread::default(),
                    continue_existing: false,
                },
                &run_id,
                "local",
                None,
                Vec::new(),
                None,
                "test",
                "1",
                || Ok(()),
            )
            .unwrap();
            let runtime = Arc::new(Mutex::new(None));
            let started = std::time::Instant::now();
            coordinate(
                boundary.clone(),
                Arc::clone(&storage),
                Arc::clone(&runtime),
                RuntimeActivityRegistry::new(),
                Arc::new(ApplicationMemoryRuntime::new(
                    directory.join("memory-config"),
                    directory.join("memory-cache"),
                )),
                run_id.clone(),
                "Reply briefly.".into(),
                String::new(),
                None,
                ChatGrant::local(),
                Arc::new(AtomicBool::new(false)),
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(VecDeque::new())),
                None,
                None,
                Some(prepared),
            );
            let events = boundary.events.lock().unwrap();
            let phase = if outcome == "publication-failed" {
                "failed"
            } else {
                outcome
            };
            assert_eq!(events.last().unwrap().phase, phase);
            if phase == "failed" {
                assert!(started.elapsed() < std::time::Duration::from_secs(30));
                assert!(events
                    .last()
                    .unwrap()
                    .failure_reason
                    .as_deref()
                    .unwrap()
                    .starts_with("Reply setup failed."));
                assert!(events.last().unwrap().text.is_empty());
            }
            assert_eq!(
                events.iter().any(|event| event.phase == "acquiring-pi"),
                index == 0
            );
            assert_eq!(boundary.acquisitions.load(Ordering::SeqCst), 1);
            if outcome == "complete" {
                assert!(events
                    .iter()
                    .any(|event| event.phase == "streaming" && !event.text.is_empty()));
            } else {
                assert!(runtime.lock().unwrap().is_none());
            }
            let history = storage.lock().unwrap().journal.events(&run_id).unwrap();
            if phase == "failed" {
                let terminal = history.last().unwrap();
                assert_eq!(terminal.event_type, "run.failed");
                let muniment_core::journal::EventPayload::Inline { payload_json } =
                    &terminal.payload
                else {
                    panic!("Missing failure reason")
                };
                assert_eq!(
                    payload_json["reason"].as_str(),
                    events.last().unwrap().failure_reason.as_deref()
                );
            }
            assert_eq!(
                history
                    .iter()
                    .filter(|event| event.event_type == "runtime.pi_acquire.started")
                    .count(),
                usize::from(index == 0)
            );
            if let Some(mut runtime) = runtime.lock().unwrap().take() {
                runtime.supervisor.shutdown().unwrap();
            };
        }
        std::env::set_var("MUNIMENT_PI_ROOT", directory.join("override"));
        assert_eq!(
            boundary.pi_install_root().unwrap(),
            directory.join("override")
        );
        std::env::set_var("MUNIMENT_PI_ROOT", "");
        assert_eq!(boundary.pi_install_root(), Err(PiLaunchError::MissingRoot));
        std::env::remove_var("MUNIMENT_PI_ROOT");
        drop(storage);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
