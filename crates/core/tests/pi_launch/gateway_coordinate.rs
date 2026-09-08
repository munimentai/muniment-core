use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use super::{ChatGrant, FetchGrantError};
use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::cas::LocalCas;
use muniment_core::chat_coordinate::coordinate;
use muniment_core::journal::RunJournal;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatStorage};
use muniment_core::run_preparation::{prepare_new_run_with_session_thread, SessionThreadStart};
use muniment_core::session_thread::SessionThread;
use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_ARTIFACT};
use serde_json::json;

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
    fn inspect_chat_session(&self, token: &str) -> Result<String, FetchGrantError> {
        Ok(token.into())
    }
    fn renew_chat_grant(&self, _: &str) -> Result<ChatGrant, FetchGrantError> {
        Err(FetchGrantError::Unavailable)
    }
}

#[test]
fn terminal_gateway_denials_fail_the_run_without_a_receipt_or_secret_journal_entry() {
    let _environment = super::ENVIRONMENT.lock().unwrap();
    let root = std::env::temp_dir().join(format!(
        "muniment-gateway-coordinate-{}",
        uuid::Uuid::new_v4()
    ));
    let revision = root.join("revisions").join(ARTIFACT.version);
    let executable = revision.join(ARTIFACT.executable);
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
    std::fs::create_dir_all(root.join("sessions")).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_sidecar-test-stub"), executable).unwrap();
    std::fs::write(revision.join(ARTIFACT.archive), ARCHIVE).unwrap();
    std::fs::write(
        root.join("current"),
        format!("muniment-pi-pointer-v1\n{}\n", ARTIFACT.version),
    )
    .unwrap();
    let storage = Arc::new(Mutex::new(ChatStorage {
        journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
        cas: LocalCas::open(&root.join("cas")).unwrap(),
    }));
    let receipt_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    receipt_listener.set_nonblocking(true).unwrap();
    std::env::set_var("MUNIMENT_PI_ROOT", &root);
    for (status, code) in [
        (429, "budget_exhausted"),
        (403, "model_not_allowed"),
        (401, "grant_expired"),
    ] {
        let run_id = uuid::Uuid::now_v7().to_string();
        let prepared = prepare_new_run_with_session_thread(
            &storage,
            SessionThreadStart {
                tracker: &SessionThread::default(),
                continue_existing: false,
            },
            &run_id,
            "local",
            Some("owner"),
            Vec::new(),
            None,
            "test",
            "1",
            || Ok(()),
        )
        .unwrap();
        std::env::set_var("PI_RESUME_STUB_GRANT_DENIAL", json!({
            "status": status, "body": {"protocol": "muniment.desktop-access/1", "error": {"code": code, "message": "The request failed."}}
        }).to_string());
        let runtime = Arc::new(Mutex::new(None));
        coordinate(
            Boundary(root.clone()),
            Arc::clone(&storage),
            Arc::clone(&runtime),
            RuntimeActivityRegistry::new(),
            Arc::new(ApplicationMemoryRuntime::new(
                root.join("memory-config"),
                root.join("memory-cache"),
            )),
            run_id.clone(),
            "Reply briefly.".into(),
            "native-secret".into(),
            Some("owner".into()),
            ChatGrant {
                gateway_url: "https://gateway.example/v1".into(),
                virtual_key: "ephemeral-secret".into(),
                model: Some("allowed-model".into()),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
                receipt_url: format!("http://{}/receipt", receipt_listener.local_addr().unwrap()),
                ..ChatGrant::local()
            },
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(VecDeque::new())),
            None,
            None,
            Some(prepared),
        );
        let events = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert!(
            events.iter().any(|event| event.event_type == "run.failed"),
            "{code}: {events:?}"
        );
        assert!(!events
            .iter()
            .any(|event| event.event_type == "run.completed"));
        let serialized = serde_json::to_string(&events).unwrap();
        for secret in ["native-secret", "ephemeral-secret", "muniment:chat-grant"] {
            assert!(!serialized.contains(secret));
        }
        assert!(receipt_listener.accept().is_err());
        if let Some(mut runtime) = runtime.lock().unwrap().take() {
            runtime.supervisor.shutdown().unwrap();
        };
    }
    std::env::remove_var("MUNIMENT_PI_ROOT");
    std::env::remove_var("PI_RESUME_STUB_GRANT_DENIAL");
    drop(storage);
    std::fs::remove_dir_all(root).unwrap();
}
