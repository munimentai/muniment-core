use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use muniment_core::chat_grant::{ChatGrant, FetchGrantError};

#[path = "pi_launch/acquisition_coordinate.rs"]
mod acquisition_coordinate;
#[path = "pi_launch/gateway_coordinate.rs"]
mod gateway_coordinate;
use muniment_core::pi_launch::{
    pi_launch_config, pi_launch_config_for_executable, PiLaunchBoundaries, PiLaunchError,
    EXCLUDED_TOOLS, IDENTITY_EXTENSION, IDENTITY_EXTENSION_FILE, SYSTEM_PROMPT,
};
use muniment_core::sidecar::{
    validate_pi_session, PiRpcWiring, SidecarConfig, SidecarStatus, SidecarSupervisor,
};
use uuid::Uuid;

mod stdin_deadline {
    use std::collections::VecDeque;
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use muniment_core::attach::RuntimeActivityRegistry;
    use muniment_core::cas::LocalCas;
    use muniment_core::chat_coordinate::coordinate;
    use muniment_core::chat_grant::ChatGrant;
    use muniment_core::journal::RunJournal;
    use muniment_core::memory_runtime::ApplicationMemoryRuntime;
    use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
    use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatStorage};
    use muniment_core::run_preparation::{prepare_new_run_with_session_thread, SessionThreadStart};
    use muniment_core::session_thread::SessionThread;
    use muniment_core::sidecar::pi_chat::FIRST_EVENT_TIMEOUT;
    use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_ARTIFACT};

    const ARCHIVE: &[u8] = b"muniment-sidecar-test-stub\n";
    const ARTIFACT: PiArtifactDescriptor = PiArtifactDescriptor {
        byte_size: ARCHIVE.len() as u64,
        sha256: "758b0db8f6304639edfca2b779e886f3006afeb006417e49dd6bce53ff2a65ab",
        ..PI_ARTIFACT
    };
    const RUN_ID: &str = "01900000-0000-7000-8000-000000000001";
    const FAILURE: &str = "The reply did not start. Try again.";

    struct Boundary {
        root: PathBuf,
        started: Instant,
    }

    impl ChatEventSink for Boundary {
        fn provenance(&self) -> (&str, &str) {
            ("test", "1")
        }

        fn deliver(&self, event: ChatEvent) -> Result<(), ()> {
            eprintln!("shell-event: {}", serde_json::to_string(&event).unwrap());
            if event.phase == "failed" && event.failure_reason.as_deref() == Some(FAILURE) {
                // Measure delivery here, not when the parent gets CPU time to read stderr.
                // Allow one second for readiness and scheduling, not another timeout.
                let bound = FIRST_EVENT_TIMEOUT + Duration::from_secs(1);
                let elapsed = self.started.elapsed();
                assert!(elapsed <= bound, "Late shell failure: {elapsed:?}");
            }
            Ok(())
        }
    }

    impl PiLaunchBoundaries for Boundary {
        fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
            Ok(self.root.join("sessions"))
        }

        fn memory_agent_extension_path(&self) -> Option<PathBuf> {
            None
        }

        fn pi_artifact(&self) -> PiArtifactDescriptor {
            ARTIFACT
        }

        fn prepare_pi_settings(
            &self,
            _: PiArtifactDescriptor,
            _: &Path,
        ) -> Result<(), PiLaunchError> {
            Ok(())
        }
    }

    #[test]
    fn blocked_stdin_fails_the_shell_and_logs_stderr_within_the_first_event_bound() {
        if let Some(root) = std::env::var_os("MUNIMENT_STDIN_DEADLINE_CHILD") {
            run_coordinate(PathBuf::from(root));
            return;
        }
        let root =
            std::env::temp_dir().join(format!("muniment-stdin-deadline-{}", uuid::Uuid::new_v4()));
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
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "stdin_deadline::blocked_stdin_fails_the_shell_and_logs_stderr_within_the_first_event_bound",
                "--nocapture",
            ])
            .env("MUNIMENT_STDIN_DEADLINE_CHILD", &root)
            .env("MUNIMENT_PI_ROOT", &root)
            .env("PI_STUB_BLOCK_STDIN", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let lines: Vec<String> = BufReader::new(child.stderr.take().unwrap())
            .lines()
            .collect::<Result<_, _>>()
            .unwrap();
        let status = child.wait().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        assert!(status.success(), "{lines:?}");
        let failure_index = lines
            .iter()
            .position(|line| {
                line.strip_prefix("shell-event: ")
                    .and_then(|event| serde_json::from_str::<serde_json::Value>(event).ok())
                    .is_some_and(|event| {
                        event["phase"] == "failed"
                            && event["failureReason"] == FAILURE
                            && event["text"] == ""
                    })
            })
            .unwrap_or_else(|| panic!("Missing shell failure: {lines:?}"));
        // The child checks the delivery bound. Both diagnostics must precede that delivery.
        for expected in [
            format!("muniment-runtime: run_id={RUN_ID} first_event absent"),
            format!("muniment-runtime: run_id={RUN_ID} pi_stderr_tail="),
        ] {
            let index = lines
                .iter()
                .position(|line| line.starts_with(&expected))
                .unwrap_or_else(|| panic!("Missing {expected}: {lines:?}"));
            assert!(
                index < failure_index,
                "Diagnostic followed shell failure: {lines:?}"
            );
        }
        assert!(lines.iter().any(|line| {
            line.contains("pi_stderr_tail=") && line.contains("Pi stub stopped reading stdin.")
        }));
        assert!(lines
            .iter()
            .any(|line| line.contains("timed out writing Pi RPC stdin")));
        assert!(lines
            .iter()
            .any(|line| line.contains("pi_spawn") && line.contains("Healthy")));
        assert!(lines.iter().any(|line| {
            line.contains("provider_request outcome=unknown_prompt_not_acknowledged")
        }));
    }

    fn run_coordinate(root: PathBuf) {
        let storage = Arc::new(Mutex::new(ChatStorage {
            journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
            cas: LocalCas::open(&root.join("cas")).unwrap(),
        }));
        let prepared = prepare_new_run_with_session_thread(
            &storage,
            SessionThreadStart {
                tracker: &SessionThread::default(),
                continue_existing: false,
            },
            RUN_ID,
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
        coordinate(
            Boundary {
                root: root.clone(),
                started: Instant::now(),
            },
            Arc::clone(&storage),
            Arc::clone(&runtime),
            RuntimeActivityRegistry::new(),
            Arc::new(ApplicationMemoryRuntime::new(
                root.join("memory-config"),
                root.join("memory-cache"),
            )),
            RUN_ID.into(),
            "x".repeat(128 * 1024),
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
        let events = storage.lock().unwrap().journal.events(RUN_ID).unwrap();
        let terminal = events.last().unwrap();
        assert_eq!(terminal.event_type, "run.failed");
        assert!(serde_json::to_string(terminal).unwrap().contains(FAILURE));
        assert_eq!(
            runtime
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .supervisor
                .status(),
            muniment_core::sidecar::SidecarStatus::Stopped
        );
    }
}

static ENVIRONMENT: Mutex<()> = Mutex::new(());

struct Boundaries {
    session_root: Result<PathBuf, PiLaunchError>,
    extension: Option<PathBuf>,
}

impl PiLaunchBoundaries for Boundaries {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
        self.session_root.clone()
    }

    fn memory_agent_extension_path(&self) -> Option<PathBuf> {
        self.extension.clone()
    }

    fn prepare_pi_settings(
        &self,
        _artifact: muniment_core::sidecar::pi_install::PiArtifactDescriptor,
        _executable: &std::path::Path,
    ) -> Result<(), PiLaunchError> {
        Ok(())
    }
}

fn grant() -> ChatGrant {
    ChatGrant {
        workspace: "/work".into(),
        gateway_url: "https://gateway.example.com".into(),
        virtual_key: "secret-key".into(),
        model: Some("model".into()),
        expires_at: None,
        native_access_token: None,
        minimum_cacheable_prefix_characters: 8_192,
        receipt_url: "https://receipts.example.com".into(),
    }
}

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("muniment-pi-launch-{}", Uuid::new_v4()));
    fs::create_dir(&path).unwrap();
    path
}

struct TrackBoundaries {
    root: PathBuf,
    artifact: muniment_core::sidecar::pi_install::PiArtifactDescriptor,
}

impl PiLaunchBoundaries for TrackBoundaries {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
        Ok(self.root.clone())
    }

    fn memory_agent_extension_path(&self) -> Option<PathBuf> {
        None
    }

    fn pi_artifact(&self) -> muniment_core::sidecar::pi_install::PiArtifactDescriptor {
        self.artifact
    }

    fn prepare_pi_settings(
        &self,
        artifact: muniment_core::sidecar::pi_install::PiArtifactDescriptor,
        _executable: &std::path::Path,
    ) -> Result<(), PiLaunchError> {
        muniment_core::pi_settings::store_pi_settings(&self.root.join("settings.json"), artifact)
            .map_err(|error| PiLaunchError::rejected("settings_write", error))
    }
}

#[test]
fn every_launch_renders_the_selected_track_before_spawn() {
    use muniment_core::sidecar::pi_install::{PI_ARTIFACT, PI_CANDIDATE_ARTIFACT};
    for artifact in [PI_ARTIFACT, PI_CANDIDATE_ARTIFACT] {
        for grant in [ChatGrant::local(), grant()] {
            let root = temporary_directory();
            fs::write(root.join("session.jsonl"), "").unwrap();
            let (locator, _) = validate_pi_session(&root, "session.jsonl").unwrap();
            for reopen in [None, Some(&locator)] {
                let path = root.join("settings.json");
                fs::write(&path, br#"{"defaultProvider":"ollama","foreign":true}"#).unwrap();
                let boundaries = TrackBoundaries {
                    root: root.clone(),
                    artifact,
                };
                let config =
                    pi_launch_config_for_executable(&boundaries, "pi".into(), &grant, reopen)
                        .unwrap();
                let settings: serde_json::Value =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                assert_eq!(settings["defaultProvider"], "ollama");
                assert_eq!(settings["foreign"], true);
                if artifact == PI_CANDIDATE_ARTIFACT {
                    assert_eq!(settings["packages"].as_array().unwrap().len(), 5);
                    assert_eq!(settings["defaultTools"].as_array().unwrap().len(), 8);
                    assert_eq!(
                        config.startup_timeout,
                        Duration::from_secs(if grant.is_local() { 120 } else { 30 })
                    );
                } else {
                    assert!(settings.get("packages").is_none());
                    assert!(settings.get("defaultTools").is_none());
                    assert_eq!(config.startup_timeout, Duration::from_secs(30));
                }
                assert_eq!(
                    config
                        .args
                        .windows(2)
                        .any(|args| args == ["--api-key", "muniment-runtime-boundary"]),
                    !grant.is_local()
                );
                assert!(!config.args.iter().any(|arg| arg == "--tools"));
                assert!(config.env_remove.iter().any(|name| name == "BUN_BE_BUN"));
                assert!(!config.env.contains_key("BUN_BE_BUN"));
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}

#[test]
fn rejects_a_candidate_launch_when_settings_cannot_be_saved() {
    let root = temporary_directory();
    fs::write(root.join("settings.json"), "null").unwrap();
    let boundaries = TrackBoundaries {
        root: root.clone(),
        artifact: muniment_core::sidecar::pi_install::PI_CANDIDATE_ARTIFACT,
    };
    for grant in [ChatGrant::local(), grant()] {
        let error =
            pi_launch_config_for_executable(&boundaries, "pi".into(), &grant, None).unwrap_err();
        assert!(
            matches!(error, PiLaunchError::RejectedConfig { step: "settings_write", ref cause }
            if cause.contains("invalid type: null"))
        );
    }
    assert_eq!(
        fs::read_to_string(root.join("settings.json")).unwrap(),
        "null"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn pinned_pi_cloud_wire_contract() {
    let Ok(executable) = std::env::var("MUNIMENT_PI_WIRE_EXECUTABLE") else {
        eprintln!("The wire test requires MUNIMENT_PI_WIRE_EXECUTABLE for Pi 0.73.1 or 0.85.1.");
        return;
    };
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pi_cloud_wire.py"
        ))
        .arg(executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rejects_a_missing_root() {
    let boundaries = Boundaries {
        session_root: Err(PiLaunchError::UnavailableSessionRoot),
        extension: None,
    };
    assert_eq!(
        pi_launch_config(&boundaries, None, &grant(), None).unwrap_err(),
        PiLaunchError::MissingRoot
    );
}

#[test]
fn rejects_an_unresolvable_executable() {
    let root = temporary_directory();
    let boundaries = Boundaries {
        session_root: Ok(root.clone()),
        extension: None,
    };
    assert_eq!(
        pi_launch_config(&boundaries, Some(&root), &grant(), None).unwrap_err(),
        PiLaunchError::UnresolvableExecutable
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reports_a_rejected_config() {
    let root = temporary_directory();
    let missing = root.join("missing");
    let boundaries = Boundaries {
        session_root: Ok(missing),
        extension: None,
    };
    let error =
        pi_launch_config_for_executable(&boundaries, "pi".into(), &grant(), None).unwrap_err();
    assert!(
        matches!(error, PiLaunchError::RejectedConfig { step: "session_root_check", ref cause }
        if cause.contains("canonicalization failed") && cause.contains("os error"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cloud_extension_failure_keeps_the_cause_and_local_mode_skips_the_write() {
    let root = temporary_directory();
    fs::create_dir(root.join("muniment-cloud-provider.mjs")).unwrap();
    let boundaries = Boundaries {
        session_root: Ok(root.clone()),
        extension: None,
    };
    pi_launch_config_for_executable(&boundaries, "pi".into(), &ChatGrant::local(), None).unwrap();
    let error =
        pi_launch_config_for_executable(&boundaries, "pi".into(), &grant(), None).unwrap_err();
    assert!(
        matches!(error, PiLaunchError::RejectedConfig { step: "cloud_extension_write", ref cause }
        if cause.contains("os error"))
    );
    // The blocked cloud provider and the identity extension every launch writes.
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn appends_a_present_extension_file_and_environment() {
    let root = temporary_directory();
    let extension = root.join("memory.js");
    fs::write(&extension, "").unwrap();
    let boundaries = Boundaries {
        session_root: Ok(root.clone()),
        extension: Some(extension.clone()),
    };
    let config = pi_launch_config_for_executable(&boundaries, "pi".into(), &grant(), None).unwrap();
    assert!(!config.env.contains_key("OPENAI_API_KEY"));
    assert!(!config.args.iter().any(|arg| arg.contains("secret-key")));
    assert_eq!(
        config.env.get("OPENAI_BASE_URL").map(String::as_str),
        Some("https://gateway.example.com")
    );
    assert_eq!(
        config.env.get("PI_DEFAULT_MODEL").map(String::as_str),
        Some("model")
    );
    assert!(config
        .args
        .windows(2)
        .any(|args| args == ["--extension", extension.to_string_lossy().as_ref()]));
    assert!(config
        .args
        .windows(2)
        .any(|args| args == ["--provider", "muniment"]));
    assert!(config
        .args
        .windows(2)
        .any(|args| args == ["--model", "model"]));
    let provider = fs::read_to_string(root.join("muniment-cloud-provider.mjs")).unwrap();
    assert!(provider.contains("pi.registerProvider('muniment'"));
    assert!(provider.contains("process.env.OPENAI_BASE_URL"));
    assert!(provider.contains("apiKey: 'muniment-runtime-boundary'"));
    assert!(provider.contains("process.env.PI_DEFAULT_MODEL"));
    assert!(!provider.contains("secret-key"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn passes_the_system_prompt_for_every_launch() {
    let root = temporary_directory();
    let extension = root.join("memory.js");
    fs::write(&extension, "").unwrap();
    fs::write(root.join("session.jsonl"), "").unwrap();
    let (locator, _) = validate_pi_session(&root, "session.jsonl").unwrap();
    for grant in [ChatGrant::local(), grant()] {
        for reopen in [None, Some(&locator)] {
            for extension in [None, Some(root.join("missing.js")), Some(extension.clone())] {
                let boundaries = Boundaries {
                    session_root: Ok(root.clone()),
                    extension,
                };
                let config =
                    pi_launch_config_for_executable(&boundaries, "pi".into(), &grant, reopen)
                        .unwrap();
                let prompts: Vec<_> = config
                    .args
                    .windows(2)
                    .filter(|args| args[0] == "--system-prompt")
                    .map(|args| args[1].as_str())
                    .collect();
                assert_eq!(prompts, [SYSTEM_PROMPT]);
                assert!(!config
                    .args
                    .iter()
                    .any(|arg| arg == "--append-system-prompt"));
                assert!(!config.args.iter().any(|arg| arg == "--tools"));
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_system_prompt_states_purpose_and_tools_and_names_no_harness_or_product() {
    let lower = SYSTEM_PROMPT.to_lowercase();
    assert!(!lower.contains("muniment"));
    assert!(!lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word == "pi"));
    for tool in [
        "read",
        "write",
        "edit",
        "bash",
        "powershell",
        "grep",
        "find",
        "ls",
        "web_search",
        "fetch_content",
        "subagent",
        "bg_run",
        "bg_status",
        "bg_logs",
        "mcp",
    ] {
        assert!(SYSTEM_PROMPT.contains(tool), "{tool}");
    }
    assert!(SYSTEM_PROMPT.contains("`timeout` in SECONDS"));
    assert!(SYSTEM_PROMPT.contains("Send anything longer to `bg_run`"));
}

#[test]
fn workspace_agents_file_does_not_remove_the_system_prompt() {
    let workspace = temporary_directory();
    let instructions = "Use the workspace instructions.\n";
    fs::write(workspace.join("AGENTS.md"), instructions).unwrap();
    // A child changes the working directory without affecting parallel tests.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "passes_the_system_prompt_for_every_launch"])
        .current_dir(&workspace)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
        "{output:?}"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("AGENTS.md")).unwrap(),
        instructions
    );
    fs::remove_dir_all(workspace).unwrap();
}

#[test]
fn local_launch_uses_pis_credential_store_without_cloud_credentials() {
    let root = temporary_directory();
    let boundaries = Boundaries {
        session_root: Ok(root.clone()),
        extension: None,
    };
    let config =
        pi_launch_config_for_executable(&boundaries, "pi".into(), &ChatGrant::local(), None)
            .unwrap();
    assert!(!config.env.contains_key("OPENAI_API_KEY"));
    assert!(!config.env.contains_key("OPENAI_BASE_URL"));
    assert!(!config.env.contains_key("PI_DEFAULT_MODEL"));
    assert_eq!(config.args[0..2], ["--mode", "rpc"]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_launch_clears_inherited_cloud_environment_in_the_child() {
    let _environment = ENVIRONMENT.lock().unwrap();
    let root = temporary_directory();
    let capture = root.join("environment.json");
    let boundaries = Boundaries {
        session_root: Ok(root.clone()),
        extension: None,
    };
    let executable_name = if cfg!(windows) {
        "sidecar-test-stub.exe"
    } else {
        "sidecar-test-stub"
    };
    let executable = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(executable_name);
    let mut config =
        pi_launch_config_for_executable(&boundaries, executable, &ChatGrant::local(), None)
            .unwrap();
    config.env.insert(
        "PI_RESUME_STUB_ENV_CAPTURE".into(),
        capture.to_string_lossy().into_owned(),
    );
    for (name, value) in [
        ("OPENAI_API_KEY", "inherited-key"),
        ("OPENAI_BASE_URL", "https://inherited.example.com"),
        ("PI_DEFAULT_MODEL", "inherited-model"),
    ] {
        std::env::set_var(name, value);
    }

    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_millis(100)))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while (!capture.is_file() || supervisor.status() != SidecarStatus::Healthy)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    for name in ["OPENAI_API_KEY", "OPENAI_BASE_URL", "PI_DEFAULT_MODEL"] {
        std::env::remove_var(name);
    }

    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    assert_eq!(fs::read_to_string(&capture).unwrap(), "{}");
    supervisor.shutdown().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn omits_an_absent_extension_file() {
    let root = temporary_directory();
    let boundaries = Boundaries {
        session_root: Ok(root.clone()),
        extension: Some(root.join("missing.js")),
    };
    let config = pi_launch_config_for_executable(&boundaries, "pi".into(), &grant(), None).unwrap();
    let extensions = |config: &SidecarConfig| -> Vec<String> {
        config
            .args
            .windows(2)
            .filter(|args| args[0] == "--extension")
            .map(|args| args[1].clone())
            .collect()
    };
    let identity = root.join(IDENTITY_EXTENSION_FILE);
    assert_eq!(
        extensions(&config),
        [
            identity.to_str().unwrap(),
            root.join("muniment-cloud-provider.mjs").to_str().unwrap()
        ]
    );
    let local =
        pi_launch_config_for_executable(&boundaries, "pi".into(), &ChatGrant::local(), None)
            .unwrap();
    assert_eq!(extensions(&local), [identity.to_str().unwrap()]);
    assert_eq!(fs::read_to_string(&identity).unwrap(), IDENTITY_EXTENSION);
    for config in [&config, &local] {
        assert!(config
            .args
            .windows(2)
            .any(|args| args == ["--exclude-tools", EXCLUDED_TOOLS]));
    }
    fs::remove_dir_all(root).unwrap();
}

/// One recorded turn: the prompt Pi assembles around the runtime's system prompt
/// and the provider payload with every extension tool. After the identity
/// extension runs, no prose names the harness or the product. A path keeps its
/// name, because the model reads files by it.
#[test]
fn the_assembled_prompt_and_the_tool_descriptions_name_neither_pi_nor_muniment() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi_turn");
    let extension = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/assistant_identity.mjs");
    let recorded_prompt = fs::read_to_string(fixtures.join("system-prompt.txt")).unwrap();
    let recorded_payload = fs::read_to_string(fixtures.join("payload.json")).unwrap();
    // The recording carries both words, so the assertion below proves the rewrite.
    assert!(recorded_prompt.contains("pi-subagents"));
    assert!(recorded_payload.contains("Muniment Home"));
    assert!(recorded_payload.contains("bg_run_pi_attested"));

    let output = std::process::Command::new("node")
        .arg(fixtures.join("check.mjs"))
        .arg(&extension)
        .arg(fixtures.join("system-prompt.txt"))
        .arg(fixtures.join("payload.json"))
        .output()
        .expect("Node.js must be available to run the identity extension");
    assert!(
        output.status.success(),
        "the identity extension must run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let turn: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let prompt = turn["systemPrompt"].as_str().unwrap();
    assert!(prompt.starts_with(SYSTEM_PROMPT));
    assert!(prompt.contains("Current working directory: /Users/example/Documents/Muniment"));
    assert!(!prompt.contains("available_skills"));

    let names: Vec<&str> = turn["payload"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["function"]["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"subagent") && names.contains(&"bg_run") && names.contains(&"mcp"));
    assert!(!names.contains(&"bg_run_pi_attested"));

    let names_harness_or_product = |token: &str| {
        token.to_ascii_lowercase().contains("muniment")
            || token
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|word| word.eq_ignore_ascii_case("pi"))
    };
    let mut prose = Vec::new();
    collect_strings(&turn["payload"], &mut prose);
    prose.push(prompt.to_owned());
    let offending: Vec<&str> = prose
        .iter()
        .flat_map(|text| text.split_whitespace())
        .filter(|token| !token.contains('/') && !token.contains('\\'))
        .filter(|token| names_harness_or_product(token))
        .collect();
    assert_eq!(offending, Vec::<&str>::new());
}

fn collect_strings(value: &serde_json::Value, into: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => into.push(text.clone()),
        serde_json::Value::Array(items) => {
            items.iter().for_each(|item| collect_strings(item, into))
        }
        serde_json::Value::Object(map) => map.values().for_each(|item| collect_strings(item, into)),
        _ => {}
    }
}
