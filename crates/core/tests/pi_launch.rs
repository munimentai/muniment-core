use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use muniment_core::chat_grant::ChatGrant;
use muniment_core::pi_launch::{
    pi_launch_config, pi_launch_config_for_executable, PiLaunchBoundaries, PiLaunchError,
};
use muniment_core::sidecar::{validate_pi_session, PiRpcWiring, SidecarStatus, SidecarSupervisor};
use uuid::Uuid;

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
            .map_err(|_| PiLaunchError::RejectedConfig)
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
                    assert_eq!(settings["packages"].as_array().unwrap().len(), 4);
                    assert_eq!(settings["defaultTools"].as_array().unwrap().len(), 8);
                    assert_eq!(config.startup_timeout, Duration::from_secs(120));
                } else {
                    assert!(settings.get("packages").is_none());
                    assert!(settings.get("defaultTools").is_none());
                    assert_eq!(config.startup_timeout, Duration::from_secs(30));
                }
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
        assert_eq!(
            pi_launch_config_for_executable(&boundaries, "pi".into(), &grant, None).unwrap_err(),
            PiLaunchError::RejectedConfig,
        );
    }
    assert_eq!(
        fs::read_to_string(root.join("settings.json")).unwrap(),
        "null"
    );
    fs::remove_dir_all(root).unwrap();
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
    assert_eq!(
        pi_launch_config_for_executable(&boundaries, "pi".into(), &grant(), None).unwrap_err(),
        PiLaunchError::RejectedConfig
    );
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
    assert_eq!(
        config.env.get("OPENAI_API_KEY").map(String::as_str),
        Some("secret-key")
    );
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
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn appends_the_exact_timeout_rule_for_every_launch() {
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
                let appended: Vec<_> = config
                    .args
                    .windows(2)
                    .filter(|args| args[0] == "--append-system-prompt")
                    .map(|args| args[1].as_str())
                    .collect();
                assert_eq!(
                    appended,
                    [
                        "- `bash` reads its `timeout` in SECONDS, never milliseconds, and applies
  NO timeout at all when you omit it. Pass one on every call: 60 for a
  quick command, up to 600 for a build or a test suite. A four- or
  five-digit value is a millisecond habit from another harness and leaves
  the command unbounded, so it runs until the engine kills the whole run."
                    ]
                );
                assert!(!config.args.iter().any(|arg| arg == "--system-prompt"));
                assert!(!config.args.iter().any(|arg| arg == "--tools"));
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn workspace_agents_file_does_not_remove_the_timeout_rule() {
    let workspace = temporary_directory();
    let instructions = "Use the workspace instructions.\n";
    fs::write(workspace.join("AGENTS.md"), instructions).unwrap();
    // A child changes the working directory without affecting parallel tests.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "appends_the_exact_timeout_rule_for_every_launch"])
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
    assert!(!config.args.iter().any(|arg| arg == "--extension"));
    fs::remove_dir_all(root).unwrap();
}
