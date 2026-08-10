use std::fs;
use std::path::PathBuf;

use muniment_core::chat_grant::ChatGrant;
use muniment_core::pi_launch::{
    pi_launch_config, pi_launch_config_for_executable, PiLaunchBoundaries, PiLaunchError,
};
use uuid::Uuid;

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
