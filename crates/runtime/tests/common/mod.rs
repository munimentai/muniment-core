#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use muniment_core::chat_launch::ChatGrant;
use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_SELECTED_ARTIFACT};

static TEMPORARY_PROFILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Points the state directory at one temporary directory for the test process
/// unless a test already named one. A run's launch resolves the agent settings
/// and package tree from the state directory, so without it a test writes the
/// user's own `~/.muniment`.
pub fn isolate_state_directory() {
    let variable = muniment_core::state_root::STATE_DIRECTORY_OVERRIDE;
    if std::env::var_os(variable).is_none() {
        std::env::set_var(
            variable,
            std::env::temp_dir().join(format!("muniment-runtime-state-{}", std::process::id())),
        );
    }
}

/// Keeps prompt history in the mock keyring, or, in a build without the
/// keyring, in files under the test process's state directory.
pub fn use_test_prompt_store() {
    #[cfg(feature = "keyring")]
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    #[cfg(not(feature = "keyring"))]
    {
        isolate_state_directory();
        muniment_core::chat_prompt::install_local_prompt_store(
            muniment_core::state_root::state_directory().expect("the state directory is set"),
        );
    }
}

pub struct TemporaryProfile {
    pub root: PathBuf,
    pub profile: PathBuf,
    pub config: PathBuf,
}

impl TemporaryProfile {
    pub fn new(test_name: &str, scaffold_home: bool) -> Self {
        isolate_state_directory();
        let sequence = TEMPORARY_PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "muniment-runtime-{test_name}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let profile = root.join("profile");
        let config = root.join("config");
        let temporary_profile = Self {
            root,
            profile,
            config,
        };
        fs::create_dir_all(&temporary_profile.profile).unwrap();
        fs::create_dir_all(&temporary_profile.config).unwrap();
        if scaffold_home {
            muniment_core::home::confirm_home(
                &temporary_profile.config,
                &temporary_profile.root.join("home"),
            )
            .unwrap();
        }
        temporary_profile
    }
}

impl Drop for TemporaryProfile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn remove_journal_tables(profile: &Path, tables: &[&str]) {
    let connection = rusqlite::Connection::open(profile.join("runs.sqlite3")).unwrap();
    for table in tables {
        let sql = match *table {
            "events" => "DROP TABLE events",
            "thread_events" => "DROP TABLE thread_events",
            "run_threads" => "DROP TABLE run_threads",
            "run_workspaces" => "DROP TABLE run_workspaces",
            _ => panic!("the journal fixture table is invalid"),
        };
        connection.execute_batch(sql).unwrap();
    }
}

pub fn local_grant() -> ChatGrant {
    ChatGrant::local()
}

pub fn fixture_grant() -> ChatGrant {
    ChatGrant {
        workspace: "workspace-a".into(),
        gateway_url: "https://gateway.example.com".into(),
        virtual_key: "virtual-key".into(),
        model: None,
        expires_at: None,
        native_access_token: None,
        minimum_cacheable_prefix_characters: 8_192,
        receipt_url: "https://receipts.example.com".into(),
    }
}

/// The stub stands in for the artifact this build selects, staged under the
/// profile's own install root, so a run resolves it with or without the
/// `MUNIMENT_PI_ROOT` override.
pub fn stage_pi_stub(temporary_root: &Path) -> PiArtifactDescriptor {
    isolate_state_directory();
    let pi_root = muniment_core::chat_profile::ChatProfile::new(temporary_root).pi_install_root();
    let revision_root = pi_root.join("revisions").join(PI_SELECTED_ARTIFACT.version);
    let staged_stub = revision_root.join(PI_SELECTED_ARTIFACT.executable);
    fs::create_dir_all(staged_stub.parent().unwrap()).unwrap();
    fs::copy(build_pi_stub(), staged_stub).unwrap();
    let stub_archive = b"muniment-sidecar-test-stub\n";
    fs::write(
        revision_root.join(PI_SELECTED_ARTIFACT.archive),
        stub_archive,
    )
    .unwrap();
    fs::write(
        pi_root.join("current"),
        format!("muniment-pi-pointer-v1\n{}\n", PI_SELECTED_ARTIFACT.version),
    )
    .unwrap();
    std::env::set_var("MUNIMENT_PI_ROOT", pi_root);

    PiArtifactDescriptor {
        version: PI_SELECTED_ARTIFACT.version,
        archive: PI_SELECTED_ARTIFACT.archive,
        byte_size: stub_archive.len() as u64,
        sha256: "758b0db8f6304639edfca2b779e886f3006afeb006417e49dd6bce53ff2a65ab",
        executable: PI_SELECTED_ARTIFACT.executable,
    }
}

/// Builds the sidecar test stub in its own target directory and returns its path.
pub fn build_pi_stub() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut workspace_hasher = DefaultHasher::new();
    manifest_dir.hash(&mut workspace_hasher);
    let build_root = std::env::temp_dir().join(format!(
        "muniment-runtime-sidecar-test-stub-{:x}",
        workspace_hasher.finish()
    ));
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--quiet",
            "--package",
            "muniment-core",
            "--bin",
            "sidecar-test-stub",
            "--target-dir",
        ])
        .arg(&build_root)
        .current_dir(manifest_dir)
        // The stub needs no debug symbols or incremental state, which keeps this
        // second target directory small on the shared smoke runner.
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env("CARGO_INCREMENTAL", "0")
        .status()
        .unwrap();
    assert!(status.success());

    let stub_name = if cfg!(windows) {
        "sidecar-test-stub.exe"
    } else {
        "sidecar-test-stub"
    };
    build_root.join("debug").join(stub_name)
}
