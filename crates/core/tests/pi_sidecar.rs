use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use muniment_core::model_install::{
    AvailableSpaceError, InstallLock, InstallLockError, InstallLockState,
};
use muniment_core::sidecar::pi_install::{
    install_pi, resolve_current, FsPiLifecycleBoundary, PiDownloadRequest, PiDownloadResponse,
    PiDownloadTransport, PiTransportError, PI_SELECTED_ARTIFACT,
};
use muniment_core::sidecar::{pi_sidecar_config, PiRpcWiring, SidecarStatus, SidecarSupervisor};

use muniment_core::chat_grant::ChatGrant;
use muniment_core::pi_launch::{
    pi_launch_config_for_executable, PiLaunchBoundaries, PiLaunchError,
};

struct ArchiveTransport(PathBuf);

impl PiDownloadTransport for ArchiveTransport {
    type Body = File;
    fn download(
        &mut self,
        request: &PiDownloadRequest,
    ) -> Result<PiDownloadResponse<Self::Body>, PiTransportError> {
        assert_eq!(
            request.url(),
            format!(
                "https://github.com/earendil-works/pi/releases/download/v{}/{}",
                PI_SELECTED_ARTIFACT.version, PI_SELECTED_ARTIFACT.archive
            )
        );
        Ok(PiDownloadResponse {
            status: 200,
            body: File::open(&self.0).map_err(|_| PiTransportError::Unavailable)?,
        })
    }
}

struct Lock;
impl InstallLock for Lock {
    type Guard = ();
    fn try_lock_exclusive(&mut self) -> Result<InstallLockState<Self::Guard>, InstallLockError> {
        Ok(InstallLockState::Acquired(()))
    }
    fn wait_for_retry(
        &mut self,
        _: &dyn muniment_core::model_install::InstallCancellation,
    ) -> bool {
        true
    }
}

fn install_archive(archive: &Path, root: &Path) -> PathBuf {
    let mut transport = ArchiveTransport(archive.to_owned());
    let mut lock = Lock;
    let mut space = || Ok::<_, AvailableSpaceError>(Some(u64::MAX));
    install_pi(
        root,
        "real-release",
        &mut transport,
        &|| false,
        &mut lock,
        &mut space,
        &FsPiLifecycleBoundary,
    )
    .expect("install verified pinned Pi archive")
}

struct CandidateBoundaries(PathBuf);

impl PiLaunchBoundaries for CandidateBoundaries {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
        Ok(self.0.join("sessions"))
    }

    fn memory_agent_extension_path(&self) -> Option<PathBuf> {
        Some(self.0.join("probe.ts"))
    }
}

#[test]
fn candidate_cold_launch_without_node_or_npm() {
    use muniment_core::sidecar::pi_install::PI_CANDIDATE_ARTIFACT;
    use std::fs;
    use std::process::Command;

    if PI_SELECTED_ARTIFACT != PI_CANDIDATE_ARTIFACT {
        return;
    }
    let Ok(archive) = std::env::var("MUNIMENT_PI_ARCHIVE") else {
        eprintln!("The cold-launch test requires MUNIMENT_PI_ARCHIVE.");
        return;
    };
    // Isolate PATH and the package cache in a child test process, not the parallel test runner.
    if std::env::var_os("MUNIMENT_COLD_PI_CHILD").is_none() {
        let root = std::env::temp_dir().join(format!("muniment-cold-pi-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("empty-path")).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "candidate_cold_launch_without_node_or_npm",
                "--nocapture",
            ])
            .env("MUNIMENT_COLD_PI_CHILD", &root)
            .env("MUNIMENT_PI_ARCHIVE", fs::canonicalize(archive).unwrap())
            .env("PATH", root.join("empty-path"))
            .env("HOME", &root)
            .env("USERPROFILE", &root)
            .env("BUN_INSTALL_CACHE_DIR", root.join("bun-cache"))
            .env(
                "PI_CODING_AGENT_DIR",
                url::Url::from_directory_path(root.join("agent files"))
                    .unwrap()
                    .as_str(),
            )
            .current_dir(&root)
            .status()
            .unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(status.success());
        return;
    }
    assert!(Command::new("node").arg("--version").status().is_err());
    assert!(Command::new("npm").arg("--version").status().is_err());
    let root = PathBuf::from(std::env::var_os("MUNIMENT_COLD_PI_CHILD").unwrap());
    let executable = install_archive(Path::new(&archive), &root.join("install"));
    fs::create_dir(root.join("sessions")).unwrap();
    fs::write(
        root.join("probe.ts"),
        r#"
import { writeFileSync } from 'node:fs'
export default function (pi) {
  pi.on('session_start', () => {
    writeFileSync('tools.json', JSON.stringify(pi.getAllTools().map(tool => tool.name)))
  })
}
"#,
    )
    .unwrap();
    let cloud = ChatGrant {
        workspace: root.to_string_lossy().into_owned(),
        gateway_url: "http://127.0.0.1:1".into(),
        virtual_key: "test-key".into(),
        model: None,
        minimum_cacheable_prefix_characters: 8192,
        receipt_url: "http://127.0.0.1:1".into(),
    };
    for grant in [ChatGrant::local(), cloud] {
        let start = Instant::now();
        let mut config = pi_launch_config_for_executable(
            &CandidateBoundaries(root.clone()),
            executable.clone(),
            &grant,
            None,
        )
        .unwrap();
        let acquisition_elapsed = start.elapsed();
        config.health_interval = Duration::from_secs(60);
        let wiring = PiRpcWiring::new();
        let mut supervisor =
            SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_secs(120)))
                .unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline
            && !matches!(
                supervisor.status(),
                SidecarStatus::Healthy | SidecarStatus::Failed
            )
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let status = supervisor.status();
        let readiness_elapsed = start.elapsed();
        supervisor.shutdown().unwrap();
        assert_eq!(status, SidecarStatus::Healthy);
        eprintln!(
            "The candidate acquired packages in {:.1} seconds and reached readiness in {:.1} seconds without Node or npm.",
            acquisition_elapsed.as_secs_f64(), readiness_elapsed.as_secs_f64()
        );
        let tools: Vec<String> =
            serde_json::from_slice(&fs::read(root.join("tools.json")).unwrap()).unwrap();
        for name in [
            "read",
            "bash",
            "powershell",
            "edit",
            "write",
            "grep",
            "find",
            "ls",
            "web_search",
            "fetch_content",
            "subagent",
            "bg_run",
            "mcp",
        ] {
            assert!(
                tools.iter().any(|tool| tool == name),
                "The tool {name} is missing. The tools are {tools:?}."
            );
        }
    }
    let settings: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("agent files/settings.json")).unwrap()).unwrap();
    assert_eq!(settings["packages"].as_array().unwrap().len(), 4);
    assert_eq!(settings["defaultTools"].as_array().unwrap().len(), 8);
}

/// Opt-in because release/CI jobs must acquire the pinned executable rather
/// than committing it. Example:
/// `MUNIMENT_PI_ARCHIVE=/path/to/pi-<target>.<tar.gz|zip> cargo test --test pi_sidecar`
/// Set `MUNIMENT_PI_CANDIDATE=1` at build time to test the candidate archive.
#[test]
fn real_pinned_pi_reaches_ready_through_the_supervisor() {
    let Ok(archive) = std::env::var("MUNIMENT_PI_ARCHIVE") else {
        eprintln!(
            "skipping real Pi {} spawn: MUNIMENT_PI_ARCHIVE is not set",
            PI_SELECTED_ARTIFACT.version
        );
        return;
    };
    let root = std::env::temp_dir().join(format!("muniment-real-pi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let executable = install_archive(Path::new(&archive), &root);
    assert_eq!(resolve_current(&root).unwrap(), executable);
    assert_eq!(
        executable,
        root.join("revisions")
            .join(PI_SELECTED_ARTIFACT.version)
            .join(PI_SELECTED_ARTIFACT.executable)
    );

    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let mut config = pi_sidecar_config(executable.to_string_lossy(), &sessions, None).unwrap();
    config.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_secs(10)))
            .expect("spawn pinned Pi artifact");

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline
        && !matches!(
            supervisor.status(),
            SidecarStatus::Healthy | SidecarStatus::Failed
        )
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    assert!(wiring.transport().is_some());
    supervisor.shutdown().expect("shut down Pi");
    std::fs::remove_dir_all(root).expect("remove test installation");
}
