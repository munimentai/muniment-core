use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use muniment_core::model_install::{
    AvailableSpaceError, InstallLock, InstallLockError, InstallLockState,
};
use muniment_core::sidecar::pi_install::{
    install_pi, resolve_current, FsPiLifecycleBoundary, PiDownloadRequest, PiDownloadResponse,
    PiDownloadTransport, PiTransportError,
};
use muniment_core::sidecar::{
    pi_sidecar_config, PiRpcWiring, SidecarStatus, SidecarSupervisor, PI_VERSION,
};

struct ArchiveTransport(PathBuf);

impl PiDownloadTransport for ArchiveTransport {
    type Body = File;
    fn download(
        &mut self,
        _: &PiDownloadRequest,
    ) -> Result<PiDownloadResponse<Self::Body>, PiTransportError> {
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

/// Opt-in because release/CI jobs must acquire the pinned executable rather
/// than committing it. Example:
/// `MUNIMENT_PI_ARCHIVE=/path/to/pi-<target>.<tar.gz|zip> cargo test --test pi_sidecar`
#[test]
fn real_pinned_pi_reaches_ready_through_the_supervisor() {
    let Ok(archive) = std::env::var("MUNIMENT_PI_ARCHIVE") else {
        eprintln!("skipping real Pi {PI_VERSION} spawn: MUNIMENT_PI_ARCHIVE is not set");
        return;
    };
    let root = std::env::temp_dir().join(format!("muniment-real-pi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let executable = install_archive(Path::new(&archive), &root);
    assert_eq!(resolve_current(&root).unwrap(), executable);

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
