use std::collections::VecDeque;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use muniment_core::model_artifact::acquisition::{
    ModelArtifactAcquisitionLimits, ModelArtifactAcquisitionRuntime, ModelArtifactCancellation,
    ModelArtifactDownloadRequest, ModelArtifactDownloadResponse, ModelArtifactDownloadTransport,
    ModelArtifactTransportError,
};
use muniment_core::model_artifact::install::install_model_artifact_revision_with_progress;
use muniment_core::model_artifact::lifecycle::{
    ModelArtifactLifecycleBoundary, ModelArtifactNoticeDescriptor, ModelArtifactPersistenceError,
    ModelArtifactRevisionDescriptor, ModelArtifactRevisionLifecycle,
};
use muniment_core::model_artifact::ModelArtifactDescriptor;
use muniment_core::model_install::{
    AvailableSpaceError, InstallLock, InstallLockError, InstallLockState,
};

const MARGIN: u64 = 256 * 1024 * 1024;
static MODEL: ModelArtifactDescriptor = ModelArtifactDescriptor {
    name: "fixture",
    version: "revision",
    source_url: "https://example.invalid/model.gguf",
    license: "fixture",
    filename: "model.gguf",
    byte_size: 3,
    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
};
static REVISION: ModelArtifactRevisionDescriptor = ModelArtifactRevisionDescriptor {
    model: &MODEL,
    notice: ModelArtifactNoticeDescriptor {
        filename: "NOTICE.txt",
        contents: b"fixture notice",
    },
};
static REVISIONS: [&ModelArtifactRevisionDescriptor; 1] = [&REVISION];

struct Transport;
impl ModelArtifactDownloadTransport for Transport {
    type Body = Cursor<Vec<u8>>;

    fn download(
        &mut self,
        request: &ModelArtifactDownloadRequest,
    ) -> Result<ModelArtifactDownloadResponse<Self::Body>, ModelArtifactTransportError> {
        assert_eq!(request.offset, 1);
        Ok(ModelArtifactDownloadResponse {
            status: 206,
            content_range: Some((1, 2, 3)),
            body: Cursor::new(b"bc".to_vec()),
        })
    }
}

struct Lock(usize);
impl InstallLock for Lock {
    type Guard = ();

    fn try_lock_exclusive(&mut self) -> Result<InstallLockState<Self::Guard>, InstallLockError> {
        self.0 += 1;
        Ok(InstallLockState::Acquired(()))
    }

    fn wait_for_retry(
        &mut self,
        _: &dyn muniment_core::model_install::InstallCancellation,
    ) -> bool {
        unreachable!()
    }
}

struct Boundary(AtomicUsize);
impl ModelArtifactLifecycleBoundary for Boundary {
    type LockGuard = ();

    fn lock_exclusive(&self, _: &Path) -> Result<(), ModelArtifactPersistenceError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn sync_file(&self, _: &Path) -> Result<(), ModelArtifactPersistenceError> {
        Ok(())
    }

    fn sync_directory(&self, _: &Path) -> Result<(), ModelArtifactPersistenceError> {
        Ok(())
    }

    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), ModelArtifactPersistenceError> {
        fs::rename(staged, destination).map_err(|_| ModelArtifactPersistenceError::Failed)
    }

    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), ModelArtifactPersistenceError> {
        fs::rename(temporary, destination).map_err(|_| ModelArtifactPersistenceError::Failed)
    }
}

fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "muniment-artifact-install-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("staging/install")).unwrap();
    root
}

fn no_wait(_: Duration, _: &dyn ModelArtifactCancellation) -> bool {
    true
}

#[test]
fn coordinator_owns_locking_and_uses_model_artifacts_exact_stage_accounting() {
    let root = root();
    fs::write(root.join("staging/install/model.gguf.part"), b"a").unwrap();
    let lifecycle =
        ModelArtifactRevisionLifecycle::new(root.clone(), &REVISIONS, &REVISION).unwrap();
    let boundary = Boundary(AtomicUsize::new(0));
    let mut lock = Lock(0);
    let mut available = VecDeque::from([MARGIN + 2, MARGIN]);
    let mut checks = Vec::new();
    let mut space = || -> Result<Option<u64>, AvailableSpaceError> {
        let value = available.pop_front().unwrap();
        checks.push(value);
        Ok(Some(value))
    };

    let mut progress = Vec::new();
    let installed = install_model_artifact_revision_with_progress(
        &root.join("staging"),
        "install",
        &REVISION,
        ModelArtifactAcquisitionLimits::default(),
        &mut Transport,
        ModelArtifactAcquisitionRuntime {
            clock: &|| Duration::ZERO,
            retry_wait: &mut no_wait,
        },
        &|| false,
        &mut lock,
        &mut space,
        &lifecycle,
        &boundary,
        &mut |update| progress.push(update.downloaded_bytes),
    )
    .unwrap();

    assert_eq!(installed, root.join("revisions/fixture/revision"));
    assert_eq!(fs::read(installed.join("model.gguf")).unwrap(), b"abc");
    assert_eq!(checks, [MARGIN + 2, MARGIN]);
    assert_eq!(lock.0, 1);
    assert_eq!(boundary.0.load(Ordering::Relaxed), 0);
    assert_eq!(progress, [1, 3]);
    fs::remove_dir_all(root).unwrap();
}
