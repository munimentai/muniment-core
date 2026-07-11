use std::collections::VecDeque;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use muniment_core::llama::acquisition::{
    GemmaAcquisitionLimits, GemmaAcquisitionRuntime, GemmaCancellation, GemmaDownloadRequest,
    GemmaDownloadResponse, GemmaDownloadTransport, GemmaTransportError,
};
use muniment_core::llama::install::install_gemma_revision;
use muniment_core::llama::lifecycle::{
    GemmaLifecycleBoundary, GemmaNoticeDescriptor, GemmaPersistenceError, GemmaRevisionDescriptor,
    GemmaRevisionLifecycle,
};
use muniment_core::llama::ResidentModelDescriptor;
use muniment_core::model_install::{
    AvailableSpaceError, InstallLock, InstallLockError, InstallLockState,
};

const MARGIN: u64 = 256 * 1024 * 1024;
static MODEL: ResidentModelDescriptor = ResidentModelDescriptor {
    filename: "model.gguf",
    byte_size: 3,
    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    alias: "fixture",
    context_tokens: 1,
};
static REVISION: GemmaRevisionDescriptor = GemmaRevisionDescriptor {
    identity: "fixture-v1",
    revision: "revision",
    model: &MODEL,
    notice: GemmaNoticeDescriptor {
        filename: "NOTICE.txt",
        contents: b"fixture notice",
    },
};
static REVISIONS: [&GemmaRevisionDescriptor; 1] = [&REVISION];

struct Transport;
impl GemmaDownloadTransport for Transport {
    type Body = Cursor<Vec<u8>>;

    fn download(
        &mut self,
        request: &GemmaDownloadRequest,
    ) -> Result<GemmaDownloadResponse<Self::Body>, GemmaTransportError> {
        assert_eq!(request.offset, 1);
        Ok(GemmaDownloadResponse {
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
impl GemmaLifecycleBoundary for Boundary {
    type LockGuard = ();

    fn lock_exclusive(&self, _: &Path) -> Result<(), GemmaPersistenceError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn sync_file(&self, _: &Path) -> Result<(), GemmaPersistenceError> {
        Ok(())
    }

    fn sync_directory(&self, _: &Path) -> Result<(), GemmaPersistenceError> {
        Ok(())
    }

    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), GemmaPersistenceError> {
        fs::rename(staged, destination).map_err(|_| GemmaPersistenceError::Failed)
    }

    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), GemmaPersistenceError> {
        fs::rename(temporary, destination).map_err(|_| GemmaPersistenceError::Failed)
    }
}

fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "muniment-gemma-install-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("staging/install")).unwrap();
    root
}

fn no_wait(_: Duration, _: &dyn GemmaCancellation) -> bool {
    true
}

#[test]
fn coordinator_owns_locking_and_uses_gemmas_exact_stage_accounting() {
    let root = root();
    fs::write(root.join("staging/install/model.gguf.part"), b"a").unwrap();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &REVISIONS, &REVISION).unwrap();
    let boundary = Boundary(AtomicUsize::new(0));
    let mut lock = Lock(0);
    let mut available = VecDeque::from([MARGIN + 2, MARGIN]);
    let mut checks = Vec::new();
    let mut space = || -> Result<Option<u64>, AvailableSpaceError> {
        let value = available.pop_front().unwrap();
        checks.push(value);
        Ok(Some(value))
    };

    let installed = install_gemma_revision(
        &root.join("staging"),
        "install",
        &REVISION,
        GemmaAcquisitionLimits::default(),
        &mut Transport,
        GemmaAcquisitionRuntime {
            clock: &|| Duration::ZERO,
            retry_wait: &mut no_wait,
        },
        &|| false,
        &mut lock,
        &mut space,
        &lifecycle,
        &boundary,
    )
    .unwrap();

    assert_eq!(installed, root.join("revisions/revision"));
    assert_eq!(fs::read(installed.join("model.gguf")).unwrap(), b"abc");
    assert_eq!(checks, [MARGIN + 2, MARGIN]);
    assert_eq!(lock.0, 1);
    assert_eq!(boundary.0.load(Ordering::Relaxed), 0);
    fs::remove_dir_all(root).unwrap();
}
