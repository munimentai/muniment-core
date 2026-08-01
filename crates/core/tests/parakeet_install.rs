use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use muniment_core::asr::acquisition::{
    AsrAcquisitionLimits, AsrAcquisitionRuntime, AsrCancellation, AsrDownloadRequest,
    AsrDownloadResponse, AsrDownloadTransport, AsrTransportError,
};
use muniment_core::asr::install::install_parakeet_revision;
use muniment_core::asr::{
    AsrArtifactDescriptor, AsrArtifactManifest, AsrLifecycleBoundary, AsrPersistenceError,
    AsrRevisionLifecycle, AsrSourcedArtifactDescriptor,
};
use muniment_core::model_install::{
    AvailableSpaceError, InstallLock, InstallLockError, InstallLockState, ModelInstallError,
};

const MARGIN: u64 = 256 * 1024 * 1024;
static ARTIFACTS: [AsrArtifactDescriptor; 4] = [
    AsrArtifactDescriptor {
        filename: "encoder",
        byte_size: 1,
        sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    },
    AsrArtifactDescriptor {
        filename: "decoder",
        byte_size: 2,
        sha256: "1e0bbd6c686ba050b8eb03ffeedc64fdc9d80947fce821abbe5d6dc8d252c5ac",
    },
    AsrArtifactDescriptor {
        filename: "joiner",
        byte_size: 3,
        sha256: "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34",
    },
    AsrArtifactDescriptor {
        filename: "tokens",
        byte_size: 4,
        sha256: "975ca72b6bdf0e938bcc214727c939f7fc64109ee8f14add455a2364e8d1451f",
    },
];
static MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
    identity: "fixture",
    revision: "revision",
    artifacts: &ARTIFACTS,
    additional_artifact: Some(AsrSourcedArtifactDescriptor {
        repository: "csukuangfj/vad",
        revision: "vad-revision",
        artifact: AsrArtifactDescriptor {
            filename: "silero_vad.onnx",
            byte_size: 2,
            sha256: "8630c6c9af0730c3e9635a44c97bfb4ac4ff57c449951a60848ac666f5f2de0c",
        },
    }),
};
static MANIFESTS: [&AsrArtifactManifest; 1] = [&MANIFEST];

struct Transport;
impl AsrDownloadTransport for Transport {
    type Body = Cursor<Vec<u8>>;

    fn download(
        &mut self,
        request: &AsrDownloadRequest,
    ) -> Result<AsrDownloadResponse<Self::Body>, AsrTransportError> {
        let (status, range, body) = match request.artifact_index {
            0 => (200, None, b"a".to_vec()),
            1 => (206, Some((1, 1, 2)), b"c".to_vec()),
            2 => (200, None, b"def".to_vec()),
            3 => (206, Some((2, 3, 4)), b"ij".to_vec()),
            4 => {
                assert_eq!(
                    request.url(),
                    "https://huggingface.co/csukuangfj/vad/resolve/vad-revision/silero_vad.onnx"
                );
                (206, Some((1, 1, 2)), b"k".to_vec())
            }
            _ => unreachable!(),
        };
        assert_eq!(request.offset, range.map_or(0, |value| value.0));
        Ok(AsrDownloadResponse {
            status,
            content_range: range,
            body: Cursor::new(body),
        })
    }
}

struct Lock(usize);
impl InstallLock for Lock {
    type Guard = ();
    fn try_lock_exclusive(&mut self) -> Result<InstallLockState<()>, InstallLockError> {
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

struct Boundary;
impl AsrLifecycleBoundary for Boundary {
    fn sync_file(&self, _: &Path) -> Result<(), AsrPersistenceError> {
        Ok(())
    }
    fn sync_directory(&self, _: &Path) -> Result<(), AsrPersistenceError> {
        Ok(())
    }
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), AsrPersistenceError> {
        fs::rename(temporary, destination).map_err(|_| AsrPersistenceError::Failed)
    }
}

fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "muniment-parakeet-install-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("staging/install")).unwrap();
    root
}

fn no_wait(_: Duration, _: &dyn AsrCancellation) -> bool {
    true
}

#[test]
fn resumes_multiple_artifacts_and_publishes_under_one_coordinator_lock() {
    let root = root();
    let stage = root.join("staging/install");
    fs::write(stage.join("decoder.part"), b"b").unwrap();
    fs::write(stage.join("tokens.part"), b"gh").unwrap();
    fs::write(stage.join("silero_vad.onnx.part"), b"v").unwrap();
    let lifecycle = AsrRevisionLifecycle::new(root.clone(), &MANIFESTS, &MANIFEST).unwrap();
    let mut lock = Lock(0);
    let mut available = [MARGIN + 8, MARGIN].into_iter();
    let mut checks = Vec::new();
    let mut space = || -> Result<Option<u64>, AvailableSpaceError> {
        let value = available.next().unwrap();
        checks.push(value);
        Ok(Some(value))
    };
    let mut progress = Vec::new();

    let installed = install_parakeet_revision(
        &root.join("staging"),
        "install",
        &MANIFEST,
        AsrAcquisitionLimits::default(),
        &mut Transport,
        AsrAcquisitionRuntime {
            clock: &|| Duration::ZERO,
            retry_wait: &mut no_wait,
        },
        &|| false,
        &mut lock,
        &mut space,
        &lifecycle,
        &Boundary,
        &mut |completed, total| progress.push((completed, total)),
    )
    .unwrap();

    assert_eq!(installed, root.join("revisions/revision"));
    assert_eq!(checks, [MARGIN + 8, MARGIN]);
    assert_eq!(lock.0, 1);
    assert_eq!(progress.first(), Some(&(4, 12)));
    assert_eq!(progress.last(), Some(&(12, 12)));
    for (filename, contents) in [
        ("encoder", b"a".as_slice()),
        ("decoder", b"bc"),
        ("joiner", b"def"),
        ("tokens", b"ghij"),
        ("silero_vad.onnx", b"vk"),
    ] {
        assert_eq!(fs::read(installed.join(filename)).unwrap(), contents);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_and_unavailable_space_preserve_the_resumable_stage() {
    for (cancelled, available) in [(true, Some(u64::MAX)), (false, Some(MARGIN)), (false, None)] {
        let root = root();
        let part = root.join("staging/install/decoder.part");
        fs::write(&part, b"b").unwrap();
        let lifecycle = AsrRevisionLifecycle::new(root.clone(), &MANIFESTS, &MANIFEST).unwrap();
        let mut lock = Lock(0);
        let mut space = || Ok::<_, AvailableSpaceError>(available);

        let error = install_parakeet_revision(
            &root.join("staging"),
            "install",
            &MANIFEST,
            AsrAcquisitionLimits::default(),
            &mut Transport,
            AsrAcquisitionRuntime {
                clock: &|| Duration::ZERO,
                retry_wait: &mut no_wait,
            },
            &|| cancelled,
            &mut lock,
            &mut space,
            &lifecycle,
            &Boundary,
            &mut |_, _| {},
        )
        .unwrap_err();

        if cancelled {
            assert_eq!(error, ModelInstallError::Cancelled);
        } else if available.is_some() {
            assert!(matches!(
                error,
                ModelInstallError::StorageInsufficient { .. }
            ));
        } else {
            assert_eq!(error, ModelInstallError::StorageUnknown);
        }
        assert_eq!(fs::read(part).unwrap(), b"b");
        assert!(!root.join("current").exists());
        assert!(!root.join("revisions/revision").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
