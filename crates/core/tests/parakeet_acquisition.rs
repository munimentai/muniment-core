use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use muniment_core::asr::acquisition::{
    acquire_parakeet_stage, remaining_stage_bytes, AsrAcquisitionError, AsrAcquisitionLimits,
    AsrAcquisitionRuntime, AsrCancellation, AsrDownloadRequest, AsrDownloadResponse,
    AsrDownloadTransport, AsrTransportError,
};
use muniment_core::asr::{
    AsrArtifactDescriptor, AsrArtifactManifest, AsrSourcedArtifactDescriptor,
};

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
        byte_size: 1,
        sha256: "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
    },
    AsrArtifactDescriptor {
        filename: "tokens",
        byte_size: 2,
        sha256: "4ca669ac3713d1f4aea07dae8dcc0d1c9867d27ea82a3ba4e6158a42206f959b",
    },
];
static MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
    identity: "fixture",
    revision: "0123456789abcdef",
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

enum Reply {
    Bytes(&'static [u8]),
    Error(AsrTransportError),
}
struct Transport {
    replies: VecDeque<Reply>,
    requests: Vec<(usize, u64, Duration, String)>,
}
impl Transport {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            replies: replies.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}
impl AsrDownloadTransport for Transport {
    type Body = Cursor<Vec<u8>>;
    fn download(
        &mut self,
        request: &AsrDownloadRequest,
    ) -> Result<AsrDownloadResponse<Self::Body>, AsrTransportError> {
        self.requests.push((
            request.artifact_index,
            request.offset,
            request.limits.deadline,
            request.url().to_owned(),
        ));
        match self.replies.pop_front().unwrap() {
            Reply::Bytes(bytes) => {
                let expected = if request.artifact_index < ARTIFACTS.len() {
                    ARTIFACTS[request.artifact_index].byte_size
                } else {
                    MANIFEST.additional_artifact.unwrap().artifact.byte_size
                };
                let range =
                    (request.offset > 0).then_some((request.offset, expected - 1, expected));
                Ok(AsrDownloadResponse {
                    status: if range.is_some() { 206 } else { 200 },
                    content_range: range,
                    body: Cursor::new(bytes.to_vec()),
                })
            }
            Reply::Error(error) => Err(error),
        }
    }
}

fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "muniment-parakeet-acquisition-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}
fn no_wait(_: Duration, _: &dyn AsrCancellation) -> bool {
    true
}

#[test]
fn accounts_for_absent_mixed_and_verified_stages() {
    let root = root();
    assert_eq!(remaining_stage_bytes(&root, "install", &MANIFEST), Ok(8));
    fs::create_dir(root.join("install")).unwrap();
    fs::write(root.join("install/encoder"), b"a").unwrap();
    fs::write(root.join("install/decoder.part"), b"b").unwrap();
    assert_eq!(remaining_stage_bytes(&root, "install", &MANIFEST), Ok(6));
    fs::write(root.join("install/decoder"), b"bc").unwrap();
    fs::write(root.join("install/joiner"), b"d").unwrap();
    fs::write(root.join("install/tokens"), b"ef").unwrap();
    fs::write(root.join("install/silero_vad.onnx"), b"vk").unwrap();
    assert_eq!(remaining_stage_bytes(&root, "install", &MANIFEST), Ok(0));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accounting_rejects_oversized_and_non_regular_parts() {
    let root = root();
    fs::create_dir(root.join("install")).unwrap();
    fs::write(root.join("install/encoder.part"), b"aa").unwrap();
    assert_eq!(
        remaining_stage_bytes(&root, "install", &MANIFEST),
        Err(AsrAcquisitionError::TooLarge)
    );
    fs::remove_file(root.join("install/encoder.part")).unwrap();
    fs::create_dir(root.join("install/encoder.part")).unwrap();
    assert_eq!(
        remaining_stage_bytes(&root, "install", &MANIFEST),
        Err(AsrAcquisitionError::InvalidStage)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn resumes_files_and_returns_only_the_verified_complete_set() {
    let root = root();
    fs::create_dir(root.join("install")).unwrap();
    fs::write(root.join("install/decoder.part"), b"b").unwrap();
    fs::write(root.join("install/silero_vad.onnx.part"), b"v").unwrap();
    let mut transport = Transport::new([
        Reply::Bytes(b"a"),
        Reply::Bytes(b"c"),
        Reply::Bytes(b"d"),
        Reply::Bytes(b"ef"),
        Reply::Bytes(b"k"),
    ]);
    let mut progress = Vec::new();
    let stage = acquire_parakeet_stage(
        &root,
        "install",
        &MANIFEST,
        AsrAcquisitionLimits::default(),
        &mut transport,
        AsrAcquisitionRuntime {
            clock: &|| Duration::ZERO,
            retry_wait: &mut no_wait,
        },
        &|| false,
        &mut |completed, total| progress.push((completed, total)),
    )
    .unwrap();
    assert_eq!(
        transport
            .requests
            .iter()
            .map(|(index, offset, _, _)| (*index, *offset))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 1), (2, 0), (3, 0), (4, 1)]
    );
    assert_eq!(
        transport.requests.last().unwrap().3,
        "https://huggingface.co/csukuangfj/vad/resolve/vad-revision/silero_vad.onnx"
    );
    assert_eq!(fs::read(stage.join("decoder")).unwrap(), b"bc");
    assert!(ARTIFACTS
        .iter()
        .all(|artifact| stage.join(artifact.filename).is_file()));
    assert!(stage.join("silero_vad.onnx").is_file());
    assert!(!stage.join("decoder.part").exists());
    assert_eq!(progress, [(2, 8), (3, 8), (4, 8), (5, 8), (7, 8), (8, 8)]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reports_fresh_retried_and_completed_progress_without_double_counting() {
    let root = root();
    let mut transport = Transport::new([
        Reply::Bytes(b"a"),
        Reply::Bytes(b"b"),
        Reply::Bytes(b"c"),
        Reply::Bytes(b"d"),
        Reply::Bytes(b"ef"),
        Reply::Bytes(b"vk"),
    ]);
    let mut progress = Vec::new();

    acquire_parakeet_stage(
        &root,
        "install",
        &MANIFEST,
        AsrAcquisitionLimits::default(),
        &mut transport,
        AsrAcquisitionRuntime {
            clock: &|| Duration::ZERO,
            retry_wait: &mut no_wait,
        },
        &|| false,
        &mut |completed, total| progress.push((completed, total)),
    )
    .unwrap();

    assert_eq!(
        progress,
        [(0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (6, 8), (8, 8)]
    );
    assert_eq!(transport.requests[1].1, 0);
    assert_eq!(transport.requests[2].1, 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checksum_failure_does_not_expose_the_bad_artifact_as_complete() {
    let root = root();
    let mut transport = Transport::new([Reply::Bytes(b"x")]);
    assert!(matches!(
        acquire_parakeet_stage(
            &root,
            "install",
            &MANIFEST,
            AsrAcquisitionLimits::default(),
            &mut transport,
            AsrAcquisitionRuntime {
                clock: &|| Duration::ZERO,
                retry_wait: &mut no_wait
            },
            &|| false,
            &mut |_, _| {}
        ),
        Err(AsrAcquisitionError::Verification(_))
    ));
    assert!(!root.join("install/encoder").exists());
    assert!(!root.join("install/encoder.part").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn vad_checksum_failure_keeps_the_complete_stage_unpublished() {
    let root = root();
    fs::create_dir(root.join("install")).unwrap();
    for (artifact, contents) in ARTIFACTS.iter().zip([b"a".as_slice(), b"bc", b"d", b"ef"]) {
        fs::write(root.join("install").join(artifact.filename), contents).unwrap();
    }
    let mut transport = Transport::new([Reply::Bytes(b"xx")]);
    assert!(matches!(
        acquire_parakeet_stage(
            &root,
            "install",
            &MANIFEST,
            AsrAcquisitionLimits::default(),
            &mut transport,
            AsrAcquisitionRuntime {
                clock: &|| Duration::ZERO,
                retry_wait: &mut no_wait
            },
            &|| false,
            &mut |_, _| {}
        ),
        Err(AsrAcquisitionError::Verification(_))
    ));
    assert!(!root.join("install/silero_vad.onnx").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn one_deadline_is_shared_across_files_and_retries() {
    let root = root();
    let now = Rc::new(Cell::new(Duration::ZERO));
    let clock_now = Rc::clone(&now);
    let clock = move || clock_now.get();
    let wait_now = Rc::clone(&now);
    let mut wait = move |_: Duration, _: &dyn AsrCancellation| {
        wait_now.set(Duration::from_secs(2));
        true
    };
    let mut transport = Transport::new([
        Reply::Error(AsrTransportError::Transient),
        Reply::Bytes(b"a"),
        Reply::Bytes(b"bc"),
        Reply::Bytes(b"d"),
        Reply::Bytes(b"ef"),
        Reply::Bytes(b"vk"),
    ]);
    acquire_parakeet_stage(
        &root,
        "install",
        &MANIFEST,
        AsrAcquisitionLimits {
            deadline: Duration::from_secs(10),
            ..Default::default()
        },
        &mut transport,
        AsrAcquisitionRuntime {
            clock: &clock,
            retry_wait: &mut wait,
        },
        &|| false,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        transport
            .requests
            .iter()
            .map(|request| request.2)
            .collect::<Vec<_>>(),
        [
            Duration::from_secs(10),
            Duration::from_secs(8),
            Duration::from_secs(8),
            Duration::from_secs(8),
            Duration::from_secs(8),
            Duration::from_secs(8)
        ]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cancellation_preserves_resumable_bytes() {
    let root = root();
    fs::create_dir(root.join("install")).unwrap();
    fs::write(root.join("install/encoder.part"), b"a").unwrap();
    let mut transport = Transport::new([]);
    let mut progress = Vec::new();
    assert_eq!(
        acquire_parakeet_stage(
            &root,
            "install",
            &MANIFEST,
            AsrAcquisitionLimits::default(),
            &mut transport,
            AsrAcquisitionRuntime {
                clock: &|| Duration::ZERO,
                retry_wait: &mut no_wait
            },
            &|| true,
            &mut |completed, total| progress.push((completed, total))
        ),
        Err(AsrAcquisitionError::Cancelled)
    );
    assert_eq!(progress, [(1, 8)]);
    assert_eq!(fs::read(root.join("install/encoder.part")).unwrap(), b"a");
    fs::remove_dir_all(root).unwrap();
}
