use muniment_core::model_artifact::lifecycle::{
    ModelArtifactLifecycleError, ModelArtifactNoticeDescriptor, ModelArtifactRevisionDescriptor,
    ModelArtifactRevisionLifecycle,
};
use muniment_core::model_artifact::ModelArtifactDescriptor;

const NOTICE: ModelArtifactNoticeDescriptor = ModelArtifactNoticeDescriptor {
    filename: "NOTICE.txt",
    contents: b"fixture notice",
};

static INVALID_NAME_ARTIFACT: ModelArtifactDescriptor =
    descriptor("../extractor", "v1", 3, VALID_SHA);
static INVALID_NAME: ModelArtifactRevisionDescriptor = revision(&INVALID_NAME_ARTIFACT);
static INVALID_NAME_SET: [&ModelArtifactRevisionDescriptor; 1] = [&INVALID_NAME];

static INVALID_VERSION_ARTIFACT: ModelArtifactDescriptor =
    descriptor("extractor", "../v1", 3, VALID_SHA);
static INVALID_VERSION: ModelArtifactRevisionDescriptor = revision(&INVALID_VERSION_ARTIFACT);
static INVALID_VERSION_SET: [&ModelArtifactRevisionDescriptor; 1] = [&INVALID_VERSION];

static ZERO_SIZE_ARTIFACT: ModelArtifactDescriptor = descriptor("extractor", "v1", 0, VALID_SHA);
static ZERO_SIZE: ModelArtifactRevisionDescriptor = revision(&ZERO_SIZE_ARTIFACT);
static ZERO_SIZE_SET: [&ModelArtifactRevisionDescriptor; 1] = [&ZERO_SIZE];

static INVALID_SHA_ARTIFACT: ModelArtifactDescriptor = descriptor("extractor", "v1", 3, "abc");
static INVALID_SHA: ModelArtifactRevisionDescriptor = revision(&INVALID_SHA_ARTIFACT);
static INVALID_SHA_SET: [&ModelArtifactRevisionDescriptor; 1] = [&INVALID_SHA];

const VALID_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const fn descriptor(
    name: &'static str,
    version: &'static str,
    byte_size: u64,
    sha256: &'static str,
) -> ModelArtifactDescriptor {
    ModelArtifactDescriptor {
        name,
        version,
        source_url: "https://huggingface.co/munimentai/extractor/resolve/v1/model.onnx",
        license: "fixture",
        filename: "model.onnx",
        byte_size,
        sha256,
    }
}

const fn revision(model: &'static ModelArtifactDescriptor) -> ModelArtifactRevisionDescriptor {
    ModelArtifactRevisionDescriptor {
        model,
        notice: NOTICE,
    }
}

fn rejects(
    descriptors: &'static [&'static ModelArtifactRevisionDescriptor],
    target: &'static ModelArtifactRevisionDescriptor,
) {
    assert!(matches!(
        ModelArtifactRevisionLifecycle::new("unused".into(), descriptors, target),
        Err(ModelArtifactLifecycleError::InvalidDescriptor)
    ));
}

#[test]
fn unsafe_name_fails_closed() {
    rejects(&INVALID_NAME_SET, &INVALID_NAME);
}

#[test]
fn unsafe_version_fails_closed() {
    rejects(&INVALID_VERSION_SET, &INVALID_VERSION);
}

#[test]
fn zero_byte_size_fails_closed() {
    rejects(&ZERO_SIZE_SET, &ZERO_SIZE);
}

#[test]
fn malformed_sha256_fails_closed() {
    rejects(&INVALID_SHA_SET, &INVALID_SHA);
}
