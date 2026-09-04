use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use muniment_core::model_artifact::{
    verify_model_artifact, ModelArtifactDescriptor, ModelVerificationError,
};

static ARTIFACT: ModelArtifactDescriptor = ModelArtifactDescriptor {
    name: "extractor",
    version: "fixture-v1",
    source_url: "https://huggingface.co/munimentai/extractor/resolve/fixture-v1/model.onnx",
    license: "fixture",
    filename: "model.onnx",
    byte_size: 3,
    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
};

fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "muniment-model-verification-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}

#[test]
fn exact_size_and_digest_pass_verification() {
    let root = root();
    let path = root.join(ARTIFACT.filename);
    fs::write(&path, b"abc").unwrap();
    assert_eq!(verify_model_artifact(&path, &ARTIFACT), Ok(()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_artifact_fails_closed() {
    let root = root();
    assert_eq!(
        verify_model_artifact(root.join(ARTIFACT.filename), &ARTIFACT),
        Err(ModelVerificationError::Missing)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn non_file_artifact_fails_closed() {
    let root = root();
    let path = root.join(ARTIFACT.filename);
    fs::create_dir(&path).unwrap();
    assert_eq!(
        verify_model_artifact(&path, &ARTIFACT),
        Err(ModelVerificationError::NotRegularFile)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn byte_size_mismatch_fails_closed() {
    let root = root();
    let path = root.join(ARTIFACT.filename);
    fs::write(&path, b"ab").unwrap();
    assert_eq!(
        verify_model_artifact(&path, &ARTIFACT),
        Err(ModelVerificationError::WrongSize {
            expected: 3,
            actual: 2,
        })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sha256_mismatch_fails_closed() {
    let root = root();
    let path = root.join(ARTIFACT.filename);
    fs::write(&path, b"abd").unwrap();
    assert_eq!(
        verify_model_artifact(&path, &ARTIFACT),
        Err(ModelVerificationError::DigestMismatch)
    );
    fs::remove_dir_all(root).unwrap();
}
