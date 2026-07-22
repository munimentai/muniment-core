//! Verification and acquisition boundary for the pinned Kokoro v1.0 assets.

pub mod acquisition;
pub mod lifecycle;

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KokoroArtifactDescriptor {
    pub(crate) filename: &'static str,
    pub(crate) source_url: &'static str,
    pub(crate) byte_size: u64,
    pub(crate) sha256: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KokoroRevisionDescriptor {
    pub(crate) identity: &'static str,
    pub(crate) artifacts: &'static [KokoroArtifactDescriptor; 2],
}

pub const KOKORO_ARTIFACTS: [KokoroArtifactDescriptor; 2] = [
    KokoroArtifactDescriptor {
        filename: "kokoro-v1.0.int8.onnx",
        source_url: "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/kokoro-v1.0.int8.onnx",
        byte_size: 92_361_271,
        sha256: "6e742170d309016e5891a994e1ce1559c702a2ccd0075e67ef7157974f6406cb",
    },
    KokoroArtifactDescriptor {
        filename: "voices-v1.0.bin",
        source_url: "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/voices-v1.0.bin",
        byte_size: 28_214_398,
        sha256: "bca610b8308e8d99f32e6fe4197e7ec01679264efed0cac9140fe9c29f1fbf7d",
    },
];

pub const KOKORO_V1: KokoroRevisionDescriptor = KokoroRevisionDescriptor {
    identity: "kokoro-v1.0-int8",
    artifacts: &KOKORO_ARTIFACTS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KokoroVerificationError {
    Missing,
    UnexpectedEntry,
    NotRegularFile,
    WrongSize { expected: u64, actual: u64 },
    Unreadable,
    DigestMismatch,
}

impl std::fmt::Display for KokoroVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kokoro stage failed verification")
    }
}
impl std::error::Error for KokoroVerificationError {}

/// Verifies that a directory contains exactly the two pinned regular files.
pub fn verify_kokoro_stage(directory: &Path) -> Result<(), KokoroVerificationError> {
    verify_revision_stage(directory, &KOKORO_V1)
}

pub(crate) fn verify_revision_stage(
    directory: &Path,
    descriptor: &KokoroRevisionDescriptor,
) -> Result<(), KokoroVerificationError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| KokoroVerificationError::Missing)?;
    if !metadata.file_type().is_dir() {
        return Err(KokoroVerificationError::NotRegularFile);
    }
    let entries = fs::read_dir(directory).map_err(|_| KokoroVerificationError::Unreadable)?;
    let mut count = 0;
    for entry in entries {
        let entry = entry.map_err(|_| KokoroVerificationError::Unreadable)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(KokoroVerificationError::UnexpectedEntry)?;
        if !descriptor
            .artifacts
            .iter()
            .any(|artifact| artifact.filename == name)
        {
            return Err(KokoroVerificationError::UnexpectedEntry);
        }
        count += 1;
    }
    if count != descriptor.artifacts.len() {
        return Err(KokoroVerificationError::Missing);
    }
    for artifact in descriptor.artifacts {
        verify_kokoro_artifact(&directory.join(artifact.filename), artifact)?;
    }
    Ok(())
}

pub(crate) fn verify_kokoro_artifact(
    path: &Path,
    descriptor: &KokoroArtifactDescriptor,
) -> Result<(), KokoroVerificationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => KokoroVerificationError::Missing,
        _ => KokoroVerificationError::Unreadable,
    })?;
    if !metadata.file_type().is_file() {
        return Err(KokoroVerificationError::NotRegularFile);
    }
    if metadata.len() != descriptor.byte_size {
        return Err(KokoroVerificationError::WrongSize {
            expected: descriptor.byte_size,
            actual: metadata.len(),
        });
    }
    let file = File::open(path).map_err(|_| KokoroVerificationError::Unreadable)?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| KokoroVerificationError::Unreadable)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != descriptor.sha256 {
        return Err(KokoroVerificationError::DigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_matches_adr_0015_exactly() {
        assert_eq!(KOKORO_V1.artifacts.len(), 2);
        assert_eq!(KOKORO_ARTIFACTS[0].filename, "kokoro-v1.0.int8.onnx");
        assert_eq!(KOKORO_ARTIFACTS[0].byte_size, 92_361_271);
        assert_eq!(
            KOKORO_ARTIFACTS[0].sha256,
            "6e742170d309016e5891a994e1ce1559c702a2ccd0075e67ef7157974f6406cb"
        );
        assert_eq!(KOKORO_ARTIFACTS[1].filename, "voices-v1.0.bin");
        assert_eq!(KOKORO_ARTIFACTS[1].byte_size, 28_214_398);
        assert_eq!(
            KOKORO_ARTIFACTS[1].sha256,
            "bca610b8308e8d99f32e6fe4197e7ec01679264efed0cac9140fe9c29f1fbf7d"
        );
        for artifact in KOKORO_ARTIFACTS {
            assert_eq!(artifact.source_url, format!("https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/{}", artifact.filename));
        }
    }
}
