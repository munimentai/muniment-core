//! Verified acquisition and lifecycle management for pinned model artifacts.

pub mod acquisition;
pub mod install;
pub mod lifecycle;

use std::fs::File;
use std::io::{BufReader, Read};

use sha2::{Digest, Sha256};

/// The immutable identity and integrity pins for one model artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelArtifactDescriptor {
    pub name: &'static str,
    pub version: &'static str,
    pub source_url: &'static str,
    pub license: &'static str,
    pub filename: &'static str,
    pub byte_size: u64,
    pub sha256: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelVerificationError {
    Missing,
    NotRegularFile,
    WrongSize { expected: u64, actual: u64 },
    Unreadable,
    DigestMismatch,
}

impl std::fmt::Display for ModelVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "model artifact is missing"),
            Self::NotRegularFile => write!(f, "model artifact is not a regular file"),
            Self::WrongSize { expected, actual } => write!(
                f,
                "model artifact has wrong size (expected {expected} bytes, found {actual})"
            ),
            Self::Unreadable => write!(f, "model artifact cannot be read"),
            Self::DigestMismatch => write!(f, "model artifact digest does not match"),
        }
    }
}

impl std::error::Error for ModelVerificationError {}

/// Checks the file type, exact byte size, and SHA-256 digest in bounded memory.
pub fn verify_model_artifact(
    path: impl AsRef<std::path::Path>,
    descriptor: &ModelArtifactDescriptor,
) -> Result<(), ModelVerificationError> {
    let path = path.as_ref();
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ModelVerificationError::Missing
        } else {
            ModelVerificationError::Unreadable
        }
    })?;
    if !metadata.is_file() {
        return Err(ModelVerificationError::NotRegularFile);
    }
    if metadata.len() != descriptor.byte_size {
        return Err(ModelVerificationError::WrongSize {
            expected: descriptor.byte_size,
            actual: metadata.len(),
        });
    }
    let file = File::open(path).map_err(|_| ModelVerificationError::Unreadable)?;
    let actual = hash_reader(BufReader::new(file))?;
    if actual != descriptor.sha256 {
        return Err(ModelVerificationError::DigestMismatch);
    }
    Ok(())
}

fn hash_reader(mut reader: impl Read) -> Result<String, ModelVerificationError> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher).map_err(|_| ModelVerificationError::Unreadable)?;
    Ok(format!("{:x}", hasher.finalize()))
}
