//! Verification boundary for the pinned offline ASR model set.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsrArtifactDescriptor {
    pub filename: &'static str,
    pub byte_size: u64,
    pub sha256: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsrArtifactManifest {
    pub revision: &'static str,
    pub artifacts: &'static [AsrArtifactDescriptor; 4],
}

pub const PARAKEET_ARTIFACTS: [AsrArtifactDescriptor; 4] = [
    AsrArtifactDescriptor {
        filename: "encoder.int8.onnx",
        byte_size: 652_184_281,
        sha256: "acfc2b4456377e15d04f0243af540b7fe7c992f8d898d751cf134c3a55fd2247",
    },
    AsrArtifactDescriptor {
        filename: "decoder.int8.onnx",
        byte_size: 11_845_275,
        sha256: "179e50c43d1a9de79c8a24149a2f9bac6eb5981823f2a2ed88d655b24248db4e",
    },
    AsrArtifactDescriptor {
        filename: "joiner.int8.onnx",
        byte_size: 6_355_277,
        sha256: "3164c13fc2821009440d20fcb5fdc78bff28b4db2f8d0f0b329101719c0948b3",
    },
    AsrArtifactDescriptor {
        filename: "tokens.txt",
        byte_size: 93_939,
        sha256: "d58544679ea4bc6ac563d1f545eb7d474bd6cfa467f0a6e2c1dc1c7d37e3c35d",
    },
];

pub const PARAKEET_MODEL_MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
    revision: "2bda32ec70b097a55adaa07d9a7173915b43cc78",
    artifacts: &PARAKEET_ARTIFACTS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsrModelSetVerificationError {
    Missing,
    NotRegularFile,
    WrongSize { expected: u64, actual: u64 },
    Unreadable,
    DigestMismatch,
}

impl std::fmt::Display for AsrModelSetVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "ASR model set is incomplete"),
            Self::NotRegularFile => write!(f, "ASR model set contains a non-regular artifact"),
            Self::WrongSize { .. } => {
                write!(f, "ASR model set contains an artifact with the wrong size")
            }
            Self::Unreadable => write!(f, "ASR model set contains an unreadable artifact"),
            Self::DigestMismatch => write!(
                f,
                "ASR model set contains an artifact with an invalid digest"
            ),
        }
    }
}

impl std::error::Error for AsrModelSetVerificationError {}

/// Verifies the complete pinned Parakeet model set without loading an artifact
/// into memory. Success is reported only after all four artifacts pass.
pub fn verify_parakeet_model_set(
    model_set_directory: impl AsRef<Path>,
) -> Result<(), AsrModelSetVerificationError> {
    verify_model_set(model_set_directory.as_ref(), &PARAKEET_MODEL_MANIFEST)
}

fn verify_model_set(
    directory: &Path,
    manifest: &AsrArtifactManifest,
) -> Result<(), AsrModelSetVerificationError> {
    for descriptor in manifest.artifacts {
        verify_artifact(&directory.join(descriptor.filename), descriptor)?;
    }
    Ok(())
}

fn verify_artifact(
    path: &Path,
    descriptor: &AsrArtifactDescriptor,
) -> Result<(), AsrModelSetVerificationError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AsrModelSetVerificationError::Missing
        } else {
            AsrModelSetVerificationError::Unreadable
        }
    })?;
    if !metadata.is_file() {
        return Err(AsrModelSetVerificationError::NotRegularFile);
    }
    if metadata.len() != descriptor.byte_size {
        return Err(AsrModelSetVerificationError::WrongSize {
            expected: descriptor.byte_size,
            actual: metadata.len(),
        });
    }

    let file = File::open(path).map_err(|_| AsrModelSetVerificationError::Unreadable)?;
    let digest = hash_reader(BufReader::new(file))?;
    if digest != descriptor.sha256 {
        return Err(AsrModelSetVerificationError::DigestMismatch);
    }
    Ok(())
}

fn hash_reader(mut reader: impl Read) -> Result<String, AsrModelSetVerificationError> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher)
        .map_err(|_| AsrModelSetVerificationError::Unreadable)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};
    use std::sync::atomic::{AtomicU64, Ordering};

    const FIXTURES: [AsrArtifactDescriptor; 4] = [
        AsrArtifactDescriptor {
            filename: "one",
            byte_size: 1,
            sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        },
        AsrArtifactDescriptor {
            filename: "two",
            byte_size: 1,
            sha256: "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
        },
        AsrArtifactDescriptor {
            filename: "three",
            byte_size: 1,
            sha256: "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
        },
        AsrArtifactDescriptor {
            filename: "four",
            byte_size: 1,
            sha256: "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
        },
    ];
    const MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
        revision: "test",
        artifacts: &FIXTURES,
    };

    fn fixture_directory() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "muniment-asr-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        for (name, contents) in [
            ("one", b'a'),
            ("two", b'b'),
            ("three", b'c'),
            ("four", b'd'),
        ] {
            std::fs::write(path.join(name), [contents]).unwrap();
        }
        path
    }

    #[test]
    fn verifies_complete_set() {
        let directory = fixture_directory();
        assert_eq!(verify_model_set(&directory, &MANIFEST), Ok(()));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reports_each_artifact_failure_class_and_late_failure() {
        let directory = fixture_directory();
        std::fs::remove_file(directory.join("four")).unwrap();
        assert_eq!(
            verify_model_set(&directory, &MANIFEST),
            Err(AsrModelSetVerificationError::Missing)
        );
        std::fs::create_dir(directory.join("four")).unwrap();
        assert_eq!(
            verify_model_set(&directory, &MANIFEST),
            Err(AsrModelSetVerificationError::NotRegularFile)
        );
        std::fs::remove_dir(directory.join("four")).unwrap();
        std::fs::write(directory.join("four"), b"too long").unwrap();
        assert_eq!(
            verify_model_set(&directory, &MANIFEST),
            Err(AsrModelSetVerificationError::WrongSize {
                expected: 1,
                actual: 8
            })
        );
        std::fs::write(directory.join("four"), b"x").unwrap();
        assert_eq!(
            verify_model_set(&directory, &MANIFEST),
            Err(AsrModelSetVerificationError::DigestMismatch)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    struct Unreadable;
    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture secret",
            ))
        }
    }

    #[test]
    fn reports_unreadable_stream_without_exposing_cause() {
        assert_eq!(
            hash_reader(Unreadable),
            Err(AsrModelSetVerificationError::Unreadable)
        );
        assert!(!AsrModelSetVerificationError::Unreadable
            .to_string()
            .contains("secret"));
    }

    #[cfg(unix)]
    #[test]
    fn reports_unreadable_artifact() {
        use std::os::unix::fs::symlink;

        let directory = fixture_directory();
        std::fs::remove_file(directory.join("four")).unwrap();
        symlink("four", directory.join("four")).unwrap();
        assert_eq!(
            verify_model_set(&directory, &MANIFEST),
            Err(AsrModelSetVerificationError::Unreadable)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hashes_streamed_content() {
        let mut bytes = Vec::new();
        Cursor::new(b"abc").read_to_end(&mut bytes).unwrap();
        assert_eq!(
            hash_reader(Cursor::new(bytes)).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn user_facing_errors_do_not_include_paths_or_contents() {
        let secret = "/caller/private/model contents";
        for error in [
            AsrModelSetVerificationError::Missing,
            AsrModelSetVerificationError::NotRegularFile,
            AsrModelSetVerificationError::WrongSize {
                expected: 1,
                actual: 2,
            },
            AsrModelSetVerificationError::Unreadable,
            AsrModelSetVerificationError::DigestMismatch,
        ] {
            assert!(!error.to_string().contains(secret));
        }
    }
}
