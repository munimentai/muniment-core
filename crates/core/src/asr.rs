//! Verification boundary for the pinned offline ASR model set.

pub mod acquisition;
pub mod capture;
pub mod install;
pub mod pipeline;
mod recognizer;
pub mod utterance;
mod vad;
pub mod validation;

pub use pipeline::{DictationPipeline, DictationPipelineError, DictationPipelinePushError};
pub use recognizer::{OfflineParakeetRecognizer, OfflineRecognitionError};
pub use vad::{
    SileroVoiceActivityDetector, VadDecisionSource, VadError, VAD_FRAME_SIZE, VAD_SAMPLE_RATE,
};

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsrArtifactDescriptor {
    pub filename: &'static str,
    pub byte_size: u64,
    pub sha256: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsrArtifactManifest {
    pub identity: &'static str,
    pub revision: &'static str,
    pub artifacts: &'static [AsrArtifactDescriptor; 4],
    pub additional_artifact: Option<AsrSourcedArtifactDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsrSourcedArtifactDescriptor {
    pub repository: &'static str,
    pub revision: &'static str,
    pub artifact: AsrArtifactDescriptor,
}

pub const PARAKEET_ARTIFACTS: [AsrArtifactDescriptor; 4] = [
    AsrArtifactDescriptor {
        filename: "encoder.int8.onnx",
        byte_size: 652_282_294,
        sha256: "e38b783d40dba5755bcb2a3e703305d9e7a3d6f10c8c6d943c329e58b6dd8d07",
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
    identity: "parakeet-tdt-0.6b-v3-int8-v1",
    revision: "6da52323c581857056f9845291a40fb3846304eb",
    artifacts: &PARAKEET_ARTIFACTS,
    additional_artifact: Some(AsrSourcedArtifactDescriptor {
        repository: "csukuangfj/vad",
        revision: "af4fcfc9b8305246b1fe2ebcaf248975673166f1",
        artifact: AsrArtifactDescriptor {
            filename: "silero_vad.onnx",
            byte_size: 1_807_522,
            sha256: "a35ebf52fd3ce5f1469b2a36158dba761bc47b973ea3382b3186ca15b1f5af28",
        },
    }),
};

pub const PARAKEET_MODEL_MANIFESTS: [&AsrArtifactManifest; 1] = [&PARAKEET_MODEL_MANIFEST];

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
/// into memory. Success is reported only after every compiled artifact passes.
pub fn verify_parakeet_model_set(
    model_set_directory: impl AsRef<Path>,
) -> Result<(), AsrModelSetVerificationError> {
    verify_model_set(model_set_directory.as_ref(), &PARAKEET_MODEL_MANIFEST)
}

pub fn verify_model_set(
    directory: &Path,
    manifest: &AsrArtifactManifest,
) -> Result<(), AsrModelSetVerificationError> {
    for descriptor in manifest.artifacts {
        verify_artifact(&directory.join(descriptor.filename), descriptor)?;
    }
    if let Some(descriptor) = manifest.additional_artifact {
        verify_artifact(
            &directory.join(descriptor.artifact.filename),
            &descriptor.artifact,
        )?;
    }
    Ok(())
}

/// Platform operations whose portable durability and replacement semantics
/// cannot be provided by pure core.
pub trait AsrLifecycleBoundary {
    fn sync_file(&self, path: &Path) -> Result<(), AsrPersistenceError>;
    fn sync_directory(&self, path: &Path) -> Result<(), AsrPersistenceError>;
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), AsrPersistenceError>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AsrPersistenceError {
    Failed,
}

impl std::fmt::Debug for AsrPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AsrPersistenceError::Failed")
    }
}

impl std::fmt::Display for AsrPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ASR model state could not be persisted")
    }
}

impl std::error::Error for AsrPersistenceError {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AsrLifecycleError {
    InvalidManifest,
    InvalidPointer,
    UnknownPointer,
    RevisionMissing,
    RevisionInvalid(AsrModelSetVerificationError),
    Persistence(AsrPersistenceError),
}

impl std::fmt::Debug for AsrLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifest => f.write_str("AsrLifecycleError::InvalidManifest"),
            Self::InvalidPointer => f.write_str("AsrLifecycleError::InvalidPointer"),
            Self::UnknownPointer => f.write_str("AsrLifecycleError::UnknownPointer"),
            Self::RevisionMissing => f.write_str("AsrLifecycleError::RevisionMissing"),
            Self::RevisionInvalid(error) => f
                .debug_tuple("AsrLifecycleError::RevisionInvalid")
                .field(error)
                .finish(),
            Self::Persistence(error) => f
                .debug_tuple("AsrLifecycleError::Persistence")
                .field(error)
                .finish(),
        }
    }
}

impl std::fmt::Display for AsrLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifest => f.write_str("ASR model manifest is invalid"),
            Self::InvalidPointer => f.write_str("ASR model pointer is malformed"),
            Self::UnknownPointer => f.write_str("ASR model pointer is not recognized"),
            Self::RevisionMissing => f.write_str("ASR model revision is not installed"),
            Self::RevisionInvalid(_) => f.write_str("ASR model revision failed verification"),
            Self::Persistence(_) => f.write_str("ASR model state could not be persisted"),
        }
    }
}

impl std::error::Error for AsrLifecycleError {}

impl From<AsrPersistenceError> for AsrLifecycleError {
    fn from(value: AsrPersistenceError) -> Self {
        Self::Persistence(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsrRecovery {
    Current(PathBuf),
    RestoredPrevious(PathBuf),
    NotInstalled,
    RepairRequired,
}

/// Publication and resolution policy for a selected target among the compiled
/// ASR manifests known to this application version.
pub struct AsrRevisionLifecycle {
    root: PathBuf,
    manifests: &'static [&'static AsrArtifactManifest],
    target: &'static AsrArtifactManifest,
}

impl AsrRevisionLifecycle {
    pub fn new(
        root: PathBuf,
        manifests: &'static [&'static AsrArtifactManifest],
        target: &'static AsrArtifactManifest,
    ) -> Result<Self, AsrLifecycleError> {
        if manifests.is_empty()
            || !manifests.contains(&target)
            || manifests.iter().any(|manifest| !valid_manifest(manifest))
            || manifests.iter().enumerate().any(|(index, manifest)| {
                manifests[index + 1..].iter().any(|other| {
                    manifest.identity == other.identity && manifest.revision == other.revision
                })
            })
        {
            return Err(AsrLifecycleError::InvalidManifest);
        }
        Ok(Self {
            root,
            manifests,
            target,
        })
    }

    pub fn resolve_current(&self) -> Result<PathBuf, AsrLifecycleError> {
        self.resolve_pointer("current").map(|pointer| pointer.path)
    }

    pub fn publish(
        &self,
        staged_directory: &Path,
        boundary: &impl AsrLifecycleBoundary,
    ) -> Result<PathBuf, AsrLifecycleError> {
        self.publish_lock_held(staged_directory, boundary)
    }

    /// Publishes a verified stage while the caller retains `install.lock`.
    /// Coordinated installs use this entry point to avoid recursive locking.
    pub fn publish_lock_held(
        &self,
        staged_directory: &Path,
        boundary: &impl AsrLifecycleBoundary,
    ) -> Result<PathBuf, AsrLifecycleError> {
        if staged_directory.parent() != Some(self.root.join("staging").as_path()) {
            return Err(AsrLifecycleError::InvalidPointer);
        }
        verify_model_set(staged_directory, self.target)
            .map_err(AsrLifecycleError::RevisionInvalid)?;
        for artifact in self.target.artifacts {
            boundary.sync_file(&staged_directory.join(artifact.filename))?;
        }
        if let Some(artifact) = self.target.additional_artifact {
            boundary.sync_file(&staged_directory.join(artifact.artifact.filename))?;
        }
        boundary.sync_directory(staged_directory)?;

        let revisions = self.root.join("revisions");
        fs::create_dir_all(&revisions).map_err(|_| AsrPersistenceError::Failed)?;
        let revision = revisions.join(self.target.revision);
        // A directory can already exist for this exact identity and revision
        // when a prior application version published a smaller artifact set
        // (e.g. the four-file Parakeet manifest before the VAD artifact was
        // added). An already-complete revision is republished idempotently; a
        // legacy incomplete one is repaired in place after the pointer commits.
        let repair_incomplete = if !revision.exists() {
            fs::rename(staged_directory, &revision).map_err(|_| AsrPersistenceError::Failed)?;
            boundary.sync_directory(&revisions)?;
            false
        } else {
            verify_model_set(&revision, self.target).is_err()
        };

        if let Ok(current) = self.resolve_pointer("current") {
            self.write_pointer("previous", &current.value, boundary)?;
        }
        let target_pointer = pointer_value(self.target);
        self.write_pointer("current", &target_pointer, boundary)?;
        boundary.sync_directory(&self.root)?;

        // Repairing a legacy incomplete revision happens only once the pointer
        // has committed so an interrupted publication leaves the prior published
        // bytes and pointer unchanged and the completed stage retryable.
        if repair_incomplete {
            replace_revision_in_place(&revision, staged_directory, boundary)?;
        }
        Ok(revision)
    }

    pub fn recover(
        &self,
        boundary: &impl AsrLifecycleBoundary,
    ) -> Result<AsrRecovery, AsrLifecycleError> {
        match self.resolve_pointer("current") {
            Ok(pointer) => return Ok(AsrRecovery::Current(pointer.path)),
            Err(AsrLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {}
        }
        match self.resolve_pointer("previous") {
            Ok(pointer) => {
                self.write_pointer("current", &pointer.value, boundary)?;
                boundary.sync_directory(&self.root)?;
                Ok(AsrRecovery::RestoredPrevious(pointer.path))
            }
            Err(AsrLifecycleError::Persistence(error)) => Err(error.into()),
            Err(_)
                if !self.root.join("current").exists() && !self.root.join("previous").exists() =>
            {
                Ok(AsrRecovery::NotInstalled)
            }
            Err(_) => Ok(AsrRecovery::RepairRequired),
        }
    }

    fn resolve_pointer(&self, name: &str) -> Result<ResolvedPointer, AsrLifecycleError> {
        let value = fs::read_to_string(self.root.join(name)).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                AsrLifecycleError::RevisionMissing
            } else if error.kind() == std::io::ErrorKind::InvalidData {
                AsrLifecycleError::InvalidPointer
            } else {
                AsrLifecycleError::Persistence(AsrPersistenceError::Failed)
            }
        })?;
        let mut lines = value.lines();
        if lines.next() != Some("muniment-asr-pointer-v1")
            || lines.next().is_none()
            || lines.next().is_none()
            || lines.next().is_some()
        {
            return Err(AsrLifecycleError::InvalidPointer);
        }
        let mut lines = value.lines();
        lines.next();
        let identity = lines.next().unwrap();
        let revision = lines.next().unwrap();
        if !safe_component(identity) || !safe_component(revision) {
            return Err(AsrLifecycleError::InvalidPointer);
        }
        let manifest = self
            .manifests
            .iter()
            .copied()
            .find(|manifest| manifest.identity == identity && manifest.revision == revision)
            .ok_or(AsrLifecycleError::UnknownPointer)?;
        let path = self.root.join("revisions").join(revision);
        verify_model_set(&path, manifest).map_err(AsrLifecycleError::RevisionInvalid)?;
        Ok(ResolvedPointer { path, value })
    }

    fn write_pointer(
        &self,
        name: &str,
        value: &str,
        boundary: &impl AsrLifecycleBoundary,
    ) -> Result<(), AsrLifecycleError> {
        static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

        fs::create_dir_all(&self.root).map_err(|_| AsrPersistenceError::Failed)?;
        let (temporary, mut file) = loop {
            let temporary = self.root.join(format!(
                ".{name}.{}.{}.tmp",
                std::process::id(),
                NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => break (temporary, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(AsrPersistenceError::Failed.into()),
            }
        };
        let result: Result<(), AsrPersistenceError> = (|| {
            file.write_all(value.as_bytes())
                .map_err(|_| AsrPersistenceError::Failed)?;
            drop(file);
            boundary.sync_file(&temporary)?;
            boundary.replace_pointer(&temporary, &self.root.join(name))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(Into::into)
    }
}

struct ResolvedPointer {
    path: PathBuf,
    value: String,
}

/// Atomically swaps a legacy incomplete revision directory for the freshly
/// completed stage. The old directory is moved aside first so a failed swap can
/// be rolled back, leaving the prior published bytes and the retryable stage
/// intact.
fn replace_revision_in_place(
    revision: &Path,
    staged_directory: &Path,
    boundary: &impl AsrLifecycleBoundary,
) -> Result<(), AsrLifecycleError> {
    static NEXT_BACKUP: AtomicU64 = AtomicU64::new(0);

    let revisions = revision.parent().ok_or(AsrPersistenceError::Failed)?;
    let backup = revisions.join(format!(
        ".repair.{}.{}",
        std::process::id(),
        NEXT_BACKUP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::rename(revision, &backup).map_err(|_| AsrPersistenceError::Failed)?;
    if fs::rename(staged_directory, revision).is_err() {
        let _ = fs::rename(&backup, revision);
        return Err(AsrPersistenceError::Failed.into());
    }
    let synced = boundary.sync_directory(revisions);
    let _ = fs::remove_dir_all(&backup);
    synced?;
    Ok(())
}

fn pointer_value(manifest: &AsrArtifactManifest) -> String {
    format!(
        "muniment-asr-pointer-v1\n{}\n{}\n",
        manifest.identity, manifest.revision
    )
}

fn valid_manifest(manifest: &AsrArtifactManifest) -> bool {
    safe_component(manifest.identity)
        && safe_component(manifest.revision)
        && manifest.additional_artifact.is_none_or(|additional| {
            safe_source_component(additional.repository)
                && safe_component(additional.revision)
                && safe_component(additional.artifact.filename)
                && !manifest
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.filename == additional.artifact.filename)
        })
        && !manifest
            .artifacts
            .iter()
            .any(|artifact| !safe_component(artifact.filename))
        && !manifest
            .artifacts
            .iter()
            .enumerate()
            .any(|(index, artifact)| {
                manifest.artifacts[index + 1..]
                    .iter()
                    .any(|other| artifact.filename == other.filename)
            })
}

fn safe_source_component(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(owner), Some(repository), None)
        if safe_component(owner) && safe_component(repository))
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !Path::new(value).is_absolute()
}

pub(super) fn verify_artifact(
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
        identity: "test-manifest-v1",
        revision: "old",
        artifacts: &FIXTURES,
        additional_artifact: None,
    };
    const UPDATE_FIXTURES: [AsrArtifactDescriptor; 4] = [
        AsrArtifactDescriptor {
            filename: "one",
            byte_size: 1,
            sha256: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
        },
        AsrArtifactDescriptor {
            filename: "two",
            byte_size: 1,
            sha256: "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
        },
        AsrArtifactDescriptor {
            filename: "three",
            byte_size: 1,
            sha256: "cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29",
        },
        AsrArtifactDescriptor {
            filename: "four",
            byte_size: 1,
            sha256: "aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123",
        },
    ];
    const UPDATE_MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
        identity: "test-manifest-v2",
        revision: "new",
        artifacts: &UPDATE_FIXTURES,
        additional_artifact: None,
    };
    const KNOWN_MANIFESTS: [&AsrArtifactManifest; 2] = [&MANIFEST, &UPDATE_MANIFEST];

    // A shared identity and revision published first without, then with, an
    // additional VAD artifact. This models a legacy four-file install upgraded to
    // the complete VAD-bearing set by a newer application version.
    const LEGACY_MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
        identity: "parakeet-legacy",
        revision: "shared-rev",
        artifacts: &FIXTURES,
        additional_artifact: None,
    };
    const COMPLETE_MANIFEST: AsrArtifactManifest = AsrArtifactManifest {
        identity: "parakeet-legacy",
        revision: "shared-rev",
        artifacts: &FIXTURES,
        additional_artifact: Some(AsrSourcedArtifactDescriptor {
            repository: "csukuangfj/vad",
            revision: "vad-rev",
            artifact: AsrArtifactDescriptor {
                filename: "silero_vad.onnx",
                byte_size: 1,
                sha256: "4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080",
            },
        }),
    };
    const LEGACY_MANIFESTS: [&AsrArtifactManifest; 1] = [&LEGACY_MANIFEST];
    const COMPLETE_MANIFESTS: [&AsrArtifactManifest; 1] = [&COMPLETE_MANIFEST];

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

    struct TestBoundary {
        fail_current: AtomicBool,
    }

    impl TestBoundary {
        fn working() -> Self {
            Self {
                fail_current: AtomicBool::new(false),
            }
        }
        fn failing_current() -> Self {
            Self {
                fail_current: AtomicBool::new(true),
            }
        }
    }

    impl AsrLifecycleBoundary for TestBoundary {
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
            if destination.file_name().and_then(|name| name.to_str()) == Some("current")
                && self.fail_current.swap(false, Ordering::Relaxed)
            {
                return Err(AsrPersistenceError::Failed);
            }
            if destination.exists() {
                fs::remove_file(destination).map_err(|_| AsrPersistenceError::Failed)?;
            }
            fs::rename(temporary, destination).map_err(|_| AsrPersistenceError::Failed)
        }
    }

    fn lifecycle_fixture() -> (PathBuf, AsrRevisionLifecycle, PathBuf) {
        let root = fixture_directory();
        for artifact in MANIFEST.artifacts {
            fs::remove_file(root.join(artifact.filename)).unwrap();
        }
        fs::create_dir(root.join("staging")).unwrap();
        let stage = root.join("staging").join("install");
        fs::create_dir(&stage).unwrap();
        for (name, contents) in [
            ("one", b'a'),
            ("two", b'b'),
            ("three", b'c'),
            ("four", b'd'),
        ] {
            fs::write(stage.join(name), [contents]).unwrap();
        }
        let lifecycle =
            AsrRevisionLifecycle::new(root.clone(), &KNOWN_MANIFESTS, &MANIFEST).unwrap();
        (root, lifecycle, stage)
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

    #[test]
    fn publishes_and_resolves_only_a_verified_revision() {
        let (root, lifecycle, stage) = lifecycle_fixture();
        let revision = lifecycle.publish(&stage, &TestBoundary::working()).unwrap();
        assert_eq!(revision, root.join("revisions/old"));
        assert_eq!(lifecycle.resolve_current().unwrap(), revision);
        assert!(!stage.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_update_retains_previous_and_interrupted_replacement_keeps_current() {
        let (root, lifecycle, stage) = lifecycle_fixture();
        lifecycle.publish(&stage, &TestBoundary::working()).unwrap();
        let old_pointer = fs::read(root.join("current")).unwrap();
        let replacement_stage = root.join("staging/update");
        fs::create_dir(&replacement_stage).unwrap();
        for (name, contents) in [
            ("one", b'e'),
            ("two", b'f'),
            ("three", b'g'),
            ("four", b'h'),
        ] {
            fs::write(replacement_stage.join(name), [contents]).unwrap();
        }
        let update =
            AsrRevisionLifecycle::new(root.clone(), &KNOWN_MANIFESTS, &UPDATE_MANIFEST).unwrap();
        assert_eq!(
            update.publish(&replacement_stage, &TestBoundary::failing_current()),
            Err(AsrLifecycleError::Persistence(AsrPersistenceError::Failed))
        );
        assert_eq!(fs::read(root.join("current")).unwrap(), old_pointer);
        assert_eq!(
            update.resolve_current().unwrap(),
            root.join("revisions/old")
        );
        assert_eq!(fs::read(root.join("previous")).unwrap(), old_pointer);
        assert!(root.join("revisions/new").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_current_with_stale_pointer_temp_recovers_verified_previous() {
        let (root, lifecycle, stage) = lifecycle_fixture();
        lifecycle.publish(&stage, &TestBoundary::working()).unwrap();
        let replacement_stage = root.join("staging/update");
        fs::create_dir(&replacement_stage).unwrap();
        for (name, contents) in [
            ("one", b'e'),
            ("two", b'f'),
            ("three", b'g'),
            ("four", b'h'),
        ] {
            fs::write(replacement_stage.join(name), [contents]).unwrap();
        }
        let update =
            AsrRevisionLifecycle::new(root.clone(), &KNOWN_MANIFESTS, &UPDATE_MANIFEST).unwrap();
        update
            .publish(&replacement_stage, &TestBoundary::working())
            .unwrap();
        fs::remove_file(root.join("revisions/new/four")).unwrap();
        fs::write(root.join(".current.tmp"), "interrupted pointer write").unwrap();
        fs::create_dir(root.join("staging/tempting-complete-set")).unwrap();
        assert_eq!(
            update.recover(&TestBoundary::working()).unwrap(),
            AsrRecovery::RestoredPrevious(root.join("revisions/old"))
        );
        assert_eq!(
            update.resolve_current().unwrap(),
            root.join("revisions/old")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unknown_absolute_and_traversal_pointers_with_redacted_errors() {
        let (root, lifecycle, _) = lifecycle_fixture();
        for pointer in [
            "muniment-asr-pointer-v1\nunknown\nold\n",
            "muniment-asr-pointer-v1\ntest-manifest-v1\n/absolute\n",
            "muniment-asr-pointer-v1\ntest-manifest-v1\n../test\n",
        ] {
            fs::write(root.join("current"), pointer).unwrap();
            let error = lifecycle.resolve_current().unwrap_err();
            assert!(matches!(
                error,
                AsrLifecycleError::UnknownPointer | AsrLifecycleError::InvalidPointer
            ));
            assert!(!format!("{error:?} {error}").contains(root.to_str().unwrap()));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_incomplete_revision_is_repaired_and_failed_publish_stays_retryable() {
        let root = fixture_directory();
        for artifact in FIXTURES {
            fs::remove_file(root.join(artifact.filename)).unwrap();
        }
        fs::create_dir(root.join("staging")).unwrap();

        // Publish the legacy four-artifact revision exactly as the prior
        // application version would have, colliding on identity and revision.
        let legacy_stage = root.join("staging/legacy");
        fs::create_dir(&legacy_stage).unwrap();
        for (name, contents) in [
            ("one", b'a'),
            ("two", b'b'),
            ("three", b'c'),
            ("four", b'd'),
        ] {
            fs::write(legacy_stage.join(name), [contents]).unwrap();
        }
        let legacy =
            AsrRevisionLifecycle::new(root.clone(), &LEGACY_MANIFESTS, &LEGACY_MANIFEST).unwrap();
        legacy
            .publish(&legacy_stage, &TestBoundary::working())
            .unwrap();
        let revision = root.join("revisions/shared-rev");
        assert!(!revision.join("silero_vad.onnx").exists());
        let legacy_pointer = fs::read(root.join("current")).unwrap();

        // The upgraded application version only knows the complete manifest.
        let upgraded =
            AsrRevisionLifecycle::new(root.clone(), &COMPLETE_MANIFESTS, &COMPLETE_MANIFEST)
                .unwrap();
        let stage = root.join("staging/upgrade");
        fs::create_dir(&stage).unwrap();
        for (name, contents) in [
            ("one", b'a'),
            ("two", b'b'),
            ("three", b'c'),
            ("four", b'd'),
        ] {
            fs::write(stage.join(name), [contents]).unwrap();
        }
        fs::write(stage.join("silero_vad.onnx"), b"v").unwrap();

        // A publication interrupted at the current-pointer write leaves the
        // legacy bytes and pointer untouched and keeps the completed stage.
        assert_eq!(
            upgraded.publish(&stage, &TestBoundary::failing_current()),
            Err(AsrLifecycleError::Persistence(AsrPersistenceError::Failed))
        );
        assert_eq!(fs::read(root.join("current")).unwrap(), legacy_pointer);
        assert_eq!(verify_model_set(&revision, &LEGACY_MANIFEST), Ok(()));
        assert!(!revision.join("silero_vad.onnx").exists());
        assert!(stage.join("silero_vad.onnx").exists());

        // Retrying repairs the revision in place and makes the complete
        // five-artifact set the current revision.
        let installed = upgraded.publish(&stage, &TestBoundary::working()).unwrap();
        assert_eq!(installed, revision);
        assert_eq!(verify_model_set(&revision, &COMPLETE_MANIFEST), Ok(()));
        assert_eq!(upgraded.resolve_current().unwrap(), revision);
        assert!(!stage.exists());
        assert!(
            !root.join("revisions").read_dir().unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".repair."))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_not_installed_or_repair_required_when_no_pointer_resolves() {
        let (root, lifecycle, _) = lifecycle_fixture();
        assert_eq!(
            lifecycle.recover(&TestBoundary::working()).unwrap(),
            AsrRecovery::NotInstalled
        );
        fs::write(root.join("current"), "malformed").unwrap();
        assert_eq!(
            lifecycle.recover(&TestBoundary::working()).unwrap(),
            AsrRecovery::RepairRequired
        );
        fs::remove_dir_all(root).unwrap();
    }
}
