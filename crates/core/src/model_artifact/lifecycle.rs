//! Filesystem publication and crash recovery for model-artifact revisions.
//!
//! Locking and durable replacement are platform concerns, so callers inject
//! those operations. Core owns the layout, verification, pointer format, and
//! the rule that staging is never considered during recovery.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{verify_model_artifact, ModelArtifactDescriptor, ModelVerificationError};

const POINTER_HEADER: &str = "muniment-model-artifact-pointer-v1";

/// The only startup detail persisted by activation. These categories are
/// deliberately incapable of carrying paths, process output, or HTTP bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelArtifactActivationFailure {
    Start,
    ExitedBeforeReady,
    Readiness,
}

impl ModelArtifactActivationFailure {
    fn persisted(self) -> &'static str {
        match self {
            Self::Start => "start\n",
            Self::ExitedBeforeReady => "exited-before-ready\n",
            Self::Readiness => "readiness\n",
        }
    }
}

/// Injectable process and bounded-health boundary used by pure core.
pub trait ModelArtifactActivationBoundary {
    type Server;

    fn launch(&self, model: &Path) -> Result<Self::Server, ModelArtifactActivationFailure>;
    fn await_ready(&self, server: &mut Self::Server) -> Result<(), ModelArtifactActivationFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelArtifactUnavailable {
    CurrentInvalid,
    PreviousInvalid,
    RollbackActivationFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ModelArtifactActivation<S> {
    Active { revision: PathBuf, server: S },
    RolledBack { revision: PathBuf, server: S },
    Unavailable(ModelArtifactUnavailable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelArtifactRevisionDescriptor {
    pub model: &'static ModelArtifactDescriptor,
    pub notice: ModelArtifactNoticeDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelArtifactNoticeDescriptor {
    pub filename: &'static str,
    pub contents: &'static [u8],
}

/// Platform operations required to serialize and durably publish state.
pub trait ModelArtifactLifecycleBoundary {
    type LockGuard;

    fn lock_exclusive(&self, path: &Path)
        -> Result<Self::LockGuard, ModelArtifactPersistenceError>;
    fn sync_file(&self, path: &Path) -> Result<(), ModelArtifactPersistenceError>;
    fn sync_directory(&self, path: &Path) -> Result<(), ModelArtifactPersistenceError>;
    /// Publishes `staged` at `destination`, replacing an existing corrupt
    /// revision if necessary. The operation must be crash-safe: interruption
    /// may leave either directory unpublished, but must never expose a partial
    /// revision at `destination`.
    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), ModelArtifactPersistenceError>;
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), ModelArtifactPersistenceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelArtifactPersistenceError {
    Failed,
}

impl std::fmt::Display for ModelArtifactPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("model artifact state could not be persisted")
    }
}

impl std::error::Error for ModelArtifactPersistenceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelArtifactLifecycleError {
    InvalidDescriptor,
    InvalidStage,
    InvalidPointer,
    UnknownPointer,
    RevisionMissing,
    RevisionInvalid(ModelVerificationError),
    Persistence(ModelArtifactPersistenceError),
}

impl std::fmt::Display for ModelArtifactLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDescriptor => f.write_str("model artifact descriptor is invalid"),
            Self::InvalidStage => f.write_str("model artifact stage is invalid"),
            Self::InvalidPointer => f.write_str("model artifact pointer is malformed"),
            Self::UnknownPointer => f.write_str("model artifact pointer is not recognized"),
            Self::RevisionMissing => f.write_str("model artifact revision is not installed"),
            Self::RevisionInvalid(_) => f.write_str("model artifact revision failed verification"),
            Self::Persistence(_) => f.write_str("model artifact state could not be persisted"),
        }
    }
}

impl std::error::Error for ModelArtifactLifecycleError {}

impl From<ModelArtifactPersistenceError> for ModelArtifactLifecycleError {
    fn from(error: ModelArtifactPersistenceError) -> Self {
        Self::Persistence(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelArtifactRecovery {
    Current(PathBuf),
    RestoredPrevious(PathBuf),
    NotInstalled,
    RepairRequired,
}

pub struct ModelArtifactRevisionLifecycle {
    root: PathBuf,
    descriptors: &'static [&'static ModelArtifactRevisionDescriptor],
    target: &'static ModelArtifactRevisionDescriptor,
}

impl ModelArtifactRevisionLifecycle {
    pub fn new(
        root: PathBuf,
        descriptors: &'static [&'static ModelArtifactRevisionDescriptor],
        target: &'static ModelArtifactRevisionDescriptor,
    ) -> Result<Self, ModelArtifactLifecycleError> {
        if descriptors.is_empty()
            || !descriptors.contains(&target)
            || descriptors
                .iter()
                .any(|descriptor| !valid_descriptor(descriptor))
            || descriptors.iter().enumerate().any(|(index, descriptor)| {
                descriptors[index + 1..].iter().any(|other| {
                    descriptor.model.name == other.model.name
                        && descriptor.model.version == other.model.version
                })
            })
        {
            return Err(ModelArtifactLifecycleError::InvalidDescriptor);
        }
        Ok(Self {
            root,
            descriptors,
            target,
        })
    }

    pub fn resolve_current(&self) -> Result<PathBuf, ModelArtifactLifecycleError> {
        self.resolve_pointer("current").map(|pointer| pointer.path)
    }

    pub fn publish<B: ModelArtifactLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, ModelArtifactLifecycleError> {
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        self.publish_lock_held(staged_directory, boundary)
    }

    /// Publishes a verified stage while the caller retains `install.lock`.
    /// Coordinated installs use this entry point to avoid recursive locking.
    pub fn publish_lock_held<B: ModelArtifactLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, ModelArtifactLifecycleError> {
        if staged_directory.parent() != Some(self.root.join("staging").as_path()) {
            return Err(ModelArtifactLifecycleError::InvalidStage);
        }
        require_directory(staged_directory)
            .map_err(|_| ModelArtifactLifecycleError::InvalidStage)?;
        let staged_model = staged_directory.join(self.target.model.filename);
        let staged_notice = staged_directory.join(self.target.notice.filename);
        verify_model_artifact(&staged_model, self.target.model)
            .map_err(ModelArtifactLifecycleError::RevisionInvalid)?;
        verify_notice(&staged_notice, self.target.notice)
            .map_err(ModelArtifactLifecycleError::RevisionInvalid)?;
        boundary.sync_file(&staged_model)?;
        boundary.sync_file(&staged_notice)?;
        boundary.sync_directory(staged_directory)?;

        let revisions = self.root.join("revisions");
        create_directory(&revisions)?;
        let artifact_revisions = revisions.join(self.target.model.name);
        create_directory(&artifact_revisions)?;
        boundary.sync_directory(&revisions)?;
        let revision = artifact_revisions.join(self.target.model.version);
        let installed_is_valid = require_directory(&revision).is_ok()
            && verify_model_artifact(revision.join(self.target.model.filename), self.target.model)
                .is_ok()
            && verify_notice(
                revision.join(self.target.notice.filename),
                self.target.notice,
            )
            .is_ok();
        if !installed_is_valid {
            boundary.replace_revision(staged_directory, &revision)?;
            boundary.sync_directory(&artifact_revisions)?;
        }

        let target_pointer = pointer_value(self.target);
        if let Ok(current) = self.resolve_pointer("current") {
            if current.value != target_pointer {
                self.write_pointer("previous", &current.value, boundary)?;
            }
        }
        self.write_pointer("current", &target_pointer, boundary)?;
        boundary.sync_directory(&self.root)?;
        Ok(revision)
    }

    pub fn recover<B: ModelArtifactLifecycleBoundary>(
        &self,
        boundary: &B,
    ) -> Result<ModelArtifactRecovery, ModelArtifactLifecycleError> {
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        match self.resolve_pointer("current") {
            Ok(pointer) => return Ok(ModelArtifactRecovery::Current(pointer.path)),
            Err(ModelArtifactLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {}
        }
        match self.resolve_pointer("previous") {
            Ok(pointer) => {
                self.write_pointer("current", &pointer.value, boundary)?;
                boundary.sync_directory(&self.root)?;
                Ok(ModelArtifactRecovery::RestoredPrevious(pointer.path))
            }
            Err(ModelArtifactLifecycleError::Persistence(error)) => Err(error.into()),
            Err(_)
                if !path_entry_exists(&self.root.join("current"))
                    && !path_entry_exists(&self.root.join("previous")) =>
            {
                Ok(ModelArtifactRecovery::NotInstalled)
            }
            Err(_) => Ok(ModelArtifactRecovery::RepairRequired),
        }
    }

    /// Activates the verified current revision. A failed bounded startup marks
    /// that revision rejected, restores verified previous atomically, and
    /// makes exactly one rollback activation attempt.
    pub fn activate<B: ModelArtifactLifecycleBoundary, A: ModelArtifactActivationBoundary>(
        &self,
        persistence: &B,
        activation: &A,
    ) -> Result<ModelArtifactActivation<A::Server>, ModelArtifactLifecycleError> {
        let _lock = persistence.lock_exclusive(&self.root.join("install.lock"))?;
        let current = match self.resolve_pointer("current") {
            Ok(pointer) => pointer,
            Err(ModelArtifactLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {
                return Ok(ModelArtifactActivation::Unavailable(
                    ModelArtifactUnavailable::CurrentInvalid,
                ))
            }
        };
        if self
            .resolve_pointer("rejected")
            .is_ok_and(|rejected| rejected.value == current.value)
        {
            return self.activate_previous(persistence, activation);
        }
        match activate_pointer(&current, activation) {
            Ok(server) => Ok(ModelArtifactActivation::Active {
                revision: current.path,
                server,
            }),
            Err(failure) => {
                self.write_pointer("rejected", &current.value, persistence)?;
                persistence.sync_directory(&self.root)?;
                self.write_redacted_failure(failure, persistence)?;
                self.activate_previous(persistence, activation)
            }
        }
    }

    fn activate_previous<B: ModelArtifactLifecycleBoundary, A: ModelArtifactActivationBoundary>(
        &self,
        persistence: &B,
        activation: &A,
    ) -> Result<ModelArtifactActivation<A::Server>, ModelArtifactLifecycleError> {
        let previous = match self.resolve_pointer("previous") {
            Ok(pointer) => pointer,
            Err(ModelArtifactLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {
                return Ok(ModelArtifactActivation::Unavailable(
                    ModelArtifactUnavailable::PreviousInvalid,
                ))
            }
        };
        self.write_pointer("current", &previous.value, persistence)?;
        persistence.sync_directory(&self.root)?;
        match activate_pointer(&previous, activation) {
            Ok(server) => Ok(ModelArtifactActivation::RolledBack {
                revision: previous.path,
                server,
            }),
            Err(_) => Ok(ModelArtifactActivation::Unavailable(
                ModelArtifactUnavailable::RollbackActivationFailed,
            )),
        }
    }

    fn write_redacted_failure<B: ModelArtifactLifecycleBoundary>(
        &self,
        failure: ModelArtifactActivationFailure,
        boundary: &B,
    ) -> Result<(), ModelArtifactLifecycleError> {
        self.write_value("activation-failure", failure.persisted(), boundary)
    }

    fn resolve_pointer(&self, name: &str) -> Result<ResolvedPointer, ModelArtifactLifecycleError> {
        let pointer_path = self.root.join(name);
        let metadata = fs::symlink_metadata(&pointer_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ModelArtifactLifecycleError::RevisionMissing,
            _ => ModelArtifactLifecycleError::Persistence(ModelArtifactPersistenceError::Failed),
        })?;
        if !metadata.file_type().is_file() {
            return Err(ModelArtifactLifecycleError::InvalidPointer);
        }
        let value = fs::read_to_string(pointer_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ModelArtifactLifecycleError::RevisionMissing,
            std::io::ErrorKind::InvalidData => ModelArtifactLifecycleError::InvalidPointer,
            _ => ModelArtifactLifecycleError::Persistence(ModelArtifactPersistenceError::Failed),
        })?;
        let lines: Vec<_> = value.lines().collect();
        if lines.len() != 3
            || lines[0] != POINTER_HEADER
            || !safe_component(lines[1])
            || !safe_component(lines[2])
        {
            return Err(ModelArtifactLifecycleError::InvalidPointer);
        }
        let descriptor = self
            .descriptors
            .iter()
            .copied()
            .find(|descriptor| {
                descriptor.model.name == lines[1] && descriptor.model.version == lines[2]
            })
            .ok_or(ModelArtifactLifecycleError::UnknownPointer)?;
        let path = self
            .root
            .join("revisions")
            .join(descriptor.model.name)
            .join(descriptor.model.version);
        require_directory(&path).map_err(ModelArtifactLifecycleError::RevisionInvalid)?;
        verify_model_artifact(path.join(descriptor.model.filename), descriptor.model)
            .map_err(ModelArtifactLifecycleError::RevisionInvalid)?;
        verify_notice(path.join(descriptor.notice.filename), descriptor.notice)
            .map_err(ModelArtifactLifecycleError::RevisionInvalid)?;
        let model = path.join(descriptor.model.filename);
        Ok(ResolvedPointer { path, model, value })
    }

    fn write_pointer<B: ModelArtifactLifecycleBoundary>(
        &self,
        name: &str,
        value: &str,
        boundary: &B,
    ) -> Result<(), ModelArtifactLifecycleError> {
        self.write_value(name, value, boundary)
    }

    fn write_value<B: ModelArtifactLifecycleBoundary>(
        &self,
        name: &str,
        value: &str,
        boundary: &B,
    ) -> Result<(), ModelArtifactLifecycleError> {
        fs::create_dir_all(&self.root).map_err(|_| ModelArtifactPersistenceError::Failed)?;
        let temporary = self.root.join(format!(".{name}.tmp"));
        if let Err(error) = fs::remove_file(&temporary) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(ModelArtifactPersistenceError::Failed.into());
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| ModelArtifactPersistenceError::Failed)?;
        let result = (|| -> Result<(), ModelArtifactPersistenceError> {
            file.write_all(value.as_bytes())
                .map_err(|_| ModelArtifactPersistenceError::Failed)?;
            drop(file);
            boundary.sync_file(&temporary)?;
            boundary.replace_pointer(&temporary, &self.root.join(name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(Into::into)
    }
}

fn activate_pointer<A: ModelArtifactActivationBoundary>(
    pointer: &ResolvedPointer,
    activation: &A,
) -> Result<A::Server, ModelArtifactActivationFailure> {
    let mut server = activation.launch(&pointer.model)?;
    activation.await_ready(&mut server)?;
    Ok(server)
}

struct ResolvedPointer {
    path: PathBuf,
    model: PathBuf,
    value: String,
}

fn pointer_value(descriptor: &ModelArtifactRevisionDescriptor) -> String {
    format!(
        "{POINTER_HEADER}\n{}\n{}\n",
        descriptor.model.name, descriptor.model.version
    )
}

fn valid_descriptor(descriptor: &ModelArtifactRevisionDescriptor) -> bool {
    safe_component(descriptor.model.name)
        && safe_component(descriptor.model.version)
        && safe_component(descriptor.model.filename)
        && descriptor.model.byte_size > 0
        && valid_sha256(descriptor.model.sha256)
        && valid_source_url(descriptor.model.source_url)
        && !descriptor.model.license.is_empty()
        && safe_component(descriptor.notice.filename)
        && !descriptor.notice.contents.is_empty()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_source_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn verify_notice(
    path: impl AsRef<Path>,
    descriptor: ModelArtifactNoticeDescriptor,
) -> Result<(), ModelVerificationError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ModelVerificationError::Missing
        } else {
            ModelVerificationError::Unreadable
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ModelVerificationError::NotRegularFile);
    }
    if metadata.len() != descriptor.contents.len() as u64 {
        return Err(ModelVerificationError::WrongSize {
            expected: descriptor.contents.len() as u64,
            actual: metadata.len(),
        });
    }
    let contents = fs::read(path).map_err(|_| ModelVerificationError::Unreadable)?;
    if contents != descriptor.contents {
        return Err(ModelVerificationError::DigestMismatch);
    }
    Ok(())
}

fn path_entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !Path::new(value).is_absolute()
}

fn create_directory(path: &Path) -> Result<(), ModelArtifactPersistenceError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_directory(path).map_err(|_| ModelArtifactPersistenceError::Failed)
        }
        Err(_) => Err(ModelArtifactPersistenceError::Failed),
    }
}

fn require_directory(path: &Path) -> Result<(), ModelVerificationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ModelVerificationError::Missing
        } else {
            ModelVerificationError::Unreadable
        }
    })?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(ModelVerificationError::NotRegularFile)
    }
}
