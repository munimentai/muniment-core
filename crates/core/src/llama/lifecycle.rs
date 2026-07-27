//! Filesystem publication and crash recovery for resident-model revisions.
//!
//! Locking and durable replacement are platform concerns, so callers inject
//! those operations. Core owns the layout, verification, pointer format, and
//! the rule that staging is never considered during recovery.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{
    verify_model_artifact, ModelVerificationError, ResidentModelDescriptor, RESIDENT_MODEL,
    RESIDENT_MODEL_REVISION,
};

// Keep this legacy header spelling to preserve the persisted pointer wire format.
const POINTER_HEADER: &str = "muniment-gemma-pointer-v1";

/// The only startup detail persisted by activation. These categories are
/// deliberately incapable of carrying paths, process output, or HTTP bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentModelActivationFailure {
    Start,
    ExitedBeforeReady,
    Readiness,
}

impl ResidentModelActivationFailure {
    fn persisted(self) -> &'static str {
        match self {
            Self::Start => "start\n",
            Self::ExitedBeforeReady => "exited-before-ready\n",
            Self::Readiness => "readiness\n",
        }
    }
}

/// Injectable process and bounded-health boundary used by pure core.
pub trait ResidentModelActivationBoundary {
    type Server;

    fn launch(&self, model: &Path) -> Result<Self::Server, ResidentModelActivationFailure>;
    fn await_ready(&self, server: &mut Self::Server) -> Result<(), ResidentModelActivationFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentModelUnavailable {
    CurrentInvalid,
    PreviousInvalid,
    RollbackActivationFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResidentModelActivation<S> {
    Active { revision: PathBuf, server: S },
    RolledBack { revision: PathBuf, server: S },
    Unavailable(ResidentModelUnavailable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentModelRevisionDescriptor {
    pub identity: &'static str,
    pub revision: &'static str,
    pub model: &'static ResidentModelDescriptor,
    pub notice: ResidentModelNoticeDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentModelNoticeDescriptor {
    pub filename: &'static str,
    pub contents: &'static [u8],
}

const RESIDENT_MODEL_NOTICE: ResidentModelNoticeDescriptor = ResidentModelNoticeDescriptor {
    filename: "NOTICE.txt",
    contents: b"Qwen3.5 is provided by the Qwen team under the Apache License 2.0. Source: huggingface.co/munimentai/Qwen3.5-4B-GGUF\n",
};

pub const PINNED_RESIDENT_MODEL_REVISION: ResidentModelRevisionDescriptor =
    ResidentModelRevisionDescriptor {
        identity: "qwen3.5-4b-instruct-q4_k_m-v1",
        revision: RESIDENT_MODEL_REVISION,
        model: &RESIDENT_MODEL,
        notice: RESIDENT_MODEL_NOTICE,
    };

pub const RESIDENT_MODEL_REVISIONS: [&ResidentModelRevisionDescriptor; 1] =
    [&PINNED_RESIDENT_MODEL_REVISION];

/// Platform operations required to serialize and durably publish state.
pub trait ResidentModelLifecycleBoundary {
    type LockGuard;

    fn lock_exclusive(&self, path: &Path)
        -> Result<Self::LockGuard, ResidentModelPersistenceError>;
    fn sync_file(&self, path: &Path) -> Result<(), ResidentModelPersistenceError>;
    fn sync_directory(&self, path: &Path) -> Result<(), ResidentModelPersistenceError>;
    /// Publishes `staged` at `destination`, replacing an existing corrupt
    /// revision if necessary. The operation must be crash-safe: interruption
    /// may leave either directory unpublished, but must never expose a partial
    /// revision at `destination`.
    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), ResidentModelPersistenceError>;
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), ResidentModelPersistenceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentModelPersistenceError {
    Failed,
}

impl std::fmt::Display for ResidentModelPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("resident model state could not be persisted")
    }
}

impl std::error::Error for ResidentModelPersistenceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentModelLifecycleError {
    InvalidDescriptor,
    InvalidStage,
    InvalidPointer,
    UnknownPointer,
    RevisionMissing,
    RevisionInvalid(ModelVerificationError),
    Persistence(ResidentModelPersistenceError),
}

impl std::fmt::Display for ResidentModelLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDescriptor => f.write_str("resident model descriptor is invalid"),
            Self::InvalidStage => f.write_str("resident model stage is invalid"),
            Self::InvalidPointer => f.write_str("resident model pointer is malformed"),
            Self::UnknownPointer => f.write_str("resident model pointer is not recognized"),
            Self::RevisionMissing => f.write_str("resident model revision is not installed"),
            Self::RevisionInvalid(_) => f.write_str("resident model revision failed verification"),
            Self::Persistence(_) => f.write_str("resident model state could not be persisted"),
        }
    }
}

impl std::error::Error for ResidentModelLifecycleError {}

impl From<ResidentModelPersistenceError> for ResidentModelLifecycleError {
    fn from(error: ResidentModelPersistenceError) -> Self {
        Self::Persistence(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidentModelRecovery {
    Current(PathBuf),
    RestoredPrevious(PathBuf),
    NotInstalled,
    RepairRequired,
}

pub struct ResidentModelRevisionLifecycle {
    root: PathBuf,
    descriptors: &'static [&'static ResidentModelRevisionDescriptor],
    target: &'static ResidentModelRevisionDescriptor,
}

impl ResidentModelRevisionLifecycle {
    pub fn new(
        root: PathBuf,
        descriptors: &'static [&'static ResidentModelRevisionDescriptor],
        target: &'static ResidentModelRevisionDescriptor,
    ) -> Result<Self, ResidentModelLifecycleError> {
        if descriptors.is_empty()
            || !descriptors.contains(&target)
            || descriptors
                .iter()
                .any(|descriptor| !valid_descriptor(descriptor))
            || descriptors.iter().enumerate().any(|(index, descriptor)| {
                descriptors[index + 1..].iter().any(|other| {
                    descriptor.identity == other.identity && descriptor.revision == other.revision
                })
            })
        {
            return Err(ResidentModelLifecycleError::InvalidDescriptor);
        }
        Ok(Self {
            root,
            descriptors,
            target,
        })
    }

    pub fn resolve_current(&self) -> Result<PathBuf, ResidentModelLifecycleError> {
        self.resolve_pointer("current").map(|pointer| pointer.path)
    }

    pub fn publish<B: ResidentModelLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, ResidentModelLifecycleError> {
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        self.publish_lock_held(staged_directory, boundary)
    }

    /// Publishes a verified stage while the caller retains `install.lock`.
    /// Coordinated installs use this entry point to avoid recursive locking.
    pub fn publish_lock_held<B: ResidentModelLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, ResidentModelLifecycleError> {
        if staged_directory.parent() != Some(self.root.join("staging").as_path()) {
            return Err(ResidentModelLifecycleError::InvalidStage);
        }
        require_directory(staged_directory)
            .map_err(|_| ResidentModelLifecycleError::InvalidStage)?;
        let staged_model = staged_directory.join(self.target.model.filename);
        let staged_notice = staged_directory.join(self.target.notice.filename);
        verify_model_artifact(&staged_model, self.target.model)
            .map_err(ResidentModelLifecycleError::RevisionInvalid)?;
        verify_notice(&staged_notice, self.target.notice)
            .map_err(ResidentModelLifecycleError::RevisionInvalid)?;
        boundary.sync_file(&staged_model)?;
        boundary.sync_file(&staged_notice)?;
        boundary.sync_directory(staged_directory)?;

        let revisions = self.root.join("revisions");
        fs::create_dir_all(&revisions).map_err(|_| ResidentModelPersistenceError::Failed)?;
        let revision = revisions.join(self.target.revision);
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
            boundary.sync_directory(&revisions)?;
        }

        if let Ok(current) = self.resolve_pointer("current") {
            self.write_pointer("previous", &current.value, boundary)?;
        }
        self.write_pointer("current", &pointer_value(self.target), boundary)?;
        boundary.sync_directory(&self.root)?;
        Ok(revision)
    }

    pub fn recover<B: ResidentModelLifecycleBoundary>(
        &self,
        boundary: &B,
    ) -> Result<ResidentModelRecovery, ResidentModelLifecycleError> {
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        match self.resolve_pointer("current") {
            Ok(pointer) => return Ok(ResidentModelRecovery::Current(pointer.path)),
            Err(ResidentModelLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {}
        }
        match self.resolve_pointer("previous") {
            Ok(pointer) => {
                self.write_pointer("current", &pointer.value, boundary)?;
                boundary.sync_directory(&self.root)?;
                Ok(ResidentModelRecovery::RestoredPrevious(pointer.path))
            }
            Err(ResidentModelLifecycleError::Persistence(error)) => Err(error.into()),
            Err(_)
                if !path_entry_exists(&self.root.join("current"))
                    && !path_entry_exists(&self.root.join("previous")) =>
            {
                Ok(ResidentModelRecovery::NotInstalled)
            }
            Err(_) => Ok(ResidentModelRecovery::RepairRequired),
        }
    }

    /// Activates the verified current revision. A failed bounded startup marks
    /// that revision rejected, restores verified previous atomically, and
    /// makes exactly one rollback activation attempt.
    pub fn activate<B: ResidentModelLifecycleBoundary, A: ResidentModelActivationBoundary>(
        &self,
        persistence: &B,
        activation: &A,
    ) -> Result<ResidentModelActivation<A::Server>, ResidentModelLifecycleError> {
        let _lock = persistence.lock_exclusive(&self.root.join("install.lock"))?;
        let current = match self.resolve_pointer("current") {
            Ok(pointer) => pointer,
            Err(ResidentModelLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {
                return Ok(ResidentModelActivation::Unavailable(
                    ResidentModelUnavailable::CurrentInvalid,
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
            Ok(server) => Ok(ResidentModelActivation::Active {
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

    fn activate_previous<B: ResidentModelLifecycleBoundary, A: ResidentModelActivationBoundary>(
        &self,
        persistence: &B,
        activation: &A,
    ) -> Result<ResidentModelActivation<A::Server>, ResidentModelLifecycleError> {
        let previous = match self.resolve_pointer("previous") {
            Ok(pointer) => pointer,
            Err(ResidentModelLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {
                return Ok(ResidentModelActivation::Unavailable(
                    ResidentModelUnavailable::PreviousInvalid,
                ))
            }
        };
        self.write_pointer("current", &previous.value, persistence)?;
        persistence.sync_directory(&self.root)?;
        match activate_pointer(&previous, activation) {
            Ok(server) => Ok(ResidentModelActivation::RolledBack {
                revision: previous.path,
                server,
            }),
            Err(_) => Ok(ResidentModelActivation::Unavailable(
                ResidentModelUnavailable::RollbackActivationFailed,
            )),
        }
    }

    fn write_redacted_failure<B: ResidentModelLifecycleBoundary>(
        &self,
        failure: ResidentModelActivationFailure,
        boundary: &B,
    ) -> Result<(), ResidentModelLifecycleError> {
        self.write_value("activation-failure", failure.persisted(), boundary)
    }

    fn resolve_pointer(&self, name: &str) -> Result<ResolvedPointer, ResidentModelLifecycleError> {
        let pointer_path = self.root.join(name);
        let metadata = fs::symlink_metadata(&pointer_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ResidentModelLifecycleError::RevisionMissing,
            _ => ResidentModelLifecycleError::Persistence(ResidentModelPersistenceError::Failed),
        })?;
        if !metadata.file_type().is_file() {
            return Err(ResidentModelLifecycleError::InvalidPointer);
        }
        let value = fs::read_to_string(pointer_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ResidentModelLifecycleError::RevisionMissing,
            std::io::ErrorKind::InvalidData => ResidentModelLifecycleError::InvalidPointer,
            _ => ResidentModelLifecycleError::Persistence(ResidentModelPersistenceError::Failed),
        })?;
        let lines: Vec<_> = value.lines().collect();
        if lines.len() != 3
            || lines[0] != POINTER_HEADER
            || !safe_component(lines[1])
            || !safe_component(lines[2])
        {
            return Err(ResidentModelLifecycleError::InvalidPointer);
        }
        let descriptor = self
            .descriptors
            .iter()
            .copied()
            .find(|descriptor| descriptor.identity == lines[1] && descriptor.revision == lines[2])
            .ok_or(ResidentModelLifecycleError::UnknownPointer)?;
        let path = self.root.join("revisions").join(descriptor.revision);
        require_directory(&path).map_err(ResidentModelLifecycleError::RevisionInvalid)?;
        verify_model_artifact(path.join(descriptor.model.filename), descriptor.model)
            .map_err(ResidentModelLifecycleError::RevisionInvalid)?;
        verify_notice(path.join(descriptor.notice.filename), descriptor.notice)
            .map_err(ResidentModelLifecycleError::RevisionInvalid)?;
        let model = path.join(descriptor.model.filename);
        Ok(ResolvedPointer { path, model, value })
    }

    fn write_pointer<B: ResidentModelLifecycleBoundary>(
        &self,
        name: &str,
        value: &str,
        boundary: &B,
    ) -> Result<(), ResidentModelLifecycleError> {
        self.write_value(name, value, boundary)
    }

    fn write_value<B: ResidentModelLifecycleBoundary>(
        &self,
        name: &str,
        value: &str,
        boundary: &B,
    ) -> Result<(), ResidentModelLifecycleError> {
        fs::create_dir_all(&self.root).map_err(|_| ResidentModelPersistenceError::Failed)?;
        let temporary = self.root.join(format!(".{name}.tmp"));
        if let Err(error) = fs::remove_file(&temporary) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(ResidentModelPersistenceError::Failed.into());
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| ResidentModelPersistenceError::Failed)?;
        let result = (|| -> Result<(), ResidentModelPersistenceError> {
            file.write_all(value.as_bytes())
                .map_err(|_| ResidentModelPersistenceError::Failed)?;
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

fn activate_pointer<A: ResidentModelActivationBoundary>(
    pointer: &ResolvedPointer,
    activation: &A,
) -> Result<A::Server, ResidentModelActivationFailure> {
    let mut server = activation.launch(&pointer.model)?;
    activation.await_ready(&mut server)?;
    Ok(server)
}

struct ResolvedPointer {
    path: PathBuf,
    model: PathBuf,
    value: String,
}

fn pointer_value(descriptor: &ResidentModelRevisionDescriptor) -> String {
    format!(
        "{POINTER_HEADER}\n{}\n{}\n",
        descriptor.identity, descriptor.revision
    )
}

fn valid_descriptor(descriptor: &ResidentModelRevisionDescriptor) -> bool {
    safe_component(descriptor.identity)
        && safe_component(descriptor.revision)
        && safe_component(descriptor.model.filename)
        && valid_source_url(descriptor.model.source_url)
        && !descriptor.model.license.is_empty()
        && safe_component(descriptor.notice.filename)
        && !descriptor.notice.contents.is_empty()
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
    descriptor: ResidentModelNoticeDescriptor,
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
