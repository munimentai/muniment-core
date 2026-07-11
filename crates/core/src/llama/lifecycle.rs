//! Filesystem publication and crash recovery for resident Gemma revisions.
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

const POINTER_HEADER: &str = "muniment-gemma-pointer-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GemmaRevisionDescriptor {
    pub identity: &'static str,
    pub revision: &'static str,
    pub model: &'static ResidentModelDescriptor,
    pub notice: GemmaNoticeDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GemmaNoticeDescriptor {
    pub filename: &'static str,
    pub contents: &'static [u8],
}

const GEMMA_NOTICE: GemmaNoticeDescriptor = GemmaNoticeDescriptor {
    filename: "NOTICE.txt",
    contents: b"Gemma is provided under and subject to the Gemma Terms of Use found at ai.google.dev/gemma/terms\n",
};

pub const RESIDENT_GEMMA_REVISION: GemmaRevisionDescriptor = GemmaRevisionDescriptor {
    identity: "gemma-3-4b-it-q4_0-v1",
    revision: RESIDENT_MODEL_REVISION,
    model: &RESIDENT_MODEL,
    notice: GEMMA_NOTICE,
};

pub const RESIDENT_GEMMA_REVISIONS: [&GemmaRevisionDescriptor; 1] = [&RESIDENT_GEMMA_REVISION];

/// Platform operations required to serialize and durably publish state.
pub trait GemmaLifecycleBoundary {
    type LockGuard;

    fn lock_exclusive(&self, path: &Path) -> Result<Self::LockGuard, GemmaPersistenceError>;
    fn sync_file(&self, path: &Path) -> Result<(), GemmaPersistenceError>;
    fn sync_directory(&self, path: &Path) -> Result<(), GemmaPersistenceError>;
    /// Publishes `staged` at `destination`, replacing an existing corrupt
    /// revision if necessary. The operation must be crash-safe: interruption
    /// may leave either directory unpublished, but must never expose a partial
    /// revision at `destination`.
    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), GemmaPersistenceError>;
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), GemmaPersistenceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemmaPersistenceError {
    Failed,
}

impl std::fmt::Display for GemmaPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("resident model state could not be persisted")
    }
}

impl std::error::Error for GemmaPersistenceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemmaLifecycleError {
    InvalidDescriptor,
    InvalidStage,
    InvalidPointer,
    UnknownPointer,
    RevisionMissing,
    RevisionInvalid(ModelVerificationError),
    Persistence(GemmaPersistenceError),
}

impl std::fmt::Display for GemmaLifecycleError {
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

impl std::error::Error for GemmaLifecycleError {}

impl From<GemmaPersistenceError> for GemmaLifecycleError {
    fn from(error: GemmaPersistenceError) -> Self {
        Self::Persistence(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GemmaRecovery {
    Current(PathBuf),
    RestoredPrevious(PathBuf),
    NotInstalled,
    RepairRequired,
}

pub struct GemmaRevisionLifecycle {
    root: PathBuf,
    descriptors: &'static [&'static GemmaRevisionDescriptor],
    target: &'static GemmaRevisionDescriptor,
}

impl GemmaRevisionLifecycle {
    pub fn new(
        root: PathBuf,
        descriptors: &'static [&'static GemmaRevisionDescriptor],
        target: &'static GemmaRevisionDescriptor,
    ) -> Result<Self, GemmaLifecycleError> {
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
            return Err(GemmaLifecycleError::InvalidDescriptor);
        }
        Ok(Self {
            root,
            descriptors,
            target,
        })
    }

    pub fn resolve_current(&self) -> Result<PathBuf, GemmaLifecycleError> {
        self.resolve_pointer("current").map(|pointer| pointer.path)
    }

    pub fn publish<B: GemmaLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, GemmaLifecycleError> {
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        self.publish_lock_held(staged_directory, boundary)
    }

    /// Publishes a verified stage while the caller retains `install.lock`.
    /// Coordinated installs use this entry point to avoid recursive locking.
    pub fn publish_lock_held<B: GemmaLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, GemmaLifecycleError> {
        if staged_directory.parent() != Some(self.root.join("staging").as_path()) {
            return Err(GemmaLifecycleError::InvalidStage);
        }
        require_directory(staged_directory).map_err(|_| GemmaLifecycleError::InvalidStage)?;
        let staged_model = staged_directory.join(self.target.model.filename);
        let staged_notice = staged_directory.join(self.target.notice.filename);
        verify_model_artifact(&staged_model, self.target.model)
            .map_err(GemmaLifecycleError::RevisionInvalid)?;
        verify_notice(&staged_notice, self.target.notice)
            .map_err(GemmaLifecycleError::RevisionInvalid)?;
        boundary.sync_file(&staged_model)?;
        boundary.sync_file(&staged_notice)?;
        boundary.sync_directory(staged_directory)?;

        let revisions = self.root.join("revisions");
        fs::create_dir_all(&revisions).map_err(|_| GemmaPersistenceError::Failed)?;
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

    pub fn recover<B: GemmaLifecycleBoundary>(
        &self,
        boundary: &B,
    ) -> Result<GemmaRecovery, GemmaLifecycleError> {
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        match self.resolve_pointer("current") {
            Ok(pointer) => return Ok(GemmaRecovery::Current(pointer.path)),
            Err(GemmaLifecycleError::Persistence(error)) => return Err(error.into()),
            Err(_) => {}
        }
        match self.resolve_pointer("previous") {
            Ok(pointer) => {
                self.write_pointer("current", &pointer.value, boundary)?;
                boundary.sync_directory(&self.root)?;
                Ok(GemmaRecovery::RestoredPrevious(pointer.path))
            }
            Err(GemmaLifecycleError::Persistence(error)) => Err(error.into()),
            Err(_)
                if !path_entry_exists(&self.root.join("current"))
                    && !path_entry_exists(&self.root.join("previous")) =>
            {
                Ok(GemmaRecovery::NotInstalled)
            }
            Err(_) => Ok(GemmaRecovery::RepairRequired),
        }
    }

    fn resolve_pointer(&self, name: &str) -> Result<ResolvedPointer, GemmaLifecycleError> {
        let pointer_path = self.root.join(name);
        let metadata = fs::symlink_metadata(&pointer_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => GemmaLifecycleError::RevisionMissing,
            _ => GemmaLifecycleError::Persistence(GemmaPersistenceError::Failed),
        })?;
        if !metadata.file_type().is_file() {
            return Err(GemmaLifecycleError::InvalidPointer);
        }
        let value = fs::read_to_string(pointer_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => GemmaLifecycleError::RevisionMissing,
            std::io::ErrorKind::InvalidData => GemmaLifecycleError::InvalidPointer,
            _ => GemmaLifecycleError::Persistence(GemmaPersistenceError::Failed),
        })?;
        let lines: Vec<_> = value.lines().collect();
        if lines.len() != 3
            || lines[0] != POINTER_HEADER
            || !safe_component(lines[1])
            || !safe_component(lines[2])
        {
            return Err(GemmaLifecycleError::InvalidPointer);
        }
        let descriptor = self
            .descriptors
            .iter()
            .copied()
            .find(|descriptor| descriptor.identity == lines[1] && descriptor.revision == lines[2])
            .ok_or(GemmaLifecycleError::UnknownPointer)?;
        let path = self.root.join("revisions").join(descriptor.revision);
        require_directory(&path).map_err(GemmaLifecycleError::RevisionInvalid)?;
        verify_model_artifact(path.join(descriptor.model.filename), descriptor.model)
            .map_err(GemmaLifecycleError::RevisionInvalid)?;
        verify_notice(path.join(descriptor.notice.filename), descriptor.notice)
            .map_err(GemmaLifecycleError::RevisionInvalid)?;
        Ok(ResolvedPointer { path, value })
    }

    fn write_pointer<B: GemmaLifecycleBoundary>(
        &self,
        name: &str,
        value: &str,
        boundary: &B,
    ) -> Result<(), GemmaLifecycleError> {
        fs::create_dir_all(&self.root).map_err(|_| GemmaPersistenceError::Failed)?;
        let temporary = self.root.join(format!(".{name}.tmp"));
        if let Err(error) = fs::remove_file(&temporary) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(GemmaPersistenceError::Failed.into());
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| GemmaPersistenceError::Failed)?;
        let result = (|| -> Result<(), GemmaPersistenceError> {
            file.write_all(value.as_bytes())
                .map_err(|_| GemmaPersistenceError::Failed)?;
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

struct ResolvedPointer {
    path: PathBuf,
    value: String,
}

fn pointer_value(descriptor: &GemmaRevisionDescriptor) -> String {
    format!(
        "{POINTER_HEADER}\n{}\n{}\n",
        descriptor.identity, descriptor.revision
    )
}

fn valid_descriptor(descriptor: &GemmaRevisionDescriptor) -> bool {
    safe_component(descriptor.identity)
        && safe_component(descriptor.revision)
        && safe_component(descriptor.model.filename)
        && safe_component(descriptor.notice.filename)
        && !descriptor.notice.contents.is_empty()
}

fn verify_notice(
    path: impl AsRef<Path>,
    descriptor: GemmaNoticeDescriptor,
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
