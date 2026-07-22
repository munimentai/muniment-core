//! Durable publication and resolution of the pinned Kokoro revision.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{verify_revision_stage, KokoroRevisionDescriptor, KokoroVerificationError, KOKORO_V1};

const POINTER_HEADER: &str = "muniment-kokoro-pointer-v1";
const MAX_POINTER_BYTES: u64 = 256;

/// Operations whose locking and atomic replacement semantics are platform-specific.
pub trait KokoroLifecycleBoundary {
    type LockGuard;

    fn lock_exclusive(&self, path: &Path) -> Result<Self::LockGuard, KokoroPersistenceError>;
    fn sync_file(&self, path: &Path) -> Result<(), KokoroPersistenceError>;
    fn sync_directory(&self, path: &Path) -> Result<(), KokoroPersistenceError>;
    /// Atomically publishes a complete directory, replacing a corrupt destination.
    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), KokoroPersistenceError>;
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), KokoroPersistenceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KokoroPersistenceError {
    Failed,
}

impl std::fmt::Display for KokoroPersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kokoro model state could not be persisted")
    }
}
impl std::error::Error for KokoroPersistenceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KokoroLifecycleError {
    InvalidStage,
    Verification(KokoroVerificationError),
    Persistence(KokoroPersistenceError),
}

impl std::fmt::Display for KokoroLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidStage => "Kokoro model stage is invalid",
            Self::Verification(_) => "Kokoro model revision failed verification",
            Self::Persistence(_) => "Kokoro model state could not be persisted",
        })
    }
}
impl std::error::Error for KokoroLifecycleError {}
impl From<KokoroPersistenceError> for KokoroLifecycleError {
    fn from(value: KokoroPersistenceError) -> Self {
        Self::Persistence(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KokoroCurrentRevision {
    Current(PathBuf),
    NotInstalled,
    RepairRequired,
}

/// Lifecycle for the single Kokoro revision compiled into this application.
pub struct KokoroRevisionLifecycle {
    root: PathBuf,
    revision: &'static KokoroRevisionDescriptor,
}

impl KokoroRevisionLifecycle {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            revision: &KOKORO_V1,
        }
    }

    #[cfg(test)]
    fn with_revision(root: PathBuf, revision: &'static KokoroRevisionDescriptor) -> Self {
        Self { root, revision }
    }

    pub fn publish<B: KokoroLifecycleBoundary>(
        &self,
        staged_directory: &Path,
        boundary: &B,
    ) -> Result<PathBuf, KokoroLifecycleError> {
        require_directory(&self.root).map_err(|_| KokoroLifecycleError::InvalidStage)?;
        let _lock = boundary.lock_exclusive(&self.root.join("install.lock"))?;
        if staged_directory.parent() != Some(self.root.join("staging").as_path()) {
            return Err(KokoroLifecycleError::InvalidStage);
        }
        require_directory(&self.root.join("staging"))
            .map_err(|_| KokoroLifecycleError::InvalidStage)?;
        verify_revision_stage(staged_directory, self.revision)
            .map_err(KokoroLifecycleError::Verification)?;
        for artifact in self.revision.artifacts {
            boundary.sync_file(&staged_directory.join(artifact.filename))?;
        }
        boundary.sync_directory(staged_directory)?;

        let revisions = self.root.join("revisions");
        ensure_directory(&revisions)?;
        let installed = revisions.join(self.revision.identity);
        if verify_revision_stage(&installed, self.revision).is_err() {
            boundary.replace_revision(staged_directory, &installed)?;
            // Never point at replacement bytes until the complete snapshot and
            // its directory entry have reached the durability boundary.
            verify_revision_stage(&installed, self.revision)
                .map_err(KokoroLifecycleError::Verification)?;
            boundary.sync_directory(&revisions)?;
        }

        self.write_current(boundary)?;
        boundary.sync_directory(&self.root)?;
        Ok(installed)
    }

    /// Resolves and re-verifies a complete immutable snapshot. Staging is never consulted.
    pub fn resolve_current(&self) -> Result<KokoroCurrentRevision, KokoroPersistenceError> {
        if require_directory(&self.root).is_err() {
            return Ok(KokoroCurrentRevision::RepairRequired);
        }
        let pointer = self.root.join("current");
        let metadata = match fs::symlink_metadata(&pointer) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(KokoroCurrentRevision::NotInstalled)
            }
            Err(_) => return Err(KokoroPersistenceError::Failed),
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_POINTER_BYTES {
            return Ok(KokoroCurrentRevision::RepairRequired);
        }
        let mut value = String::new();
        let mut file = fs::File::open(&pointer).map_err(|_| KokoroPersistenceError::Failed)?;
        if Read::by_ref(&mut file)
            .take(MAX_POINTER_BYTES + 1)
            .read_to_string(&mut value)
            .is_err()
        {
            return Ok(KokoroCurrentRevision::RepairRequired);
        }
        let expected = pointer_value(self.revision);
        if value != expected {
            return Ok(KokoroCurrentRevision::RepairRequired);
        }
        let installed = self.root.join("revisions").join(self.revision.identity);
        match verify_revision_stage(&installed, self.revision) {
            Ok(()) => Ok(KokoroCurrentRevision::Current(installed)),
            Err(_) => Ok(KokoroCurrentRevision::RepairRequired),
        }
    }

    fn write_current<B: KokoroLifecycleBoundary>(
        &self,
        boundary: &B,
    ) -> Result<(), KokoroLifecycleError> {
        static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
        let (temporary, mut file) = loop {
            let temporary = self.root.join(format!(
                ".current.{}.{}.tmp",
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
                Err(_) => return Err(KokoroPersistenceError::Failed.into()),
            }
        };
        let result = (|| -> Result<(), KokoroPersistenceError> {
            file.write_all(pointer_value(self.revision).as_bytes())
                .map_err(|_| KokoroPersistenceError::Failed)?;
            drop(file);
            boundary.sync_file(&temporary)?;
            boundary.replace_pointer(&temporary, &self.root.join("current"))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(Into::into)
    }
}

fn pointer_value(revision: &KokoroRevisionDescriptor) -> String {
    format!("{POINTER_HEADER}\n{}\n", revision.identity)
}

fn require_directory(path: &Path) -> Result<(), ()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        _ => Err(()),
    }
}

fn ensure_directory(path: &Path) -> Result<(), KokoroPersistenceError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_directory(path).map_err(|_| KokoroPersistenceError::Failed)
        }
        Err(_) => Err(KokoroPersistenceError::Failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kokoro::KokoroArtifactDescriptor;
    use std::cell::{Cell, RefCell};

    static ARTIFACTS: [KokoroArtifactDescriptor; 2] = [
        KokoroArtifactDescriptor {
            filename: "model",
            source_url: "unused",
            byte_size: 1,
            sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        },
        KokoroArtifactDescriptor {
            filename: "voices",
            source_url: "unused",
            byte_size: 1,
            sha256: "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
        },
    ];
    static REVISION: KokoroRevisionDescriptor = KokoroRevisionDescriptor {
        identity: "fixture-v1",
        artifacts: &ARTIFACTS,
    };

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fail {
        None,
        SyncFile(usize),
        SyncStage,
        ReplaceRevision,
        SyncRevisions,
        ReplacePointer,
        SyncRoot,
    }

    struct Boundary {
        fail: Fail,
        files: Cell<usize>,
        events: RefCell<Vec<&'static str>>,
    }
    impl Boundary {
        fn new(fail: Fail) -> Self {
            Self {
                fail,
                files: Cell::new(0),
                events: RefCell::new(vec![]),
            }
        }
    }
    impl KokoroLifecycleBoundary for Boundary {
        type LockGuard = ();
        fn lock_exclusive(&self, _: &Path) -> Result<(), KokoroPersistenceError> {
            Ok(())
        }
        fn sync_file(&self, path: &Path) -> Result<(), KokoroPersistenceError> {
            let n = self.files.get();
            self.files.set(n + 1);
            if self.fail == Fail::SyncFile(n) {
                return Err(KokoroPersistenceError::Failed);
            }
            self.events.borrow_mut().push(
                if path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains("current")
                {
                    "pointer-file"
                } else {
                    "artifact"
                },
            );
            Ok(())
        }
        fn sync_directory(&self, path: &Path) -> Result<(), KokoroPersistenceError> {
            let name = path.file_name().and_then(|v| v.to_str());
            let point = match (path.parent().and_then(Path::file_name), name) {
                (Some(parent), _) if parent == "staging" => (Fail::SyncStage, "stage"),
                (_, Some("revisions")) => (Fail::SyncRevisions, "revisions"),
                _ => (Fail::SyncRoot, "root"),
            };
            if self.fail == point.0 {
                return Err(KokoroPersistenceError::Failed);
            }
            self.events.borrow_mut().push(point.1);
            Ok(())
        }
        fn replace_revision(
            &self,
            staged: &Path,
            destination: &Path,
        ) -> Result<(), KokoroPersistenceError> {
            if self.fail == Fail::ReplaceRevision {
                return Err(KokoroPersistenceError::Failed);
            }
            if destination.exists() {
                fs::remove_dir_all(destination).map_err(|_| KokoroPersistenceError::Failed)?;
            }
            fs::rename(staged, destination).map_err(|_| KokoroPersistenceError::Failed)
        }
        fn replace_pointer(
            &self,
            temporary: &Path,
            destination: &Path,
        ) -> Result<(), KokoroPersistenceError> {
            if self.fail == Fail::ReplacePointer {
                return Err(KokoroPersistenceError::Failed);
            }
            if destination.exists() {
                fs::remove_file(destination).map_err(|_| KokoroPersistenceError::Failed)?;
            }
            fs::rename(temporary, destination).map_err(|_| KokoroPersistenceError::Failed)
        }
    }

    fn fixture() -> (PathBuf, KokoroRevisionLifecycle, PathBuf) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "muniment-kokoro-lifecycle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("staging")).unwrap();
        let stage = root.join("staging/install");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("model"), b"a").unwrap();
        fs::write(stage.join("voices"), b"b").unwrap();
        (
            root.clone(),
            KokoroRevisionLifecycle::with_revision(root, &REVISION),
            stage,
        )
    }

    #[test]
    fn first_publish_and_idempotent_republish_resolve_verified_snapshot() {
        let (root, lifecycle, stage) = fixture();
        let boundary = Boundary::new(Fail::None);
        let installed = lifecycle.publish(&stage, &boundary).unwrap();
        assert_eq!(
            lifecycle.resolve_current().unwrap(),
            KokoroCurrentRevision::Current(installed.clone())
        );
        let second = root.join("staging/second");
        fs::create_dir(&second).unwrap();
        fs::write(second.join("model"), b"a").unwrap();
        fs::write(second.join("voices"), b"b").unwrap();
        assert_eq!(
            lifecycle
                .publish(&second, &Boundary::new(Fail::None))
                .unwrap(),
            installed
        );
        assert!(
            second.exists(),
            "idempotent publication must not replace immutable bytes"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_install_is_repaired_but_failed_replacement_never_gets_a_pointer() {
        let (root, lifecycle, stage) = fixture();
        fs::create_dir(root.join("revisions")).unwrap();
        fs::create_dir(root.join("revisions/fixture-v1")).unwrap();
        fs::write(root.join("revisions/fixture-v1/model"), b"x").unwrap();
        assert!(lifecycle
            .publish(&stage, &Boundary::new(Fail::ReplaceRevision))
            .is_err());
        assert!(!root.join("current").exists());
        assert!(stage.exists());
        lifecycle
            .publish(&stage, &Boundary::new(Fail::None))
            .unwrap();
        assert!(matches!(
            lifecycle.resolve_current().unwrap(),
            KokoroCurrentRevision::Current(_)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hostile_pointers_links_and_entries_require_repair_or_reject_publication() {
        let (root, lifecycle, stage) = fixture();
        for value in [
            "bad",
            "muniment-kokoro-pointer-v1\nother\n",
            "muniment-kokoro-pointer-v1\nfixture-v1\nextra\n",
        ] {
            fs::write(root.join("current"), value).unwrap();
            assert_eq!(
                lifecycle.resolve_current().unwrap(),
                KokoroCurrentRevision::RepairRequired
            );
        }
        fs::write(root.join("current"), vec![b'x'; 257]).unwrap();
        assert_eq!(
            lifecycle.resolve_current().unwrap(),
            KokoroCurrentRevision::RepairRequired
        );
        fs::remove_file(root.join("current")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let external = root.join("external-pointer");
            fs::write(&external, pointer_value(&REVISION)).unwrap();
            symlink(&external, root.join("current")).unwrap();
            assert_eq!(
                lifecycle.resolve_current().unwrap(),
                KokoroCurrentRevision::RepairRequired
            );
            fs::remove_file(root.join("current")).unwrap();
        }
        fs::write(stage.join("extra"), b"x").unwrap();
        assert!(matches!(
            lifecycle.publish(&stage, &Boundary::new(Fail::None)),
            Err(KokoroLifecycleError::Verification(
                KokoroVerificationError::UnexpectedEntry
            ))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            fs::remove_file(stage.join("extra")).unwrap();
            fs::remove_file(stage.join("model")).unwrap();
            symlink("voices", stage.join("model")).unwrap();
            assert!(lifecycle
                .publish(&stage, &Boundary::new(Fail::None))
                .is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn public_errors_are_typed_and_do_not_disclose_paths() {
        let (root, lifecycle, stage) = fixture();
        fs::write(stage.join("model"), b"wrong").unwrap();
        let error = lifecycle
            .publish(&stage, &Boundary::new(Fail::None))
            .unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(root.to_str().unwrap()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_and_corrupt_current_states_are_distinguished() {
        let (root, lifecycle, stage) = fixture();
        assert_eq!(
            lifecycle.resolve_current().unwrap(),
            KokoroCurrentRevision::NotInstalled
        );
        lifecycle
            .publish(&stage, &Boundary::new(Fail::None))
            .unwrap();
        fs::write(root.join("revisions/fixture-v1/voices"), b"x").unwrap();
        assert_eq!(
            lifecycle.resolve_current().unwrap(),
            KokoroCurrentRevision::RepairRequired
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_interruption_boundary_preserves_an_existing_valid_current() {
        for fail in [
            Fail::SyncFile(0),
            Fail::SyncFile(1),
            Fail::SyncFile(2),
            Fail::SyncStage,
            Fail::ReplacePointer,
            Fail::SyncRoot,
        ] {
            let (root, lifecycle, stage) = fixture();
            lifecycle
                .publish(&stage, &Boundary::new(Fail::None))
                .unwrap();
            let retry = root.join("staging/retry");
            fs::create_dir(&retry).unwrap();
            fs::write(retry.join("model"), b"a").unwrap();
            fs::write(retry.join("voices"), b"b").unwrap();
            assert!(lifecycle.publish(&retry, &Boundary::new(fail)).is_err());
            assert!(matches!(
                lifecycle.resolve_current().unwrap(),
                KokoroCurrentRevision::Current(_)
            ));
            assert!(fs::read_dir(&root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".current.")
            }));
            fs::remove_dir_all(root).unwrap();
        }

        for fail in [Fail::ReplaceRevision, Fail::SyncRevisions] {
            let (root, lifecycle, stage) = fixture();
            assert!(lifecycle.publish(&stage, &Boundary::new(fail)).is_err());
            assert_eq!(
                lifecycle.resolve_current().unwrap(),
                KokoroCurrentRevision::NotInstalled
            );
            let installed = root.join("revisions/fixture-v1");
            if installed.exists() {
                assert_eq!(verify_revision_stage(&installed, &REVISION), Ok(()));
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}
