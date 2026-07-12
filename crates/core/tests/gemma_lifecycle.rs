use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use muniment_core::llama::lifecycle::{
    GemmaActivation, GemmaActivationBoundary, GemmaActivationFailure, GemmaLifecycleBoundary,
    GemmaLifecycleError, GemmaNoticeDescriptor, GemmaPersistenceError, GemmaRecovery,
    GemmaRevisionDescriptor, GemmaRevisionLifecycle, GemmaUnavailable,
};
use muniment_core::llama::ResidentModelDescriptor;

static OLD_MODEL: ResidentModelDescriptor = ResidentModelDescriptor {
    filename: "model.gguf",
    byte_size: 3,
    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    alias: "fixture",
    context_tokens: 1,
};
static NEW_MODEL: ResidentModelDescriptor = ResidentModelDescriptor {
    filename: "model.gguf",
    byte_size: 3,
    sha256: "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34",
    alias: "fixture",
    context_tokens: 1,
};
static OLD: GemmaRevisionDescriptor = GemmaRevisionDescriptor {
    identity: "gemma-fixture-v1",
    revision: "old",
    model: &OLD_MODEL,
    notice: GemmaNoticeDescriptor {
        filename: "NOTICE.txt",
        contents: b"notice-v1",
    },
};
static NEW: GemmaRevisionDescriptor = GemmaRevisionDescriptor {
    identity: "gemma-fixture-v2",
    revision: "new",
    model: &NEW_MODEL,
    notice: GemmaNoticeDescriptor {
        filename: "NOTICE.txt",
        contents: b"notice-v2",
    },
};
static KNOWN: [&GemmaRevisionDescriptor; 2] = [&OLD, &NEW];

struct Boundary {
    locks: AtomicUsize,
    fail_current: AtomicBool,
    revision_failure: AtomicUsize,
    fail_pointer_after_replace: Mutex<Option<&'static str>>,
}

impl Boundary {
    fn working() -> Self {
        Self {
            locks: AtomicUsize::new(0),
            fail_current: AtomicBool::new(false),
            revision_failure: AtomicUsize::new(0),
            fail_pointer_after_replace: Mutex::new(None),
        }
    }
    fn failing_current() -> Self {
        Self {
            locks: AtomicUsize::new(0),
            fail_current: AtomicBool::new(true),
            revision_failure: AtomicUsize::new(0),
            fail_pointer_after_replace: Mutex::new(None),
        }
    }
    fn failing_revision_at(step: usize) -> Self {
        Self {
            locks: AtomicUsize::new(0),
            fail_current: AtomicBool::new(false),
            revision_failure: AtomicUsize::new(step),
            fail_pointer_after_replace: Mutex::new(None),
        }
    }
    fn interrupt_after_pointer(name: &'static str) -> Self {
        Self {
            locks: AtomicUsize::new(0),
            fail_current: AtomicBool::new(false),
            revision_failure: AtomicUsize::new(0),
            fail_pointer_after_replace: Mutex::new(Some(name)),
        }
    }
}

impl GemmaLifecycleBoundary for Boundary {
    type LockGuard = ();
    fn lock_exclusive(&self, path: &Path) -> Result<(), GemmaPersistenceError> {
        assert_eq!(path.file_name().unwrap(), "install.lock");
        self.locks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn sync_file(&self, _: &Path) -> Result<(), GemmaPersistenceError> {
        Ok(())
    }
    fn sync_directory(&self, _: &Path) -> Result<(), GemmaPersistenceError> {
        Ok(())
    }
    fn replace_revision(
        &self,
        staged: &Path,
        destination: &Path,
    ) -> Result<(), GemmaPersistenceError> {
        if self.revision_failure.load(Ordering::Relaxed) == 1 {
            return Err(GemmaPersistenceError::Failed);
        }
        let quarantine = destination.with_extension("replaced");
        if quarantine.exists() {
            fs::remove_dir_all(&quarantine).map_err(|_| GemmaPersistenceError::Failed)?;
        }
        if destination.exists() || fs::symlink_metadata(destination).is_ok() {
            fs::rename(destination, &quarantine).map_err(|_| GemmaPersistenceError::Failed)?;
        }
        if self.revision_failure.load(Ordering::Relaxed) == 2 {
            return Err(GemmaPersistenceError::Failed);
        }
        fs::rename(staged, destination).map_err(|_| GemmaPersistenceError::Failed)
    }
    fn replace_pointer(
        &self,
        temporary: &Path,
        destination: &Path,
    ) -> Result<(), GemmaPersistenceError> {
        if destination.file_name().and_then(|name| name.to_str()) == Some("current")
            && self.fail_current.swap(false, Ordering::Relaxed)
        {
            return Err(GemmaPersistenceError::Failed);
        }
        if destination.exists() {
            fs::remove_file(destination).unwrap();
        }
        fs::rename(temporary, destination).map_err(|_| GemmaPersistenceError::Failed)?;
        let name = destination.file_name().and_then(|name| name.to_str());
        let mut failure = self.fail_pointer_after_replace.lock().unwrap();
        if failure.as_deref() == name {
            failure.take();
            return Err(GemmaPersistenceError::Failed);
        }
        Ok(())
    }
}

fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "muniment-gemma-lifecycle-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("staging")).unwrap();
    root
}

fn stage(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let stage = root.join("staging").join(name);
    fs::create_dir(&stage).unwrap();
    fs::write(stage.join("model.gguf"), bytes).unwrap();
    let notice = if bytes == b"def" {
        NEW.notice.contents
    } else {
        OLD.notice.contents
    };
    fs::write(stage.join("NOTICE.txt"), notice).unwrap();
    stage
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    Ready,
    StartFails,
    ExitsBeforeReady,
    ReadinessFails,
}

struct ActivationBoundary {
    attempts: Mutex<Vec<Attempt>>,
    launched: Mutex<Vec<PathBuf>>,
}

impl ActivationBoundary {
    fn new(attempts: Vec<Attempt>) -> Self {
        Self {
            attempts: Mutex::new(attempts.into_iter().rev().collect()),
            launched: Mutex::new(Vec::new()),
        }
    }
}

impl GemmaActivationBoundary for ActivationBoundary {
    type Server = (PathBuf, Attempt);

    fn launch(&self, model: &Path) -> Result<Self::Server, GemmaActivationFailure> {
        self.launched.lock().unwrap().push(model.to_owned());
        let attempt = self.attempts.lock().unwrap().pop().unwrap();
        if matches!(attempt, Attempt::StartFails) {
            Err(GemmaActivationFailure::Start)
        } else {
            Ok((model.to_owned(), attempt))
        }
    }

    fn await_ready(&self, server: &mut Self::Server) -> Result<(), GemmaActivationFailure> {
        match server.1 {
            Attempt::Ready => Ok(()),
            Attempt::ExitsBeforeReady => Err(GemmaActivationFailure::ExitedBeforeReady),
            Attempt::ReadinessFails => Err(GemmaActivationFailure::Readiness),
            Attempt::StartFails => unreachable!(),
        }
    }
}

fn published_update(root: &Path) -> GemmaRevisionLifecycle {
    GemmaRevisionLifecycle::new(root.to_owned(), &KNOWN, &OLD)
        .unwrap()
        .publish(&stage(root, "old-activation", b"abc"), &Boundary::working())
        .unwrap();
    let update = GemmaRevisionLifecycle::new(root.to_owned(), &KNOWN, &NEW).unwrap();
    update
        .publish(&stage(root, "new-activation", b"def"), &Boundary::working())
        .unwrap();
    update
}

#[test]
fn activation_returns_current_only_after_readiness() {
    let root = root();
    let lifecycle = published_update(&root);
    let activation = ActivationBoundary::new(vec![Attempt::Ready]);
    let result = lifecycle
        .activate(&Boundary::working(), &activation)
        .unwrap();
    assert!(matches!(
        result,
        GemmaActivation::Active { revision, .. } if revision == root.join("revisions/new")
    ));
    assert_eq!(activation.launched.lock().unwrap().len(), 1);
    assert!(!root.join("activation-failure").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_current_is_rejected_and_verified_previous_activates_once() {
    let root = root();
    let lifecycle = published_update(&root);
    let activation = ActivationBoundary::new(vec![Attempt::ReadinessFails, Attempt::Ready]);
    let result = lifecycle
        .activate(&Boundary::working(), &activation)
        .unwrap();
    assert!(matches!(
        result,
        GemmaActivation::RolledBack { revision, .. } if revision == root.join("revisions/old")
    ));
    assert_eq!(
        lifecycle.resolve_current().unwrap(),
        root.join("revisions/old")
    );
    assert_eq!(
        fs::read_to_string(root.join("activation-failure")).unwrap(),
        "readiness\n"
    );
    let rejected = fs::read_to_string(root.join("rejected")).unwrap();
    assert!(rejected.ends_with("\nnew\n"));
    assert!(!rejected.contains(root.to_str().unwrap()));
    assert_eq!(activation.launched.lock().unwrap().len(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_current_without_valid_previous_is_typed_unavailable() {
    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &NEW).unwrap();
    lifecycle
        .publish(&stage(&root, "only-new", b"def"), &Boundary::working())
        .unwrap();
    let activation = ActivationBoundary::new(vec![Attempt::StartFails]);
    assert!(matches!(
        lifecycle
            .activate(&Boundary::working(), &activation)
            .unwrap(),
        GemmaActivation::Unavailable(GemmaUnavailable::PreviousInvalid)
    ));
    assert_eq!(activation.launched.lock().unwrap().len(), 1);
    assert_eq!(
        fs::read_to_string(root.join("activation-failure")).unwrap(),
        "start\n"
    );
    let automatic_retry = ActivationBoundary::new(vec![]);
    assert!(matches!(
        lifecycle
            .activate(&Boundary::working(), &automatic_retry)
            .unwrap(),
        GemmaActivation::Unavailable(GemmaUnavailable::PreviousInvalid)
    ));
    assert!(automatic_retry.launched.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_rollback_activation_stops_after_exactly_two_attempts() {
    let root = root();
    let lifecycle = published_update(&root);
    let activation = ActivationBoundary::new(vec![Attempt::StartFails, Attempt::ExitsBeforeReady]);
    assert!(matches!(
        lifecycle
            .activate(&Boundary::working(), &activation)
            .unwrap(),
        GemmaActivation::Unavailable(GemmaUnavailable::RollbackActivationFailed)
    ));
    assert_eq!(activation.launched.lock().unwrap().len(), 2);
    assert_eq!(
        lifecycle.resolve_current().unwrap(),
        root.join("revisions/old")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_activation_state_replacement_never_relaunches_rejected_current() {
    for interrupted_pointer in ["rejected", "activation-failure", "current"] {
        let root = root();
        let lifecycle = published_update(&root);
        let failed = ActivationBoundary::new(vec![Attempt::ReadinessFails]);

        assert_eq!(
            lifecycle.activate(
                &Boundary::interrupt_after_pointer(interrupted_pointer),
                &failed,
            ),
            Err(GemmaLifecycleError::Persistence(
                GemmaPersistenceError::Failed
            ))
        );

        let retry = ActivationBoundary::new(vec![Attempt::Ready]);
        let result = lifecycle.activate(&Boundary::working(), &retry).unwrap();
        assert!(matches!(
            result,
            GemmaActivation::Active { revision, .. }
                | GemmaActivation::RolledBack { revision, .. }
                if revision == root.join("revisions/old")
        ));
        assert_eq!(
            retry.launched.lock().unwrap().as_slice(),
            &[root.join("revisions/old/model.gguf")]
        );
        assert_eq!(
            lifecycle.resolve_current().unwrap(),
            root.join("revisions/old")
        );
        if let Ok(diagnostic) = fs::read_to_string(root.join("activation-failure")) {
            assert_eq!(diagnostic, "readiness\n");
            assert!(!diagnostic.contains(root.to_str().unwrap()));
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn notice_must_match_the_revision_descriptor_for_publication_and_resolution() {
    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();

    let missing = stage(&root, "missing-notice", b"abc");
    fs::remove_file(missing.join("NOTICE.txt")).unwrap();
    assert!(matches!(
        lifecycle.publish(&missing, &Boundary::working()),
        Err(GemmaLifecycleError::RevisionInvalid(_))
    ));

    let wrong_association = stage(&root, "wrong-notice", b"abc");
    fs::write(wrong_association.join("NOTICE.txt"), NEW.notice.contents).unwrap();
    assert!(matches!(
        lifecycle.publish(&wrong_association, &Boundary::working()),
        Err(GemmaLifecycleError::RevisionInvalid(_))
    ));

    lifecycle
        .publish(&stage(&root, "valid", b"abc"), &Boundary::working())
        .unwrap();
    fs::write(root.join("revisions/old/NOTICE.txt"), b"tampered").unwrap();
    assert!(matches!(
        lifecycle.resolve_current(),
        Err(GemmaLifecycleError::RevisionInvalid(_))
    ));
    assert_eq!(
        lifecycle.recover(&Boundary::working()).unwrap(),
        GemmaRecovery::RepairRequired
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn publishes_only_verified_stage_under_an_exclusive_lock() {
    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    let bad = stage(&root, "bad", b"abd");
    let boundary = Boundary::working();
    assert!(matches!(
        lifecycle.publish(&bad, &boundary),
        Err(GemmaLifecycleError::RevisionInvalid(_))
    ));
    assert!(!root.join("current").exists());

    let good = stage(&root, "good", b"abc");
    let revision = lifecycle.publish(&good, &boundary).unwrap();
    assert_eq!(revision, root.join("revisions/old"));
    assert_eq!(lifecycle.resolve_current().unwrap(), revision);
    assert_eq!(boundary.locks.load(Ordering::Relaxed), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_pointer_replace_keeps_verified_current_and_previous() {
    let root = root();
    let old = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    old.publish(&stage(&root, "old", b"abc"), &Boundary::working())
        .unwrap();
    let old_pointer = fs::read(root.join("current")).unwrap();

    let update = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &NEW).unwrap();
    assert_eq!(
        update.publish(&stage(&root, "new", b"def"), &Boundary::failing_current()),
        Err(GemmaLifecycleError::Persistence(
            GemmaPersistenceError::Failed
        ))
    );
    assert_eq!(fs::read(root.join("current")).unwrap(), old_pointer);
    assert_eq!(fs::read(root.join("previous")).unwrap(), old_pointer);
    assert_eq!(
        update.resolve_current().unwrap(),
        root.join("revisions/old")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_current_restores_verified_previous_and_never_promotes_staging() {
    let root = root();
    let old = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    old.publish(&stage(&root, "old", b"abc"), &Boundary::working())
        .unwrap();
    let update = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &NEW).unwrap();
    update
        .publish(&stage(&root, "new", b"def"), &Boundary::working())
        .unwrap();
    fs::write(root.join("revisions/new/model.gguf"), b"bad").unwrap();
    stage(&root, "tempting", b"def");
    fs::write(root.join(".current.tmp"), b"interrupted pointer").unwrap();

    let boundary = Boundary::working();
    assert_eq!(
        update.recover(&boundary).unwrap(),
        GemmaRecovery::RestoredPrevious(root.join("revisions/old"))
    );
    assert_eq!(
        update.resolve_current().unwrap(),
        root.join("revisions/old")
    );
    assert_eq!(boundary.locks.load(Ordering::Relaxed), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verified_stage_repairs_corrupt_existing_revision() {
    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    lifecycle
        .publish(&stage(&root, "first", b"abc"), &Boundary::working())
        .unwrap();
    fs::write(root.join("revisions/old/model.gguf"), b"bad").unwrap();

    let repaired = lifecycle
        .publish(&stage(&root, "repair", b"abc"), &Boundary::working())
        .unwrap();
    assert_eq!(repaired, root.join("revisions/old"));
    assert_eq!(fs::read(repaired.join("model.gguf")).unwrap(), b"abc");
    assert_eq!(lifecycle.resolve_current().unwrap(), repaired);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_corrupt_revision_replacement_never_exposes_staged_bytes() {
    for failure_step in [1, 2] {
        let root = root();
        let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
        lifecycle
            .publish(&stage(&root, "first", b"abc"), &Boundary::working())
            .unwrap();
        fs::write(root.join("revisions/old/model.gguf"), b"bad").unwrap();
        let repair = stage(&root, "repair", b"abc");

        assert_eq!(
            lifecycle.publish(&repair, &Boundary::failing_revision_at(failure_step)),
            Err(GemmaLifecycleError::Persistence(
                GemmaPersistenceError::Failed
            ))
        );
        assert!(lifecycle.resolve_current().is_err());
        assert!(repair.exists());

        lifecycle.publish(&repair, &Boundary::working()).unwrap();
        assert_eq!(
            lifecycle.resolve_current().unwrap(),
            root.join("revisions/old")
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn rejects_linked_stage_directory_and_model() {
    use std::os::unix::fs::symlink;

    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    let outside = root.with_extension("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("model.gguf"), b"abc").unwrap();
    let linked_stage = root.join("staging/linked-stage");
    symlink(&outside, &linked_stage).unwrap();
    assert_eq!(
        lifecycle.publish(&linked_stage, &Boundary::working()),
        Err(GemmaLifecycleError::InvalidStage)
    );

    let model_stage = root.join("staging/linked-model");
    fs::create_dir(&model_stage).unwrap();
    symlink(outside.join("model.gguf"), model_stage.join("model.gguf")).unwrap();
    assert!(matches!(
        lifecycle.publish(&model_stage, &Boundary::working()),
        Err(GemmaLifecycleError::RevisionInvalid(_))
    ));
    assert!(!root.join("current").exists());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn recovery_rejects_linked_revision_directory_and_model() {
    use std::os::unix::fs::symlink;

    for link_directory in [true, false] {
        let root = root();
        let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
        lifecycle
            .publish(&stage(&root, "first", b"abc"), &Boundary::working())
            .unwrap();
        let revision = root.join("revisions/old");
        let outside = root.with_extension("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("model.gguf"), b"abc").unwrap();
        if link_directory {
            fs::remove_dir_all(&revision).unwrap();
            symlink(&outside, &revision).unwrap();
        } else {
            fs::remove_file(revision.join("model.gguf")).unwrap();
            symlink(outside.join("model.gguf"), revision.join("model.gguf")).unwrap();
        }

        assert!(matches!(
            lifecycle.resolve_current(),
            Err(GemmaLifecycleError::RevisionInvalid(_))
        ));
        assert_eq!(
            lifecycle.recover(&Boundary::working()).unwrap(),
            GemmaRecovery::RepairRequired
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn linked_pointer_files_require_repair_even_when_the_target_looks_valid() {
    use std::os::unix::fs::symlink;

    for external_contents in [
        "muniment-gemma-pointer-v1\ngemma-fixture-v1\nold\n",
        "malformed",
    ] {
        let root = root();
        let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
        let external = root.with_extension("pointer");
        fs::write(&external, external_contents).unwrap();
        symlink(&external, root.join("current")).unwrap();

        assert_eq!(
            lifecycle.resolve_current(),
            Err(GemmaLifecycleError::InvalidPointer)
        );
        assert_eq!(
            lifecycle.recover(&Boundary::working()).unwrap(),
            GemmaRecovery::RepairRequired
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(external).unwrap();
    }

    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    symlink(root.join("does-not-exist"), root.join("current")).unwrap();
    assert_eq!(
        lifecycle.resolve_current(),
        Err(GemmaLifecycleError::InvalidPointer)
    );
    assert_eq!(
        lifecycle.recover(&Boundary::working()).unwrap(),
        GemmaRecovery::RepairRequired
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_or_unsafe_pointers_require_repair_without_leaking_paths() {
    let root = root();
    let lifecycle = GemmaRevisionLifecycle::new(root.clone(), &KNOWN, &OLD).unwrap();
    for pointer in [
        "muniment-gemma-pointer-v1\nunknown\nold\n",
        "muniment-gemma-pointer-v1\ngemma-fixture-v1\n../old\n",
        "malformed",
    ] {
        fs::write(root.join("current"), pointer).unwrap();
        let error = lifecycle.resolve_current().unwrap_err();
        assert!(!format!("{error:?} {error}").contains(root.to_str().unwrap()));
        assert_eq!(
            lifecycle.recover(&Boundary::working()).unwrap(),
            GemmaRecovery::RepairRequired
        );
    }
    fs::remove_file(root.join("current")).unwrap();
    assert_eq!(
        lifecycle.recover(&Boundary::working()).unwrap(),
        GemmaRecovery::NotInstalled
    );
    fs::remove_dir_all(root).unwrap();
}
