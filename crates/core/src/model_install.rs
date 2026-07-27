//! Shared orchestration for acquiring and publishing pinned model revisions.
//!
//! Platform adapters own locking and free-space discovery. Model-specific
//! code owns calculating the bytes still missing from its resumable stage,
//! acquisition, and publication.

const STORAGE_MARGIN_BYTES: u64 = 256 * 1024 * 1024;

pub trait InstallCancellation {
    fn is_cancelled(&self) -> bool;
}

impl<F: Fn() -> bool> InstallCancellation for F {
    fn is_cancelled(&self) -> bool {
        self()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallLockError {
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallLockState<G> {
    Acquired(G),
    Contended,
}

/// Cancellable exclusive-lock boundary. `wait_for_retry` should block only
/// briefly and return `false` when cancellation interrupts the wait.
pub trait InstallLock {
    type Guard;

    fn try_lock_exclusive(&mut self) -> Result<InstallLockState<Self::Guard>, InstallLockError>;
    fn wait_for_retry(&mut self, cancellation: &dyn InstallCancellation) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailableSpaceError {
    Failed,
}

pub trait AvailableSpace {
    /// Returns available bytes on the volume containing the model root.
    fn available_bytes(&mut self) -> Result<Option<u64>, AvailableSpaceError>;
}

impl<F> AvailableSpace for F
where
    F: FnMut() -> Result<Option<u64>, AvailableSpaceError>,
{
    fn available_bytes(&mut self) -> Result<Option<u64>, AvailableSpaceError> {
        self()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelInstallError<A, P> {
    Lock(InstallLockError),
    Cancelled,
    StorageUnknown,
    StorageInsufficient { required: u64, available: u64 },
    StorageRequirementOverflow,
    Acquisition(A),
    Publication(P),
}

impl<A, P> std::fmt::Display for ModelInstallError<A, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Lock(_) => "model installation lock is unavailable",
            Self::Cancelled => "model installation was cancelled",
            Self::StorageUnknown => "available model storage could not be determined",
            Self::StorageInsufficient { .. } => "available model storage is insufficient",
            Self::StorageRequirementOverflow => "model storage requirement is invalid",
            Self::Acquisition(_) => "model acquisition failed",
            Self::Publication(_) => "model publication failed",
        })
    }
}

impl<A: std::fmt::Debug, P: std::fmt::Debug> std::error::Error for ModelInstallError<A, P> {}

/// Runs one complete pinned-model install while retaining a single lock guard.
///
/// `remaining_stage_bytes` is evaluated immediately before acquisition and
/// again after acquisition, so resumable stages are charged only for their
/// exact missing pinned bytes at each storage precondition.
pub fn install_model<L, S, C, R, A, P, Stage, Output, AcquisitionError, PublicationError>(
    lock: &mut L,
    space: &mut S,
    cancellation: &C,
    mut remaining_stage_bytes: R,
    acquire: A,
    publish_lock_held: P,
) -> Result<Output, ModelInstallError<AcquisitionError, PublicationError>>
where
    L: InstallLock,
    S: AvailableSpace,
    C: InstallCancellation,
    R: FnMut() -> Result<u64, AcquisitionError>,
    A: FnOnce() -> Result<Stage, AcquisitionError>,
    P: FnOnce(Stage) -> Result<Output, PublicationError>,
{
    let _guard = loop {
        if cancellation.is_cancelled() {
            return Err(ModelInstallError::Cancelled);
        }
        match lock.try_lock_exclusive().map_err(ModelInstallError::Lock)? {
            InstallLockState::Acquired(guard) => break guard,
            InstallLockState::Contended => {
                if !lock.wait_for_retry(cancellation) || cancellation.is_cancelled() {
                    return Err(ModelInstallError::Cancelled);
                }
            }
        }
    };

    check_space(
        space,
        remaining_stage_bytes().map_err(ModelInstallError::Acquisition)?,
    )?;
    if cancellation.is_cancelled() {
        return Err(ModelInstallError::Cancelled);
    }
    let stage = acquire().map_err(ModelInstallError::Acquisition)?;
    if cancellation.is_cancelled() {
        return Err(ModelInstallError::Cancelled);
    }
    check_space(
        space,
        remaining_stage_bytes().map_err(ModelInstallError::Acquisition)?,
    )?;
    if cancellation.is_cancelled() {
        return Err(ModelInstallError::Cancelled);
    }
    publish_lock_held(stage).map_err(ModelInstallError::Publication)
}

fn check_space<A, P>(
    space: &mut impl AvailableSpace,
    remaining: u64,
) -> Result<(), ModelInstallError<A, P>> {
    let required = remaining
        .checked_add(STORAGE_MARGIN_BYTES)
        .ok_or(ModelInstallError::StorageRequirementOverflow)?;
    let available = space
        .available_bytes()
        .map_err(|_| ModelInstallError::StorageUnknown)?
        .ok_or(ModelInstallError::StorageUnknown)?;
    if available < required {
        return Err(ModelInstallError::StorageInsufficient {
            required,
            available,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const MARGIN: u64 = 256 * 1024 * 1024;

    struct TestLock {
        attempts: RefCell<Vec<InstallLockState<()>>>,
        waits: Cell<usize>,
        cancel_during_wait: Cell<bool>,
    }

    impl TestLock {
        fn acquired() -> Self {
            Self {
                attempts: RefCell::new(vec![InstallLockState::Acquired(())]),
                waits: Cell::new(0),
                cancel_during_wait: Cell::new(false),
            }
        }
    }

    impl InstallLock for TestLock {
        type Guard = ();

        fn try_lock_exclusive(
            &mut self,
        ) -> Result<InstallLockState<Self::Guard>, InstallLockError> {
            Ok(self.attempts.borrow_mut().remove(0))
        }

        fn wait_for_retry(&mut self, _cancellation: &dyn InstallCancellation) -> bool {
            self.waits.set(self.waits.get() + 1);
            !self.cancel_during_wait.get()
        }
    }

    fn successful_fixture_install(label: &'static str, artifact_count: usize) {
        let mut lock = TestLock::acquired();
        let mut checks = vec![Some(MARGIN), Some(MARGIN + 8)].into_iter();
        let mut space = || Ok(checks.next().unwrap());
        let remaining = Cell::new(0);
        let acquired = Cell::new(false);
        let published = Cell::new(false);
        let result = install_model(
            &mut lock,
            &mut space,
            &|| false,
            || Ok::<_, &'static str>(remaining.get()),
            || {
                acquired.set(true);
                Ok((label, artifact_count))
            },
            |stage| {
                published.set(true);
                Ok::<_, &'static str>(stage)
            },
        );
        assert_eq!(result, Ok((label, artifact_count)));
        assert!(acquired.get() && published.get());
    }

    #[test]
    fn one_contract_installs_resident_model_and_parakeet_fixtures() {
        successful_fixture_install("gemma", 1);
        successful_fixture_install("parakeet", 4);
    }

    #[test]
    fn contention_is_observed_then_the_same_install_acquires() {
        let mut lock = TestLock {
            attempts: RefCell::new(vec![
                InstallLockState::Contended,
                InstallLockState::Acquired(()),
            ]),
            waits: Cell::new(0),
            cancel_during_wait: Cell::new(false),
        };
        let mut space = || Ok(Some(MARGIN));
        let result = install_model(
            &mut lock,
            &mut space,
            &|| false,
            || Ok::<_, ()>(0),
            || Ok(()),
            |_| Ok::<_, ()>(()),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(lock.waits.get(), 1);
    }

    #[test]
    fn cancellation_while_contended_never_acquires_or_publishes() {
        let mut lock = TestLock {
            attempts: RefCell::new(vec![InstallLockState::Contended]),
            waits: Cell::new(0),
            cancel_during_wait: Cell::new(true),
        };
        let downloaded = Cell::new(false);
        let published = Cell::new(false);
        let mut space = || Ok(Some(u64::MAX));
        let result = install_model(
            &mut lock,
            &mut space,
            &|| false,
            || Ok::<_, ()>(0),
            || {
                downloaded.set(true);
                Ok(())
            },
            |_| {
                published.set(true);
                Ok::<_, ()>(())
            },
        );
        assert_eq!(result, Err(ModelInstallError::Cancelled));
        assert!(!downloaded.get() && !published.get());
    }

    #[test]
    fn unknown_and_insufficient_initial_space_prevent_download_and_publication() {
        for available in [None, Some(MARGIN + 9)] {
            let mut lock = TestLock::acquired();
            let mut space = || Ok(available);
            let called = Cell::new(false);
            let result = install_model(
                &mut lock,
                &mut space,
                &|| false,
                || Ok::<_, ()>(10),
                || {
                    called.set(true);
                    Ok(())
                },
                |_| {
                    called.set(true);
                    Ok::<_, ()>(())
                },
            );
            assert!(matches!(
                result,
                Err(ModelInstallError::StorageUnknown)
                    | Err(ModelInstallError::StorageInsufficient { .. })
            ));
            assert!(!called.get());
        }
    }

    #[test]
    fn space_lost_before_publication_prevents_publication() {
        let mut lock = TestLock::acquired();
        let mut values = vec![Some(MARGIN + 10), Some(MARGIN - 1)].into_iter();
        let mut space = || Ok(values.next().unwrap());
        let remaining = Cell::new(10);
        let published = Cell::new(false);
        let result = install_model(
            &mut lock,
            &mut space,
            &|| false,
            || Ok::<_, ()>(remaining.get()),
            || {
                remaining.set(0);
                Ok(())
            },
            |_| {
                published.set(true);
                Ok::<_, ()>(())
            },
        );
        assert_eq!(
            result,
            Err(ModelInstallError::StorageInsufficient {
                required: MARGIN,
                available: MARGIN - 1,
            })
        );
        assert!(!published.get());
    }
}
