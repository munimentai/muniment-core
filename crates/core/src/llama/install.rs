//! Coordinated acquisition and publication of a resident-model revision.

use std::path::{Path, PathBuf};

use crate::model_install::{
    install_model, AvailableSpace, InstallCancellation, InstallLock, ModelInstallError,
};

use super::acquisition::{
    acquire_resident_model_stage_with_progress, remaining_stage_bytes, ModelDownloadProgress,
    ResidentModelAcquisitionClock, ResidentModelAcquisitionError, ResidentModelAcquisitionLimits,
    ResidentModelAcquisitionRuntime, ResidentModelCancellation, ResidentModelDownloadTransport,
    ResidentModelRetryWait,
};
use super::lifecycle::{
    ResidentModelLifecycleBoundary, ResidentModelLifecycleError, ResidentModelRevisionDescriptor,
    ResidentModelRevisionLifecycle,
};

pub type ResidentModelInstallError =
    ModelInstallError<ResidentModelAcquisitionError, ResidentModelLifecycleError>;

/// Acquires and publishes one pinned resident-model revision under the shared install
/// lock and exact resumable-stage storage checks.
#[allow(clippy::too_many_arguments)]
pub fn install_resident_model_revision<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static ResidentModelRevisionDescriptor,
    limits: ResidentModelAcquisitionLimits,
    transport: &mut T,
    runtime: ResidentModelAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &ResidentModelRevisionLifecycle,
    lifecycle_boundary: &B,
) -> Result<PathBuf, ResidentModelInstallError>
where
    T: ResidentModelDownloadTransport,
    C: ResidentModelCancellation + InstallCancellation,
    K: ResidentModelAcquisitionClock,
    W: ResidentModelRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: ResidentModelLifecycleBoundary,
{
    install_resident_model_revision_with_progress(
        staging_root,
        install_id,
        descriptor,
        limits,
        transport,
        runtime,
        cancellation,
        lock,
        space,
        lifecycle,
        lifecycle_boundary,
        &mut |_| {},
    )
}

/// Installs a revision while reporting resumable, transport-independent byte progress.
#[allow(clippy::too_many_arguments)]
pub fn install_resident_model_revision_with_progress<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static ResidentModelRevisionDescriptor,
    limits: ResidentModelAcquisitionLimits,
    transport: &mut T,
    runtime: ResidentModelAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &ResidentModelRevisionLifecycle,
    lifecycle_boundary: &B,
    progress: &mut dyn FnMut(ModelDownloadProgress),
) -> Result<PathBuf, ResidentModelInstallError>
where
    T: ResidentModelDownloadTransport,
    C: ResidentModelCancellation + InstallCancellation,
    K: ResidentModelAcquisitionClock,
    W: ResidentModelRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: ResidentModelLifecycleBoundary,
{
    install_model(
        lock,
        space,
        cancellation,
        || remaining_stage_bytes(staging_root, install_id, descriptor),
        || {
            acquire_resident_model_stage_with_progress(
                staging_root,
                install_id,
                descriptor,
                limits,
                transport,
                runtime,
                cancellation,
                progress,
            )
        },
        |stage| lifecycle.publish_lock_held(&stage, lifecycle_boundary),
    )
}
