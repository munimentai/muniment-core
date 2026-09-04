//! Coordinated acquisition and publication of a model-artifact revision.

use std::path::{Path, PathBuf};

use crate::model_install::{
    install_model, AvailableSpace, InstallCancellation, InstallLock, ModelInstallError,
};

use super::acquisition::{
    acquire_model_artifact_stage_with_progress, remaining_stage_bytes,
    ModelArtifactAcquisitionClock, ModelArtifactAcquisitionError, ModelArtifactAcquisitionLimits,
    ModelArtifactAcquisitionRuntime, ModelArtifactCancellation, ModelArtifactDownloadTransport,
    ModelArtifactRetryWait, ModelDownloadProgress,
};
use super::lifecycle::{
    ModelArtifactLifecycleBoundary, ModelArtifactLifecycleError, ModelArtifactRevisionDescriptor,
    ModelArtifactRevisionLifecycle,
};

pub type ModelArtifactInstallError =
    ModelInstallError<ModelArtifactAcquisitionError, ModelArtifactLifecycleError>;

/// Acquires and publishes one pinned model-artifact revision under the shared install
/// lock and exact resumable-stage storage checks.
#[allow(clippy::too_many_arguments)]
pub fn install_model_artifact_revision<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static ModelArtifactRevisionDescriptor,
    limits: ModelArtifactAcquisitionLimits,
    transport: &mut T,
    runtime: ModelArtifactAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &ModelArtifactRevisionLifecycle,
    lifecycle_boundary: &B,
) -> Result<PathBuf, ModelArtifactInstallError>
where
    T: ModelArtifactDownloadTransport,
    C: ModelArtifactCancellation + InstallCancellation,
    K: ModelArtifactAcquisitionClock,
    W: ModelArtifactRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: ModelArtifactLifecycleBoundary,
{
    install_model_artifact_revision_with_progress(
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
pub fn install_model_artifact_revision_with_progress<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static ModelArtifactRevisionDescriptor,
    limits: ModelArtifactAcquisitionLimits,
    transport: &mut T,
    runtime: ModelArtifactAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &ModelArtifactRevisionLifecycle,
    lifecycle_boundary: &B,
    progress: &mut dyn FnMut(ModelDownloadProgress),
) -> Result<PathBuf, ModelArtifactInstallError>
where
    T: ModelArtifactDownloadTransport,
    C: ModelArtifactCancellation + InstallCancellation,
    K: ModelArtifactAcquisitionClock,
    W: ModelArtifactRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: ModelArtifactLifecycleBoundary,
{
    install_model(
        lock,
        space,
        cancellation,
        || remaining_stage_bytes(staging_root, install_id, descriptor),
        || {
            acquire_model_artifact_stage_with_progress(
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
