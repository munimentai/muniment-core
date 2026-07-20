//! Coordinated acquisition and publication of a resident Gemma revision.

use std::path::{Path, PathBuf};

use crate::model_install::{
    install_model, AvailableSpace, InstallCancellation, InstallLock, ModelInstallError,
};

use super::acquisition::{
    acquire_gemma_stage_with_progress, remaining_stage_bytes, GemmaAcquisitionClock,
    GemmaAcquisitionError, GemmaAcquisitionLimits, GemmaAcquisitionRuntime, GemmaCancellation,
    GemmaDownloadTransport, GemmaRetryWait, ModelDownloadProgress,
};
use super::lifecycle::{
    GemmaLifecycleBoundary, GemmaLifecycleError, GemmaRevisionDescriptor, GemmaRevisionLifecycle,
};

pub type GemmaInstallError = ModelInstallError<GemmaAcquisitionError, GemmaLifecycleError>;

/// Acquires and publishes one pinned Gemma revision under the shared install
/// lock and exact resumable-stage storage checks.
#[allow(clippy::too_many_arguments)]
pub fn install_gemma_revision<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static GemmaRevisionDescriptor,
    limits: GemmaAcquisitionLimits,
    transport: &mut T,
    runtime: GemmaAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &GemmaRevisionLifecycle,
    lifecycle_boundary: &B,
) -> Result<PathBuf, GemmaInstallError>
where
    T: GemmaDownloadTransport,
    C: GemmaCancellation + InstallCancellation,
    K: GemmaAcquisitionClock,
    W: GemmaRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: GemmaLifecycleBoundary,
{
    install_gemma_revision_with_progress(
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
pub fn install_gemma_revision_with_progress<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static GemmaRevisionDescriptor,
    limits: GemmaAcquisitionLimits,
    transport: &mut T,
    runtime: GemmaAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &GemmaRevisionLifecycle,
    lifecycle_boundary: &B,
    progress: &mut dyn FnMut(ModelDownloadProgress),
) -> Result<PathBuf, GemmaInstallError>
where
    T: GemmaDownloadTransport,
    C: GemmaCancellation + InstallCancellation,
    K: GemmaAcquisitionClock,
    W: GemmaRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: GemmaLifecycleBoundary,
{
    install_model(
        lock,
        space,
        cancellation,
        || remaining_stage_bytes(staging_root, install_id, descriptor),
        || {
            acquire_gemma_stage_with_progress(
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
