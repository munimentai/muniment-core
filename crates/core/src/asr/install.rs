//! Coordinated acquisition and publication of a Parakeet revision.

use std::path::{Path, PathBuf};

use crate::model_install::{
    install_model, AvailableSpace, InstallCancellation, InstallLock, ModelInstallError,
};

use super::acquisition::{
    acquire_parakeet_stage, remaining_stage_bytes, AsrAcquisitionClock, AsrAcquisitionError,
    AsrAcquisitionLimits, AsrAcquisitionRuntime, AsrCancellation, AsrDownloadTransport,
    AsrRetryWait,
};
use super::{AsrArtifactManifest, AsrLifecycleBoundary, AsrLifecycleError, AsrRevisionLifecycle};

pub type ParakeetInstallError = ModelInstallError<AsrAcquisitionError, AsrLifecycleError>;

/// Acquires and publishes one pinned Parakeet revision under the shared
/// install lock and exact resumable-stage storage checks.
#[allow(clippy::too_many_arguments)]
pub fn install_parakeet_revision<T, C, K, W, L, S, B>(
    staging_root: &Path,
    install_id: &str,
    manifest: &'static AsrArtifactManifest,
    limits: AsrAcquisitionLimits,
    transport: &mut T,
    runtime: AsrAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    lock: &mut L,
    space: &mut S,
    lifecycle: &AsrRevisionLifecycle,
    lifecycle_boundary: &B,
) -> Result<PathBuf, ParakeetInstallError>
where
    T: AsrDownloadTransport,
    C: AsrCancellation + InstallCancellation,
    K: AsrAcquisitionClock,
    W: AsrRetryWait,
    L: InstallLock,
    S: AvailableSpace,
    B: AsrLifecycleBoundary,
{
    install_model(
        lock,
        space,
        cancellation,
        || remaining_stage_bytes(staging_root, install_id, manifest),
        || {
            acquire_parakeet_stage(
                staging_root,
                install_id,
                manifest,
                limits,
                transport,
                runtime,
                cancellation,
            )
        },
        |stage| lifecycle.publish_lock_held(&stage, lifecycle_boundary),
    )
}
