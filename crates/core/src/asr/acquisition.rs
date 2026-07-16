//! Bounded, resumable acquisition of the pinned Parakeet model set.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    verify_artifact, verify_model_set, AsrArtifactDescriptor, AsrArtifactManifest,
    AsrModelSetVerificationError,
};

const SOURCE_REPOSITORY: &str = "csukuangfj/sherpa-onnx-nemo-parakeet-tdt-0.6b-v3-int8";
const READ_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsrAcquisitionLimits {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub deadline: Duration,
    pub max_attempts: u8,
}

impl Default for AsrAcquisitionLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            deadline: Duration::from_secs(30 * 60),
            max_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsrDownloadRequest {
    url: String,
    pub artifact_index: usize,
    pub offset: u64,
    pub limits: AsrAcquisitionLimits,
}

impl AsrDownloadRequest {
    pub fn url(&self) -> &str {
        &self.url
    }

    #[cfg(test)]
    pub(crate) fn for_transport_test(
        url: String,
        offset: u64,
        limits: AsrAcquisitionLimits,
    ) -> Self {
        Self {
            url,
            artifact_index: 0,
            offset,
            limits,
        }
    }
}

pub struct AsrDownloadResponse<R> {
    pub status: u16,
    /// Inclusive response range `(first, last, complete_length)` for a 206.
    pub content_range: Option<(u64, u64, u64)>,
    pub body: R,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsrTransportError {
    Transient,
    Unavailable,
    Rejected,
}

pub trait AsrDownloadTransport {
    type Body: Read;
    fn download(
        &mut self,
        request: &AsrDownloadRequest,
    ) -> Result<AsrDownloadResponse<Self::Body>, AsrTransportError>;
}

pub trait AsrCancellation {
    fn is_cancelled(&self) -> bool;
}
impl<F: Fn() -> bool> AsrCancellation for F {
    fn is_cancelled(&self) -> bool {
        self()
    }
}

pub trait AsrAcquisitionClock {
    fn now(&self) -> Duration;
}
impl<F: Fn() -> Duration> AsrAcquisitionClock for F {
    fn now(&self) -> Duration {
        self()
    }
}

pub trait AsrRetryWait {
    fn wait(&mut self, maximum_delay: Duration, cancellation: &dyn AsrCancellation) -> bool;
}
impl<F> AsrRetryWait for F
where
    F: FnMut(Duration, &dyn AsrCancellation) -> bool,
{
    fn wait(&mut self, delay: Duration, cancellation: &dyn AsrCancellation) -> bool {
        self(delay, cancellation)
    }
}

pub struct AsrAcquisitionRuntime<'a, K, W> {
    pub clock: &'a K,
    pub retry_wait: &'a mut W,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsrAcquisitionError {
    InvalidStage,
    InvalidLimits,
    Cancelled,
    Retryable,
    Unavailable,
    Rejected,
    InvalidResponse,
    TooLarge,
    Verification(AsrModelSetVerificationError),
    Persistence,
}

impl std::fmt::Display for AsrAcquisitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidStage => "ASR model stage is invalid",
            Self::InvalidLimits => "ASR model acquisition limits are invalid",
            Self::Cancelled => "ASR model download was cancelled",
            Self::Retryable => "ASR model download can be retried",
            Self::Unavailable => "ASR model artifact is unavailable",
            Self::Rejected => "ASR model download was rejected",
            Self::InvalidResponse => "ASR model server response is invalid",
            Self::TooLarge => "ASR model download exceeded its pinned size",
            Self::Verification(_) => "ASR model download failed verification",
            Self::Persistence => "ASR model stage could not be persisted",
        })
    }
}
impl std::error::Error for AsrAcquisitionError {}

/// Returns the aggregate pinned bytes not yet present in a resumable stage.
pub fn remaining_stage_bytes(
    staging_root: &Path,
    install_id: &str,
    manifest: &AsrArtifactManifest,
) -> Result<u64, AsrAcquisitionError> {
    if !safe_component(install_id) {
        return Err(AsrAcquisitionError::InvalidStage);
    }
    require_directory(staging_root)?;
    let stage = staging_root.join(install_id);
    match fs::symlink_metadata(&stage) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(AsrAcquisitionError::InvalidStage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return manifest
                .artifacts
                .iter()
                .chain(
                    manifest
                        .additional_artifact
                        .as_ref()
                        .map(|additional| &additional.artifact),
                )
                .try_fold(0_u64, |total, artifact| {
                    total
                        .checked_add(artifact.byte_size)
                        .ok_or(AsrAcquisitionError::TooLarge)
                })
        }
        Err(_) => return Err(AsrAcquisitionError::Persistence),
    }

    manifest
        .artifacts
        .iter()
        .chain(
            manifest
                .additional_artifact
                .as_ref()
                .map(|additional| &additional.artifact),
        )
        .try_fold(0_u64, |total, artifact| {
            let completed = stage.join(artifact.filename);
            let missing = match fs::symlink_metadata(&completed) {
                Ok(metadata) if !metadata.file_type().is_file() => {
                    return Err(AsrAcquisitionError::InvalidStage)
                }
                Ok(_) if verify_artifact(&completed, artifact).is_ok() => 0,
                Ok(_) => artifact
                    .byte_size
                    .checked_sub(strict_part_length(
                        &stage.join(format!("{}.part", artifact.filename)),
                        artifact.byte_size,
                    )?)
                    .ok_or(AsrAcquisitionError::TooLarge)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => artifact
                    .byte_size
                    .checked_sub(strict_part_length(
                        &stage.join(format!("{}.part", artifact.filename)),
                        artifact.byte_size,
                    )?)
                    .ok_or(AsrAcquisitionError::TooLarge)?,
                Err(_) => return Err(AsrAcquisitionError::Persistence),
            };
            total
                .checked_add(missing)
                .ok_or(AsrAcquisitionError::TooLarge)
        })
}

/// Returns `staging/<id>` only after every pinned artifact verifies.
pub fn acquire_parakeet_stage<T, C, K, W>(
    staging_root: &Path,
    install_id: &str,
    manifest: &'static AsrArtifactManifest,
    limits: AsrAcquisitionLimits,
    transport: &mut T,
    runtime: AsrAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
) -> Result<PathBuf, AsrAcquisitionError>
where
    T: AsrDownloadTransport,
    C: AsrCancellation,
    K: AsrAcquisitionClock,
    W: AsrRetryWait,
{
    if !safe_component(install_id) {
        return Err(AsrAcquisitionError::InvalidStage);
    }
    if limits.max_attempts == 0
        || limits.connect_timeout.is_zero()
        || limits.read_timeout.is_zero()
        || limits.deadline.is_zero()
    {
        return Err(AsrAcquisitionError::InvalidLimits);
    }
    let started_at = runtime.clock.now();
    require_directory(staging_root)?;
    let stage = staging_root.join(install_id);
    match fs::create_dir(&stage) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_directory(&stage)?
        }
        Err(_) => return Err(AsrAcquisitionError::Persistence),
    }

    for (artifact_index, artifact) in manifest
        .artifacts
        .iter()
        .chain(
            manifest
                .additional_artifact
                .as_ref()
                .map(|additional| &additional.artifact),
        )
        .enumerate()
    {
        acquire_artifact(
            &stage,
            artifact_index,
            artifact,
            manifest,
            limits,
            transport,
            runtime.clock,
            runtime.retry_wait,
            started_at,
            cancellation,
        )?;
    }
    verify_model_set(&stage, manifest).map_err(AsrAcquisitionError::Verification)?;
    Ok(stage)
}

#[allow(clippy::too_many_arguments)]
fn acquire_artifact<T, C, K, W>(
    stage: &Path,
    artifact_index: usize,
    artifact: &AsrArtifactDescriptor,
    manifest: &AsrArtifactManifest,
    limits: AsrAcquisitionLimits,
    transport: &mut T,
    clock: &K,
    retry_wait: &mut W,
    started_at: Duration,
    cancellation: &C,
) -> Result<(), AsrAcquisitionError>
where
    T: AsrDownloadTransport,
    C: AsrCancellation,
    K: AsrAcquisitionClock,
    W: AsrRetryWait,
{
    let completed = stage.join(artifact.filename);
    match fs::symlink_metadata(&completed) {
        Ok(metadata)
            if metadata.file_type().is_file() && verify_artifact(&completed, artifact).is_ok() =>
        {
            return Ok(())
        }
        Ok(_) => remove_file(&completed)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(AsrAcquisitionError::Persistence),
    }
    let part = stage.join(format!("{}.part", artifact.filename));

    for attempt in 0..limits.max_attempts {
        if cancellation.is_cancelled() {
            return Err(AsrAcquisitionError::Cancelled);
        }
        let remaining = remaining_budget(clock, started_at, limits.deadline)?;
        let offset = part_length(&part, artifact.byte_size)?;
        if offset == artifact.byte_size {
            return finish_artifact(&part, &completed, artifact);
        }
        let request = AsrDownloadRequest {
            url: source_url(manifest, artifact_index, artifact),
            artifact_index,
            offset,
            limits: AsrAcquisitionLimits {
                connect_timeout: limits.connect_timeout.min(remaining),
                read_timeout: limits.read_timeout.min(remaining),
                deadline: remaining,
                max_attempts: limits.max_attempts,
            },
        };
        let response = match transport.download(&request) {
            Ok(response) => response,
            Err(AsrTransportError::Transient) if attempt + 1 < limits.max_attempts => {
                wait_before_retry(
                    retry_wait,
                    clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
                continue;
            }
            Err(AsrTransportError::Transient) => return Err(AsrAcquisitionError::Retryable),
            Err(AsrTransportError::Unavailable) => return Err(AsrAcquisitionError::Unavailable),
            Err(AsrTransportError::Rejected) => return Err(AsrAcquisitionError::Rejected),
        };
        let append = match validate_response(&response, offset, artifact.byte_size) {
            Ok(value) => value,
            Err(AsrAcquisitionError::InvalidResponse) => {
                remove_file(&part)?;
                if attempt + 1 < limits.max_attempts {
                    wait_before_retry(
                        retry_wait,
                        clock,
                        started_at,
                        limits.deadline,
                        attempt,
                        cancellation,
                    )?;
                    continue;
                }
                return Err(AsrAcquisitionError::Retryable);
            }
            Err(AsrAcquisitionError::Retryable) if attempt + 1 < limits.max_attempts => {
                wait_before_retry(
                    retry_wait,
                    clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
                continue;
            }
            Err(error) => return Err(error),
        };
        if !append {
            remove_file(&part)?;
        }
        match stream_response(
            response.body,
            &part,
            artifact.byte_size,
            clock,
            started_at,
            limits.deadline,
            cancellation,
        ) {
            Ok(true) => return finish_artifact(&part, &completed, artifact),
            Ok(false) | Err(AsrAcquisitionError::Retryable)
                if attempt + 1 < limits.max_attempts =>
            {
                wait_before_retry(
                    retry_wait,
                    clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
            }
            Ok(false) | Err(AsrAcquisitionError::Retryable) => {
                return Err(AsrAcquisitionError::Retryable)
            }
            Err(error) => return Err(error),
        }
    }
    Err(AsrAcquisitionError::Retryable)
}

fn validate_response<R>(
    response: &AsrDownloadResponse<R>,
    offset: u64,
    expected: u64,
) -> Result<bool, AsrAcquisitionError> {
    match response.status {
        200 if response.content_range.is_none() => Ok(false),
        206 => match response.content_range {
            Some((first, last, total))
                if first == offset
                    && total == expected
                    && last >= first
                    && last == expected.saturating_sub(1) =>
            {
                Ok(true)
            }
            _ => Err(AsrAcquisitionError::InvalidResponse),
        },
        416 => Err(AsrAcquisitionError::InvalidResponse),
        500..=599 => Err(AsrAcquisitionError::Retryable),
        404 | 410 => Err(AsrAcquisitionError::Unavailable),
        _ => Err(AsrAcquisitionError::Rejected),
    }
}

fn stream_response<R: Read, C: AsrCancellation, K: AsrAcquisitionClock>(
    mut body: R,
    part: &Path,
    expected: u64,
    clock: &K,
    started_at: Duration,
    deadline: Duration,
    cancellation: &C,
) -> Result<bool, AsrAcquisitionError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(part)
        .map_err(|_| AsrAcquisitionError::Persistence)?;
    let mut total = file
        .metadata()
        .map_err(|_| AsrAcquisitionError::Persistence)?
        .len();
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        if cancellation.is_cancelled() {
            file.flush().map_err(|_| AsrAcquisitionError::Persistence)?;
            return Err(AsrAcquisitionError::Cancelled);
        }
        remaining_budget(clock, started_at, deadline)?;
        let count = body
            .read(&mut buffer)
            .map_err(|_| AsrAcquisitionError::Retryable)?;
        remaining_budget(clock, started_at, deadline)?;
        if count == 0 {
            file.flush().map_err(|_| AsrAcquisitionError::Persistence)?;
            return Ok(total == expected);
        }
        total = total
            .checked_add(count as u64)
            .ok_or(AsrAcquisitionError::TooLarge)?;
        if total > expected {
            drop(file);
            remove_file(part)?;
            return Err(AsrAcquisitionError::TooLarge);
        }
        file.write_all(&buffer[..count])
            .map_err(|_| AsrAcquisitionError::Persistence)?;
    }
}

fn finish_artifact(
    part: &Path,
    completed: &Path,
    artifact: &AsrArtifactDescriptor,
) -> Result<(), AsrAcquisitionError> {
    if let Err(error) = verify_artifact(part, artifact) {
        remove_file(part)?;
        return Err(AsrAcquisitionError::Verification(error));
    }
    fs::rename(part, completed).map_err(|_| AsrAcquisitionError::Persistence)
}

fn wait_before_retry<W: AsrRetryWait, K: AsrAcquisitionClock>(
    retry_wait: &mut W,
    clock: &K,
    started_at: Duration,
    deadline: Duration,
    attempt: u8,
    cancellation: &dyn AsrCancellation,
) -> Result<(), AsrAcquisitionError> {
    if cancellation.is_cancelled() {
        return Err(AsrAcquisitionError::Cancelled);
    }
    let remaining = remaining_budget(clock, started_at, deadline)?;
    let delay = Duration::from_secs(1_u64 << attempt.min(2)).min(remaining);
    if !retry_wait.wait(delay, cancellation) || cancellation.is_cancelled() {
        return Err(AsrAcquisitionError::Cancelled);
    }
    remaining_budget(clock, started_at, deadline).map(|_| ())
}

fn remaining_budget<K: AsrAcquisitionClock>(
    clock: &K,
    started_at: Duration,
    deadline: Duration,
) -> Result<Duration, AsrAcquisitionError> {
    deadline
        .checked_sub(clock.now().saturating_sub(started_at))
        .filter(|value| !value.is_zero())
        .ok_or(AsrAcquisitionError::Retryable)
}

fn part_length(path: &Path, maximum: u64) -> Result<u64, AsrAcquisitionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(AsrAcquisitionError::Persistence),
    };
    if !metadata.file_type().is_file() {
        return Err(AsrAcquisitionError::InvalidStage);
    }
    if metadata.len() > maximum {
        remove_file(path)?;
        return Ok(0);
    }
    Ok(metadata.len())
}

fn strict_part_length(path: &Path, maximum: u64) -> Result<u64, AsrAcquisitionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(AsrAcquisitionError::Persistence),
    };
    if !metadata.file_type().is_file() {
        return Err(AsrAcquisitionError::InvalidStage);
    }
    if metadata.len() > maximum {
        return Err(AsrAcquisitionError::TooLarge);
    }
    Ok(metadata.len())
}

fn remove_file(path: &Path) -> Result<(), AsrAcquisitionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AsrAcquisitionError::Persistence),
    }
}

fn source_url(
    manifest: &AsrArtifactManifest,
    artifact_index: usize,
    artifact: &AsrArtifactDescriptor,
) -> String {
    let (repository, revision) = if artifact_index == manifest.artifacts.len() {
        let additional = manifest
            .additional_artifact
            .expect("additional artifact index comes from the compiled manifest");
        (additional.repository, additional.revision)
    } else {
        (SOURCE_REPOSITORY, manifest.revision)
    };
    format!(
        "https://huggingface.co/{repository}/resolve/{revision}/{}",
        artifact.filename
    )
}
fn require_directory(path: &Path) -> Result<(), AsrAcquisitionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        _ => Err(AsrAcquisitionError::InvalidStage),
    }
}
fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !Path::new(value).is_absolute()
}
