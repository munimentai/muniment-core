//! Bounded, resumable acquisition of a resident-model revision.
//!
//! HTTP and clock readings remain injected native-adapter concerns. Core supplies the only
//! permitted URL, response limits, resume rules, staging layout, and artifact
//! verification contract.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::lifecycle::ResidentModelRevisionDescriptor;
use super::{verify_model_artifact, ModelVerificationError};

const READ_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentModelAcquisitionLimits {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub deadline: Duration,
    pub max_attempts: u8,
}

impl Default for ResidentModelAcquisitionLimits {
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
pub struct ResidentModelDownloadRequest {
    url: String,
    pub offset: u64,
    pub limits: ResidentModelAcquisitionLimits,
}

impl ResidentModelDownloadRequest {
    pub fn url(&self) -> &str {
        &self.url
    }

    #[cfg(test)]
    pub(crate) fn for_transport_test(
        url: String,
        offset: u64,
        limits: ResidentModelAcquisitionLimits,
    ) -> Self {
        Self {
            url,
            offset,
            limits,
        }
    }
}

pub struct ResidentModelDownloadResponse<R> {
    pub status: u16,
    /// Inclusive response range `(first, last, complete_length)` for a 206.
    pub content_range: Option<(u64, u64, u64)>,
    pub body: R,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentModelTransportError {
    /// A timeout, disconnect, or 5xx response which can be attempted again.
    Transient,
    /// The immutable upstream artifact is currently unavailable.
    Unavailable,
    /// A certificate, redirect-policy, or other non-retryable rejection.
    Rejected,
}

pub trait ResidentModelDownloadTransport {
    type Body: Read;

    /// Implementations must enforce the supplied timeouts, HTTPS-only redirect
    /// policy, proxy/certificate policy, and return redacted error categories.
    fn download(
        &mut self,
        request: &ResidentModelDownloadRequest,
    ) -> Result<ResidentModelDownloadResponse<Self::Body>, ResidentModelTransportError>;
}

pub trait ResidentModelCancellation {
    fn is_cancelled(&self) -> bool;
}

/// Monotonic time source used to enforce one deadline across every retry and
/// body read. The returned duration needs no particular epoch; it must only
/// advance monotonically during one acquisition call.
pub trait ResidentModelAcquisitionClock {
    fn now(&self) -> Duration;
}

/// Retry-delay boundary. Implementations apply jitter up to `maximum_delay`
/// and poll `cancellation` while waiting so cancellation remains prompt.
pub trait ResidentModelRetryWait {
    /// Returns `false` when cancellation interrupted the wait.
    fn wait(
        &mut self,
        maximum_delay: Duration,
        cancellation: &dyn ResidentModelCancellation,
    ) -> bool;
}

impl<F> ResidentModelRetryWait for F
where
    F: FnMut(Duration, &dyn ResidentModelCancellation) -> bool,
{
    fn wait(
        &mut self,
        maximum_delay: Duration,
        cancellation: &dyn ResidentModelCancellation,
    ) -> bool {
        self(maximum_delay, cancellation)
    }
}

impl<F: Fn() -> Duration> ResidentModelAcquisitionClock for F {
    fn now(&self) -> Duration {
        self()
    }
}

pub struct ResidentModelAcquisitionRuntime<'a, K, W> {
    pub clock: &'a K,
    pub retry_wait: &'a mut W,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelDownloadProgress {
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
}

impl<F: Fn() -> bool> ResidentModelCancellation for F {
    fn is_cancelled(&self) -> bool {
        self()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidentModelAcquisitionError {
    InvalidStage,
    InvalidLimits,
    Cancelled,
    Retryable,
    Unavailable,
    Rejected,
    InvalidResponse,
    TooLarge,
    Verification(ModelVerificationError),
    Persistence,
}

impl std::fmt::Display for ResidentModelAcquisitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidStage => "resident model stage is invalid",
            Self::InvalidLimits => "resident model acquisition limits are invalid",
            Self::Cancelled => "resident model download was cancelled",
            Self::Retryable => "resident model download can be retried",
            Self::Unavailable => "resident model artifact is unavailable",
            Self::Rejected => "resident model download was rejected",
            Self::InvalidResponse => "resident model server response is invalid",
            Self::TooLarge => "resident model download exceeded its pinned size",
            Self::Verification(_) => "resident model download failed verification",
            Self::Persistence => "resident model stage could not be persisted",
        })
    }
}

impl std::error::Error for ResidentModelAcquisitionError {}

/// Returns the pinned model bytes not yet present in a resumable stage.
pub fn remaining_stage_bytes(
    staging_root: &Path,
    install_id: &str,
    descriptor: &ResidentModelRevisionDescriptor,
) -> Result<u64, ResidentModelAcquisitionError> {
    if !safe_component(install_id) {
        return Err(ResidentModelAcquisitionError::InvalidStage);
    }
    require_directory(staging_root)?;
    let stage = staging_root.join(install_id);
    match fs::symlink_metadata(&stage) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(ResidentModelAcquisitionError::InvalidStage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(descriptor.model.byte_size)
        }
        Err(_) => return Err(ResidentModelAcquisitionError::Persistence),
    }

    let completed = stage.join(descriptor.model.filename);
    match fs::symlink_metadata(&completed) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(ResidentModelAcquisitionError::InvalidStage)
        }
        Ok(_) if verify_model_artifact(&completed, descriptor.model).is_ok() => return Ok(0),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ResidentModelAcquisitionError::Persistence),
    }

    let length = strict_part_length(
        &stage.join(format!("{}.part", descriptor.model.filename)),
        descriptor.model.byte_size,
    )?;
    descriptor
        .model
        .byte_size
        .checked_sub(length)
        .ok_or(ResidentModelAcquisitionError::TooLarge)
}

/// Downloads the target into `staging/<id>`, returning that directory only
/// after the pinned bytes and notice form a publication-ready stage.
pub fn acquire_resident_model_stage<
    T: ResidentModelDownloadTransport,
    C: ResidentModelCancellation,
    K: ResidentModelAcquisitionClock,
    W: ResidentModelRetryWait,
>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static ResidentModelRevisionDescriptor,
    limits: ResidentModelAcquisitionLimits,
    transport: &mut T,
    runtime: ResidentModelAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
) -> Result<PathBuf, ResidentModelAcquisitionError> {
    acquire_resident_model_stage_with_progress(
        staging_root,
        install_id,
        descriptor,
        limits,
        transport,
        runtime,
        cancellation,
        &mut |_| {},
    )
}

/// Equivalent to [`acquire_resident_model_stage`], with transport-independent progress
/// notifications suitable for desktop, CLI, and extension adapters.
#[allow(clippy::too_many_arguments)]
pub fn acquire_resident_model_stage_with_progress<
    T: ResidentModelDownloadTransport,
    C: ResidentModelCancellation,
    K: ResidentModelAcquisitionClock,
    W: ResidentModelRetryWait,
>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static ResidentModelRevisionDescriptor,
    limits: ResidentModelAcquisitionLimits,
    transport: &mut T,
    runtime: ResidentModelAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
    progress: &mut dyn FnMut(ModelDownloadProgress),
) -> Result<PathBuf, ResidentModelAcquisitionError> {
    if !safe_component(install_id)
        || limits.max_attempts == 0
        || limits.connect_timeout.is_zero()
        || limits.read_timeout.is_zero()
        || limits.deadline.is_zero()
    {
        return Err(if !safe_component(install_id) {
            ResidentModelAcquisitionError::InvalidStage
        } else {
            ResidentModelAcquisitionError::InvalidLimits
        });
    }
    let started_at = runtime.clock.now();
    require_directory(staging_root)?;
    let stage = staging_root.join(install_id);
    match fs::create_dir(&stage) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            require_directory(&stage)?
        }
        Err(_) => return Err(ResidentModelAcquisitionError::Persistence),
    }
    let part = stage.join(format!("{}.part", descriptor.model.filename));
    let completed = stage.join(descriptor.model.filename);
    match fs::symlink_metadata(&completed) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && verify_model_artifact(&completed, descriptor.model).is_ok() =>
        {
            write_notice(&stage, descriptor)?;
            progress(ModelDownloadProgress {
                downloaded_bytes: descriptor.model.byte_size,
                total_bytes: descriptor.model.byte_size,
            });
            return Ok(stage);
        }
        Ok(_) => remove_part(&completed)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ResidentModelAcquisitionError::Persistence),
    }

    for attempt in 0..limits.max_attempts {
        if cancellation.is_cancelled() {
            return Err(ResidentModelAcquisitionError::Cancelled);
        }
        let remaining = remaining_budget(runtime.clock, started_at, limits.deadline)?;
        let offset = part_length(&part, descriptor.model.byte_size)?;
        progress(ModelDownloadProgress {
            downloaded_bytes: offset,
            total_bytes: descriptor.model.byte_size,
        });
        if offset == descriptor.model.byte_size {
            return finish_stage(stage, part, descriptor);
        }
        let request = ResidentModelDownloadRequest {
            url: source_url(descriptor),
            offset,
            limits: ResidentModelAcquisitionLimits {
                connect_timeout: limits.connect_timeout.min(remaining),
                read_timeout: limits.read_timeout.min(remaining),
                deadline: remaining,
                max_attempts: limits.max_attempts,
            },
        };
        let response = match transport.download(&request) {
            Ok(response) => response,
            Err(ResidentModelTransportError::Transient) if attempt + 1 < limits.max_attempts => {
                wait_before_retry(
                    runtime.retry_wait,
                    runtime.clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
                continue;
            }
            Err(ResidentModelTransportError::Transient) => {
                return Err(ResidentModelAcquisitionError::Retryable)
            }
            Err(ResidentModelTransportError::Unavailable) => {
                return Err(ResidentModelAcquisitionError::Unavailable)
            }
            Err(ResidentModelTransportError::Rejected) => {
                return Err(ResidentModelAcquisitionError::Rejected)
            }
        };
        let append = match validate_response(&response, offset, descriptor.model.byte_size) {
            Ok(append) => append,
            Err(ResidentModelAcquisitionError::InvalidResponse) => {
                remove_part(&part)?;
                if attempt + 1 < limits.max_attempts {
                    wait_before_retry(
                        runtime.retry_wait,
                        runtime.clock,
                        started_at,
                        limits.deadline,
                        attempt,
                        cancellation,
                    )?;
                    continue;
                }
                return Err(ResidentModelAcquisitionError::Retryable);
            }
            Err(ResidentModelAcquisitionError::Retryable) if attempt + 1 < limits.max_attempts => {
                wait_before_retry(
                    runtime.retry_wait,
                    runtime.clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
                continue;
            }
            Err(ResidentModelAcquisitionError::Retryable) => {
                return Err(ResidentModelAcquisitionError::Retryable)
            }
            Err(error) => return Err(error),
        };
        if !append {
            remove_part(&part)?;
        }
        match stream_response(
            response.body,
            &part,
            descriptor.model.byte_size,
            runtime.clock,
            started_at,
            limits.deadline,
            cancellation,
            progress,
        ) {
            Ok(true) => return finish_stage(stage, part, descriptor),
            Ok(false) if attempt + 1 < limits.max_attempts => {
                wait_before_retry(
                    runtime.retry_wait,
                    runtime.clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
                continue;
            }
            Ok(false) => return Err(ResidentModelAcquisitionError::Retryable),
            Err(ResidentModelAcquisitionError::Retryable) if attempt + 1 < limits.max_attempts => {
                wait_before_retry(
                    runtime.retry_wait,
                    runtime.clock,
                    started_at,
                    limits.deadline,
                    attempt,
                    cancellation,
                )?;
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(ResidentModelAcquisitionError::Retryable)
}

fn validate_response<R>(
    response: &ResidentModelDownloadResponse<R>,
    offset: u64,
    expected: u64,
) -> Result<bool, ResidentModelAcquisitionError> {
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
            _ => Err(ResidentModelAcquisitionError::InvalidResponse),
        },
        416 => Err(ResidentModelAcquisitionError::InvalidResponse),
        500..=599 => Err(ResidentModelAcquisitionError::Retryable),
        404 | 410 => Err(ResidentModelAcquisitionError::Unavailable),
        _ => Err(ResidentModelAcquisitionError::Rejected),
    }
}

fn wait_before_retry<W: ResidentModelRetryWait, K: ResidentModelAcquisitionClock>(
    retry_wait: &mut W,
    clock: &K,
    started_at: Duration,
    deadline: Duration,
    attempt: u8,
    cancellation: &dyn ResidentModelCancellation,
) -> Result<(), ResidentModelAcquisitionError> {
    if cancellation.is_cancelled() {
        return Err(ResidentModelAcquisitionError::Cancelled);
    }
    let remaining = remaining_budget(clock, started_at, deadline)?;
    let backoff = Duration::from_secs(1_u64 << attempt.min(2));
    if !retry_wait.wait(backoff.min(remaining), cancellation) || cancellation.is_cancelled() {
        return Err(ResidentModelAcquisitionError::Cancelled);
    }
    remaining_budget(clock, started_at, deadline).map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn stream_response<R: Read, C: ResidentModelCancellation, K: ResidentModelAcquisitionClock>(
    mut body: R,
    part: &Path,
    expected: u64,
    clock: &K,
    started_at: Duration,
    deadline: Duration,
    cancellation: &C,
    progress: &mut dyn FnMut(ModelDownloadProgress),
) -> Result<bool, ResidentModelAcquisitionError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(part)
        .map_err(|_| ResidentModelAcquisitionError::Persistence)?;
    let mut total = file
        .metadata()
        .map_err(|_| ResidentModelAcquisitionError::Persistence)?
        .len();
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        if cancellation.is_cancelled() {
            file.flush()
                .map_err(|_| ResidentModelAcquisitionError::Persistence)?;
            return Err(ResidentModelAcquisitionError::Cancelled);
        }
        remaining_budget(clock, started_at, deadline)?;
        let count = body
            .read(&mut buffer)
            .map_err(|_| ResidentModelAcquisitionError::Retryable)?;
        remaining_budget(clock, started_at, deadline)?;
        if count == 0 {
            file.flush()
                .map_err(|_| ResidentModelAcquisitionError::Persistence)?;
            return Ok(total == expected);
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ResidentModelAcquisitionError::TooLarge)?;
        if total > expected {
            drop(file);
            remove_part(part)?;
            return Err(ResidentModelAcquisitionError::TooLarge);
        }
        file.write_all(&buffer[..count])
            .map_err(|_| ResidentModelAcquisitionError::Persistence)?;
        progress(ModelDownloadProgress {
            downloaded_bytes: total,
            total_bytes: expected,
        });
    }
}

fn remaining_budget<K: ResidentModelAcquisitionClock>(
    clock: &K,
    started_at: Duration,
    deadline: Duration,
) -> Result<Duration, ResidentModelAcquisitionError> {
    let elapsed = clock.now().saturating_sub(started_at);
    deadline
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ResidentModelAcquisitionError::Retryable)
}

fn finish_stage(
    stage: PathBuf,
    part: PathBuf,
    descriptor: &'static ResidentModelRevisionDescriptor,
) -> Result<PathBuf, ResidentModelAcquisitionError> {
    match verify_model_artifact(&part, descriptor.model) {
        Ok(()) => {}
        Err(error) => {
            remove_part(&part)?;
            return Err(ResidentModelAcquisitionError::Verification(error));
        }
    }
    let completed = stage.join(descriptor.model.filename);
    fs::rename(&part, completed).map_err(|_| ResidentModelAcquisitionError::Persistence)?;
    write_notice(&stage, descriptor)?;
    Ok(stage)
}

fn write_notice(
    stage: &Path,
    descriptor: &ResidentModelRevisionDescriptor,
) -> Result<(), ResidentModelAcquisitionError> {
    let path = stage.join(descriptor.notice.filename);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|_| ResidentModelAcquisitionError::Persistence)?;
    file.write_all(descriptor.notice.contents)
        .map_err(|_| ResidentModelAcquisitionError::Persistence)
}

fn part_length(path: &Path, maximum: u64) -> Result<u64, ResidentModelAcquisitionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(ResidentModelAcquisitionError::Persistence),
    };
    if !metadata.file_type().is_file() {
        return Err(ResidentModelAcquisitionError::InvalidStage);
    }
    if metadata.len() > maximum {
        remove_part(path)?;
        return Ok(0);
    }
    Ok(metadata.len())
}

fn strict_part_length(path: &Path, maximum: u64) -> Result<u64, ResidentModelAcquisitionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(ResidentModelAcquisitionError::Persistence),
    };
    if !metadata.file_type().is_file() {
        return Err(ResidentModelAcquisitionError::InvalidStage);
    }
    if metadata.len() > maximum {
        return Err(ResidentModelAcquisitionError::TooLarge);
    }
    Ok(metadata.len())
}

fn remove_part(path: &Path) -> Result<(), ResidentModelAcquisitionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ResidentModelAcquisitionError::Persistence),
    }
}

fn source_url(descriptor: &ResidentModelRevisionDescriptor) -> String {
    descriptor.model.source_url.to_owned()
}

fn require_directory(path: &Path) -> Result<(), ResidentModelAcquisitionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ResidentModelAcquisitionError::InvalidStage)?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(ResidentModelAcquisitionError::InvalidStage)
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !Path::new(value).is_absolute()
}
