//! Bounded, resumable acquisition of a resident Gemma revision.
//!
//! HTTP and clock readings remain injected native-adapter concerns. Core supplies the only
//! permitted URL, response limits, resume rules, staging layout, and artifact
//! verification contract.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::lifecycle::GemmaRevisionDescriptor;
use super::{verify_model_artifact, ModelVerificationError};

const SOURCE_REPOSITORY: &str = "google/gemma-3-4b-it-qat-q4_0-gguf";
const READ_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GemmaAcquisitionLimits {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub deadline: Duration,
    pub max_attempts: u8,
}

impl Default for GemmaAcquisitionLimits {
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
pub struct GemmaDownloadRequest {
    url: String,
    pub offset: u64,
    pub limits: GemmaAcquisitionLimits,
}

impl GemmaDownloadRequest {
    pub fn url(&self) -> &str {
        &self.url
    }
}

pub struct GemmaDownloadResponse<R> {
    pub status: u16,
    /// Inclusive response range `(first, last, complete_length)` for a 206.
    pub content_range: Option<(u64, u64, u64)>,
    pub body: R,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemmaTransportError {
    /// A timeout, disconnect, or 5xx response which can be attempted again.
    Transient,
    /// The immutable upstream artifact is currently unavailable.
    Unavailable,
    /// A certificate, redirect-policy, or other non-retryable rejection.
    Rejected,
}

pub trait GemmaDownloadTransport {
    type Body: Read;

    /// Implementations must enforce the supplied timeouts, HTTPS-only redirect
    /// policy, proxy/certificate policy, and return redacted error categories.
    fn download(
        &mut self,
        request: &GemmaDownloadRequest,
    ) -> Result<GemmaDownloadResponse<Self::Body>, GemmaTransportError>;
}

pub trait GemmaCancellation {
    fn is_cancelled(&self) -> bool;
}

/// Monotonic time source used to enforce one deadline across every retry and
/// body read. The returned duration needs no particular epoch; it must only
/// advance monotonically during one acquisition call.
pub trait GemmaAcquisitionClock {
    fn now(&self) -> Duration;
}

/// Retry-delay boundary. Implementations apply jitter up to `maximum_delay`
/// and poll `cancellation` while waiting so cancellation remains prompt.
pub trait GemmaRetryWait {
    /// Returns `false` when cancellation interrupted the wait.
    fn wait(&mut self, maximum_delay: Duration, cancellation: &dyn GemmaCancellation) -> bool;
}

impl<F> GemmaRetryWait for F
where
    F: FnMut(Duration, &dyn GemmaCancellation) -> bool,
{
    fn wait(&mut self, maximum_delay: Duration, cancellation: &dyn GemmaCancellation) -> bool {
        self(maximum_delay, cancellation)
    }
}

impl<F: Fn() -> Duration> GemmaAcquisitionClock for F {
    fn now(&self) -> Duration {
        self()
    }
}

pub struct GemmaAcquisitionRuntime<'a, K, W> {
    pub clock: &'a K,
    pub retry_wait: &'a mut W,
}

impl<F: Fn() -> bool> GemmaCancellation for F {
    fn is_cancelled(&self) -> bool {
        self()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GemmaAcquisitionError {
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

impl std::fmt::Display for GemmaAcquisitionError {
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

impl std::error::Error for GemmaAcquisitionError {}

/// Downloads the target into `staging/<id>`, returning that directory only
/// after the pinned bytes and notice form a publication-ready stage.
pub fn acquire_gemma_stage<
    T: GemmaDownloadTransport,
    C: GemmaCancellation,
    K: GemmaAcquisitionClock,
    W: GemmaRetryWait,
>(
    staging_root: &Path,
    install_id: &str,
    descriptor: &'static GemmaRevisionDescriptor,
    limits: GemmaAcquisitionLimits,
    transport: &mut T,
    runtime: GemmaAcquisitionRuntime<'_, K, W>,
    cancellation: &C,
) -> Result<PathBuf, GemmaAcquisitionError> {
    if !safe_component(install_id)
        || limits.max_attempts == 0
        || limits.connect_timeout.is_zero()
        || limits.read_timeout.is_zero()
        || limits.deadline.is_zero()
    {
        return Err(if !safe_component(install_id) {
            GemmaAcquisitionError::InvalidStage
        } else {
            GemmaAcquisitionError::InvalidLimits
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
        Err(_) => return Err(GemmaAcquisitionError::Persistence),
    }
    let part = stage.join(format!("{}.part", descriptor.model.filename));
    let completed = stage.join(descriptor.model.filename);
    match fs::symlink_metadata(&completed) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && verify_model_artifact(&completed, descriptor.model).is_ok() =>
        {
            write_notice(&stage, descriptor)?;
            return Ok(stage);
        }
        Ok(_) => remove_part(&completed)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(GemmaAcquisitionError::Persistence),
    }

    for attempt in 0..limits.max_attempts {
        if cancellation.is_cancelled() {
            return Err(GemmaAcquisitionError::Cancelled);
        }
        let remaining = remaining_budget(runtime.clock, started_at, limits.deadline)?;
        let offset = part_length(&part, descriptor.model.byte_size)?;
        if offset == descriptor.model.byte_size {
            return finish_stage(stage, part, descriptor);
        }
        let request = GemmaDownloadRequest {
            url: source_url(descriptor),
            offset,
            limits: GemmaAcquisitionLimits {
                connect_timeout: limits.connect_timeout.min(remaining),
                read_timeout: limits.read_timeout.min(remaining),
                deadline: remaining,
                max_attempts: limits.max_attempts,
            },
        };
        let response = match transport.download(&request) {
            Ok(response) => response,
            Err(GemmaTransportError::Transient) if attempt + 1 < limits.max_attempts => {
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
            Err(GemmaTransportError::Transient) => return Err(GemmaAcquisitionError::Retryable),
            Err(GemmaTransportError::Unavailable) => {
                return Err(GemmaAcquisitionError::Unavailable)
            }
            Err(GemmaTransportError::Rejected) => return Err(GemmaAcquisitionError::Rejected),
        };
        let append = match validate_response(&response, offset, descriptor.model.byte_size) {
            Ok(append) => append,
            Err(GemmaAcquisitionError::InvalidResponse) => {
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
                return Err(GemmaAcquisitionError::Retryable);
            }
            Err(GemmaAcquisitionError::Retryable) if attempt + 1 < limits.max_attempts => {
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
            Err(GemmaAcquisitionError::Retryable) => return Err(GemmaAcquisitionError::Retryable),
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
            Ok(false) => return Err(GemmaAcquisitionError::Retryable),
            Err(GemmaAcquisitionError::Retryable) if attempt + 1 < limits.max_attempts => {
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
    Err(GemmaAcquisitionError::Retryable)
}

fn validate_response<R>(
    response: &GemmaDownloadResponse<R>,
    offset: u64,
    expected: u64,
) -> Result<bool, GemmaAcquisitionError> {
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
            _ => Err(GemmaAcquisitionError::InvalidResponse),
        },
        416 => Err(GemmaAcquisitionError::InvalidResponse),
        500..=599 => Err(GemmaAcquisitionError::Retryable),
        404 | 410 => Err(GemmaAcquisitionError::Unavailable),
        _ => Err(GemmaAcquisitionError::Rejected),
    }
}

fn wait_before_retry<W: GemmaRetryWait, K: GemmaAcquisitionClock>(
    retry_wait: &mut W,
    clock: &K,
    started_at: Duration,
    deadline: Duration,
    attempt: u8,
    cancellation: &dyn GemmaCancellation,
) -> Result<(), GemmaAcquisitionError> {
    if cancellation.is_cancelled() {
        return Err(GemmaAcquisitionError::Cancelled);
    }
    let remaining = remaining_budget(clock, started_at, deadline)?;
    let backoff = Duration::from_secs(1_u64 << attempt.min(2));
    if !retry_wait.wait(backoff.min(remaining), cancellation) || cancellation.is_cancelled() {
        return Err(GemmaAcquisitionError::Cancelled);
    }
    remaining_budget(clock, started_at, deadline).map(|_| ())
}

fn stream_response<R: Read, C: GemmaCancellation, K: GemmaAcquisitionClock>(
    mut body: R,
    part: &Path,
    expected: u64,
    clock: &K,
    started_at: Duration,
    deadline: Duration,
    cancellation: &C,
) -> Result<bool, GemmaAcquisitionError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(part)
        .map_err(|_| GemmaAcquisitionError::Persistence)?;
    let mut total = file
        .metadata()
        .map_err(|_| GemmaAcquisitionError::Persistence)?
        .len();
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        if cancellation.is_cancelled() {
            file.flush()
                .map_err(|_| GemmaAcquisitionError::Persistence)?;
            return Err(GemmaAcquisitionError::Cancelled);
        }
        remaining_budget(clock, started_at, deadline)?;
        let count = body
            .read(&mut buffer)
            .map_err(|_| GemmaAcquisitionError::Retryable)?;
        remaining_budget(clock, started_at, deadline)?;
        if count == 0 {
            file.flush()
                .map_err(|_| GemmaAcquisitionError::Persistence)?;
            return Ok(total == expected);
        }
        total = total
            .checked_add(count as u64)
            .ok_or(GemmaAcquisitionError::TooLarge)?;
        if total > expected {
            drop(file);
            remove_part(part)?;
            return Err(GemmaAcquisitionError::TooLarge);
        }
        file.write_all(&buffer[..count])
            .map_err(|_| GemmaAcquisitionError::Persistence)?;
    }
}

fn remaining_budget<K: GemmaAcquisitionClock>(
    clock: &K,
    started_at: Duration,
    deadline: Duration,
) -> Result<Duration, GemmaAcquisitionError> {
    let elapsed = clock.now().saturating_sub(started_at);
    deadline
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(GemmaAcquisitionError::Retryable)
}

fn finish_stage(
    stage: PathBuf,
    part: PathBuf,
    descriptor: &'static GemmaRevisionDescriptor,
) -> Result<PathBuf, GemmaAcquisitionError> {
    match verify_model_artifact(&part, descriptor.model) {
        Ok(()) => {}
        Err(error) => {
            remove_part(&part)?;
            return Err(GemmaAcquisitionError::Verification(error));
        }
    }
    let completed = stage.join(descriptor.model.filename);
    fs::rename(&part, completed).map_err(|_| GemmaAcquisitionError::Persistence)?;
    write_notice(&stage, descriptor)?;
    Ok(stage)
}

fn write_notice(
    stage: &Path,
    descriptor: &GemmaRevisionDescriptor,
) -> Result<(), GemmaAcquisitionError> {
    let path = stage.join(descriptor.notice.filename);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|_| GemmaAcquisitionError::Persistence)?;
    file.write_all(descriptor.notice.contents)
        .map_err(|_| GemmaAcquisitionError::Persistence)
}

fn part_length(path: &Path, maximum: u64) -> Result<u64, GemmaAcquisitionError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(GemmaAcquisitionError::Persistence),
    };
    if !metadata.file_type().is_file() {
        return Err(GemmaAcquisitionError::InvalidStage);
    }
    if metadata.len() > maximum {
        remove_part(path)?;
        return Ok(0);
    }
    Ok(metadata.len())
}

fn remove_part(path: &Path) -> Result<(), GemmaAcquisitionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(GemmaAcquisitionError::Persistence),
    }
}

fn source_url(descriptor: &GemmaRevisionDescriptor) -> String {
    format!(
        "https://huggingface.co/{SOURCE_REPOSITORY}/resolve/{}/{}",
        descriptor.revision, descriptor.model.filename
    )
}

fn require_directory(path: &Path) -> Result<(), GemmaAcquisitionError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| GemmaAcquisitionError::InvalidStage)?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(GemmaAcquisitionError::InvalidStage)
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !Path::new(value).is_absolute()
}
