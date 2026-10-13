//! Runtime composition for a prepared migration handoff.

use crate::attach_listener::{
    run_bound_attach_listener, AttachListenerError, AttachListenerInputs,
};
use muniment_attach::{
    handshake_migration_control_stream, ClientError, MigrationControlFailure,
    MigrationControlOutcome,
};
use muniment_core::attach::linux::{
    AttachFilesystem, AttachFilesystemError, AttachTransport, InstanceLockError, ThreadListService,
};
use muniment_core::attach::{mint_handoff_nonce, HandoffNonceRandomnessError};
use std::fmt;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const RETRY_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CONTROL_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationTakeoverError {
    NonceRandomness,
    Filesystem,
    DesktopUnavailable,
    Control(ClientError),
    ControlRequest(MigrationControlFailure),
    MigrationNotReady,
    Unauthorized,
    UnsupportedOperation,
    InstanceLock,
    DeadlineElapsed,
    Listener(AttachListenerError),
}

impl fmt::Display for MigrationTakeoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonceRandomness => formatter.write_str("handoff nonce randomness is unavailable"),
            Self::Filesystem => formatter.write_str("runtime handoff filesystem setup failed"),
            Self::DesktopUnavailable => {
                formatter.write_str("the desktop attach endpoint is unavailable")
            }
            Self::Control(error) => error.fmt(formatter),
            Self::ControlRequest(error) => error.fmt(formatter),
            Self::MigrationNotReady => formatter.write_str("the migration is not ready"),
            Self::Unauthorized => formatter.write_str("the migration request is unauthorized"),
            Self::UnsupportedOperation => {
                formatter.write_str("the desktop does not support migration control")
            }
            Self::InstanceLock => formatter.write_str("runtime handoff instance lock failed"),
            Self::DeadlineElapsed => formatter.write_str("the migration takeover deadline elapsed"),
            Self::Listener(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MigrationTakeoverError {}

/// Requests a migration handoff and serves companion sessions until `stop` fires.
pub fn run_migration_takeover<S, F, E>(
    profile_directory: impl AsRef<Path>,
    listener_inputs: AttachListenerInputs<'_>,
    service_factory: F,
    deadline: Instant,
    stop: Receiver<()>,
) -> Result<(), MigrationTakeoverError>
where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    run_migration_takeover_with_activation(
        profile_directory,
        listener_inputs,
        service_factory,
        deadline,
        || {},
        stop,
    )
}

/// Requests a migration handoff and calls `activated` after taking ownership.
pub fn run_migration_takeover_with_activation<S, F, E, A>(
    profile_directory: impl AsRef<Path>,
    listener_inputs: AttachListenerInputs<'_>,
    service_factory: F,
    deadline: Instant,
    activated: A,
    stop: Receiver<()>,
) -> Result<(), MigrationTakeoverError>
where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
    A: FnOnce(),
{
    let nonce = mint_handoff_nonce().map_err(map_nonce_error)?;
    let filesystem =
        AttachFilesystem::from_runtime_directory(profile_directory.as_ref().as_os_str())
            .map_err(map_filesystem_error)?;

    if !request_handoff(
        &filesystem,
        &nonce,
        listener_inputs.runtime_version,
        deadline,
        &stop,
    )? {
        return Ok(());
    }

    let instance_lock = loop {
        check_deadline(deadline)?;
        match filesystem.acquire_instance_lock() {
            Ok(lock) => break lock,
            Err(InstanceLockError::AlreadyHeld) => {
                if stop_before_retry(&stop, deadline)? {
                    return Ok(());
                }
            }
            Err(_) => return Err(MigrationTakeoverError::InstanceLock),
        }
    };
    let transport = loop {
        check_deadline(deadline)?;
        match AttachTransport::bind(&filesystem) {
            Ok(transport) => break transport,
            Err(_) => {
                if stop_before_retry(&stop, deadline)? {
                    return Ok(());
                }
            }
        }
    };
    activated();

    run_bound_attach_listener(
        instance_lock,
        transport,
        listener_inputs,
        Some(nonce),
        service_factory,
        stop,
    )
    .map_err(MigrationTakeoverError::Listener)
}

fn request_handoff(
    filesystem: &AttachFilesystem,
    nonce: &str,
    runtime_version: &str,
    deadline: Instant,
    stop: &Receiver<()>,
) -> Result<bool, MigrationTakeoverError> {
    loop {
        let io_timeout = remaining(deadline)?;
        let stream = match connect_before(filesystem.endpoint_path(), deadline, stop)? {
            Some(stream) => stream,
            None => return Ok(false),
        };
        let remaining = remaining(deadline)?;
        let deadline_ms = remaining
            .min(MAX_CONTROL_DEADLINE)
            .as_millis()
            .clamp(1, 60_000) as u64;
        let outcome = match request_control(
            stream,
            nonce,
            runtime_version,
            io_timeout,
            deadline_ms,
            deadline,
            stop,
        )? {
            Some(outcome) => outcome,
            None => return Ok(false),
        };
        match outcome {
            MigrationControlOutcome::Accepted => return Ok(true),
            MigrationControlOutcome::MigrationNotReady { retryable: true } => {
                if stop_before_retry(stop, deadline)? {
                    return Ok(false);
                }
            }
            MigrationControlOutcome::MigrationNotReady { retryable: false } => {
                if stop_before_retry(stop, deadline)? {
                    return Ok(false);
                }
            }
            MigrationControlOutcome::Unauthorized => {
                return Err(MigrationTakeoverError::Unauthorized)
            }
            MigrationControlOutcome::UnsupportedOperation => {
                if stop_before_retry(stop, deadline)? {
                    return Ok(false);
                }
            }
        }
    }
}

fn stop_before_retry(
    stop: &Receiver<()>,
    deadline: Instant,
) -> Result<bool, MigrationTakeoverError> {
    let wait = remaining(deadline)?.min(RETRY_INTERVAL);
    match stop.recv_timeout(wait) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(true),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(false),
    }
}

fn connect_before(
    path: &Path,
    deadline: Instant,
    stop: &Receiver<()>,
) -> Result<Option<UnixStream>, MigrationTakeoverError> {
    let path = path.to_owned();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = result_tx.send(UnixStream::connect(path));
    });
    loop {
        if stop_requested(stop) {
            return Ok(None);
        }
        match result_rx.recv_timeout(remaining(deadline)?.min(RETRY_INTERVAL)) {
            Ok(Ok(stream)) => return Ok(Some(stream)),
            Ok(Err(_)) => return Err(MigrationTakeoverError::DesktopUnavailable),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(MigrationTakeoverError::DesktopUnavailable);
            }
        }
    }
}

fn request_control(
    stream: UnixStream,
    nonce: &str,
    runtime_version: &str,
    io_timeout: Duration,
    deadline_ms: u64,
    deadline: Instant,
    stop: &Receiver<()>,
) -> Result<Option<MigrationControlOutcome>, MigrationTakeoverError> {
    let interrupt = stream
        .try_clone()
        .map_err(|_| MigrationTakeoverError::DesktopUnavailable)?;
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = handshake_migration_control_stream(
                stream,
                runtime_version,
                io_timeout.min(MAX_CONTROL_DEADLINE),
            )
            .map_err(|error| control_error_before(error, deadline))
            .and_then(|mut client| {
                client
                    .control_migration(nonce, deadline_ms)
                    .map_err(|error| control_request_error_before(error, deadline))
            });
            let _ = result_tx.send(result);
        });
        loop {
            if stop_requested(stop) {
                let _ = interrupt.shutdown(Shutdown::Both);
                return Ok(None);
            }
            match result_rx.recv_timeout(remaining(deadline)?.min(RETRY_INTERVAL)) {
                Ok(result) => return result.map(Some),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(MigrationTakeoverError::DesktopUnavailable);
                }
            }
        }
    })
}

fn stop_requested(stop: &Receiver<()>) -> bool {
    matches!(
        stop.try_recv(),
        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
    )
}

fn control_error_before(error: ClientError, deadline: Instant) -> MigrationTakeoverError {
    if remaining(deadline).is_err() {
        MigrationTakeoverError::DeadlineElapsed
    } else {
        MigrationTakeoverError::Control(error)
    }
}

fn control_request_error_before(
    error: MigrationControlFailure,
    deadline: Instant,
) -> MigrationTakeoverError {
    if remaining(deadline).is_err() {
        MigrationTakeoverError::DeadlineElapsed
    } else {
        MigrationTakeoverError::ControlRequest(error)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, MigrationTakeoverError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(MigrationTakeoverError::DeadlineElapsed)
}

fn check_deadline(deadline: Instant) -> Result<(), MigrationTakeoverError> {
    remaining(deadline).map(|_| ())
}

fn map_nonce_error(_: HandoffNonceRandomnessError) -> MigrationTakeoverError {
    MigrationTakeoverError::NonceRandomness
}

fn map_filesystem_error(_: AttachFilesystemError) -> MigrationTakeoverError {
    MigrationTakeoverError::Filesystem
}
