//! The entry that runs the runtime for a host with no OS service registration.

use std::fmt;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use muniment_core::attach::linux::{AttachFilesystem, AttachTransport};

use crate::host::RuntimeHost;
use crate::retention_schedule::{start_retention_schedule, RetentionScheduleCommand};
use crate::{run_bound_attach_listener, AttachListenerError, RuntimeAttachState};

const RETENTION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Where one runtime keeps its state and serves its attach endpoint.
pub struct RuntimeDirectories {
    /// The state root: the run journal, content store, memory and records.
    pub profile: PathBuf,
    /// The config root: the local-mode marker and the Home record.
    pub config: PathBuf,
    /// The directory that holds the attach endpoint and its instance lock.
    pub endpoint: PathBuf,
}

/// The reason the runtime could not serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunRuntimeError {
    State,
    Listener(AttachListenerError),
}

impl fmt::Display for RunRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State => formatter.write_str("runtime attach state could not be opened"),
            Self::Listener(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RunRuntimeError {}

/// Opens the runtime state for `host` and serves attach connections until
/// `stop` fires or its sender drops. The runtime owns the endpoint's instance
/// lock before its retention and agent schedules start, so one runtime runs them.
pub fn run_runtime(
    host: RuntimeHost,
    directories: &RuntimeDirectories,
    stop: Receiver<()>,
) -> Result<(), RunRuntimeError> {
    let state = Arc::new(
        RuntimeAttachState::open(host, &directories.profile, &directories.config)
            .map_err(|_| RunRuntimeError::State)?,
    );
    let filesystem = AttachFilesystem::from_runtime_directory(directories.endpoint.as_os_str())
        .map_err(|_| RunRuntimeError::Listener(AttachListenerError::Filesystem))?;
    let instance_lock = filesystem
        .acquire_instance_lock()
        .map_err(|_| RunRuntimeError::Listener(AttachListenerError::InstanceLock))?;
    let transport = AttachTransport::bind(&filesystem)
        .map_err(|_| RunRuntimeError::Listener(AttachListenerError::Bind))?;
    let (commands, command_rx) = mpsc::channel();
    let retention =
        start_retention_schedule(Arc::clone(&state), RETENTION_INTERVAL, command_rx, None);
    let service_state = Arc::clone(&state);
    let result = run_bound_attach_listener(
        instance_lock,
        transport,
        state.attach_listener_inputs(),
        None,
        move || service_state.attach_service(),
        stop,
    )
    .map_err(RunRuntimeError::Listener);
    let _ = commands.send(RetentionScheduleCommand::Stop);
    retention.join().expect("retention schedule does not panic");
    result
}
