//! Runtime-owned Windows attach accept loop.

use muniment_core::attach::WindowsAttachAcceptError;
use muniment_core::runtime_eprintln as eprintln;
use std::time::Duration;
#[cfg(target_os = "windows")]
use std::time::Instant;

#[cfg(test)]
use muniment_core::attach::thread_service::ThreadListService;
#[cfg(all(test, target_os = "windows"))]
use muniment_core::attach::WindowsAttachServeOutcome;
#[cfg(target_os = "windows")]
use muniment_core::attach::{
    approval_waiter_with_claims, serve_windows_attach_session_with_state,
    WindowsAttachAcceptOutcome as CoreWindowsAttachAcceptOutcome, WindowsAttachBindError,
    WindowsAttachListener, WindowsAttachStopEvent,
};
#[cfg(test)]
use muniment_core::attach::{DesktopAttachService, ProtocolError};
#[cfg(target_os = "windows")]
use std::path::Path;
#[cfg(any(unix, target_os = "windows"))]
use std::sync::Arc;

#[cfg(target_os = "windows")]
use crate::host::RuntimeHost;
#[cfg(test)]
use crate::RuntimeAttachBoundaries;
#[cfg(any(unix, target_os = "windows"))]
use crate::RuntimeAttachState;

const FAILED_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);
#[cfg(target_os = "windows")]
const WINDOWS_ATTACH_SESSION_TIMEOUT: Duration = Duration::from_secs(5);
/// The consecutive failed accept limit for one activation.
pub const MAX_CONSECUTIVE_FAILED_ACCEPTS: usize = 5;

/// The result of one attach accept and serve attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachAcceptOutcome {
    Served,
    Stopped,
    Failed,
    AcceptFailed(WindowsAttachAcceptError),
}

/// A signal that stops a blocked Windows attach accept.
pub trait WindowsAttachStopSignal: Send + 'static {
    fn signal(&self);
}

/// The boundary for one Windows attach accept and serve attempt.
pub trait WindowsAttachAcceptBoundary {
    type StopSignal: WindowsAttachStopSignal;

    fn stop_signal(&self) -> Self::StopSignal;

    fn retention_state(&self) -> Option<Arc<RuntimeAttachState>> {
        None
    }

    fn serve_next(&mut self) -> WindowsAttachAcceptOutcome;
}

/// A bound Windows attach acceptor.
#[cfg(target_os = "windows")]
pub struct WindowsAttachAcceptor {
    listener: WindowsAttachListener,
    stop: Arc<WindowsAttachStopEvent>,
    state: Arc<RuntimeAttachState>,
}

#[cfg(test)]
fn runtime_attach_service_factory(
    state: Arc<RuntimeAttachState>,
) -> impl Fn() -> Result<DesktopAttachService<RuntimeAttachBoundaries>, ProtocolError> + Send + Sync
{
    move || state.attach_service()
}

#[cfg(target_os = "windows")]
impl WindowsAttachAcceptor {
    /// Binds the current user's attach pipe within the supplied wait and
    /// opens the runtime state of one host.
    pub fn bind(
        host: RuntimeHost,
        state_directory: impl AsRef<Path>,
        bounded_wait: Duration,
    ) -> Result<Self, WindowsAttachBindError> {
        let state_directory = state_directory.as_ref();
        let listener = WindowsAttachListener::bind(state_directory, bounded_wait)?;
        let stop = Arc::new(
            WindowsAttachStopEvent::new()
                .map_err(|error| WindowsAttachBindError::Pipe(std::io::Error::other(error)))?,
        );
        let state = Arc::new(
            RuntimeAttachState::open(host, state_directory, state_directory).map_err(|error| {
                WindowsAttachBindError::Pipe(std::io::Error::other(format!(
                    "could not open runtime attach state: {error:?}"
                )))
            })?,
        );
        Ok(Self {
            listener,
            stop,
            state,
        })
    }
}

#[cfg(target_os = "windows")]
impl WindowsAttachStopSignal for Arc<WindowsAttachStopEvent> {
    fn signal(&self) {
        let _ = WindowsAttachStopEvent::signal(self);
    }
}

#[cfg(target_os = "windows")]
impl WindowsAttachAcceptBoundary for WindowsAttachAcceptor {
    type StopSignal = Arc<WindowsAttachStopEvent>;

    fn stop_signal(&self) -> Self::StopSignal {
        Arc::clone(&self.stop)
    }

    fn retention_state(&self) -> Option<Arc<RuntimeAttachState>> {
        Some(Arc::clone(&self.state))
    }

    fn serve_next(&mut self) -> WindowsAttachAcceptOutcome {
        match self.listener.accept_until(&self.stop) {
            Ok(CoreWindowsAttachAcceptOutcome::Connected(mut stream)) => {
                stream.set_stop_event(Arc::clone(&self.stop));
                let state = Arc::clone(&self.state);
                std::thread::spawn(move || {
                    let Ok(mut service) = state.attach_service() else {
                        return;
                    };
                    let approval = service.boundaries.signed_workspace_approval();
                    let coordinator = service.boundaries.approval_coordinator();
                    let live_connections = service.boundaries.live_connections();
                    let approval_waiter = service.boundaries.approval_coordinator();
                    let waiter_approval = approval.clone();
                    let waiter = approval_waiter_with_claims(
                        move |challenge: &muniment_core::attach::PairingChallenge,
                              kind: &str,
                              version: &str,
                              remaining: Duration| {
                            Some(crate::attach_boundaries::request_approval(
                                &waiter_approval,
                                &approval_waiter,
                                challenge.as_str(),
                                kind,
                                version,
                                remaining,
                            ))
                        },
                    );
                    let deadline = Instant::now() + WINDOWS_ATTACH_SESSION_TIMEOUT;
                    let _ = serve_windows_attach_session_with_state(
                        stream,
                        env!("CARGO_PKG_VERSION"),
                        deadline,
                        &mut service,
                        approval.approval(),
                        coordinator,
                        waiter,
                        &live_connections,
                    );
                });
                WindowsAttachAcceptOutcome::Served
            }
            Ok(CoreWindowsAttachAcceptOutcome::Stopped) => WindowsAttachAcceptOutcome::Stopped,
            Err(error) => WindowsAttachAcceptOutcome::AcceptFailed(error),
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
fn windows_attach_accept_outcome(
    result: Result<WindowsAttachServeOutcome, WindowsAttachAcceptError>,
) -> WindowsAttachAcceptOutcome {
    match result {
        Ok(WindowsAttachServeOutcome::Served) => WindowsAttachAcceptOutcome::Served,
        Ok(WindowsAttachServeOutcome::Stopped) => WindowsAttachAcceptOutcome::Stopped,
        Err(error) => WindowsAttachAcceptOutcome::AcceptFailed(error),
    }
}

/// The reason the Windows attach accept loop ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachAcceptLoopExit {
    Stopped,
    Failed,
    AcceptFailed(WindowsAttachAcceptError),
}

/// Serves Windows attach sessions until stopped or accepts keep failing.
pub fn run_windows_attach_accept_loop(
    acceptor: &mut impl WindowsAttachAcceptBoundary,
) -> WindowsAttachAcceptLoopExit {
    let mut consecutive_failed_accepts = 0;
    loop {
        match acceptor.serve_next() {
            WindowsAttachAcceptOutcome::Stopped => return WindowsAttachAcceptLoopExit::Stopped,
            failure @ (WindowsAttachAcceptOutcome::Failed
            | WindowsAttachAcceptOutcome::AcceptFailed(_)) => {
                let exit = match failure {
                    WindowsAttachAcceptOutcome::AcceptFailed(error) => {
                        eprintln!("muniment-runtime: attach accept failed: {error}");
                        WindowsAttachAcceptLoopExit::AcceptFailed(error)
                    }
                    _ => WindowsAttachAcceptLoopExit::Failed,
                };
                consecutive_failed_accepts += 1;
                if consecutive_failed_accepts == MAX_CONSECUTIVE_FAILED_ACCEPTS {
                    return exit;
                }
                std::thread::sleep(FAILED_ACCEPT_RETRY_DELAY);
            }
            WindowsAttachAcceptOutcome::Served => {
                consecutive_failed_accepts = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_a_service_from_fresh_runtime_attach_state() {
        use muniment_core::attach::thread_service::ThreadListRequest;

        let directory = temporary_state_directory("service");
        let state = Arc::new(
            RuntimeAttachState::open(crate::host::RuntimeHost::default(), &directory, &directory)
                .unwrap(),
        );

        let mut service = runtime_attach_service_factory(state)().unwrap();
        let page = service
            .list_threads(
                "workspace",
                ThreadListRequest {
                    limit: 20,
                    cursor: None,
                },
            )
            .unwrap();

        assert!(page.threads.is_empty());
        assert!(directory.join("attach-idempotency.sqlite3").is_file());
        drop(service);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn returns_a_runtime_attach_state_open_failure() {
        let directory = temporary_state_directory("state-error");
        std::fs::create_dir_all(directory.join("runs.sqlite3")).unwrap();

        assert!(RuntimeAttachState::open(
            crate::host::RuntimeHost::default(),
            &directory,
            &directory
        )
        .is_err());

        std::fs::remove_dir_all(directory).unwrap();
    }

    fn temporary_state_directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "muniment-windows-attach-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn maps_each_accept_result() {
        assert_eq!(
            windows_attach_accept_outcome(Ok(WindowsAttachServeOutcome::Served)),
            WindowsAttachAcceptOutcome::Served
        );
        assert_eq!(
            windows_attach_accept_outcome(Ok(WindowsAttachServeOutcome::Stopped)),
            WindowsAttachAcceptOutcome::Stopped
        );
        for error in [
            WindowsAttachAcceptError::DeadlineExpired,
            WindowsAttachAcceptError::CreateEvent(1),
            WindowsAttachAcceptError::CreateInstance(1),
            WindowsAttachAcceptError::VerifyInstanceSecurity(None),
            WindowsAttachAcceptError::VerifyInstanceSecurity(Some(5)),
            WindowsAttachAcceptError::Connect(1),
            WindowsAttachAcceptError::Disconnect(1),
            WindowsAttachAcceptError::Wait(1),
            WindowsAttachAcceptError::Cancel(1),
        ] {
            assert_eq!(
                windows_attach_accept_outcome(Err(error)),
                WindowsAttachAcceptOutcome::AcceptFailed(error)
            );
        }
    }
}
