//! Runtime-owned macOS attach acceptor.

use std::io;
use std::path::{Path, PathBuf};
#[cfg(any(unix, target_os = "windows"))]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use muniment_core::attach::{
    approval_waiter_with_claims, serve_macos_attach_session_with_state, MacosAttachListener,
    MacosAttachStopEvent, MacosAttachWaitOutcome,
};
#[cfg(any(unix, target_os = "windows"))]
use muniment_core::attach::{DesktopAttachService, ProtocolError};

#[cfg(target_os = "macos")]
use crate::attach_boundaries::request_approval;
#[cfg(any(unix, target_os = "windows"))]
use crate::host::RuntimeHost;
#[cfg(any(unix, target_os = "windows"))]
use crate::{
    RuntimeAttachBoundaries, RuntimeAttachState, WindowsAttachAcceptBoundary,
    WindowsAttachAcceptOutcome, WindowsAttachStopSignal,
};

#[cfg(target_os = "macos")]
const MACOS_ATTACH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MACOS_ATTACH_DIRECTORY: &str = "muniment";
const MACOS_ATTACH_SOCKET: &str = "attach-v1.sock";
// Reserve one byte in macOS sun_path for the null terminator.
const MACOS_ATTACH_SOCKET_PATH_CAPACITY: usize = 104;

/// The reason a macOS attach acceptor could not bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachBindFailure {
    Contended,
    Unavailable,
    SocketPathTooLong,
    DesktopExecutableCheckFailed,
    StateOpenFailed,
}

/// Returns the attach socket path for a profile.
pub fn macos_attach_socket_path(profile_directory: &Path) -> PathBuf {
    profile_directory
        .join(MACOS_ATTACH_DIRECTORY)
        .join(MACOS_ATTACH_SOCKET)
}

fn classify_bind_failure(path: &Path, error: &io::Error) -> MacosAttachBindFailure {
    if error.kind() == io::ErrorKind::AddrInUse {
        MacosAttachBindFailure::Contended
    } else if error.kind() == io::ErrorKind::InvalidInput
        && path.as_os_str().as_encoded_bytes().len() >= MACOS_ATTACH_SOCKET_PATH_CAPACITY
    {
        MacosAttachBindFailure::SocketPathTooLong
    } else {
        MacosAttachBindFailure::Unavailable
    }
}

/// Injected boundary for one macOS accept and serve attempt.
#[doc(hidden)]
#[cfg(any(unix, target_os = "windows"))]
pub trait MacosAttachServeBoundary {
    type StopSignal: WindowsAttachStopSignal;

    fn stop_signal(&self) -> Self::StopSignal;

    fn serve_next(
        &mut self,
        service_factory: Arc<
            dyn Fn() -> Result<DesktopAttachService<RuntimeAttachBoundaries>, ProtocolError>
                + Send
                + Sync,
        >,
    ) -> WindowsAttachAcceptOutcome;
}

/// A macOS acceptor with an injected transport boundary.
#[doc(hidden)]
#[cfg(any(unix, target_os = "windows"))]
pub struct MacosAttachAcceptorWithBoundary<B> {
    boundary: B,
    state: Arc<RuntimeAttachState>,
}

#[cfg(any(unix, target_os = "windows"))]
impl<B> MacosAttachAcceptorWithBoundary<B> {
    /// Binds a transport boundary and opens one activation state.
    #[doc(hidden)]
    pub fn bind_with(
        host: RuntimeHost,
        profile_directory: impl AsRef<Path>,
        config_directory: impl AsRef<Path>,
        bind_boundary: impl FnOnce(&Path) -> io::Result<B>,
    ) -> Result<Self, MacosAttachBindFailure> {
        let profile_directory = profile_directory.as_ref();
        let socket_path = macos_attach_socket_path(profile_directory);
        let boundary = bind_boundary(&socket_path)
            .map_err(|error| classify_bind_failure(&socket_path, &error))?;
        let state = Arc::new(
            RuntimeAttachState::open(host, profile_directory, config_directory)
                .map_err(|_| MacosAttachBindFailure::StateOpenFailed)?,
        );
        Ok(Self { boundary, state })
    }
}

#[cfg(any(unix, target_os = "windows"))]
impl<B: MacosAttachServeBoundary> WindowsAttachAcceptBoundary
    for MacosAttachAcceptorWithBoundary<B>
{
    type StopSignal = B::StopSignal;

    fn stop_signal(&self) -> Self::StopSignal {
        self.boundary.stop_signal()
    }

    fn retention_state(&self) -> Option<Arc<RuntimeAttachState>> {
        Some(Arc::clone(&self.state))
    }

    fn serve_next(&mut self) -> WindowsAttachAcceptOutcome {
        let state = Arc::clone(&self.state);
        self.boundary
            .serve_next(Arc::new(move || state.attach_service()))
    }
}

/// A bound macOS attach acceptor.
#[cfg(target_os = "macos")]
pub type MacosAttachAcceptor = MacosAttachAcceptorWithBoundary<SystemMacosAttachBoundary>;

/// The native macOS attach transport boundary.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub struct SystemMacosAttachBoundary {
    listener: MacosAttachListener,
    stop: Arc<MacosAttachStopEvent>,
    expected_desktop_executable: PathBuf,
    runtime_version: &'static str,
}

#[cfg(target_os = "macos")]
impl MacosAttachAcceptorWithBoundary<SystemMacosAttachBoundary> {
    /// Opens the activation state and binds its profile attach socket. The
    /// host names the desktop executable that peers must run.
    pub fn bind(
        host: RuntimeHost,
        profile_directory: impl AsRef<Path>,
        config_directory: impl AsRef<Path>,
    ) -> Result<Self, MacosAttachBindFailure> {
        let expected_desktop_executable = host
            .expected_desktop_executable
            .clone()
            .ok_or(MacosAttachBindFailure::DesktopExecutableCheckFailed)?;
        let runtime_version = host.runtime_version;
        Self::bind_with(host, profile_directory, config_directory, move |path| {
            let listener = MacosAttachListener::bind(path)?;
            let stop = Arc::new(MacosAttachStopEvent::new()?);
            Ok(SystemMacosAttachBoundary {
                listener,
                stop,
                expected_desktop_executable,
                runtime_version,
            })
        })
    }
}

#[cfg(target_os = "macos")]
impl WindowsAttachStopSignal for Arc<MacosAttachStopEvent> {
    fn signal(&self) {
        let _ = MacosAttachStopEvent::signal(self);
    }
}

#[cfg(target_os = "macos")]
impl MacosAttachServeBoundary for SystemMacosAttachBoundary {
    type StopSignal = Arc<MacosAttachStopEvent>;

    fn stop_signal(&self) -> Self::StopSignal {
        Arc::clone(&self.stop)
    }

    fn serve_next(
        &mut self,
        service_factory: Arc<
            dyn Fn() -> Result<DesktopAttachService<RuntimeAttachBoundaries>, ProtocolError>
                + Send
                + Sync,
        >,
    ) -> WindowsAttachAcceptOutcome {
        match self.listener.accept_until(&self.stop) {
            Ok(MacosAttachWaitOutcome::Connected(stream)) => {
                let expected_desktop_executable = self.expected_desktop_executable.clone();
                let runtime_version = self.runtime_version;
                std::thread::spawn(move || {
                    let mut service = match service_factory() {
                        Ok(service) => service,
                        Err(error) => {
                            muniment_core::runtime_eprintln!(
                                "muniment-runtime: desktop session closed reason=service creation failed {error}"
                            );
                            return;
                        }
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
                            Some(request_approval(
                                &waiter_approval,
                                &approval_waiter,
                                challenge.as_str(),
                                kind,
                                version,
                                remaining,
                            ))
                        },
                    );
                    let result = serve_macos_attach_session_with_state(
                        stream,
                        &expected_desktop_executable,
                        runtime_version,
                        MACOS_ATTACH_HANDSHAKE_TIMEOUT,
                        &mut service,
                        approval.approval(),
                        coordinator,
                        waiter,
                        &live_connections,
                    );
                    // The desktop request loop and presenter refusal path log their own close reasons.
                    if let Err(error) = result {
                        if !matches!(
                            error,
                            muniment_core::attach::MacosAttachSessionError::DesktopClientSession(_)
                                | muniment_core::attach::MacosAttachSessionError::ApprovalPresenterUnavailable
                        ) {
                            muniment_core::runtime_eprintln!(
                                "muniment-runtime: attach session closed reason={error:?}"
                            );
                        }
                    }
                });
                WindowsAttachAcceptOutcome::Served
            }
            Ok(MacosAttachWaitOutcome::Stopped) => WindowsAttachAcceptOutcome::Stopped,
            Err(error) => {
                muniment_core::runtime_eprintln!(
                    "muniment-runtime: attach accept failed reason={error:?}"
                );
                WindowsAttachAcceptOutcome::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_profile_attach_socket_path() {
        assert_eq!(
            macos_attach_socket_path(Path::new("/profiles/current")),
            Path::new("/profiles/current/muniment/attach-v1.sock")
        );
    }

    #[test]
    fn distinguishes_long_socket_paths_from_other_invalid_input() {
        let suffix_length = "/muniment/attach-v1.sock".len();
        for bytes in [103, 104, 105, 108] {
            let profile = PathBuf::from(format!("/{}", "a".repeat(bytes - suffix_length - 1)));
            let result = MacosAttachAcceptorWithBoundary::<()>::bind_with(
                RuntimeHost::default(),
                &profile,
                &profile,
                |_| Err(io::Error::from(io::ErrorKind::InvalidInput)),
            );
            assert_eq!(
                result.err(),
                Some(if bytes == 103 {
                    MacosAttachBindFailure::Unavailable
                } else {
                    MacosAttachBindFailure::SocketPathTooLong
                })
            );
        }
    }

    #[test]
    fn counts_socket_path_bytes_not_characters() {
        let profile = PathBuf::from(format!("/{}a", "é".repeat(39)));
        let socket = macos_attach_socket_path(&profile);
        assert_eq!(socket.as_os_str().as_encoded_bytes().len(), 104);
        assert_eq!(
            MacosAttachAcceptorWithBoundary::<()>::bind_with(
                RuntimeHost::default(),
                &profile,
                &profile,
                |_| { Err(io::Error::from(io::ErrorKind::InvalidInput)) }
            )
            .err(),
            Some(MacosAttachBindFailure::SocketPathTooLong)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classifies_the_native_socket_path_limit() {
        use std::os::unix::net::SocketAddr;

        let valid = PathBuf::from(format!("/{}", "a".repeat(102)));
        assert!(SocketAddr::from_pathname(&valid).is_ok());
        let invalid = PathBuf::from(format!("/{}", "a".repeat(103)));
        let error = SocketAddr::from_pathname(&invalid).unwrap_err();
        assert_eq!(
            classify_bind_failure(&invalid, &error),
            MacosAttachBindFailure::SocketPathTooLong
        );
    }

    #[test]
    fn distinguishes_a_contended_bind() {
        assert_eq!(
            classify_bind_failure(
                Path::new("/tmp/attach.sock"),
                &io::Error::from(io::ErrorKind::AddrInUse)
            ),
            MacosAttachBindFailure::Contended
        );
        assert_eq!(
            classify_bind_failure(
                Path::new("/tmp/attach.sock"),
                &io::Error::from(io::ErrorKind::PermissionDenied)
            ),
            MacosAttachBindFailure::Unavailable
        );
        assert_eq!(
            classify_bind_failure(
                Path::new("/tmp/attach.sock"),
                &io::Error::from(io::ErrorKind::InvalidInput)
            ),
            MacosAttachBindFailure::Unavailable
        );
    }
}
