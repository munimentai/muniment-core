//! Linux filesystem boundary for the companion attach endpoint.

use std::env;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
use super::companion_session::post_dispatch_deadline;
use super::companion_session::{
    read_before, read_request_before, serve_requests as serve_companion_requests, write_before,
    write_protocol_error, write_request_error, AuthorizedSession,
};
use super::desktop_dispatch::{dispatch_request, hex, SessionRegistries};
pub use super::desktop_dispatch::{
    MAX_PERMISSION_GATE_ID_LENGTH, MAX_RUN_MESSAGE_TEXT_LENGTH, MAX_RUN_START_CONTEXT_LENGTH,
    MAX_RUN_START_TEXT_LENGTH,
};
pub use super::desktop_service_message::{
    ArtifactFetchResult, CompanionProvenance, MigrationControlRequest, PermissionAnswerAccepted,
    PermissionAnswerRequest, PermissionDecision, RunCancelAccepted, RunCancelRequest,
    RunMessageAccepted, RunMessageRequest, RunPermissionAnswerAccepted, RunPermissionAnswerRequest,
    RunResumeAccepted, RunResumeRequest, RunStartAccepted, RunStreamPage, RunSubmitAccepted,
    RunSubmitRequest, ThreadCreateAccepted,
};
use super::desktop_session::serve_desktop_client_requests;
pub use super::live_connections::LiveConnectionRegistry;
pub use super::termination::TerminationSignalWait;
pub use super::thread_service::{
    CompanionRecord, RedactedThreadEntry, RedactedThreadSummary, RunStartRequest, ThreadListPage,
    ThreadListRequest, ThreadListService, ThreadOpenPage, ThreadOpenRequest,
};
pub use super::AttachSessionError;
pub use super::EntitlementSnapshotResult;
use super::{
    encode_frame, welcome, Approval, AuthorizationClock, AuthorizationError, AuthorizationState,
    AuthorizationTokenGenerator, ConnectionBinding, FirstMessage, NegotiationError, Operation,
    Protocol, ProtocolError, Response, Success, VersionRange, CHALLENGE_LIFETIME, MAX_FRAME_LENGTH,
};
use crate::browser_control::LinuxProcReader;

const ATTACH_DIRECTORY: &[u8] = b"muniment\0";
const ENDPOINT_NAME: &str = "attach-v1.sock";
const INSTANCE_LOCK_NAME: &[u8] = b"instance.lock\0";
const PRIVATE_MODE: libc::mode_t = 0o700;
const PRIVATE_FILE_MODE: libc::mode_t = 0o600;
const SOCKET_MODE: libc::mode_t = 0o600;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const DESKTOP_PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachListenerStartFailure {
    Filesystem,
    InstanceLock,
    Bind,
}

pub fn attach_listener_start_diagnostic(reason: AttachListenerStartFailure) -> &'static str {
    match reason {
        AttachListenerStartFailure::Filesystem => {
            "muniment-desktop: attach listener filesystem setup failed"
        }
        AttachListenerStartFailure::InstanceLock => {
            "muniment-desktop: attach listener did not get the instance lock. This is expected for a second desktop instance"
        }
        AttachListenerStartFailure::Bind => {
            "muniment-desktop: attach listener bind failed"
        }
    }
}

/// A verified, pinned filesystem boundary for the Linux attach endpoint.
#[derive(Debug)]
pub struct AttachFilesystem {
    runtime_directory: OwnedFd,
    attach_directory: OwnedFd,
    endpoint_path: PathBuf,
}

impl AttachFilesystem {
    /// Validates `XDG_RUNTIME_DIR` and prepares its private attach directory.
    pub fn from_environment() -> Result<Self, AttachFilesystemError> {
        let runtime =
            env::var_os("XDG_RUNTIME_DIR").ok_or(AttachFilesystemError::RuntimeDirectoryMissing)?;
        Self::from_runtime_directory(runtime)
    }

    /// Validates an explicit runtime directory. This is also useful to contract tests.
    pub fn from_runtime_directory(
        runtime: impl AsRef<OsStr>,
    ) -> Result<Self, AttachFilesystemError> {
        Self::from_runtime_directory_with_hook(runtime, || {})
    }

    /// Prepares the boundary, invoking `after_create` after a successful `mkdirat`
    /// and before opening the new entry. The hook makes replacement-race contract
    /// tests deterministic; production callers should use `from_environment`.
    #[doc(hidden)]
    pub fn from_runtime_directory_with_hook(
        runtime: impl AsRef<OsStr>,
        after_create: impl FnOnce(),
    ) -> Result<Self, AttachFilesystemError> {
        let runtime = Path::new(runtime.as_ref());
        if !runtime.is_absolute() {
            return Err(AttachFilesystemError::RuntimeDirectoryNotAbsolute);
        }
        if runtime.as_os_str().as_bytes().ends_with(b"/") {
            return Err(AttachFilesystemError::RuntimeDirectoryInvalid);
        }

        let runtime_c = CString::new(runtime.as_os_str().as_bytes())
            .map_err(|_| AttachFilesystemError::RuntimeDirectoryInvalid)?;
        let runtime_directory = open_directory(
            libc::AT_FDCWD,
            runtime_c.as_ptr(),
            AttachFilesystemError::RuntimeDirectoryOpen,
        )?;
        validate_directory(
            &runtime_directory,
            false,
            AttachFilesystemError::RuntimeDirectoryMetadata,
            AttachFilesystemError::RuntimeDirectoryWrongOwner,
            AttachFilesystemError::RuntimeDirectoryInsecure,
        )?;

        let name = ATTACH_DIRECTORY.as_ptr().cast();
        let created =
            unsafe { libc::mkdirat(runtime_directory.as_raw_fd(), name, PRIVATE_MODE) } == 0;
        if !created {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(AttachFilesystemError::AttachDirectoryCreate);
            }
        } else {
            after_create();
        }

        let attach_directory = open_directory(
            runtime_directory.as_raw_fd(),
            name,
            AttachFilesystemError::AttachDirectoryOpen,
        )?;

        if created && unsafe { libc::fchmod(attach_directory.as_raw_fd(), PRIVATE_MODE) } != 0 {
            return Err(AttachFilesystemError::AttachDirectoryPermissions);
        }
        validate_directory(
            &attach_directory,
            true,
            AttachFilesystemError::AttachDirectoryMetadata,
            AttachFilesystemError::AttachDirectoryWrongOwner,
            AttachFilesystemError::AttachDirectoryInsecure,
        )?;

        Ok(Self {
            runtime_directory,
            attach_directory,
            endpoint_path: runtime.join("muniment").join(ENDPOINT_NAME),
        })
    }

    pub fn endpoint_path(&self) -> &Path {
        &self.endpoint_path
    }

    pub fn runtime_directory(&self) -> BorrowedFd<'_> {
        self.runtime_directory.as_fd()
    }

    pub fn attach_directory(&self) -> BorrowedFd<'_> {
        self.attach_directory.as_fd()
    }

    /// Acquires the non-blocking exclusive lock for this attach directory.
    pub fn acquire_instance_lock(&self) -> Result<InstanceLock, InstanceLockError> {
        let descriptor = unsafe {
            libc::openat(
                self.attach_directory.as_raw_fd(),
                INSTANCE_LOCK_NAME.as_ptr().cast(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                PRIVATE_FILE_MODE,
            )
        };
        if descriptor < 0 {
            return Err(InstanceLockError::Open);
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        if unsafe { libc::flock(descriptor.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::WouldBlock {
                InstanceLockError::AlreadyHeld
            } else {
                InstanceLockError::Lock
            });
        }
        Ok(InstanceLock {
            _descriptor: descriptor,
        })
    }
}

/// An owned instance lock that releases when dropped.
#[derive(Debug)]
pub struct InstanceLock {
    _descriptor: OwnedFd,
}

/// Reasons an instance lock cannot be acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceLockError {
    Open,
    AlreadyHeld,
    Lock,
}

impl fmt::Display for InstanceLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Open => "instance lock file could not be opened safely",
            Self::AlreadyHeld => "instance lock is already held",
            Self::Lock => "instance lock could not be acquired",
        })
    }
}

impl std::error::Error for InstanceLockError {}

/// A pathname Unix listener published inside a verified [`AttachFilesystem`].
#[derive(Debug)]
pub struct AttachTransport<'a> {
    filesystem: &'a AttachFilesystem,
    listener: Option<UnixListener>,
    stop: AttachStopHandle,
    identity: EndpointIdentity,
}

/// A shared request to stop an attach listener.
#[derive(Clone, Debug)]
pub struct AttachStopHandle {
    state: Arc<AttachStopState>,
}

#[derive(Debug)]
struct AttachStopState {
    requested: AtomicBool,
    event: OwnedFd,
}

impl AttachStopHandle {
    /// Stops the listener. This method may be called more than once.
    pub fn stop(&self) {
        if self.state.requested.swap(true, Ordering::AcqRel) {
            return;
        }
        let value = 1_u64.to_ne_bytes();
        unsafe {
            libc::write(
                self.state.event.as_raw_fd(),
                value.as_ptr().cast(),
                value.len(),
            );
        }
    }
}

impl<'a> AttachTransport<'a> {
    /// Publishes a blocking stream listener. No accept thread is started.
    pub fn bind(filesystem: &'a AttachFilesystem) -> Result<Self, AttachTransportError> {
        Self::bind_with_quarantine_candidate_hook(filesystem, || {}, || {}, || {}, |_| {})
    }

    /// Binds while invoking deterministic race hooks used by contract tests.
    #[doc(hidden)]
    pub fn bind_with_hooks(
        filesystem: &'a AttachFilesystem,
        after_bind: impl FnOnce(),
        before_stale_remove: impl FnOnce(),
    ) -> Result<Self, AttachTransportError> {
        Self::bind_with_quarantine_candidate_hook(
            filesystem,
            after_bind,
            before_stale_remove,
            || {},
            |_| {},
        )
    }

    /// Binds with an additional hook after a stale entry has been quarantined.
    #[doc(hidden)]
    pub fn bind_with_race_hooks(
        filesystem: &'a AttachFilesystem,
        after_bind: impl FnOnce(),
        before_stale_remove: impl FnOnce(),
        after_stale_quarantine: impl FnOnce(),
    ) -> Result<Self, AttachTransportError> {
        Self::bind_with_quarantine_candidate_hook(
            filesystem,
            after_bind,
            before_stale_remove,
            after_stale_quarantine,
            |_| {},
        )
    }

    /// Binds with a hook before each quarantine move attempt.
    #[doc(hidden)]
    pub fn bind_with_quarantine_candidate_hook(
        filesystem: &'a AttachFilesystem,
        after_bind: impl FnOnce(),
        before_stale_remove: impl FnOnce(),
        after_stale_quarantine: impl FnOnce(),
        quarantine_candidate: impl FnMut(&str),
    ) -> Result<Self, AttachTransportError> {
        let uid = unsafe { libc::geteuid() };
        recover_stale_endpoint(
            filesystem,
            uid,
            before_stale_remove,
            after_stale_quarantine,
            quarantine_candidate,
        )?;

        let bind_path = pinned_endpoint_path(filesystem);
        let listener = UnixListener::bind(&bind_path).map_err(|_| AttachTransportError::Bind)?;
        let created_identity = match endpoint_identity(filesystem) {
            Ok(identity) => identity,
            Err(_) => {
                drop(listener);
                return Err(AttachTransportError::EndpointMetadata);
            }
        };
        if listener.set_nonblocking(true).is_err() {
            drop(listener);
            remove_if_identity(filesystem, created_identity);
            return Err(AttachTransportError::Bind);
        }
        after_bind();
        if apply_socket_permissions(filesystem, created_identity).is_err() {
            drop(listener);
            remove_if_identity(filesystem, created_identity);
            return Err(AttachTransportError::Permissions);
        }

        let identity = match verified_endpoint(filesystem, uid) {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                remove_if_identity(filesystem, created_identity);
                return Err(error);
            }
        };
        if identity != created_identity {
            drop(listener);
            remove_if_identity(filesystem, created_identity);
            return Err(AttachTransportError::EndpointMetadata);
        }
        let event = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if event < 0 {
            drop(listener);
            remove_if_identity(filesystem, created_identity);
            return Err(AttachTransportError::Bind);
        }
        Ok(Self {
            filesystem,
            listener: Some(listener),
            stop: AttachStopHandle {
                state: Arc::new(AttachStopState {
                    requested: AtomicBool::new(false),
                    event: unsafe { OwnedFd::from_raw_fd(event) },
                }),
            },
            identity,
        })
    }

    /// Accepts and authenticates one connection using Linux `SO_PEERCRED`.
    pub fn accept(&self) -> Result<(UnixStream, PeerCredentials), AttachAcceptError> {
        let listener = self.listener.as_ref().ok_or(AttachAcceptError::Closed)?;
        let (stream, _) = loop {
            if self.stop.state.requested.load(Ordering::Acquire) {
                return Err(AttachAcceptError::Closed);
            }
            let mut descriptors = [
                libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.stop.state.event.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result =
                unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(AttachAcceptError::Accept);
            }
            if self.stop.state.requested.load(Ordering::Acquire) {
                return Err(AttachAcceptError::Closed);
            }
            if descriptors[0].revents != 0 {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(_) => return Err(AttachAcceptError::Accept),
                }
            }
        };
        let credentials = peer_credentials(&stream)?;
        if credentials.uid != unsafe { libc::geteuid() } {
            return Err(AttachAcceptError::WrongUid(credentials));
        }
        Ok((stream, credentials))
    }

    /// Returns a handle that may stop this listener from another thread.
    pub fn stop_handle(&self) -> AttachStopHandle {
        self.stop.clone()
    }

    pub fn local_path(&self) -> &Path {
        self.filesystem.endpoint_path()
    }

    /// Closes acceptance and safely withdraws this listener's pathname.
    pub fn shutdown(mut self) {
        self.close_and_remove();
    }

    /// Shuts down while invoking a deterministic check/remove race hook.
    #[doc(hidden)]
    pub fn shutdown_with_hook(mut self, before_remove: impl FnOnce()) {
        self.listener.take();
        let _ = remove_exact_endpoint_with_hook(self.filesystem, self.identity, before_remove);
    }

    fn close_and_remove(&mut self) {
        self.listener.take();
        remove_if_identity(self.filesystem, self.identity);
    }
}

impl Drop for AttachTransport<'_> {
    fn drop(&mut self) {
        self.close_and_remove();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// The result of the explicit, visible desktop approval prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve(Approval),
    Deny,
}

/// Bounded seam for receiving desktop approval actions.
pub trait ApprovalWaiter {
    /// Returns the next action available within `remaining`, or `None` when that
    /// bound expires. Implementations must not wait longer than `remaining`.
    fn wait(
        &mut self,
        challenge: &super::PairingChallenge,
        claimed_kind: &str,
        claimed_version: &str,
        remaining: Duration,
    ) -> Option<ApprovalDecision>;
}

impl<F> ApprovalWaiter for F
where
    F: FnMut(&super::PairingChallenge, Duration) -> Option<ApprovalDecision>,
{
    fn wait(
        &mut self,
        challenge: &super::PairingChallenge,
        _: &str,
        _: &str,
        remaining: Duration,
    ) -> Option<ApprovalDecision> {
        self(challenge, remaining)
    }
}

pub struct ClaimedApprovalWaiter<F>(F);

pub fn approval_waiter_with_claims<F>(waiter: F) -> ClaimedApprovalWaiter<F> {
    ClaimedApprovalWaiter(waiter)
}

impl<F> ApprovalWaiter for ClaimedApprovalWaiter<F>
where
    F: FnMut(&super::PairingChallenge, &str, &str, Duration) -> Option<ApprovalDecision>,
{
    fn wait(
        &mut self,
        challenge: &super::PairingChallenge,
        claimed_kind: &str,
        claimed_version: &str,
        remaining: Duration,
    ) -> Option<ApprovalDecision> {
        (self.0)(challenge, claimed_kind, claimed_version, remaining)
    }
}

/// Injectable dependencies for the authorization phase of a Linux session.
pub struct AuthorizationSessionDependencies<R, C, G, W> {
    pub fill_random: R,
    pub clock: C,
    pub tokens: G,
    pub approvals: W,
}

/// Injectable authority for migration control session admission.
pub struct MigrationControlSessionDependencies<'a> {
    pub expected_executable: &'a Path,
    pub process_reader: &'a dyn LinuxProcReader,
}

/// Shared state used by session admission paths.
pub struct SessionRegistryDependencies<'a> {
    pub registry: &'a LiveConnectionRegistry,
    pub migration: Option<MigrationControlSessionDependencies<'a>>,
    pub handoff_nonce: Option<&'a str>,
}

/// Completes the single hello/welcome exchange allowed before authorization.
/// `credentials` must be the value returned alongside `stream` by [`AttachTransport::accept`].
pub fn run_authenticated_session(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
) -> Result<(), AttachSessionError> {
    run_authenticated_session_with(
        stream,
        credentials,
        desktop_version,
        HELLO_TIMEOUT,
        |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| ()),
    )
}

/// Runs the default authenticated session with the desktop's concrete request service.
pub fn run_authenticated_session_with_service<S: ThreadListService>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    service: &mut S,
) -> Result<(), AttachSessionError> {
    run_authenticated_session_with_service_and_timeout(
        stream,
        credentials,
        desktop_version,
        service,
        HELLO_TIMEOUT,
    )
}

#[doc(hidden)]
pub fn run_authenticated_session_with_service_and_timeout<S: ThreadListService>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    service: &mut S,
    timeout: Duration,
) -> Result<(), AttachSessionError> {
    let mut random = |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| ());
    run_authenticated_session_with_authorization(
        stream,
        credentials,
        desktop_version,
        timeout,
        AuthorizationSessionDependencies {
            fill_random: &mut random,
            clock: SessionClock(Instant::now()),
            tokens: SessionTokens,
            approvals: |_: &super::PairingChallenge, _: Duration| Some(ApprovalDecision::Deny),
        },
        service,
    )
}

pub fn run_authenticated_session_with_service_and_approvals<
    S: ThreadListService,
    W: ApprovalWaiter,
>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    service: &mut S,
    approvals: W,
) -> Result<(), AttachSessionError> {
    run_authenticated_session_with_service_approvals_and_registry(
        stream,
        credentials,
        desktop_version,
        service,
        approvals,
        &LiveConnectionRegistry::default(),
        None,
    )
}

/// Runs the concrete request service with approvals and a shared live-connection registry.
pub fn run_authenticated_session_with_service_approvals_and_registry<
    S: ThreadListService,
    W: ApprovalWaiter,
>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    service: &mut S,
    approvals: W,
    registry: &LiveConnectionRegistry,
    handoff_nonce: Option<&str>,
) -> Result<(), AttachSessionError> {
    run_authenticated_session_with_service_approvals_registry_and_timeout(
        stream,
        credentials,
        desktop_version,
        service,
        approvals,
        SessionRegistryDependencies {
            registry,
            migration: None,
            handoff_nonce,
        },
        HELLO_TIMEOUT,
    )
}

/// Runs the concrete service with companion approvals and migration peer admission.
pub fn run_authenticated_session_with_service_approvals_registry_and_migration<
    S: ThreadListService,
    W: ApprovalWaiter,
>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    service: &mut S,
    approvals: W,
    registry: &LiveConnectionRegistry,
    migration: MigrationControlSessionDependencies<'_>,
) -> Result<(), AttachSessionError> {
    let mut random = |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| ());
    run_authenticated_session_with_authorization_registry_and_migration(
        stream,
        credentials,
        desktop_version,
        HELLO_TIMEOUT,
        AuthorizationSessionDependencies {
            fill_random: &mut random,
            clock: SessionClock(Instant::now()),
            tokens: SessionTokens,
            approvals,
        },
        service,
        SessionRegistryDependencies {
            registry,
            migration: Some(migration),
            handoff_nonce: None,
        },
    )
}

#[doc(hidden)]
pub fn run_authenticated_session_with_service_approvals_registry_and_timeout<
    S: ThreadListService,
    W: ApprovalWaiter,
>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    service: &mut S,
    approvals: W,
    session: SessionRegistryDependencies<'_>,
    timeout: Duration,
) -> Result<(), AttachSessionError> {
    let mut random = |bytes: &mut [u8]| getrandom::fill(bytes).map_err(|_| ());
    run_session(
        stream,
        credentials,
        desktop_version,
        timeout,
        AuthorizationSessionDependencies {
            fill_random: &mut random,
            clock: SessionClock(Instant::now()),
            tokens: SessionTokens,
            approvals,
        },
        service,
        session,
    )
}

/// Testable form of [`run_authenticated_session`] with bounded timing and randomness seams.
#[doc(hidden)]
pub fn run_authenticated_session_with<R>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    timeout: Duration,
    fill_random: R,
) -> Result<(), AttachSessionError>
where
    R: FnMut(&mut [u8]) -> Result<(), ()>,
{
    let mut unavailable =
        |_: &str, _: ThreadListRequest| Err(ProtocolError::unsupported_operation());
    run_authenticated_session_with_authorization(
        stream,
        credentials,
        desktop_version,
        timeout,
        AuthorizationSessionDependencies {
            fill_random,
            clock: SessionClock(Instant::now()),
            tokens: SessionTokens,
            approvals: |_: &super::PairingChallenge, _: Duration| Some(ApprovalDecision::Deny),
        },
        &mut unavailable,
    )
}

#[derive(Clone)]
struct SessionClock(Instant);
impl AuthorizationClock for SessionClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

struct SessionTokens;
impl AuthorizationTokenGenerator for SessionTokens {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), super::AuthorizationRandomnessError> {
        getrandom::fill(bytes).map_err(|_| super::AuthorizationRandomnessError)
    }
}

/// Negotiates and waits for a deterministic desktop approval decision.
#[doc(hidden)]
pub fn run_authenticated_session_with_authorization<R, C, G, W, S>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    timeout: Duration,
    dependencies: AuthorizationSessionDependencies<R, C, G, W>,
    service: &mut S,
) -> Result<(), AttachSessionError>
where
    R: FnMut(&mut [u8]) -> Result<(), ()>,
    C: AuthorizationClock + Clone,
    G: AuthorizationTokenGenerator,
    W: ApprovalWaiter,
    S: ThreadListService,
{
    run_authenticated_session_with_authorization_and_registry(
        stream,
        credentials,
        desktop_version,
        timeout,
        dependencies,
        service,
        &LiveConnectionRegistry::default(),
    )
}

/// Runs an authenticated session tracked by a shared live-connection registry.
#[doc(hidden)]
pub fn run_authenticated_session_with_authorization_and_registry<R, C, G, W, S>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    timeout: Duration,
    dependencies: AuthorizationSessionDependencies<R, C, G, W>,
    service: &mut S,
    registry: &LiveConnectionRegistry,
) -> Result<(), AttachSessionError>
where
    R: FnMut(&mut [u8]) -> Result<(), ()>,
    C: AuthorizationClock + Clone,
    G: AuthorizationTokenGenerator,
    W: ApprovalWaiter,
    S: ThreadListService,
{
    run_session(
        stream,
        credentials,
        desktop_version,
        timeout,
        dependencies,
        service,
        SessionRegistryDependencies {
            registry,
            migration: None,
            handoff_nonce: None,
        },
    )
}

/// Runs a session with an injected migration control peer authority.
#[doc(hidden)]
pub fn run_authenticated_session_with_authorization_registry_and_migration<R, C, G, W, S>(
    stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    timeout: Duration,
    dependencies: AuthorizationSessionDependencies<R, C, G, W>,
    service: &mut S,
    session: SessionRegistryDependencies<'_>,
) -> Result<(), AttachSessionError>
where
    R: FnMut(&mut [u8]) -> Result<(), ()>,
    C: AuthorizationClock + Clone,
    G: AuthorizationTokenGenerator,
    W: ApprovalWaiter,
    S: ThreadListService,
{
    run_session(
        stream,
        credentials,
        desktop_version,
        timeout,
        dependencies,
        service,
        session,
    )
}

fn run_session<R, C, G, W, S>(
    mut stream: UnixStream,
    credentials: PeerCredentials,
    desktop_version: &str,
    timeout: Duration,
    dependencies: AuthorizationSessionDependencies<R, C, G, W>,
    service: &mut S,
    session: SessionRegistryDependencies<'_>,
) -> Result<(), AttachSessionError>
where
    R: FnMut(&mut [u8]) -> Result<(), ()>,
    C: AuthorizationClock + Clone,
    G: AuthorizationTokenGenerator,
    W: ApprovalWaiter,
    S: ThreadListService,
{
    let AuthorizationSessionDependencies {
        mut fill_random,
        clock,
        tokens,
        mut approvals,
    } = dependencies;
    let result = (|| {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(AttachSessionError::Timeout)?;
        let mut prefix = [0u8; 4];
        read_before(&mut stream, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_FRAME_LENGTH {
            write_protocol_error(&mut stream, ProtocolError::payload_too_large(), deadline);
            return Err(AttachSessionError::PayloadTooLarge);
        }
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + length, 0);
        read_before(&mut stream, &mut frame[4..], deadline)?;
        let message = match super::decode_frame::<FirstMessage>(&frame) {
            Ok(Some((message, _))) => message,
            _ => {
                write_protocol_error(&mut stream, ProtocolError::malformed_frame(), deadline);
                return Err(AttachSessionError::MalformedFrame);
            }
        };
        let (
            client_nonce,
            authorized_client_id,
            authorized_client_credential,
            companion_kind,
            companion_version,
        ) = match &message {
            FirstMessage::Hello(hello) => (
                hello.client_nonce.clone(),
                hello.authorized_client_id.as_str().to_owned(),
                hello.authorized_client_credential.clone(),
                hello.client.kind.clone(),
                hello.client.version.clone(),
            ),
            _ => {
                write_protocol_error(&mut stream, ProtocolError::malformed_frame(), deadline);
                return Err(AttachSessionError::MalformedFrame);
            }
        };
        let selected = match super::negotiate_first(message, DESKTOP_PROTOCOL) {
            Ok(selected) => selected,
            Err(NegotiationError::Incompatible(error)) => {
                write_protocol_error(&mut stream, error, deadline);
                return Err(AttachSessionError::ProtocolIncompatible);
            }
            Err(_) => {
                write_protocol_error(&mut stream, ProtocolError::malformed_frame(), deadline);
                return Err(AttachSessionError::MalformedFrame);
            }
        };

        let migration_peer = session.migration.as_ref().is_some_and(|migration| {
            u32::try_from(credentials.pid).is_ok_and(|peer_pid| {
                super::verify_migration_control_peer_with_reader(
                    peer_pid,
                    migration.expected_executable,
                    migration.process_reader,
                )
                .is_ok()
            })
        });

        let mut nonce = [0u8; 16];
        fill_random(&mut nonce).map_err(|_| AttachSessionError::Randomness)?;
        let server_nonce = hex(&nonce);
        let binding = ConnectionBinding {
            connection_id: server_nonce.clone(),
            client_nonce,
            server_nonce: server_nonce.clone(),
            companion_identity: format!("{}:{}", credentials.uid, credentials.pid),
            companion_kind: companion_kind.clone(),
        };
        if migration_peer {
            return run_migration_control_session(
                MigrationSessionInputs {
                    stream: &mut stream,
                    credentials,
                    desktop_version,
                    selected,
                    timeout,
                    server_nonce,
                },
                &mut fill_random,
                service,
            );
        }
        let reconnect = authorized_client_credential
            .as_deref()
            .and_then(|credential| {
                let approval = service.reconnect_approval()?;
                service
                    .authorize_client(
                        &authorized_client_id,
                        Some(credential),
                        "",
                        &companion_kind,
                        &companion_version,
                    )
                    .ok()
                    .map(|credential| (approval, credential))
            });
        let mut authorization = AuthorizationState::new(clock.clone(), tokens, binding.clone());
        let challenge_expires_at = clock.now() + CHALLENGE_LIFETIME;
        let challenge = authorization
            .issue_challenge()
            .map_err(|error| match error {
                AuthorizationError::Randomness => AttachSessionError::Randomness,
                _ => AttachSessionError::Authorization,
            })?;
        let authorization_deadline = Instant::now()
            .checked_add(CHALLENGE_LIFETIME)
            .ok_or(AttachSessionError::Timeout)?;
        let response = if reconnect.is_some() {
            muniment_attach::reconnect_welcome(
                selected,
                desktop_version,
                server_nonce,
                challenge.as_str(),
            )
        } else {
            welcome(selected, desktop_version, server_nonce, challenge.as_str())
        };
        let response = match session.handoff_nonce {
            Some(handoff_nonce) => response.with_handoff_nonce(handoff_nonce),
            None => response,
        };
        write_before(
            &mut stream,
            &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
            deadline,
        )?;

        let (approval, reconnect_credential) = match reconnect {
            Some((approval, credential)) => (approval, Some(credential)),
            None => {
                let remaining = challenge_expires_at.saturating_sub(clock.now());
                let Some(ApprovalDecision::Approve(approval)) =
                    approvals.wait(&challenge, &companion_kind, &companion_version, remaining)
                else {
                    return Ok(());
                };
                (approval, None)
            }
        };
        let (capability, grant) = authorization
            .approve(&challenge, approval)
            .map_err(|error| match error {
                AuthorizationError::Randomness => AttachSessionError::Randomness,
                AuthorizationError::ChallengeExpired => AttachSessionError::Timeout,
                _ => AttachSessionError::Authorization,
            })?;
        if reconnect_credential.is_none() {
            // Reject one already-queued repeat action against the consumed challenge.
            if let Some(ApprovalDecision::Approve(approval)) = approvals.wait(
                &challenge,
                &companion_kind,
                &companion_version,
                Duration::ZERO,
            ) {
                if authorization.approve(&challenge, approval)
                    != Err(AuthorizationError::ChallengeConsumed)
                {
                    return Err(AttachSessionError::Authorization);
                }
            }
        }
        let remaining = grant.expires_at.saturating_sub(clock.now()).as_secs();
        let mut workspace_scopes = std::collections::BTreeMap::new();
        workspace_scopes.insert(grant.workspace.clone(), grant.scopes.clone());
        let client_credential = match reconnect_credential {
            Some(credential) => credential,
            None => {
                let mut credential_bytes = [0u8; 32];
                fill_random(&mut credential_bytes).map_err(|_| AttachSessionError::Randomness)?;
                let issued_credential = hex(&credential_bytes);
                match service.authorize_client(
                    &authorized_client_id,
                    authorized_client_credential.as_deref(),
                    &issued_credential,
                    &companion_kind,
                    &companion_version,
                ) {
                    Ok(credential) => credential,
                    Err(error) => {
                        write_protocol_error(&mut stream, error, authorization_deadline);
                        return Err(AttachSessionError::Authorization);
                    }
                }
            }
        };
        let response = super::authorized_with_client_credential(
            &grant.profile,
            capability.as_str(),
            remaining,
            grant.idle_timeout.as_secs(),
            workspace_scopes,
            client_credential.clone(),
        );
        let connection_event_id = super::Id::new(uuid::Uuid::new_v4().to_string())
            .map_err(|_| AttachSessionError::Randomness)?;
        let connection = session.registry.register(
            client_credential,
            capability.as_str().to_owned(),
            connection_event_id,
        );
        write_before(
            &mut stream,
            &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
            authorization_deadline,
        )?;
        let provenance = CompanionProvenance {
            profile: grant.profile.clone(),
            companion_kind: binding.companion_kind.clone(),
            companion_version,
            peer_uid: credentials.uid,
            peer_pid: credentials.pid as u32,
        };
        serve_requests(
            &mut stream,
            timeout,
            AuthorizedSession {
                binding: &binding,
                provenance: &provenance,
                workspace: &grant.workspace,
                connection: &connection,
            },
            &mut authorization,
            service,
        )?;
        Ok(())
    })();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    result
}

struct MigrationSessionInputs<'a> {
    stream: &'a mut UnixStream,
    credentials: PeerCredentials,
    desktop_version: &'a str,
    selected: u32,
    timeout: Duration,
    server_nonce: String,
}

fn run_migration_control_session<S: ThreadListService>(
    inputs: MigrationSessionInputs<'_>,
    fill_random: &mut impl FnMut(&mut [u8]) -> Result<(), ()>,
    service: &mut S,
) -> Result<(), AttachSessionError> {
    let MigrationSessionInputs {
        stream,
        credentials,
        desktop_version,
        selected,
        timeout,
        server_nonce,
    } = inputs;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(AttachSessionError::Timeout)?;
    let response = muniment_attach::reconnect_welcome(selected, desktop_version, server_nonce, "");
    write_before(
        stream,
        &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
        deadline,
    )?;
    let mut capability_bytes = [0u8; 32];
    fill_random(&mut capability_bytes).map_err(|_| AttachSessionError::Randomness)?;
    let capability = hex(&capability_bytes);
    let authorized = muniment_attach::PeerAuthorizedGrant {
        capability: capability.clone(),
        expires_at: timeout.as_secs(),
        idle_timeout_seconds: timeout.as_secs(),
    };
    write_before(
        stream,
        &encode_frame(&authorized).map_err(|_| AttachSessionError::MalformedFrame)?,
        deadline,
    )?;
    let provenance = CompanionProvenance {
        profile: String::new(),
        companion_kind: String::new(),
        companion_version: String::new(),
        peer_uid: credentials.uid,
        peer_pid: credentials.pid as u32,
    };
    let mut registries = SessionRegistries::default();
    loop {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(AttachSessionError::Timeout)?;
        let request = read_request_before(stream, deadline)?;
        let request_id = request.request_id.clone();
        if request.operation != Operation::MigrationControl || request.capability != capability {
            write_request_error(
                stream,
                Some(request_id),
                ProtocolError::unauthorized(),
                deadline,
            );
            continue;
        }
        match dispatch_request(
            request,
            "",
            provenance.clone(),
            service,
            &mut Vec::new(),
            &mut None,
            &mut registries,
        ) {
            Ok(dispatched) => {
                let response = Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body: dispatched.body,
                };
                write_before(
                    stream,
                    &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
                    deadline,
                )?;
            }
            Err(failure) => write_request_error(stream, Some(request_id), failure.error, deadline),
        }
    }
}

/// Serves requests authorized by an admitted desktop client capability.
pub fn serve_desktop_client_session<S: ThreadListService>(
    mut stream: UnixStream,
    session: &super::DesktopClientSession,
    service: &mut S,
) -> Result<(), AttachSessionError> {
    service.bind_authorized_client(&session.client_identity);
    let result = serve_desktop_client_requests(
        &mut stream,
        &session.capability,
        &session.workspace,
        session.provenance.clone(),
        service,
    );
    let _ = stream.shutdown(std::net::Shutdown::Both);
    result
}

fn serve_requests<C, G, S>(
    stream: &mut UnixStream,
    timeout: Duration,
    session: AuthorizedSession<'_>,
    authorization: &mut AuthorizationState<C, G>,
    service: &mut S,
) -> Result<(), AttachSessionError>
where
    C: AuthorizationClock,
    G: AuthorizationTokenGenerator,
    S: ThreadListService,
{
    serve_companion_requests(stream, timeout, session, authorization, service)
}

#[cfg(test)]
mod tests {
    use super::post_dispatch_deadline;
    use std::time::{Duration, Instant};

    #[test]
    fn post_dispatch_deadline_uses_each_configured_limit() {
        let now = Instant::now();

        assert_eq!(
            post_dispatch_deadline(now, Duration::from_secs(2), Duration::from_secs(9)),
            Ok(now + Duration::from_secs(2))
        );
        assert_eq!(
            post_dispatch_deadline(now, Duration::from_secs(9), Duration::from_secs(7)),
            Ok(now + Duration::from_secs(7))
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachAcceptError {
    Closed,
    Accept,
    PeerCredentials,
    WrongUid(PeerCredentials),
}

impl fmt::Display for AttachAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "attach listener is closed",
            Self::Accept => "attach connection could not be accepted",
            Self::PeerCredentials => "attach peer credentials could not be verified",
            Self::WrongUid(_) => "attach peer has the wrong owner",
        })
    }
}

impl std::error::Error for AttachAcceptError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachTransportError {
    ExistingEndpointUnsafe,
    ExistingListener,
    ExistingEndpointProbe,
    ExistingEndpointRemove,
    Bind,
    Permissions,
    EndpointMetadata,
    EndpointWrongOwner,
    EndpointWrongType,
    EndpointInsecure,
}

impl fmt::Display for AttachTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExistingEndpointUnsafe => "existing attach endpoint is unsafe",
            Self::ExistingListener => "attach endpoint is already in use",
            Self::ExistingEndpointProbe => "existing attach endpoint could not be probed",
            Self::ExistingEndpointRemove => "stale attach endpoint could not be removed safely",
            Self::Bind => "attach endpoint could not be bound",
            Self::Permissions => "attach endpoint permissions could not be applied",
            Self::EndpointMetadata => "attach endpoint could not be verified",
            Self::EndpointWrongOwner => "attach endpoint has the wrong owner",
            Self::EndpointWrongType => "attach endpoint has the wrong type",
            Self::EndpointInsecure => "attach endpoint permissions are insecure",
        })
    }
}

impl std::error::Error for AttachTransportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointIdentity {
    device: u64,
    inode: u64,
}

fn pinned_endpoint_path(filesystem: &AttachFilesystem) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        filesystem.attach_directory.as_raw_fd(),
        ENDPOINT_NAME
    ))
}

fn endpoint_metadata(filesystem: &AttachFilesystem) -> io::Result<std::fs::Metadata> {
    std::fs::symlink_metadata(pinned_endpoint_path(filesystem))
}

fn endpoint_identity(filesystem: &AttachFilesystem) -> io::Result<EndpointIdentity> {
    let metadata = endpoint_metadata(filesystem)?;
    Ok(EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn verified_endpoint(
    filesystem: &AttachFilesystem,
    uid: libc::uid_t,
) -> Result<EndpointIdentity, AttachTransportError> {
    let metadata =
        endpoint_metadata(filesystem).map_err(|_| AttachTransportError::EndpointMetadata)?;
    if metadata.file_type().is_symlink() || metadata.mode() & libc::S_IFMT != libc::S_IFSOCK {
        return Err(AttachTransportError::EndpointWrongType);
    }
    if metadata.uid() != uid {
        return Err(AttachTransportError::EndpointWrongOwner);
    }
    if metadata.mode() & 0o777 != SOCKET_MODE {
        return Err(AttachTransportError::EndpointInsecure);
    }
    Ok(EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn recover_stale_endpoint(
    filesystem: &AttachFilesystem,
    uid: libc::uid_t,
    before_remove: impl FnOnce(),
    after_quarantine: impl FnOnce(),
    quarantine_candidate: impl FnMut(&str),
) -> Result<(), AttachTransportError> {
    let pinned = match open_endpoint(filesystem) {
        Ok(endpoint) => endpoint,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(AttachTransportError::ExistingEndpointUnsafe),
    };
    let metadata = File::from(
        pinned
            .try_clone()
            .map_err(|_| AttachTransportError::ExistingEndpointUnsafe)?,
    )
    .metadata()
    .map_err(|_| AttachTransportError::ExistingEndpointUnsafe)?;
    if metadata.mode() & libc::S_IFMT != libc::S_IFSOCK || metadata.uid() != uid {
        return Err(AttachTransportError::ExistingEndpointUnsafe);
    }
    let identity = EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    match UnixStream::connect(pinned_endpoint_path(filesystem)) {
        Ok(_) => return Err(AttachTransportError::ExistingListener),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(AttachTransportError::ExistingEndpointProbe),
    }
    remove_pinned_endpoint_with_hooks(
        filesystem,
        identity,
        pinned,
        before_remove,
        after_quarantine,
        quarantine_candidate,
    )
    .map_err(|_| AttachTransportError::ExistingEndpointRemove)
}

fn open_endpoint(filesystem: &AttachFilesystem) -> io::Result<OwnedFd> {
    let name = CString::new(ENDPOINT_NAME).unwrap();
    let fd = unsafe {
        libc::openat(
            filesystem.attach_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn apply_socket_permissions(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
) -> io::Result<()> {
    let name = CString::new(ENDPOINT_NAME).unwrap();
    let fd = unsafe {
        libc::openat(
            filesystem.attach_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let endpoint = unsafe { OwnedFd::from_raw_fd(fd) };
    let metadata = File::from(endpoint.try_clone()?).metadata()?;
    if (EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }) != identity
    {
        return Err(io::Error::other("endpoint identity changed"));
    }
    std::fs::set_permissions(
        PathBuf::from(format!("/proc/self/fd/{}", endpoint.as_raw_fd())),
        std::fs::Permissions::from_mode(SOCKET_MODE),
    )
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, AttachAcceptError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(AttachAcceptError::PeerCredentials);
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn remove_if_identity(filesystem: &AttachFilesystem, identity: EndpointIdentity) {
    let _ = remove_exact_endpoint(filesystem, identity);
}

fn remove_exact_endpoint(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
) -> io::Result<()> {
    remove_exact_endpoint_with_hook(filesystem, identity, || {})
}

fn remove_exact_endpoint_with_hook(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
    before_remove: impl FnOnce(),
) -> io::Result<()> {
    remove_exact_endpoint_with_hooks(filesystem, identity, before_remove, || {})
}

fn remove_exact_endpoint_with_hooks(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
    before_remove: impl FnOnce(),
    after_quarantine: impl FnOnce(),
) -> io::Result<()> {
    let pinned = open_endpoint(filesystem)?;
    remove_pinned_endpoint_with_hooks(
        filesystem,
        identity,
        pinned,
        before_remove,
        after_quarantine,
        |_| {},
    )
}

fn remove_pinned_endpoint_with_hooks(
    filesystem: &AttachFilesystem,
    identity: EndpointIdentity,
    pinned: OwnedFd,
    before_remove: impl FnOnce(),
    after_quarantine: impl FnOnce(),
    mut quarantine_candidate: impl FnMut(&str),
) -> io::Result<()> {
    let directory = filesystem.attach_directory.as_raw_fd();
    let from = CString::new(ENDPOINT_NAME).unwrap();
    let pinned_metadata = File::from(pinned.try_clone()?).metadata()?;
    if (EndpointIdentity {
        device: pinned_metadata.dev(),
        inode: pinned_metadata.ino(),
    }) != identity
        || pinned_metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
        || pinned_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::other("endpoint identity changed"));
    }

    before_remove();
    let (quarantine, to) = loop {
        let quarantine = quarantine_name()?;
        quarantine_candidate(&quarantine);
        let to = CString::new(quarantine.clone()).unwrap();
        if unsafe {
            libc::renameat2(
                directory,
                from.as_ptr(),
                directory,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            break (quarantine, to);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
    };
    after_quarantine();
    let metadata = std::fs::symlink_metadata(PathBuf::from(format!(
        "/proc/self/fd/{directory}/{quarantine}"
    )))?;
    let moved = EndpointIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if moved == identity
        && metadata.mode() & libc::S_IFMT == libc::S_IFSOCK
        && metadata.uid() == unsafe { libc::geteuid() }
    {
        if unsafe { libc::unlinkat(directory, to.as_ptr(), 0) } == 0 {
            return Ok(());
        }
        return Err(io::Error::last_os_error());
    }
    restore_quarantined_entry(directory, &to, &from)?;
    Err(io::Error::other("endpoint identity changed"))
}

fn quarantine_name() -> io::Result<String> {
    let mut random = [0_u8; 16];
    let mut filled = 0;
    while filled < random.len() {
        let result = unsafe {
            libc::getrandom(
                random[filled..].as_mut_ptr().cast(),
                random.len() - filled,
                0,
            )
        };
        if result > 0 {
            filled += result as usize;
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    let token = u128::from_ne_bytes(random);
    Ok(format!(".attach-v1.sock.{token:032x}"))
}

fn restore_quarantined_entry(
    directory: libc::c_int,
    quarantine: &CString,
    endpoint: &CString,
) -> io::Result<()> {
    if unsafe {
        libc::renameat2(
            directory,
            quarantine.as_ptr(),
            directory,
            endpoint.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == 0
    {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EEXIST) {
        return Err(error);
    }
    if unsafe {
        libc::renameat2(
            directory,
            quarantine.as_ptr(),
            directory,
            endpoint.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn open_directory(
    parent: libc::c_int,
    path: *const libc::c_char,
    error: AttachFilesystemError,
) -> Result<OwnedFd, AttachFilesystemError> {
    let fd = unsafe {
        libc::openat(
            parent,
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(error)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn validate_directory(
    directory: &OwnedFd,
    exact_private_mode: bool,
    metadata_error: AttachFilesystemError,
    owner_error: AttachFilesystemError,
    mode_error: AttachFilesystemError,
) -> Result<(), AttachFilesystemError> {
    let metadata = File::from(directory.try_clone().map_err(|_| metadata_error)?)
        .metadata()
        .map_err(|_| metadata_error)?;
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(owner_error);
    }
    let mode = metadata.mode() & 0o777;
    if (exact_private_mode && mode != PRIVATE_MODE) || (!exact_private_mode && mode & 0o077 != 0) {
        return Err(mode_error);
    }
    Ok(())
}

/// Fail-closed reasons for rejecting the Linux attach filesystem boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachFilesystemError {
    RuntimeDirectoryMissing,
    RuntimeDirectoryNotAbsolute,
    RuntimeDirectoryInvalid,
    RuntimeDirectoryOpen,
    RuntimeDirectoryMetadata,
    RuntimeDirectoryWrongOwner,
    RuntimeDirectoryInsecure,
    AttachDirectoryCreate,
    AttachDirectoryOpen,
    AttachDirectoryMetadata,
    AttachDirectoryWrongOwner,
    AttachDirectoryInsecure,
    AttachDirectoryPermissions,
}

impl fmt::Display for AttachFilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RuntimeDirectoryMissing => "runtime directory is not configured",
            Self::RuntimeDirectoryNotAbsolute => "runtime directory is not absolute",
            Self::RuntimeDirectoryInvalid => "runtime directory value is invalid",
            Self::RuntimeDirectoryOpen => "runtime directory could not be opened safely",
            Self::RuntimeDirectoryMetadata => "runtime directory could not be verified",
            Self::RuntimeDirectoryWrongOwner => "runtime directory has the wrong owner",
            Self::RuntimeDirectoryInsecure => "runtime directory permissions are insecure",
            Self::AttachDirectoryCreate => "attach directory could not be created",
            Self::AttachDirectoryOpen => "attach directory could not be opened safely",
            Self::AttachDirectoryMetadata => "attach directory could not be verified",
            Self::AttachDirectoryWrongOwner => "attach directory has the wrong owner",
            Self::AttachDirectoryInsecure => "attach directory permissions are insecure",
            Self::AttachDirectoryPermissions => "attach directory permissions could not be applied",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AttachFilesystemError {}
