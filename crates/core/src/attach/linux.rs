//! Linux filesystem boundary for the companion attach endpoint.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::env;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{
    encode_frame, welcome, Approval, AuthorizationClock, AuthorizationError, AuthorizationState,
    AuthorizationTokenGenerator, ConnectionBinding, Envelope, ErrorEnvelope, Event, EventName,
    Failure, FirstMessage, NegotiationError, Operation, Protocol, ProtocolError, Request, Response,
    Success, VersionRange, WorkspaceOnboardRequest, WorkspaceOnboarded, CHALLENGE_LIFETIME,
    MAX_FRAME_LENGTH, MAX_TEXT_LENGTH,
};
use super::{
    RunEventAdmission, RunStreamCursor, MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS,
    MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
};
use crate::browser_control::LinuxProcReader;
use crate::journal::{
    thread_summaries::ThreadSummaryListError, RunEventPageError, RunJournal, MAX_THREAD_TITLE_CHARS,
};

const ATTACH_DIRECTORY: &[u8] = b"muniment\0";
const ENDPOINT_NAME: &str = "attach-v1.sock";
const INSTANCE_LOCK_NAME: &[u8] = b"instance.lock\0";
const PRIVATE_MODE: libc::mode_t = 0o700;
const PRIVATE_FILE_MODE: libc::mode_t = 0o600;
const SOCKET_MODE: libc::mode_t = 0o600;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const DESKTOP_PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };
const MAX_THREAD_ID_LENGTH: usize = 36;
const MAX_CURSOR_LENGTH: usize = 1024;
const MAX_RESPONSE_BODY_LENGTH: usize = MAX_FRAME_LENGTH - 4096;
const MAX_HANDOFF_NONCE_BYTES: usize = 128;
const MAX_HANDOFF_DEADLINE_MS: u64 = 60_000;
pub const MAX_RUN_START_TEXT_LENGTH: usize = 32 * 1024;
pub const MAX_RUN_START_CONTEXT_LENGTH: usize = 64 * 1024;
pub const MAX_PERMISSION_GATE_ID_LENGTH: usize = 256;

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

/// This wait handles `SIGTERM` and `SIGINT` synchronously.
pub struct TerminationSignalWait {
    signals: libc::sigset_t,
}

impl TerminationSignalWait {
    /// Creates a wait and blocks both signals on this thread.
    pub fn new() -> io::Result<Self> {
        let mut signals = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut signals) } != 0
            || unsafe { libc::sigaddset(&mut signals, libc::SIGTERM) } != 0
            || unsafe { libc::sigaddset(&mut signals, libc::SIGINT) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mask_result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) };
        if mask_result != 0 {
            return Err(io::Error::from_raw_os_error(mask_result));
        }

        Ok(Self { signals })
    }

    /// Blocks until this thread receives either signal.
    pub fn wait(self) -> io::Result<()> {
        let mut signal = 0;
        let wait_result = unsafe { libc::sigwait(&self.signals, &mut signal) };
        if wait_result != 0 {
            return Err(io::Error::from_raw_os_error(wait_result));
        }
        Ok(())
    }
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

/// Closed outcomes from the bounded, pre-authorization attach exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachSessionError {
    Closed,
    Timeout,
    MalformedFrame,
    PayloadTooLarge,
    ProtocolIncompatible,
    Randomness,
    Authorization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveConnectionState {
    Active,
    Blocked,
    Revoked,
}

struct LiveConnection {
    capability: String,
    connection_event_id: super::Id,
    state: Mutex<LiveConnectionState>,
}

struct CredentialConnections {
    gate: Arc<Mutex<()>>,
    state: LiveConnectionState,
    connections: HashMap<super::Id, Arc<LiveConnection>>,
}

impl Default for CredentialConnections {
    fn default() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
            state: LiveConnectionState::Active,
            connections: HashMap::new(),
        }
    }
}

type ConnectionsByCredential = HashMap<String, CredentialConnections>;

/// Tracks authorized attach connections by the client credential that authenticated them.
#[derive(Clone, Default)]
pub struct LiveConnectionRegistry {
    connections: Arc<Mutex<ConnectionsByCredential>>,
}

impl LiveConnectionRegistry {
    /// Stops request admission for every live connection authenticated by `credential`.
    pub fn block(&self, credential: &str) -> usize {
        self.set_state(credential, |state| {
            if *state == LiveConnectionState::Active {
                *state = LiveConnectionState::Blocked;
            }
        })
    }

    /// Restarts request admission for every blocked connection authenticated by `credential`.
    pub fn resume(&self, credential: &str) -> usize {
        self.set_state(credential, |state| {
            if *state == LiveConnectionState::Blocked {
                *state = LiveConnectionState::Active;
            }
        })
    }

    /// Revokes every live connection authenticated by `credential`.
    pub fn revoke(&self, credential: &str) -> usize {
        self.set_state(credential, |state| *state = LiveConnectionState::Revoked)
    }

    fn set_state(&self, credential: &str, update: impl Fn(&mut LiveConnectionState)) -> usize {
        let mut connections = self.connections.lock().expect("live connection registry");
        let entries = connections.entry(credential.to_owned()).or_default();
        let gate = Arc::clone(&entries.gate);
        let _gate = gate.lock().expect("credential admission gate");
        update(&mut entries.state);
        for connection in entries.connections.values() {
            let mut state = connection.state.lock().expect("live connection state");
            *state = entries.state;
        }
        entries.connections.len()
    }

    fn register(
        &self,
        credential: String,
        capability: String,
        connection_event_id: super::Id,
    ) -> RegisteredConnection {
        let mut connections = self.connections.lock().expect("live connection registry");
        let entries = connections.entry(credential.clone()).or_default();
        let gate = Arc::clone(&entries.gate);
        let _gate = gate.lock().expect("credential admission gate");
        let connection = Arc::new(LiveConnection {
            capability,
            connection_event_id: connection_event_id.clone(),
            state: Mutex::new(entries.state),
        });
        entries
            .connections
            .insert(connection_event_id.clone(), Arc::clone(&connection));
        drop(_gate);
        RegisteredConnection {
            registry: self.clone(),
            credential,
            connection_event_id,
            connection,
            gate,
        }
    }
}

struct RegisteredConnection {
    registry: LiveConnectionRegistry,
    credential: String,
    connection_event_id: super::Id,
    connection: Arc<LiveConnection>,
    gate: Arc<Mutex<()>>,
}

struct AuthorizedSession<'a> {
    binding: &'a ConnectionBinding,
    provenance: &'a CompanionProvenance,
    workspace: &'a str,
    connection: &'a RegisteredConnection,
}

impl Drop for RegisteredConnection {
    fn drop(&mut self) {
        let mut connections = self
            .registry
            .connections
            .lock()
            .expect("live connection registry");
        if let Some(entries) = connections.get_mut(&self.credential) {
            entries.connections.remove(&self.connection_event_id);
        }
    }
}

impl fmt::Display for AttachSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "attach stream closed",
            Self::Timeout => "attach hello timed out",
            Self::MalformedFrame => "attach frame is malformed",
            Self::PayloadTooLarge => "attach payload exceeds the allowed size",
            Self::ProtocolIncompatible => "attach protocol is incompatible",
            Self::Randomness => "attach session randomness is unavailable",
            Self::Authorization => "attach authorization failed",
        })
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadListRequest {
    pub limit: u8,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedactedThreadSummary {
    pub thread_id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreadListPage {
    pub threads: Vec<RedactedThreadSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadOpenRequest {
    pub thread_id: String,
    pub limit: u8,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedactedThreadEntry {
    pub run_seq: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreadOpenPage {
    pub thread_id: String,
    pub entries: Vec<RedactedThreadEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunStartRequest {
    pub text: String,
    pub context: Option<serde_json::Value>,
    pub thread_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompanionProvenance {
    pub profile: String,
    pub companion_kind: String,
    pub companion_version: String,
    pub peer_uid: u32,
    pub peer_pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RunStartAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadCreateAccepted {
    pub thread_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationControlRequest {
    pub handoff_nonce: String,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunCancelRequest {
    pub run_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RunCancelAccepted {
    pub run_id: String,
    pub accepted_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionAnswerRequest {
    pub run_id: String,
    pub gate_id: String,
    pub decision: PermissionDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct PermissionAnswerAccepted {
    pub run_id: String,
    pub gate_id: String,
    pub decision: PermissionDecision,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunStreamPage {
    pub run_id: String,
    pub first_available_run_seq: u64,
    pub current_run_seq: u64,
    pub events: Vec<crate::journal::RunEventProjection>,
    pub exhausted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementSnapshotResult {
    pub snapshot: crate::auth::EntitlementSnapshotView,
    pub changed_snapshot_version: Option<u64>,
}

/// Deterministic desktop service seam for authorized attach requests.
pub trait ThreadListService {
    fn bind_authorized_client(&mut self, _client_identity: &str) {}

    fn reconnect_approval(&self) -> Option<Approval> {
        None
    }

    fn authorize_client(
        &mut self,
        client_identity: &str,
        _presented_credential: Option<&str>,
        issued_credential: &str,
        _claimed_kind: &str,
        _claimed_version: &str,
    ) -> Result<String, ProtocolError> {
        self.bind_authorized_client(client_identity);
        Ok(issued_credential.to_owned())
    }

    fn onboard_workspace(
        &mut self,
        _workspace: &str,
        _request: WorkspaceOnboardRequest,
    ) -> Result<WorkspaceOnboarded, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn ensure_home(&mut self) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn session_status(&mut self) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn entitlement_snapshot(&mut self) -> Result<EntitlementSnapshotResult, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn list_devices(&mut self) -> Result<crate::auth::NativeDeviceList, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn list_companions(&mut self) -> Result<Vec<super::CompanionRecord>, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn revoke_companion(
        &mut self,
        _client_identity: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn sign_out(
        &mut self,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn control_migration(
        &mut self,
        _request: MigrationControlRequest,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn authorized_workspace(&self, _session_workspace: &str, _workspace: &str) -> Option<String> {
        None
    }

    fn list_threads(
        &mut self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError>;

    fn open_thread(
        &mut self,
        _workspace: &str,
        _request: ThreadOpenRequest,
    ) -> Result<ThreadOpenPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn create_thread(
        &mut self,
        _workspace: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<ThreadCreateAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn rename_thread(
        &mut self,
        _workspace: &str,
        _thread_id: &super::Id,
        _title: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn delete_thread(
        &mut self,
        _workspace: &str,
        _thread_id: &super::Id,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn start_run(
        &mut self,
        _workspace: &str,
        _execution_root: &str,
        _request: RunStartRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunStartAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn answer_permission(
        &mut self,
        _workspace: &str,
        _request: PermissionAnswerRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<PermissionAnswerAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn cancel_run(
        &mut self,
        _workspace: &str,
        _request: RunCancelRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunCancelAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn stream_run(
        &mut self,
        _workspace: &str,
        _run_id: &str,
        _after_run_seq: u64,
    ) -> Result<RunStreamPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn subscribe_run_commits(
        &mut self,
        _run_id: &str,
    ) -> Result<Option<crate::journal::CommitSubscription>, ProtocolError> {
        Ok(None)
    }
}

impl<F> ThreadListService for F
where
    F: FnMut(&str, ThreadListRequest) -> Result<ThreadListPage, ProtocolError>,
{
    fn list_threads(
        &mut self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        self(workspace, request)
    }
}

impl ThreadListService for RunJournal {
    fn subscribe_run_commits(
        &mut self,
        run_id: &str,
    ) -> Result<Option<crate::journal::CommitSubscription>, ProtocolError> {
        if self.path.is_none() {
            return Ok(None);
        }
        self.subscribe_commits(run_id)
            .map(Some)
            .map_err(|_| ProtocolError::persistence_failed())
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<RunStreamPage, ProtocolError> {
        let mut page = self
            .workspace_catch_up(
                workspace,
                run_id,
                after_run_seq,
                MAX_RUN_STREAM_WINDOW_EVENTS,
                MAX_RUN_STREAM_WINDOW_BYTES,
            )
            .map_err(|error| match error {
                RunEventPageError::InvalidCursor => ProtocolError::invalid_cursor(),
                RunEventPageError::NotFoundOrInaccessible => ProtocolError::invalid_request(),
                RunEventPageError::InvalidLimit => ProtocolError::invalid_request(),
                RunEventPageError::Journal(_) => ProtocolError::persistence_failed(),
            })?;
        let projected = self
            .projected_run_stream_text(workspace, run_id, page.current_run_seq)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let projected_len = page
            .events
            .iter()
            .take_while(|event| projected.contains_key(&event.run_seq))
            .count();
        if projected_len != page.events.len() {
            page.events.truncate(projected_len);
            page.exhausted = false;
        }
        for event in &mut page.events {
            if event.event_type == "model.stream.delta" {
                event.text = match projected.get(&event.run_seq) {
                    Some(crate::assistant_text::stream::AssistantText::Released(text)) => {
                        Some(text.clone())
                    }
                    _ => None,
                };
            }
        }
        Ok(RunStreamPage {
            run_id: run_id.to_owned(),
            first_available_run_seq: page.first_available_run_seq,
            current_run_seq: page.current_run_seq,
            events: page.events,
            exhausted: page.exhausted,
        })
    }

    fn list_threads(
        &mut self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        let page = self
            .workspace_thread_summaries(
                workspace,
                usize::from(request.limit),
                request.cursor.as_deref(),
            )
            .map_err(|error| match error {
                ThreadSummaryListError::InvalidLimit { .. } => ProtocolError::invalid_request(),
                ThreadSummaryListError::InvalidCursor => ProtocolError::invalid_cursor(),
                ThreadSummaryListError::Journal(_) => ProtocolError::persistence_failed(),
            })?;
        Ok(ThreadListPage {
            threads: page
                .summaries
                .into_iter()
                .map(|summary| RedactedThreadSummary {
                    thread_id: summary.thread_id,
                    title: summary.title,
                    updated_at: summary.updated_at,
                })
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    fn open_thread(
        &mut self,
        workspace: &str,
        request: ThreadOpenRequest,
    ) -> Result<ThreadOpenPage, ProtocolError> {
        let mut boundary = self
            .ledger_thread_projection_boundary(
                workspace,
                &request.thread_id,
                request.cursor.as_deref(),
            )
            .map_err(|error| match error {
                RunEventPageError::InvalidLimit => ProtocolError::invalid_request(),
                RunEventPageError::InvalidCursor => ProtocolError::invalid_cursor(),
                RunEventPageError::NotFoundOrInaccessible => ProtocolError::invalid_request(),
                RunEventPageError::Journal(_) => ProtocolError::persistence_failed(),
            })?;
        let projected = self
            .ledger_thread_projection_entries(
                workspace,
                &request.thread_id,
                &boundary,
                usize::from(request.limit) + 1,
            )
            .map_err(|error| match error {
                RunEventPageError::InvalidCursor => ProtocolError::invalid_cursor(),
                RunEventPageError::NotFoundOrInaccessible => ProtocolError::invalid_request(),
                _ => ProtocolError::persistence_failed(),
            })?;
        let mut assistant_text = BTreeMap::new();
        for entry in &projected {
            if entry.kind == "assistant_message"
                && !assistant_text.contains_key(&(entry.run_id.clone(), entry.snapshot_seq))
            {
                let ordinals = projected
                    .iter()
                    .filter(|candidate| {
                        candidate.kind == "assistant_message"
                            && candidate.run_id == entry.run_id
                            && candidate.snapshot_seq == entry.snapshot_seq
                    })
                    .map(|candidate| candidate.entry_ordinal)
                    .collect::<Vec<_>>();
                let projection = self
                    .projected_assistant_text(
                        workspace,
                        &entry.run_id,
                        entry.snapshot_seq,
                        &ordinals,
                    )
                    .map_err(|_| ProtocolError::persistence_failed())?;
                assistant_text.insert((entry.run_id.clone(), entry.snapshot_seq), projection);
            }
        }
        let mut expanded = projected
            .into_iter()
            .map(|entry| {
                let text = if entry.kind == "assistant_message" {
                    assistant_text
                        .get(&(entry.run_id.clone(), entry.snapshot_seq))
                        .and_then(|projection| projection.get(&entry.entry_ordinal))
                        .cloned()
                        .flatten()
                } else {
                    entry.text
                };
                (
                    (entry.run_ordinal, entry.run_seq, entry.entry_ordinal),
                    RedactedThreadEntry {
                        run_seq: entry.run_seq,
                        kind: entry.kind,
                        text,
                    },
                )
            })
            .collect::<Vec<_>>();
        if request.cursor.is_some() && expanded.is_empty() {
            return Err(ProtocolError::invalid_cursor());
        }
        let has_more = expanded.len() > usize::from(request.limit);
        expanded.truncate(usize::from(request.limit));
        let mut entries = Vec::new();
        let mut emitted_position = None;
        let mut page_length = serde_json::to_vec(&ThreadOpenPage {
            thread_id: request.thread_id.clone(),
            entries: Vec::new(),
            next_cursor: Some("x".repeat(MAX_CURSOR_LENGTH)),
        })
        .map_err(|_| ProtocolError::persistence_failed())?
        .len();
        for (position, entry) in expanded.iter() {
            let entry_length = serde_json::to_vec(entry)
                .map_err(|_| ProtocolError::persistence_failed())?
                .len();
            let separator_length = usize::from(!entries.is_empty());
            if page_length + separator_length + entry_length > MAX_RESPONSE_BODY_LENGTH {
                break;
            }
            page_length += separator_length + entry_length;
            entries.push(entry.clone());
            emitted_position = Some(*position);
        }
        let next_cursor = if has_more || entries.len() < expanded.len() {
            let (run_ordinal, run_seq, entry_ordinal) =
                emitted_position.ok_or_else(ProtocolError::persistence_failed)?;
            boundary.last_run_ordinal = run_ordinal;
            boundary.last_run_seq = run_seq;
            boundary.last_entry_ordinal = entry_ordinal;
            Some(
                self.ledger_thread_projection_cursor(&request.thread_id, workspace, &boundary)
                    .map_err(|_| ProtocolError::persistence_failed())?,
            )
        } else {
            None
        };
        Ok(ThreadOpenPage {
            thread_id: request.thread_id,
            entries,
            next_cursor,
        })
    }
}

impl std::error::Error for AttachSessionError {}

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
    let authorized = muniment_attach::MigrationControlAuthorized {
        profile_id: String::new(),
        capability: capability.clone(),
        expires_at: timeout.as_secs(),
        idle_timeout_seconds: timeout.as_secs(),
        workspace_scopes: BTreeMap::new(),
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
        match dispatch_request(request, "", provenance.clone(), service, &mut Vec::new()) {
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
    let result = serve_desktop_client_requests(&mut stream, session, service);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    result
}

fn serve_desktop_client_requests<S: ThreadListService>(
    stream: &mut UnixStream,
    session: &super::DesktopClientSession,
    service: &mut S,
) -> Result<(), AttachSessionError> {
    let mut subscriptions = Vec::new();
    loop {
        let live_events = match poll_run_streams(service, &mut subscriptions) {
            Ok(events) => events,
            Err(error) => {
                write_protocol_error(stream, error, Instant::now() + HELLO_TIMEOUT);
                return Err(AttachSessionError::Closed);
            }
        };
        for event in live_events {
            let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
            write_before(stream, &frame, Instant::now() + HELLO_TIMEOUT)?;
        }

        match wait_until_readable(stream, Instant::now() + Duration::from_millis(50)) {
            Ok(()) => {}
            Err(AttachSessionError::Closed) => return Ok(()),
            Err(AttachSessionError::Timeout) => continue,
            Err(error) => return Err(error),
        }
        let deadline = Instant::now() + HELLO_TIMEOUT;
        let request = match read_request_before(stream, deadline) {
            Ok(request) => request,
            Err(AttachSessionError::Closed) => return Ok(()),
            Err(error) => return Err(error),
        };
        let request_id = request.request_id.clone();
        if request.capability != session.capability
            || matches!(
                request.operation,
                Operation::MigrationControl | Operation::ApprovalPresent
            )
        {
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
            &session.workspace,
            session.provenance.clone(),
            service,
            &mut subscriptions,
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
                for event in dispatched.events {
                    write_before(
                        stream,
                        &encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?,
                        deadline,
                    )?;
                }
            }
            Err(failure) => {
                write_request_error(stream, Some(request_id), failure.error, deadline);
                for event in failure.events {
                    write_before(
                        stream,
                        &encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?,
                        deadline,
                    )?;
                }
            }
        }
    }
}

fn read_request_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Request, AttachSessionError> {
    let mut prefix = [0u8; 4];
    read_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
        return Err(AttachSessionError::PayloadTooLarge);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    read_before(stream, &mut frame[4..], deadline)?;
    match super::decode_frame::<Envelope>(&frame) {
        Ok(Some((Envelope::Request(request), consumed))) if consumed == frame.len() => Ok(request),
        _ => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            Err(AttachSessionError::MalformedFrame)
        }
    }
}

fn read_before(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), AttachSessionError> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(AttachSessionError::Timeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| AttachSessionError::Closed)?;
        match stream.read(bytes) {
            Ok(0) => return Err(AttachSessionError::Closed),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(AttachSessionError::Timeout)
            }
            Err(_) => return Err(AttachSessionError::Closed),
        }
    }
    Ok(())
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
    let mut subscriptions = Vec::new();
    loop {
        let gate = session
            .connection
            .gate
            .lock()
            .expect("credential admission gate");
        let state = session
            .connection
            .connection
            .state
            .lock()
            .expect("live connection state");
        match *state {
            LiveConnectionState::Blocked => {
                drop(state);
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            LiveConnectionState::Revoked => {
                send_revocation(stream, timeout, session.connection)?;
                return Ok(());
            }
            LiveConnectionState::Active => {}
        }
        // Give an already-buffered request a chance to supply its correlation ID even when
        // the grant has just expired. Validation below still prevents stale dispatch.
        let (authorization_expired, idle_remaining) = match authorization.remaining_lifetime() {
            Ok(remaining) => (false, remaining.max(Duration::from_millis(1))),
            Err(_) => (true, Duration::from_millis(1)),
        };
        let idle_deadline = Instant::now()
            .checked_add(idle_remaining)
            .ok_or(AttachSessionError::Timeout)?;
        let live_events = if authorization_expired {
            Vec::new()
        } else {
            match poll_run_streams(service, &mut subscriptions) {
                Ok(events) => events,
                Err(error) => {
                    write_protocol_error(stream, error, Instant::now() + timeout);
                    return Err(AttachSessionError::Closed);
                }
            }
        };
        for event in live_events {
            let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
            write_before(
                stream,
                &frame,
                (Instant::now() + timeout).min(idle_deadline),
            )?;
        }
        drop(state);
        drop(gate);
        let poll_deadline = (Instant::now() + Duration::from_millis(50)).min(idle_deadline);
        let mut prefix = [0; 4];
        match wait_until_readable(stream, poll_deadline) {
            Ok(()) => {}
            Err(AttachSessionError::Closed) => return Ok(()),
            Err(AttachSessionError::Timeout) => {
                if Instant::now() < idle_deadline {
                    continue;
                }
                let deadline = Instant::now() + timeout;
                write_protocol_error(stream, ProtocolError::unauthorized(), deadline);
                return Err(AttachSessionError::Authorization);
            }
            Err(error) => return Err(error),
        }
        match read_before(stream, &mut prefix, idle_deadline) {
            Ok(()) => {}
            Err(AttachSessionError::Closed) => return Ok(()),
            Err(error) => return Err(error),
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(AttachSessionError::Timeout)?
            .min(idle_deadline);
        let frame = match read_frame_after_prefix(stream, prefix, deadline) {
            Ok(frame) => frame,
            Err(error @ AttachSessionError::PayloadTooLarge) => {
                write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
                return Err(error);
            }
            Err(error @ AttachSessionError::Timeout) => return Err(error),
            Err(error @ AttachSessionError::Closed) => return Err(error),
            Err(error) => {
                write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
                return Err(error);
            }
        };
        let request = match super::decode_frame::<Envelope>(&frame) {
            Ok(Some((Envelope::Request(request), consumed))) if consumed == frame.len() => request,
            _ => {
                write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
                return Err(AttachSessionError::MalformedFrame);
            }
        };
        let (admission_gate, admission) = loop {
            let gate = session
                .connection
                .gate
                .lock()
                .expect("credential admission gate");
            let state = session
                .connection
                .connection
                .state
                .lock()
                .expect("live connection state");
            match *state {
                LiveConnectionState::Active => break (gate, state),
                LiveConnectionState::Blocked => {
                    drop(state);
                    drop(gate);
                    std::thread::sleep(Duration::from_millis(50));
                }
                LiveConnectionState::Revoked => {
                    drop(state);
                    drop(gate);
                    send_revocation(stream, timeout, session.connection)?;
                    return Ok(());
                }
            }
        };
        if authorization_expired {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::unauthorized(),
                Instant::now() + timeout,
            );
            return Err(AttachSessionError::Authorization);
        }
        if matches!(
            request.operation,
            Operation::ThreadRename
                | Operation::ThreadDelete
                | Operation::SessionStatus
                | Operation::EntitlementSnapshot
                | Operation::DeviceList
                | Operation::SessionSignOut
                | Operation::CompanionList
                | Operation::CompanionRevoke
        ) {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::unauthorized(),
                deadline,
            );
            return Err(AttachSessionError::Authorization);
        }
        let required_scope = match request.operation {
            Operation::WorkspaceOnboard | Operation::HomeEnsure => None,
            Operation::ThreadList
            | Operation::ThreadOpen
            | Operation::RunStream
            | Operation::RunCursorAck => Some("thread.read"),
            Operation::ThreadCreate
            | Operation::RunStart
            | Operation::RunCancel
            | Operation::PermissionAnswer => Some("run.write"),
            _ => None,
        };
        if authorization
            .validate_request_with_scope(
                &request.capability,
                session.binding,
                &session.provenance.profile,
                session.workspace,
                required_scope,
            )
            .is_err()
        {
            write_request_error(
                stream,
                Some(request.request_id),
                ProtocolError::unauthorized(),
                deadline,
            );
            return Err(AttachSessionError::Authorization);
        }
        let request_id = request.request_id.clone();
        match dispatch_request(
            request,
            session.workspace,
            session.provenance.clone(),
            service,
            &mut subscriptions,
        ) {
            Ok(dispatched) => {
                let response = Response {
                    protocol: Protocol,
                    request_id,
                    ok: Success,
                    body: dispatched.body,
                };
                let frame =
                    encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?;
                write_before(stream, &frame, deadline)?;
                for event in dispatched.events {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    write_before(stream, &frame, deadline)?;
                }
            }
            Err(failure) => {
                write_request_error(stream, Some(request_id), failure.error, deadline);
                for event in failure.events {
                    let frame =
                        encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
                    write_before(stream, &frame, deadline)?;
                }
            }
        }
        drop(admission);
        drop(admission_gate);
    }
}

fn send_revocation(
    stream: &mut UnixStream,
    timeout: Duration,
    connection: &RegisteredConnection,
) -> Result<(), AttachSessionError> {
    let event = Event {
        protocol: Protocol,
        subscription_id: connection.connection.connection_event_id.clone(),
        event: EventName::CapabilityRevoked,
        run_id: None,
        run_seq: None,
        body: serde_json::json!({
            "capability": &connection.connection.capability,
            "reason": "companion_revoked",
        }),
    };
    let frame = encode_frame(&event).map_err(|_| AttachSessionError::MalformedFrame)?;
    write_before(stream, &frame, Instant::now() + timeout)?;
    stream.flush().map_err(|_| AttachSessionError::Closed)
}

fn wait_until_readable(stream: &UnixStream, deadline: Instant) -> Result<(), AttachSessionError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(AttachSessionError::Timeout)?;
    let millis = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
    if result == 0 {
        return Err(AttachSessionError::Timeout);
    }
    if result < 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            Err(AttachSessionError::Timeout)
        } else {
            Err(AttachSessionError::Closed)
        };
    }
    if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
        && descriptor.revents & libc::POLLIN == 0
    {
        return Err(AttachSessionError::Closed);
    }
    Ok(())
}

struct DispatchResult {
    body: serde_json::Value,
    events: Vec<Event>,
}

struct DispatchFailure {
    error: ProtocolError,
    events: Vec<Event>,
}

impl From<ProtocolError> for DispatchFailure {
    fn from(error: ProtocolError) -> Self {
        Self {
            error,
            events: Vec::new(),
        }
    }
}

const MAX_ACTIVE_RUN_STREAMS: usize = 64;

struct ActiveRunStream {
    cursor: RunStreamCursor,
    pending: VecDeque<Event>,
    workspace: String,
    snapshot_run_seq: u64,
    fetched_through_run_seq: u64,
    exhausted: bool,
    caught_up: bool,
    commit_hints: Option<crate::journal::CommitSubscription>,
}

fn poll_run_streams<S: ThreadListService>(
    service: &mut S,
    subscriptions: &mut [ActiveRunStream],
) -> Result<Vec<Event>, ProtocolError> {
    let mut events = Vec::new();
    for stream in subscriptions {
        let window = stream.cursor.window();
        if !stream.pending.is_empty()
            || stream.cursor.outstanding_events() == window.max_events
            || stream.cursor.outstanding_bytes() == window.max_bytes
            || stream.cursor.outstanding_text_bytes() == window.max_text_bytes
        {
            continue;
        }
        let mut wake = false;
        if let Some(receiver) = stream.commit_hints.as_ref() {
            loop {
                match receiver.try_recv() {
                    Ok(hint) => {
                        if hint.run_id == stream.cursor.run_id().as_str() {
                            wake = true;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        stream.commit_hints = None;
                        break;
                    }
                }
            }
        }
        if !wake {
            continue;
        }
        let page = service.stream_run(
            &stream.workspace,
            stream.cursor.run_id().as_str(),
            stream.fetched_through_run_seq,
        )?;
        stream.snapshot_run_seq = page.current_run_seq;
        append_run_stream_page(stream, page)?;
        events.extend(drain_run_stream(stream)?);
    }
    Ok(events)
}

fn append_run_stream_page(
    stream: &mut ActiveRunStream,
    page: RunStreamPage,
) -> Result<(), ProtocolError> {
    let expected = stream.fetched_through_run_seq.saturating_add(1);
    if page.run_id != stream.cursor.run_id().as_str()
        || page.first_available_run_seq != stream.cursor.first_available_run_seq()
        || page.current_run_seq < stream.snapshot_run_seq
        || page.events.iter().enumerate().any(|(index, event)| {
            event.run_id != page.run_id || event.run_seq != expected.saturating_add(index as u64)
        })
    {
        return Err(ProtocolError::persistence_failed());
    }
    for journal_event in page.events {
        if journal_event.run_seq > stream.snapshot_run_seq {
            break;
        }
        let (event_name, body) = if journal_event.event_type == "permission.requested" {
            let projection = journal_event
                .pending_permission
                .as_ref()
                .filter(|projection| projection.valid)
                .ok_or_else(ProtocolError::persistence_failed)?;
            if projection.gate_id.trim().is_empty()
                || projection.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH
                || projection.kind != "confirm"
                || projection.title.trim().is_empty()
                || projection.title.len() > 1_024
                || projection
                    .message
                    .as_ref()
                    .is_some_and(|message| message.len() > 4_096)
            {
                return Err(ProtocolError::persistence_failed());
            }
            let mut body = serde_json::json!({
                "gate_id": projection.gate_id,
                "kind": projection.kind,
                "title": projection.title,
            });
            if let Some(message) = &projection.message {
                body["message"] = serde_json::json!(message);
            }
            (EventName::PermissionPending, body)
        } else {
            let mut payload = serde_json::json!({ "withheld": true });
            match journal_event.event_type.as_str() {
                "model.stream.delta" => {
                    if let Some(text) = &journal_event.text {
                        payload = serde_json::json!({ "text": text });
                    }
                }
                "tool.effect.started" | "tool.effect.completed" | "tool.effect.failed" => {
                    let effect_id = journal_event
                        .effect_id
                        .as_ref()
                        .filter(|effect_id| !effect_id.is_empty() && effect_id.len() <= 65_536)
                        .filter(|_| journal_event.tool_effect_valid)
                        .ok_or_else(ProtocolError::persistence_failed)?;
                    if journal_event
                        .display_name
                        .as_ref()
                        .is_some_and(|display_name| display_name.len() > 65_536)
                        || (journal_event.event_type != "tool.effect.started"
                            && journal_event.display_name.is_some())
                    {
                        return Err(ProtocolError::persistence_failed());
                    }
                    payload = serde_json::json!({ "effect_id": effect_id });
                    if let Some(display_name) = &journal_event.display_name {
                        payload["display_name"] = serde_json::json!(display_name);
                    }
                }
                _ => {}
            }
            if let Some(receipt) = &journal_event.receipt {
                payload["receipt"] = serde_json::to_value(receipt)
                    .map_err(|_| ProtocolError::persistence_failed())?;
            }
            (
                EventName::RunEvent,
                serde_json::json!({
                    "event_type": journal_event.event_type,
                    "event_version": journal_event.event_version,
                    "recorded_at": journal_event.recorded_at,
                    "payload": payload
                }),
            )
        };
        let event = Event {
            protocol: Protocol,
            subscription_id: stream.cursor.subscription_id().clone(),
            event: event_name,
            run_id: Some(stream.cursor.run_id().clone()),
            run_seq: Some(journal_event.run_seq),
            body,
        };
        if encode_frame(&event)
            .map_err(|_| ProtocolError::persistence_failed())?
            .len()
            > MAX_RUN_STREAM_WINDOW_BYTES
        {
            return Err(ProtocolError::persistence_failed());
        }
        stream.fetched_through_run_seq = journal_event.run_seq;
        stream.pending.push_back(event);
    }
    stream.exhausted = stream.fetched_through_run_seq == stream.snapshot_run_seq;
    Ok(())
}

fn drain_run_stream(stream: &mut ActiveRunStream) -> Result<Vec<Event>, ProtocolError> {
    let mut events = Vec::new();
    while let Some(event) = stream.pending.front() {
        let run_seq = event
            .run_seq
            .ok_or_else(ProtocolError::persistence_failed)?;
        let bytes = encode_frame(event)
            .map_err(|_| ProtocolError::persistence_failed())?
            .len();
        let text_bytes = event.body["payload"]["text"].as_str().map_or(0, str::len);
        match stream
            .cursor
            .admit_event(
                event
                    .run_id
                    .as_ref()
                    .ok_or_else(ProtocolError::persistence_failed)?,
                run_seq,
                bytes,
                text_bytes,
            )
            .map_err(|_| ProtocolError::invalid_cursor())?
        {
            RunEventAdmission::Sent => {
                events.push(stream.pending.pop_front().expect("front existed"))
            }
            RunEventAdmission::Paused => break,
        }
    }
    if stream.exhausted && stream.pending.is_empty() && !stream.caught_up {
        stream.caught_up = true;
        events.push(Event {
            protocol: Protocol,
            subscription_id: stream.cursor.subscription_id().clone(),
            event: EventName::SubscriptionCaughtUp,
            run_id: Some(stream.cursor.run_id().clone()),
            run_seq: Some(stream.cursor.current_run_seq()),
            body: serde_json::json!({}),
        });
    }
    Ok(events)
}

fn response_only(body: serde_json::Value) -> DispatchResult {
    DispatchResult {
        body,
        events: Vec::new(),
    }
}

fn bounded_response(body: serde_json::Value) -> Result<DispatchResult, DispatchFailure> {
    if serde_json::to_vec(&body)
        .map_err(|_| ProtocolError::persistence_failed())?
        .len()
        > MAX_RESPONSE_BODY_LENGTH
    {
        return Err(ProtocolError::persistence_failed().into());
    }
    Ok(response_only(body))
}

fn dispatch_request<S: ThreadListService>(
    request: Request,
    workspace: &str,
    provenance: CompanionProvenance,
    service: &mut S,
    subscriptions: &mut Vec<ActiveRunStream>,
) -> Result<DispatchResult, DispatchFailure> {
    request.validate_idempotency_key()?;
    if matches!(
        request.operation,
        Operation::SessionStatus
            | Operation::EntitlementSnapshot
            | Operation::DeviceList
            | Operation::SessionSignOut
            | Operation::CompanionList
    ) {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        let body = match request.operation {
            Operation::SessionStatus => serde_json::to_value(service.session_status()?),
            Operation::EntitlementSnapshot => {
                let result = service.entitlement_snapshot()?;
                Ok(serde_json::json!({
                    "snapshot": result.snapshot,
                    "changed_snapshot_version": result.changed_snapshot_version,
                }))
            }
            Operation::DeviceList => serde_json::to_value(service.list_devices()?),
            Operation::CompanionList => {
                let companions = service.list_companions()?;
                Ok(serde_json::json!({
                    "companions": companions.into_iter().map(|companion| serde_json::json!({
                        "identity": companion.identity,
                        "claimed_kind": companion.claimed_kind,
                        "claimed_version": companion.claimed_version,
                        "approved_at": companion.approved_at,
                    })).collect::<Vec<_>>(),
                }))
            }
            Operation::SessionSignOut => {
                let idempotency_key = request
                    .idempotency_key
                    .as_ref()
                    .ok_or_else(ProtocolError::idempotency_key_required)?;
                Ok(serde_json::json!({
                    "status": service.sign_out(
                        &request.request_id,
                        idempotency_key,
                        provenance,
                    )?,
                }))
            }
            _ => unreachable!(),
        }
        .map_err(|_| ProtocolError::persistence_failed())?;
        return bounded_response(body);
    }
    if request.operation == Operation::CompanionRevoke {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            client_identity: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.client_identity.is_empty() || body.client_identity.len() > MAX_TEXT_LENGTH {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        service.revoke_companion(
            &body.client_identity,
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        return bounded_response(serde_json::json!({}));
    }
    if request.operation == Operation::WorkspaceOnboard {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            opened_directory: String,
            memory_location: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.opened_directory.is_empty()
            || body.memory_location.is_empty()
            || body.opened_directory.len() > MAX_TEXT_LENGTH
            || body.memory_location.len() > MAX_TEXT_LENGTH
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let result = service.onboard_workspace(
            workspace,
            WorkspaceOnboardRequest {
                opened_directory: body.opened_directory,
                memory_location: body.memory_location,
            },
        )?;
        if result.opened_directory.len() > MAX_TEXT_LENGTH
            || result.memory_location.len() > MAX_TEXT_LENGTH
            || result
                .instructions
                .as_ref()
                .is_some_and(|value| value.len() > MAX_TEXT_LENGTH)
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "opened_directory": result.opened_directory,
            "memory_location": result.memory_location,
            "instructions": result.instructions,
        })));
    }
    if request.operation == Operation::HomeEnsure {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        service.ensure_home()?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::MigrationControl {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            handoff_nonce: String,
            deadline_ms: u64,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.handoff_nonce.is_empty()
            || body.handoff_nonce.len() > MAX_HANDOFF_NONCE_BYTES
            || !body
                .handoff_nonce
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            || !(1..=MAX_HANDOFF_DEADLINE_MS).contains(&body.deadline_ms)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let handoff_nonce = body.handoff_nonce.clone();
        service.control_migration(
            MigrationControlRequest {
                handoff_nonce: body.handoff_nonce,
                deadline_ms: body.deadline_ms,
            },
            provenance,
        )?;
        return Ok(response_only(serde_json::json!({
            "handoff_nonce": handoff_nonce,
        })));
    }
    if request.operation == Operation::ThreadCreate {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let accepted =
            service.create_thread(workspace, &request.request_id, idempotency_key, provenance)?;
        if super::Id::new(accepted.thread_id.clone()).is_err() {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "thread_id": accepted.thread_id,
        })));
    }
    if request.operation == Operation::ThreadRename {
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
            title: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let thread_id =
            super::Id::new(body.thread_id).map_err(|_| ProtocolError::invalid_request())?;
        if body.title.is_empty() || body.title.chars().count() > MAX_THREAD_TITLE_CHARS {
            return Err(ProtocolError::invalid_request().into());
        }
        service.rename_thread(
            workspace,
            &thread_id,
            &body.title,
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::ThreadDelete {
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let thread_id =
            super::Id::new(body.thread_id).map_err(|_| ProtocolError::invalid_request())?;
        service.delete_thread(
            workspace,
            &thread_id,
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::RunCursorAck {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            subscription_id: String,
            through_run_seq: u64,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let subscription_id =
            super::Id::new(body.subscription_id).map_err(|_| ProtocolError::invalid_request())?;
        let Some(index) = subscriptions
            .iter()
            .position(|stream| stream.cursor.subscription_id() == &subscription_id)
        else {
            return Err(ProtocolError::invalid_cursor().into());
        };
        if subscriptions[index]
            .cursor
            .acknowledge(body.through_run_seq)
            .is_err()
        {
            let stream = subscriptions.remove(index);
            return Err(DispatchFailure {
                error: ProtocolError::invalid_cursor(),
                events: vec![Event {
                    protocol: Protocol,
                    subscription_id: stream.cursor.subscription_id().clone(),
                    event: EventName::StreamClosed,
                    run_id: Some(stream.cursor.run_id().clone()),
                    run_seq: Some(stream.cursor.highest_sent_run_seq()),
                    body: serde_json::json!({"code": "invalid_cursor", "resumable": true}),
                }],
            });
        }
        while subscriptions[index].pending.is_empty() && !subscriptions[index].exhausted {
            let fetched_through_run_seq = subscriptions[index].fetched_through_run_seq;
            let page = service.stream_run(
                &subscriptions[index].workspace,
                subscriptions[index].cursor.run_id().as_str(),
                subscriptions[index].fetched_through_run_seq,
            )?;
            append_run_stream_page(&mut subscriptions[index], page)?;
            if subscriptions[index].fetched_through_run_seq == fetched_through_run_seq {
                break;
            }
        }
        let events = drain_run_stream(&mut subscriptions[index])?;
        return Ok(DispatchResult {
            body: serde_json::json!({
                "subscription_id": subscription_id.as_str(),
                "through_run_seq": body.through_run_seq,
            }),
            events,
        });
    }
    if request.operation == Operation::RunStart {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            text: String,
            #[serde(default)]
            workspace: Option<String>,
            #[serde(default)]
            context: Option<serde_json::Value>,
            #[serde(default)]
            thread_id: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let context_length = body
            .context
            .as_ref()
            .map(|context| serde_json::to_vec(context).map(|bytes| bytes.len()))
            .transpose()
            .map_err(|_| ProtocolError::invalid_request())?
            .unwrap_or(0);
        if body.text.trim().is_empty()
            || body.text.len() > MAX_RUN_START_TEXT_LENGTH
            || body
                .workspace
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_TEXT_LENGTH)
            || body
                .thread_id
                .as_ref()
                .is_some_and(|value| value.len() > 36 || super::Id::new(value.clone()).is_err())
            || context_length > MAX_RUN_START_CONTEXT_LENGTH
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let execution_root = match body.workspace.as_deref() {
            Some(requested_workspace) => service
                .authorized_workspace(workspace, requested_workspace)
                .ok_or_else(ProtocolError::unauthorized)?,
            None => workspace.to_owned(),
        };
        let accepted = service.start_run(
            workspace,
            &execution_root,
            RunStartRequest {
                text: body.text,
                context: body.context,
                thread_id: body.thread_id,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if super::Id::new(accepted.run_id.clone()).is_err()
            || super::Id::new(accepted.thread_id.clone()).is_err()
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "thread_id": accepted.thread_id,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::RunCancel {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let requested_run_id = body.run_id.clone();
        let accepted = service.cancel_run(
            workspace,
            RunCancelRequest {
                run_id: body.run_id,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if accepted.run_id != requested_run_id
            || super::Id::new(accepted.run_id.clone()).is_err()
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::PermissionAnswer {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
            gate_id: String,
            decision: PermissionDecision,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        if body.gate_id.trim().is_empty() || body.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let accepted = service.answer_permission(
            workspace,
            PermissionAnswerRequest {
                run_id: body.run_id,
                gate_id: body.gate_id,
                decision: body.decision,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if super::Id::new(accepted.run_id.clone()).is_err()
            || accepted.gate_id.trim().is_empty()
            || accepted.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "gate_id": accepted.gate_id,
            "decision": accepted.decision,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::RunStream {
        if subscriptions.len() >= MAX_ACTIVE_RUN_STREAMS {
            return Err(ProtocolError::invalid_request().into());
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
            after_run_seq: u64,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let run_id =
            super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        let subscription = service.subscribe_run_commits(run_id.as_str())?;
        let page = service.stream_run(workspace, run_id.as_str(), body.after_run_seq)?;
        if let Some(subscription) = subscription.as_ref() {
            if page.current_run_seq < subscription.committed_high_water {
                return Err(ProtocolError::persistence_failed().into());
            }
        }
        if page.run_id != run_id.as_str()
            || page.first_available_run_seq == 0
            || (page.first_available_run_seq > page.current_run_seq
                && page.first_available_run_seq != page.current_run_seq.saturating_add(1))
            || (page.exhausted
                && body.after_run_seq.saturating_add(page.events.len() as u64)
                    != page.current_run_seq)
            || page.events.iter().enumerate().any(|(index, event)| {
                event.run_id != page.run_id
                    || event.run_seq != body.after_run_seq.saturating_add(index as u64 + 1)
                    || event.run_seq > page.current_run_seq
            })
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        let mut subscription_random = [0u8; 16];
        getrandom::fill(&mut subscription_random)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let subscription_id = super::Id::new(hex(&subscription_random))
            .map_err(|_| ProtocolError::persistence_failed())?;
        let cursor = RunStreamCursor::new(
            subscription_id.clone(),
            run_id.clone(),
            page.first_available_run_seq,
            page.current_run_seq,
            body.after_run_seq,
            MAX_RUN_STREAM_WINDOW_EVENTS,
            MAX_RUN_STREAM_WINDOW_BYTES,
            MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
        )
        .map_err(|_| ProtocolError::invalid_cursor())?;
        let snapshot_run_seq = page.current_run_seq;
        let first_available_run_seq = page.first_available_run_seq;
        let mut active = ActiveRunStream {
            cursor,
            pending: VecDeque::new(),
            workspace: workspace.to_owned(),
            snapshot_run_seq,
            fetched_through_run_seq: body.after_run_seq,
            exhausted: false,
            caught_up: false,
            commit_hints: subscription,
        };
        append_run_stream_page(&mut active, page)?;
        let events = drain_run_stream(&mut active)?;
        subscriptions.push(active);
        return Ok(DispatchResult {
            body: serde_json::json!({
                "subscription_id": subscription_id,
                "run_id": run_id,
                "first_available_run_seq": first_available_run_seq,
                "current_run_seq": snapshot_run_seq,
                "window": {
                    "max_events": MAX_RUN_STREAM_WINDOW_EVENTS,
                    "max_bytes": MAX_RUN_STREAM_WINDOW_BYTES,
                    "max_text_bytes": MAX_RUN_STREAM_WINDOW_TEXT_BYTES
                }
            }),
            events,
        });
    }
    if request.operation == Operation::ThreadOpen {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
            limit: u8,
            #[serde(default)]
            cursor: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.thread_id.is_empty()
            || body.thread_id.len() > MAX_THREAD_ID_LENGTH
            || body.limit == 0
            || body.limit > 100
            || body
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let limit = body.limit;
        let requested_thread_id = body.thread_id.clone();
        let page = service.open_thread(
            workspace,
            ThreadOpenRequest {
                thread_id: body.thread_id,
                limit,
                cursor: body.cursor,
            },
        )?;
        if page.entries.len() > usize::from(limit)
            || page.thread_id != requested_thread_id
            || page.thread_id.is_empty()
            || page.thread_id.len() > MAX_TEXT_LENGTH
            || page.entries.iter().any(|entry| {
                entry.run_seq == 0
                    || entry.kind.is_empty()
                    || entry.kind.len() > MAX_TEXT_LENGTH
                    || entry
                        .text
                        .as_ref()
                        .is_some_and(|text| text.len() > MAX_TEXT_LENGTH)
            })
            || page
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        let value = serde_json::to_value(page).map_err(|_| ProtocolError::persistence_failed())?;
        if serde_json::to_vec(&value)
            .map_err(|_| ProtocolError::persistence_failed())?
            .len()
            > MAX_RESPONSE_BODY_LENGTH
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(value));
    }
    if request.operation != Operation::ThreadList {
        return Err(ProtocolError::unsupported_operation().into());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        limit: u8,
        #[serde(default)]
        cursor: Option<String>,
    }
    let body: Body =
        serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
    if body.limit == 0
        || body.limit > 100
        || body
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
    {
        return Err(ProtocolError::invalid_request().into());
    }
    let limit = body.limit;
    let page = service.list_threads(
        workspace,
        ThreadListRequest {
            limit,
            cursor: body.cursor,
        },
    )?;
    if page.threads.len() > usize::from(limit)
        || page.threads.iter().any(|thread| {
            thread.thread_id.is_empty()
                || thread.thread_id.len() > MAX_TEXT_LENGTH
                || thread.title.len() > MAX_TEXT_LENGTH
                || thread.updated_at.is_empty()
                || thread.updated_at.len() > MAX_TEXT_LENGTH
        })
        || page
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
    {
        return Err(ProtocolError::persistence_failed().into());
    }
    Ok(serde_json::to_value(page)
        .map(response_only)
        .map_err(|_| ProtocolError::persistence_failed())?)
}

fn read_frame_after_prefix(
    stream: &mut UnixStream,
    prefix: [u8; 4],
    deadline: Instant,
) -> Result<Vec<u8>, AttachSessionError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(AttachSessionError::PayloadTooLarge);
    }
    let mut frame = vec![0; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_before(stream, &mut frame[4..], deadline)?;
    Ok(frame)
}

fn write_request_error(
    stream: &mut UnixStream,
    request_id: Option<super::Id>,
    error: ProtocolError,
    deadline: Instant,
) {
    let envelope = ErrorEnvelope {
        protocol: Protocol,
        request_id,
        ok: Failure,
        error,
    };
    if let Ok(frame) = encode_frame(&envelope) {
        let _ = write_before(stream, &frame, deadline);
    }
}

fn write_before(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), AttachSessionError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(AttachSessionError::Timeout)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| AttachSessionError::Closed)?;
    stream.write_all(bytes).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            AttachSessionError::Timeout
        } else {
            AttachSessionError::Closed
        }
    })
}

fn write_protocol_error(stream: &mut UnixStream, error: ProtocolError, deadline: Instant) {
    let envelope = ErrorEnvelope {
        protocol: Protocol,
        request_id: None,
        ok: Failure,
        error,
    };
    if let Ok(frame) = encode_frame(&envelope) {
        let _ = write_before(stream, &frame, deadline);
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    encoded
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
