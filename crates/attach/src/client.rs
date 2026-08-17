use std::fmt;

/// Closed, redacted outcomes from the companion pairing handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    UnsupportedPlatform,
    AuthorizationExpired,
    ThreadNotFound,
    RequestRejected,
    DesktopFailed,
    RuntimeDirectoryMissing,
    RuntimeDirectoryRelative,
    DesktopUnavailable,
    DesktopBusy,
    Timeout,
    ConnectionClosed,
    MalformedFrame,
    PayloadTooLarge,
    UnexpectedMessage,
    CapabilityRevoked,
    ProtocolIncompatible,
    RandomnessUnavailable,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => "desktop attach is unsupported on this platform",
            Self::AuthorizationExpired => "desktop authorization is no longer valid",
            Self::ThreadNotFound => "the desktop could not find the thread",
            Self::RequestRejected => "the desktop rejected the thread request",
            Self::DesktopFailed => "the desktop could not read threads",
            Self::RuntimeDirectoryMissing => "XDG_RUNTIME_DIR is not set",
            Self::RuntimeDirectoryRelative => "XDG_RUNTIME_DIR must be an absolute path",
            Self::DesktopUnavailable => "the Muniment desktop attach service is unavailable",
            Self::DesktopBusy => "the Muniment desktop attach service is busy",
            Self::Timeout => "the desktop did not complete pairing in time",
            Self::ConnectionClosed => "the desktop closed the pairing connection",
            Self::MalformedFrame => "the desktop sent a malformed attach message",
            Self::PayloadTooLarge => "the desktop sent an oversized attach message",
            Self::UnexpectedMessage => "the desktop sent an unexpected pairing message",
            Self::CapabilityRevoked => "the desktop revoked the capability",
            Self::ProtocolIncompatible => "the desktop and CLI attach protocols are incompatible",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
        })
    }
}

impl std::error::Error for ClientError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationControlOutcome {
    Accepted,
    MigrationNotReady { retryable: bool },
    Unauthorized,
    UnsupportedOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPresentRequest {
    pub challenge: String,
    pub claimed_kind: String,
    pub claimed_version: String,
    pub workspace: String,
    pub scopes: Vec<String>,
    pub deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalPresenterServeOutcome {
    ConnectionClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationControlFailure {
    InvalidNonce,
    InvalidDeadline,
    NonceMismatch,
    Client(ClientError),
}

impl fmt::Display for MigrationControlFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidNonce => "the handoff nonce is invalid",
            Self::InvalidDeadline => "the handoff deadline is invalid",
            Self::NonceMismatch => "the desktop returned a different handoff nonce",
            Self::Client(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for MigrationControlFailure {}

impl From<ClientError> for MigrationControlFailure {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSummary {
    pub expires_in_seconds: u64,
    pub idle_timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStartAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSubmitAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub attachments: Vec<RunSubmitAttachment>,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResumeAccepted {
    pub run_id: String,
    pub thread_id: String,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSubmitAttachment {
    pub display_name: String,
    pub byte_length: u64,
    pub media_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadCreateAccepted {
    pub thread_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCancelAccepted {
    pub run_id: String,
    pub accepted_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMessageAccepted {
    pub run_id: String,
    pub accepted_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allow,
    Deny,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionAnswerAccepted {
    pub run_id: String,
    pub gate_id: String,
    pub decision: PermissionDecision,
    pub committed_seq: u64,
    pub accepted_at: String,
}

impl fmt::Debug for PermissionAnswerAccepted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionAnswerAccepted")
            .field("run_id", &self.run_id)
            .field("gate_id", &"[redacted]")
            .field("decision", &self.decision)
            .field("committed_seq", &self.committed_seq)
            .field("accepted_at", &self.accepted_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum ChatPermissionAnswer {
    Select(String),
    Confirm(bool),
    Input(String),
    Editor(String),
    Cancelled,
    CodeDiff {
        gate_id: String,
        effect_id: String,
        code_diff_id: String,
        diff_sha256: String,
        write_plan_sha256: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPermissionAnswerAccepted {
    pub run_id: String,
    pub gate_id: String,
    pub answer: ChatPermissionAnswer,
    pub committed_seq: u64,
    pub accepted_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStreamWindow {
    pub max_events: usize,
    pub max_bytes: usize,
    pub max_text_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStreamSubscription {
    pub subscription_id: String,
    pub run_id: String,
    pub first_available_run_seq: u64,
    pub current_run_seq: u64,
    pub window: RunStreamWindow,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedRunEvent {
    pub run_seq: u64,
    pub event_type: String,
    pub event_version: u32,
    pub recorded_at: String,
    pub text: Option<String>,
    pub effect_id: Option<String>,
    pub display_name: Option<String>,
    pub receipt: Option<RunReceipt>,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReceipt {
    pub route: Option<String>,
    pub model: Option<String>,
    pub cost: Option<String>,
    pub time: Option<String>,
    pub capabilities: Vec<ReceiptCapability>,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCapability {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionKind {
    Confirm,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingPermission {
    #[serde(skip)]
    pub run_seq: u64,
    pub gate_id: String,
    pub kind: PermissionKind,
    pub title: String,
    #[serde(default, deserialize_with = "deserialize_optional_permission_message")]
    pub message: Option<String>,
}

fn deserialize_optional_permission_message<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

impl fmt::Debug for PendingPermission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingPermission")
            .field("run_seq", &self.run_seq)
            .field("gate_id", &"[redacted]")
            .field("kind", &self.kind)
            .field("title", &"[redacted]")
            .field("message", &self.message.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl fmt::Debug for RedactedRunEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedRunEvent")
            .field("run_seq", &self.run_seq)
            .field("event_type", &self.event_type)
            .field("event_version", &self.event_version)
            .field("recorded_at", &self.recorded_at)
            .field("text", &self.text.as_ref().map(|_| "[redacted]"))
            .field("effect_id", &self.effect_id.as_ref().map(|_| "[redacted]"))
            .field(
                "display_name",
                &self.display_name.as_ref().map(|_| "[redacted]"),
            )
            .field("receipt", &self.receipt.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum RunStreamMessage {
    Event(RedactedRunEvent),
    PermissionPending(PendingPermission),
    CaughtUp { current_run_seq: u64 },
    StreamClosed { code: String, resumable: bool },
    CapabilityRevoked { capability: String, reason: String },
}

impl fmt::Debug for RunStreamMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(event) => formatter.debug_tuple("Event").field(event).finish(),
            Self::PermissionPending(permission) => formatter
                .debug_tuple("PermissionPending")
                .field(permission)
                .finish(),
            Self::CaughtUp { current_run_seq } => formatter
                .debug_struct("CaughtUp")
                .field("current_run_seq", current_run_seq)
                .finish(),
            Self::StreamClosed { code, resumable } => formatter
                .debug_struct("StreamClosed")
                .field("code", code)
                .field("resumable", resumable)
                .finish(),
            Self::CapabilityRevoked { reason, .. } => formatter
                .debug_struct("CapabilityRevoked")
                .field("capability", &"[redacted]")
                .field("reason", reason)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedThreadSummary {
    pub thread_id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadListPage {
    pub threads: Vec<RedactedThreadSummary>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedThreadEntry {
    pub run_seq: u64,
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadOpenPage {
    pub thread_id: String,
    pub entries: Vec<RedactedThreadEntry>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

impl fmt::Debug for ThreadOpenPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadOpenPage")
            .field("thread_id", &self.thread_id)
            .field("entries", &self.entries)
            .field("has_more", &self.next_cursor.is_some())
            .finish()
    }
}

impl fmt::Debug for ThreadListPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadListPage")
            .field("threads", &self.threads)
            .field("has_more", &self.next_cursor.is_some())
            .finish()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        ApprovalDecision, ApprovalPresentRequest, ApprovalPresenterServeOutcome,
        AuthorizationSummary, ChatPermissionAnswer, ClientError, MigrationControlFailure,
        MigrationControlOutcome, PendingPermission, PermissionAnswerAccepted, PermissionDecision,
        RedactedRunEvent, RunCancelAccepted, RunMessageAccepted, RunPermissionAnswerAccepted,
        RunResumeAccepted, RunStartAccepted, RunStreamMessage, RunStreamSubscription,
        RunSubmitAccepted, ThreadCreateAccepted, ThreadListPage, ThreadOpenPage,
    };
    use crate::{
        decode_frame, encode_frame, Authorization, Authorized, Client,
        DesktopClientAuthorizedGrant, Envelope, ErrorCode, ErrorEnvelope, EventName, FrameError,
        Hello, Id, Operation, PeerAuthorizedGrant, Protocol, Request, Response, VersionRange,
        Welcome, WorkspaceOnboarded, MAX_FRAME_LENGTH, MAX_TEXT_LENGTH, PROTOCOL,
    };
    use serde::de::DeserializeOwned;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::env;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    unsafe extern "C" {
        fn poll(descriptors: *mut PollFd, count: usize, timeout: i32) -> i32;
        fn socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
        fn connect(socket: i32, address: *const UnixSocketAddress, length: u32) -> i32;
        fn getsockopt(
            socket: i32,
            level: i32,
            option: i32,
            value: *mut i32,
            length: *mut u32,
        ) -> i32;
    }

    const POLLIN: i16 = 0x001;
    const POLLOUT: i16 = 0x004;

    #[repr(C)]
    struct UnixSocketAddress {
        family: u16,
        path: [u8; 108],
    }

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
    const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
    const DESKTOP_CLIENT_LOCK_TIMEOUT: Duration = Duration::from_millis(100);
    const THREAD_LIST_LIMIT: u8 = 100;
    const THREAD_OPEN_LIMIT: u8 = 100;
    const MAX_THREAD_ID_LENGTH: usize = 36;
    const MAX_CURSOR_LENGTH: usize = 1024;
    const MAX_RUN_START_TEXT_LENGTH: usize = 32 * 1024;
    const MAX_RUN_MESSAGE_TEXT_LENGTH: usize = 32 * 1024;
    const MAX_RUN_START_CONTEXT_LENGTH: usize = 64 * 1024;
    const MAX_PERMISSION_GATE_ID_LENGTH: usize = 256;
    const MAX_PERMISSION_TITLE_LENGTH: usize = 1_024;
    const MAX_PERMISSION_MESSAGE_LENGTH: usize = 4_096;
    const MAX_RUN_STREAM_WINDOW_EVENTS: usize = 1_024;
    const MAX_RUN_STREAM_WINDOW_BYTES: usize = 4 * 1024 * 1024;
    const MAX_RUN_STREAM_WINDOW_TEXT_BYTES: usize = 262_144;
    const MAX_HANDOFF_NONCE_BYTES: usize = 128;
    const MAX_HANDOFF_DEADLINE_MS: u64 = 60_000;
    const MAX_APPROVAL_DEADLINE_MS: u64 = 120_000;

    struct ActiveRunStream {
        subscription_id: Id,
        run_id: Id,
        current_run_seq: u64,
        highest_run_seq: u64,
        acknowledged_run_seq: u64,
        max_unacknowledged_events: usize,
        caught_up: bool,
        pending_messages: VecDeque<RunStreamMessage>,
    }

    struct ClientIdentity<'a> {
        kind: &'a str,
        id: &'a str,
        credential: Option<&'a str>,
    }

    /// An authorization bound to the connection on which pairing completed.
    pub struct AuthorizedClient {
        stream: UnixStream,
        profile_id: String,
        capability: String,
        summary: AuthorizationSummary,
        authorized_at: Instant,
        io_timeout: Duration,
        active_run_stream: Option<ActiveRunStream>,
        authorized_client_credential: String,
    }

    impl std::fmt::Debug for AuthorizedClient {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("AuthorizedClient { .. }")
        }
    }

    impl AuthorizedClient {
        pub fn profile_id(&self) -> &str {
            &self.profile_id
        }

        pub fn authorization_summary(&self) -> AuthorizationSummary {
            self.summary.clone()
        }

        pub fn authorized_client_credential(&self) -> &str {
            &self.authorized_client_credential
        }

        pub fn onboard_workspace(
            &mut self,
            opened_directory: &str,
            memory_location: &str,
        ) -> Result<WorkspaceOnboarded, ClientError> {
            if opened_directory.is_empty()
                || memory_location.is_empty()
                || opened_directory.len() > MAX_TEXT_LENGTH
                || memory_location.len() > MAX_TEXT_LENGTH
            {
                return Err(ClientError::UnexpectedMessage);
            }
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::WorkspaceOnboard,
                capability: self.capability.clone(),
                idempotency_key: None,
                body: serde_json::json!({
                    "opened_directory": opened_directory, "memory_location": memory_location
                }),
            };
            let response = self.send_request(request, &request_id)?;
            serde_json::from_value(response.body).map_err(|_| ClientError::UnexpectedMessage)
        }

        pub fn ensure_home(&mut self) -> Result<(), ClientError> {
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::HomeEnsure,
                capability: self.capability.clone(),
                idempotency_key: None,
                body: serde_json::json!({}),
            };
            let response = self.send_request(request, &request_id)?;
            if response.body != serde_json::json!({}) {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(())
        }

        fn send_request(
            &mut self,
            request: Request,
            request_id: &Id,
        ) -> Result<Response, ClientError> {
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            match serde_json::from_value(read_value(&mut self.stream, deadline)?)
                .map_err(|_| ClientError::UnexpectedMessage)?
            {
                Envelope::Response(response) if &response.request_id == request_id => Ok(response),
                Envelope::Error(error) if error.request_id.as_ref() == Some(request_id) => {
                    Err(map_protocol_error(error.error.code()))
                }
                Envelope::Event(event)
                    if Self::validate_capability_revocation(&event)?.is_some() =>
                {
                    Err(ClientError::CapabilityRevoked)
                }
                _ => Err(ClientError::UnexpectedMessage),
            }
        }

        pub fn list_threads(
            &mut self,
            cursor: Option<&str>,
        ) -> Result<ThreadListPage, ClientError> {
            if cursor.is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH) {
                return Err(ClientError::UnexpectedMessage);
            }
            let request_id = fresh_request_id()?;
            let mut body = serde_json::json!({ "limit": THREAD_LIST_LIMIT });
            if let Some(cursor) = cursor {
                body["cursor"] = Value::String(cursor.into());
            }
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::ThreadList,
                capability: self.capability.clone(),
                idempotency_key: None,
                body,
            };
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event)
                        if Self::validate_capability_revocation(&event)?.is_some() =>
                    {
                        return Err(ClientError::CapabilityRevoked);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let page: ThreadListPage = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if page.threads.len() > usize::from(THREAD_LIST_LIMIT)
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
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(page)
        }

        pub fn create_thread(&mut self) -> Result<ThreadCreateAccepted, ClientError> {
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::ThreadCreate,
                capability: self.capability.clone(),
                idempotency_key: Some(fresh_request_id()?),
                body: serde_json::json!({}),
            };
            let response = self.send_request(request, &request_id)?;
            let accepted: ThreadCreateAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if Id::new(accepted.thread_id.clone()).is_err() {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn open_thread(
            &mut self,
            thread_id: &str,
            cursor: Option<&str>,
        ) -> Result<ThreadOpenPage, ClientError> {
            if thread_id.is_empty()
                || thread_id.len() > MAX_THREAD_ID_LENGTH
                || cursor
                    .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            let request_id = fresh_request_id()?;
            let mut body = serde_json::json!({
                "thread_id": thread_id,
                "limit": THREAD_OPEN_LIMIT
            });
            if let Some(cursor) = cursor {
                body["cursor"] = Value::String(cursor.into());
            }
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::ThreadOpen,
                capability: self.capability.clone(),
                idempotency_key: None,
                body,
            };
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event)
                        if Self::validate_capability_revocation(&event)?.is_some() =>
                    {
                        return Err(ClientError::CapabilityRevoked);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let page: ThreadOpenPage = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if page.thread_id != thread_id
                || page.entries.len() > usize::from(THREAD_OPEN_LIMIT)
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
                    .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(page)
        }

        pub fn start_run(
            &mut self,
            text: &str,
            context: Option<Value>,
        ) -> Result<RunStartAccepted, ClientError> {
            self.start_run_in_workspace(text, context, None)
        }

        pub fn start_run_in_workspace(
            &mut self,
            text: &str,
            context: Option<Value>,
            workspace: Option<&str>,
        ) -> Result<RunStartAccepted, ClientError> {
            self.start_run_in_workspace_thread(text, context, workspace, None)
        }

        pub fn start_run_in_workspace_thread(
            &mut self,
            text: &str,
            context: Option<Value>,
            workspace: Option<&str>,
            thread_id: Option<&str>,
        ) -> Result<RunStartAccepted, ClientError> {
            let context_length = context
                .as_ref()
                .map(|context| serde_json::to_vec(context).map(|bytes| bytes.len()))
                .transpose()
                .map_err(|_| ClientError::UnexpectedMessage)?
                .unwrap_or(0);
            if text.trim().is_empty()
                || text.len() > MAX_RUN_START_TEXT_LENGTH
                || workspace.is_some_and(|value| value.is_empty() || value.len() > MAX_TEXT_LENGTH)
                || thread_id.is_some_and(|value| value.len() > 36 || Id::new(value).is_err())
                || context_length > MAX_RUN_START_CONTEXT_LENGTH
            {
                return Err(ClientError::UnexpectedMessage);
            }

            let request_id = fresh_request_id()?;
            let idempotency_key = fresh_request_id()?;
            let mut body = serde_json::json!({ "text": text });
            if let Some(context) = context {
                body["context"] = context;
            }
            if let Some(workspace) = workspace {
                body["workspace"] = Value::String(workspace.to_owned());
            }
            if let Some(thread_id) = thread_id {
                body["thread_id"] = Value::String(thread_id.to_owned());
            }
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::RunStart,
                capability: self.capability.clone(),
                idempotency_key: Some(idempotency_key),
                body,
            };
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event)
                        if Self::validate_capability_revocation(&event)?.is_some() =>
                    {
                        return Err(ClientError::CapabilityRevoked);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let accepted: RunStartAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if Id::new(accepted.run_id.clone()).is_err()
                || Id::new(accepted.thread_id.clone()).is_err()
                || accepted.committed_seq == 0
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn answer_permission(
            &mut self,
            run_id: &str,
            gate_id: &str,
            decision: PermissionDecision,
        ) -> Result<PermissionAnswerAccepted, ClientError> {
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            if gate_id.trim().is_empty() || gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let request_id = fresh_request_id()?;
            let idempotency_key = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::PermissionAnswer,
                capability: self.capability.clone(),
                idempotency_key: Some(idempotency_key),
                body: serde_json::json!({
                    "run_id": run_id.as_str(),
                    "gate_id": gate_id,
                    "decision": decision,
                }),
            };
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event)
                        if Self::validate_capability_revocation(&event)?.is_some() =>
                    {
                        return Err(ClientError::CapabilityRevoked);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let accepted: PermissionAnswerAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if accepted.run_id != run_id.as_str()
                || accepted.gate_id != gate_id
                || accepted.decision != decision
                || accepted.committed_seq == 0
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn run_cancel(&mut self, run_id: &str) -> Result<RunCancelAccepted, ClientError> {
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::RunCancel,
                capability: self.capability.clone(),
                idempotency_key: Some(fresh_request_id()?),
                body: serde_json::json!({"run_id": run_id.as_str()}),
            };
            let deadline = deadline(self.io_timeout);
            write_all_before(
                &mut self.stream,
                &encode_frame(&request).map_err(map_frame_error)?,
                deadline,
            )?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|value| value != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event)
                        if Self::validate_capability_revocation(&event)?.is_some() =>
                    {
                        return Err(ClientError::CapabilityRevoked);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let accepted: RunCancelAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if accepted.run_id != run_id.as_str()
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn subscribe_run(
            &mut self,
            run_id: &str,
            after_run_seq: u64,
        ) -> Result<RunStreamSubscription, ClientError> {
            if after_run_seq == u64::MAX {
                return Err(ClientError::UnexpectedMessage);
            }
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::RunStream,
                capability: self.capability.clone(),
                idempotency_key: None,
                body: serde_json::json!({
                    "run_id": run_id.as_str(),
                    "after_run_seq": after_run_seq,
                }),
            };
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|p| p != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event)
                        if Self::validate_capability_revocation(&event)?.is_some() =>
                    {
                        return Err(ClientError::CapabilityRevoked);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let summary: RunStreamSubscription = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            let subscription_id = Id::new(summary.subscription_id.clone())
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if summary.run_id != run_id.as_str()
                || summary.first_available_run_seq == 0
                || summary.first_available_run_seq > summary.current_run_seq
                || after_run_seq > summary.current_run_seq
                || after_run_seq.saturating_add(1) < summary.first_available_run_seq
                || summary.window.max_events == 0
                || summary.window.max_events > MAX_RUN_STREAM_WINDOW_EVENTS
                || summary.window.max_bytes == 0
                || summary.window.max_bytes > MAX_RUN_STREAM_WINDOW_BYTES
                || summary.window.max_text_bytes == 0
                || summary.window.max_text_bytes > MAX_RUN_STREAM_WINDOW_TEXT_BYTES
            {
                return Err(ClientError::UnexpectedMessage);
            }
            self.active_run_stream = Some(ActiveRunStream {
                subscription_id,
                run_id,
                current_run_seq: summary.current_run_seq,
                highest_run_seq: after_run_seq,
                acknowledged_run_seq: after_run_seq,
                max_unacknowledged_events: summary.window.max_events,
                caught_up: false,
                pending_messages: VecDeque::new(),
            });
            Ok(summary)
        }

        pub fn acknowledge_run_cursor(&mut self, through_run_seq: u64) -> Result<(), ClientError> {
            let active = self
                .active_run_stream
                .as_ref()
                .ok_or(ClientError::UnexpectedMessage)?;
            if through_run_seq <= active.acknowledged_run_seq
                || through_run_seq > active.highest_run_seq
            {
                return Err(ClientError::UnexpectedMessage);
            }
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::RunCursorAck,
                capability: self.capability.clone(),
                idempotency_key: None,
                body: serde_json::json!({
                    "subscription_id": active.subscription_id.as_str(),
                    "through_run_seq": through_run_seq,
                }),
            };
            let subscription_id = active.subscription_id.clone();
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let response = loop {
                let value = read_value(&mut self.stream, deadline)?;
                if value
                    .get("protocol")
                    .and_then(Value::as_str)
                    .is_some_and(|p| p != PROTOCOL)
                {
                    return Err(ClientError::ProtocolIncompatible);
                }
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => {
                        break response;
                    }
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    Envelope::Event(event) => {
                        if Self::validate_capability_revocation(&event)?.is_some() {
                            return Err(ClientError::CapabilityRevoked);
                        }
                        let message = self.validate_run_stream_event(event)?;
                        self.active_run_stream
                            .as_mut()
                            .ok_or(ClientError::UnexpectedMessage)?
                            .pending_messages
                            .push_back(message);
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                }
            };
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Acknowledged {
                subscription_id: String,
                through_run_seq: u64,
            }
            let acknowledged: Acknowledged = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if acknowledged.subscription_id != subscription_id.as_str()
                || acknowledged.through_run_seq != through_run_seq
            {
                return Err(ClientError::UnexpectedMessage);
            }
            self.active_run_stream
                .as_mut()
                .ok_or(ClientError::UnexpectedMessage)?
                .acknowledged_run_seq = through_run_seq;
            Ok(())
        }

        pub fn read_run_stream_message(&mut self) -> Result<RunStreamMessage, ClientError> {
            if let Some(message) = self
                .active_run_stream
                .as_mut()
                .ok_or(ClientError::UnexpectedMessage)?
                .pending_messages
                .pop_front()
            {
                return Ok(message);
            }
            let authorization_remaining = Duration::from_secs(self.summary.expires_in_seconds)
                .saturating_sub(self.authorized_at.elapsed());
            let wait =
                authorization_remaining.min(Duration::from_secs(self.summary.idle_timeout_seconds));
            if wait.is_zero() {
                return Err(ClientError::AuthorizationExpired);
            }
            let value = read_value(&mut self.stream, deadline(wait))?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|p| p != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let event =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Event(event) => event,
                    Envelope::Error(error) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            self.validate_run_stream_event(event)
        }

        pub fn read_capability_revocation_if_ready(&mut self) -> Result<bool, ClientError> {
            let mut descriptor = PollFd {
                fd: self.stream.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            };
            // SAFETY: `descriptor` points to one valid pollfd for the duration of this call.
            let ready = unsafe { poll(&mut descriptor, 1, 0) };
            if ready < 0 {
                return Err(ClientError::DesktopUnavailable);
            }
            if ready == 0 {
                return Ok(false);
            }
            let authorization_remaining = Duration::from_secs(self.summary.expires_in_seconds)
                .saturating_sub(self.authorized_at.elapsed());
            let wait =
                authorization_remaining.min(Duration::from_secs(self.summary.idle_timeout_seconds));
            if wait.is_zero() {
                return Err(ClientError::AuthorizationExpired);
            }
            let value = read_value(&mut self.stream, deadline(wait))?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let event =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Event(event) => event,
                    Envelope::Error(error) => return Err(map_protocol_error(error.error.code())),
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            if Self::validate_capability_revocation(&event)?.is_some() {
                return Ok(true);
            }
            let message = self.validate_run_stream_event(event)?;
            self.active_run_stream
                .as_mut()
                .ok_or(ClientError::UnexpectedMessage)?
                .pending_messages
                .push_back(message);
            Ok(false)
        }

        fn validate_run_stream_event(
            &mut self,
            event: crate::Event,
        ) -> Result<RunStreamMessage, ClientError> {
            if let Some(message) = Self::validate_capability_revocation(&event)? {
                return Ok(message);
            }
            let active = self
                .active_run_stream
                .as_mut()
                .ok_or(ClientError::UnexpectedMessage)?;
            if event.subscription_id != active.subscription_id
                || event.run_id.as_ref() != Some(&active.run_id)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            match event.event {
                EventName::RunEvent | EventName::PermissionPending => {
                    let run_seq = event.run_seq.ok_or(ClientError::UnexpectedMessage)?;
                    if run_seq == 0
                        || run_seq > active.highest_run_seq.saturating_add(1)
                        || (!active.caught_up && run_seq > active.current_run_seq)
                        || run_seq.saturating_sub(active.acknowledged_run_seq)
                            > active.max_unacknowledged_events as u64
                    {
                        return Err(ClientError::UnexpectedMessage);
                    }
                    if event.event == EventName::PermissionPending {
                        let mut body: PendingPermission = serde_json::from_value(event.body)
                            .map_err(|_| ClientError::UnexpectedMessage)?;
                        if body.gate_id.trim().is_empty()
                            || body.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH
                            || body.title.trim().is_empty()
                            || body.title.len() > MAX_PERMISSION_TITLE_LENGTH
                            || body.message.as_ref().is_some_and(|message| {
                                message.len() > MAX_PERMISSION_MESSAGE_LENGTH
                            })
                        {
                            return Err(ClientError::UnexpectedMessage);
                        }
                        body.run_seq = run_seq;
                        active.highest_run_seq = active.highest_run_seq.max(run_seq);
                        if active.caught_up {
                            active.current_run_seq = run_seq;
                        }
                        return Ok(RunStreamMessage::PermissionPending(body));
                    }
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Body {
                        event_type: String,
                        event_version: u32,
                        recorded_at: String,
                        payload: Withheld,
                    }
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Withheld {
                        #[serde(default)]
                        withheld: bool,
                        #[serde(default)]
                        text: Option<String>,
                        #[serde(default)]
                        effect_id: Option<String>,
                        #[serde(default)]
                        display_name: Option<String>,
                        #[serde(default)]
                        receipt: Option<crate::RunReceipt>,
                    }
                    let body: Body = serde_json::from_value(event.body)
                        .map_err(|_| ClientError::UnexpectedMessage)?;
                    if body.event_type.trim().is_empty()
                        || body.event_type.len() > MAX_TEXT_LENGTH
                        || body.event_version == 0
                        || body.recorded_at.is_empty()
                        || body.recorded_at.len() > MAX_TEXT_LENGTH
                        || !is_rfc3339(&body.recorded_at)
                        || (body.event_type == "model.stream.delta"
                            && (body.payload.withheld == body.payload.text.is_some()
                                || body.payload.effect_id.is_some()
                                || body.payload.display_name.is_some()))
                        || (matches!(
                            body.event_type.as_str(),
                            "tool.effect.started" | "tool.effect.completed" | "tool.effect.failed"
                        ) && (body.payload.withheld
                            || body.payload.text.is_some()
                            || body.payload.effect_id.as_ref().is_none_or(|effect_id| {
                                effect_id.is_empty() || effect_id.len() > 65_536
                            })
                            || body
                                .payload
                                .display_name
                                .as_ref()
                                .is_some_and(|display_name| {
                                    display_name.len() > 65_536
                                        || body.event_type != "tool.effect.started"
                                })))
                        || (!matches!(
                            body.event_type.as_str(),
                            "model.stream.delta"
                                | "tool.effect.started"
                                | "tool.effect.completed"
                                | "tool.effect.failed"
                        ) && (!body.payload.withheld
                            || body.payload.text.is_some()
                            || body.payload.effect_id.is_some()
                            || body.payload.display_name.is_some()))
                        || body
                            .payload
                            .text
                            .as_ref()
                            .is_some_and(|text| text.is_empty() || text.len() > 65_536)
                        || (body.payload.receipt.is_some() && body.event_type != "run.completed")
                        || body.payload.receipt.as_ref().is_some_and(|receipt| {
                            let valid = |value: &Option<String>| {
                                value.as_ref().is_none_or(|value| {
                                    !value.trim().is_empty() && value.len() <= 1_024
                                })
                            };
                            !valid(&receipt.route)
                                || !valid(&receipt.model)
                                || !valid(&receipt.cost)
                                || !valid(&receipt.time)
                                || receipt.capabilities.len() > 64
                                || receipt.capabilities.iter().any(|capability| {
                                    capability.name.trim().is_empty()
                                        || capability.name.len() > 1_024
                                        || capability.version.trim().is_empty()
                                        || capability.version.len() > 1_024
                                })
                        })
                    {
                        return Err(ClientError::UnexpectedMessage);
                    }
                    active.highest_run_seq = active.highest_run_seq.max(run_seq);
                    if active.caught_up {
                        active.current_run_seq = run_seq;
                    }
                    Ok(RunStreamMessage::Event(RedactedRunEvent {
                        run_seq,
                        event_type: body.event_type,
                        event_version: body.event_version,
                        recorded_at: body.recorded_at,
                        text: body.payload.text,
                        effect_id: body.payload.effect_id,
                        display_name: body.payload.display_name,
                        receipt: body.payload.receipt,
                    }))
                }
                EventName::SubscriptionCaughtUp => {
                    if active.caught_up
                        || event.run_seq != Some(active.current_run_seq)
                        || active.highest_run_seq != active.current_run_seq
                        || event.body != serde_json::json!({})
                    {
                        return Err(ClientError::UnexpectedMessage);
                    }
                    active.caught_up = true;
                    Ok(RunStreamMessage::CaughtUp {
                        current_run_seq: active.current_run_seq,
                    })
                }
                EventName::StreamClosed => {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Body {
                        code: String,
                        #[serde(default)]
                        resumable: Value,
                    }
                    let body: Body = serde_json::from_value(event.body)
                        .map_err(|_| ClientError::UnexpectedMessage)?;
                    if body.code.trim().is_empty() || body.code.len() > MAX_TEXT_LENGTH {
                        return Err(ClientError::UnexpectedMessage);
                    }
                    Ok(RunStreamMessage::StreamClosed {
                        code: body.code,
                        resumable: body.resumable.as_bool().unwrap_or(false),
                    })
                }
                _ => Err(ClientError::UnexpectedMessage),
            }
        }

        fn validate_capability_revocation(
            event: &crate::Event,
        ) -> Result<Option<RunStreamMessage>, ClientError> {
            if event.event != EventName::CapabilityRevoked {
                return Ok(None);
            }
            if event.run_id.is_some() || event.run_seq.is_some() {
                return Err(ClientError::UnexpectedMessage);
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Body {
                capability: String,
                reason: String,
            }
            let body: Body = serde_json::from_value(event.body.clone())
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if body.capability.trim().is_empty()
                || body.capability.len() > MAX_TEXT_LENGTH
                || body.reason.trim().is_empty()
                || body.reason.len() > MAX_TEXT_LENGTH
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(Some(RunStreamMessage::CapabilityRevoked {
                capability: body.capability,
                reason: body.reason,
            }))
        }
    }

    /// A connection-bound client for the peer-authorized migration session.
    pub struct MigrationControlClient {
        stream: UnixStream,
        capability: String,
        summary: AuthorizationSummary,
        io_timeout: Duration,
    }

    /// A connection-bound client for the peer-authorized desktop session.
    pub struct DesktopClient {
        stream: UnixStream,
        profile_id: String,
        workspace_scopes: BTreeMap<String, BTreeSet<String>>,
        capability: String,
        summary: AuthorizationSummary,
        authorized_at: Instant,
        chat_subscription_id: Option<Id>,
        io_timeout: Duration,
    }

    #[derive(Clone, Debug, Default)]
    pub struct DesktopClientHolder {
        inner: Arc<(Mutex<Option<DesktopClient>>, Condvar)>,
    }

    impl DesktopClientHolder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn request(
            &self,
            operation: Operation,
            idempotency_key: Option<Id>,
            body: Value,
        ) -> Result<Response, ClientError> {
            self.with_client(|client| client.request(operation, idempotency_key, body))
        }

        pub fn rename_thread(&self, thread_id: &str, title: &str) -> Result<(), ClientError> {
            self.with_client(|client| client.rename_thread(thread_id, title))
        }

        pub fn delete_thread(&self, thread_id: &str) -> Result<(), ClientError> {
            self.with_client(|client| client.delete_thread(thread_id))
        }

        pub fn thread_select(&self, thread_id: &str) -> Result<(), ClientError> {
            self.with_client(|client| client.thread_select(thread_id))
        }

        pub fn session_status(&self) -> Result<Value, ClientError> {
            self.with_client(DesktopClient::session_status)
        }

        pub fn entitlement_snapshot(&self) -> Result<Value, ClientError> {
            self.with_client(DesktopClient::entitlement_snapshot)
        }

        pub fn list_devices(&self) -> Result<Value, ClientError> {
            self.with_client(DesktopClient::list_devices)
        }

        pub fn sign_out(&self) -> Result<Value, ClientError> {
            self.with_client(DesktopClient::sign_out)
        }

        pub fn sign_in(&self) -> Result<Value, ClientError> {
            self.with_client(DesktopClient::sign_in)
        }

        pub fn thread_summaries(
            &self,
            limit: u8,
            cursor: Option<&str>,
        ) -> Result<Value, ClientError> {
            self.with_client(|client| client.thread_summaries(limit, cursor))
        }

        pub fn thread_history(
            &self,
            thread_id: &str,
            limit: u8,
            cursor: Option<&str>,
        ) -> Result<Value, ClientError> {
            self.with_client(|client| client.thread_history(thread_id, limit, cursor))
        }

        pub fn list_companions(&self) -> Result<Value, ClientError> {
            self.with_client(DesktopClient::list_companions)
        }

        pub fn revoke_companion(&self, client_identity: &str) -> Result<Value, ClientError> {
            self.with_client(|client| client.revoke_companion(client_identity))
        }

        pub fn run_submit(
            &self,
            text: &str,
            files: &[String],
            thread_id: Option<&str>,
        ) -> Result<RunSubmitAccepted, ClientError> {
            self.with_client(|client| client.run_submit(text, files, thread_id))
        }

        pub fn run_cancel(&self, run_id: &str) -> Result<RunCancelAccepted, ClientError> {
            self.with_client(|client| client.run_cancel(run_id))
        }

        pub fn run_resume(&self, run_id: &str) -> Result<RunResumeAccepted, ClientError> {
            self.with_client(|client| client.run_resume(run_id))
        }

        pub fn run_permission_answer(
            &self,
            run_id: &str,
            gate_id: &str,
            answer: ChatPermissionAnswer,
        ) -> Result<RunPermissionAnswerAccepted, ClientError> {
            self.with_client(|client| client.run_permission_answer(run_id, gate_id, answer))
        }

        pub fn run_steer(
            &self,
            run_id: &str,
            text: &str,
        ) -> Result<RunMessageAccepted, ClientError> {
            self.with_client(|client| client.run_steer(run_id, text))
        }

        pub fn run_follow_up(
            &self,
            run_id: &str,
            text: &str,
        ) -> Result<RunMessageAccepted, ClientError> {
            self.with_client(|client| client.run_follow_up(run_id, text))
        }

        fn with_client<T>(
            &self,
            call: impl FnOnce(&mut DesktopClient) -> Result<T, ClientError>,
        ) -> Result<T, ClientError> {
            let (client, wake) = &*self.inner;
            let mut client = Self::lock_client(client)?;
            let result = call(client.as_mut().ok_or(ClientError::DesktopUnavailable)?);
            if result.is_err() {
                *client = None;
                wake.notify_all();
            }
            result
        }

        fn lock_client(
            client: &Mutex<Option<DesktopClient>>,
        ) -> Result<MutexGuard<'_, Option<DesktopClient>>, ClientError> {
            let deadline = Instant::now() + DESKTOP_CLIENT_LOCK_TIMEOUT;
            loop {
                match client.try_lock() {
                    Ok(client) => return Ok(client),
                    Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
                    Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                        return Err(ClientError::DesktopBusy);
                    }
                    Err(TryLockError::WouldBlock) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct DesktopClientStopHandle {
        inner: Arc<(Mutex<DesktopClientStopState>, Condvar)>,
        notification: Arc<(Mutex<Option<std::thread::ThreadId>>, Condvar)>,
    }

    #[derive(Debug, Default)]
    struct DesktopClientStopState {
        stopped: bool,
        stream: Option<UnixStream>,
        holder: Option<DesktopClientHolder>,
    }

    impl DesktopClientStopHandle {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn stop(&self) {
            let current_thread = std::thread::current().id();
            let (notification, notification_wake) = &*self.notification;
            let notification = notification
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let _notification = notification_wake
                .wait_while(notification, |thread| {
                    thread.is_some_and(|thread| thread != current_thread)
                })
                .unwrap_or_else(|error| error.into_inner());
            let (state, wake) = &*self.inner;
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            state.stopped = true;
            if let Some(stream) = state.stream.take() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            if let Some(holder) = state.holder.as_ref() {
                let (_, client_wake) = &*holder.inner;
                client_wake.notify_all();
            }
            wake.notify_all();
        }
    }

    /// A connection-bound client for the peer-authorized approval presenter session.
    pub struct ApprovalPresenterClient {
        stream: UnixStream,
        capability: String,
        summary: AuthorizationSummary,
        io_timeout: Duration,
    }

    #[derive(Clone, Debug, Default)]
    pub struct ApprovalPresenterStopHandle {
        inner: Arc<(Mutex<ApprovalPresenterStopState>, Condvar)>,
    }

    #[derive(Debug, Default)]
    struct ApprovalPresenterStopState {
        stopped: bool,
        stream: Option<UnixStream>,
    }

    impl ApprovalPresenterStopHandle {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn stop(&self) {
            let (state, wake) = &*self.inner;
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            state.stopped = true;
            if let Some(stream) = state.stream.take() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            wake.notify_all();
        }
    }

    impl std::fmt::Debug for ApprovalPresenterClient {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("ApprovalPresenterClient { .. }")
        }
    }

    impl ApprovalPresenterClient {
        pub fn capability(&self) -> &str {
            &self.capability
        }

        pub fn authorization_summary(&self) -> AuthorizationSummary {
            self.summary.clone()
        }

        pub fn present(
            &mut self,
            choose: impl FnOnce(&ApprovalPresentRequest) -> ApprovalDecision,
        ) -> Result<(), ClientError> {
            let request_deadline = deadline(self.io_timeout);
            let envelope: Envelope =
                serde_json::from_value(read_approval_value(&mut self.stream, request_deadline)?)
                    .map_err(|_| ClientError::UnexpectedMessage)?;
            let Envelope::Request(request) = envelope else {
                return Err(ClientError::UnexpectedMessage);
            };

            self.answer_present_request(request, choose)
        }

        fn answer_present_request(
            &mut self,
            request: Request,
            choose: impl FnOnce(&ApprovalPresentRequest) -> ApprovalDecision,
        ) -> Result<(), ClientError> {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Body {
                challenge: String,
                claimed_kind: String,
                claimed_version: String,
                workspace: String,
                scopes: Vec<String>,
                deadline_ms: u64,
            }

            let body = serde_json::from_value::<Body>(request.body.clone());
            let valid_text = |value: &str| {
                !value.is_empty()
                    && value.len() <= MAX_TEXT_LENGTH
                    && !value.chars().any(char::is_control)
            };
            let valid = request.capability == self.capability
                && request.operation == Operation::ApprovalPresent
                && request.idempotency_key.is_none()
                && body.as_ref().is_ok_and(|body| {
                    valid_text(&body.challenge)
                        && valid_text(&body.claimed_kind)
                        && valid_text(&body.claimed_version)
                        && valid_text(&body.workspace)
                        && body.scopes.len() <= crate::MAX_JSON_COLLECTION_ENTRIES
                        && body.scopes.iter().all(|scope| valid_text(scope))
                        && (1..=MAX_APPROVAL_DEADLINE_MS).contains(&body.deadline_ms)
                });
            if !valid {
                let error = ErrorEnvelope {
                    protocol: Protocol,
                    request_id: Some(request.request_id),
                    ok: crate::Failure,
                    error: crate::ProtocolError::unauthorized(),
                };
                let bytes = encode_frame(&error).map_err(map_frame_error)?;
                write_all_before(&mut self.stream, &bytes, deadline(self.io_timeout))?;
                return Err(ClientError::UnexpectedMessage);
            }

            let body = body.expect("validated approval request body");
            let approval = ApprovalPresentRequest {
                challenge: body.challenge,
                claimed_kind: body.claimed_kind,
                claimed_version: body.claimed_version,
                workspace: body.workspace,
                scopes: body.scopes,
                deadline_ms: body.deadline_ms,
            };
            let decision = choose(&approval);
            let response = Response {
                protocol: Protocol,
                request_id: request.request_id,
                ok: crate::Success,
                body: serde_json::json!({
                    "challenge": approval.challenge,
                    "decision": decision,
                }),
            };
            let bytes = encode_frame(&response).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline(self.io_timeout))
        }

        pub fn serve(
            &mut self,
            mut choose: impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
        ) -> Result<ApprovalPresenterServeOutcome, ClientError> {
            loop {
                self.stream
                    .set_read_timeout(None)
                    .map_err(|_| ClientError::DesktopUnavailable)?;
                let mut first = [0u8; 1];
                match self.stream.read(&mut first).map_err(map_io_error)? {
                    0 => return Ok(ApprovalPresenterServeOutcome::ConnectionClosed),
                    1 => {}
                    _ => unreachable!("a one-byte read returned more than one byte"),
                }

                let request_deadline = deadline(self.io_timeout);
                let mut prefix = [0u8; 4];
                prefix[0] = first[0];
                read_exact_before(&mut self.stream, &mut prefix[1..], request_deadline)?;
                let value =
                    read_approval_value_with_prefix(&mut self.stream, prefix, request_deadline)?;
                self.present_value(value, &mut choose)?;
            }
        }

        fn present_value(
            &mut self,
            value: Value,
            choose: &mut impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
        ) -> Result<(), ClientError> {
            let envelope: Envelope =
                serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)?;
            let Envelope::Request(request) = envelope else {
                return Err(ClientError::UnexpectedMessage);
            };

            self.answer_present_request(request, |approval| choose(approval))
        }

        pub fn into_stream(self) -> UnixStream {
            self.stream
        }
    }

    impl std::fmt::Debug for MigrationControlClient {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("MigrationControlClient { .. }")
        }
    }

    impl std::fmt::Debug for DesktopClient {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("DesktopClient { .. }")
        }
    }

    impl DesktopClient {
        pub fn capability(&self) -> &str {
            &self.capability
        }

        pub fn profile_id(&self) -> &str {
            &self.profile_id
        }

        pub fn workspace_scopes(&self) -> &BTreeMap<String, BTreeSet<String>> {
            &self.workspace_scopes
        }

        pub fn authorization_summary(&self) -> AuthorizationSummary {
            self.summary.clone()
        }

        pub fn request(
            &mut self,
            operation: Operation,
            idempotency_key: Option<Id>,
            body: Value,
        ) -> Result<Response, ClientError> {
            self.request_before(operation, idempotency_key, body, deadline(self.io_timeout))
        }

        fn request_before(
            &mut self,
            operation: Operation,
            idempotency_key: Option<Id>,
            body: Value,
            request_deadline: Instant,
        ) -> Result<Response, ClientError> {
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation,
                capability: self.capability.clone(),
                idempotency_key,
                body,
            };
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, request_deadline)?;
            match serde_json::from_value(read_value(&mut self.stream, request_deadline)?)
                .map_err(|_| ClientError::UnexpectedMessage)?
            {
                Envelope::Response(response) if response.request_id == request_id => Ok(response),
                Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                    Err(map_protocol_error(error.error.code()))
                }
                _ => Err(ClientError::UnexpectedMessage),
            }
        }

        pub fn rename_thread(&mut self, thread_id: &str, title: &str) -> Result<(), ClientError> {
            if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH || title.is_empty() {
                return Err(ClientError::UnexpectedMessage);
            }
            let response = self.request(
                Operation::ThreadRename,
                Some(fresh_request_id()?),
                serde_json::json!({"thread_id": thread_id, "title": title}),
            )?;
            if response.body != serde_json::json!({}) {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(())
        }

        pub fn delete_thread(&mut self, thread_id: &str) -> Result<(), ClientError> {
            if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let response = self.request(
                Operation::ThreadDelete,
                Some(fresh_request_id()?),
                serde_json::json!({"thread_id": thread_id}),
            )?;
            if response.body != serde_json::json!({}) {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(())
        }

        pub fn thread_select(&mut self, thread_id: &str) -> Result<(), ClientError> {
            if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let response = self.request(
                Operation::ThreadSelect,
                None,
                serde_json::json!({"thread_id": thread_id}),
            )?;
            if response.body != serde_json::json!({}) {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(())
        }

        pub fn run_submit(
            &mut self,
            text: &str,
            files: &[String],
            thread_id: Option<&str>,
        ) -> Result<RunSubmitAccepted, ClientError> {
            if text.trim().is_empty()
                || text.len() > MAX_TEXT_LENGTH
                || files
                    .iter()
                    .any(|file| file.trim().is_empty() || file.len() > MAX_TEXT_LENGTH)
                || thread_id.is_some_and(|thread_id| thread_id.is_empty() || thread_id.len() > 36)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            let response = self.request(
                Operation::RunSubmit,
                Some(fresh_request_id()?),
                serde_json::json!({"text": text, "files": files, "thread_id": thread_id}),
            )?;
            let accepted: RunSubmitAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if Id::new(accepted.run_id.clone()).is_err()
                || Id::new(accepted.thread_id.clone()).is_err()
                || thread_id.is_some_and(|thread_id| accepted.thread_id != thread_id)
                || accepted.committed_seq == 0
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
                || accepted.attachments.len() != files.len()
                || accepted.attachments.iter().any(|attachment| {
                    attachment.display_name.trim().is_empty()
                        || attachment.display_name.len() > MAX_TEXT_LENGTH
                        || attachment.media_type.as_ref().is_some_and(|media_type| {
                            media_type.trim().is_empty() || media_type.len() > MAX_TEXT_LENGTH
                        })
                })
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn run_cancel(&mut self, run_id: &str) -> Result<RunCancelAccepted, ClientError> {
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            let response = self.request(
                Operation::RunCancel,
                Some(fresh_request_id()?),
                serde_json::json!({"run_id": run_id.as_str()}),
            )?;
            let accepted: RunCancelAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if accepted.run_id != run_id.as_str()
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn run_resume(&mut self, run_id: &str) -> Result<RunResumeAccepted, ClientError> {
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            let response = self.request(
                Operation::RunResume,
                Some(fresh_request_id()?),
                serde_json::json!({"run_id": run_id.as_str()}),
            )?;
            let accepted: RunResumeAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if accepted.run_id != run_id.as_str()
                || Id::new(accepted.thread_id.clone()).is_err()
                || accepted.committed_seq == 0
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn run_permission_answer(
            &mut self,
            run_id: &str,
            gate_id: &str,
            answer: ChatPermissionAnswer,
        ) -> Result<RunPermissionAnswerAccepted, ClientError> {
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            if gate_id.trim().is_empty() || gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let response = self.request(
                Operation::RunPermissionAnswer,
                Some(fresh_request_id()?),
                serde_json::json!({
                    "run_id": run_id.as_str(),
                    "gate_id": gate_id,
                    "answer": &answer,
                }),
            )?;
            let accepted: RunPermissionAnswerAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if accepted.run_id != run_id.as_str()
                || accepted.gate_id != gate_id
                || accepted.answer != answer
                || accepted.committed_seq == 0
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn run_steer(
            &mut self,
            run_id: &str,
            text: &str,
        ) -> Result<RunMessageAccepted, ClientError> {
            self.run_message(Operation::RunSteer, run_id, text)
        }

        pub fn run_follow_up(
            &mut self,
            run_id: &str,
            text: &str,
        ) -> Result<RunMessageAccepted, ClientError> {
            self.run_message(Operation::RunFollowUp, run_id, text)
        }

        fn run_message(
            &mut self,
            operation: Operation,
            run_id: &str,
            text: &str,
        ) -> Result<RunMessageAccepted, ClientError> {
            let run_id = Id::new(run_id.to_owned()).map_err(|_| ClientError::UnexpectedMessage)?;
            if text.trim().is_empty() || text.len() > MAX_RUN_MESSAGE_TEXT_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let response = self.request(
                operation,
                Some(fresh_request_id()?),
                serde_json::json!({"run_id": run_id.as_str(), "text": text}),
            )?;
            let accepted: RunMessageAccepted = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if accepted.run_id != run_id.as_str()
                || accepted.accepted_at.is_empty()
                || accepted.accepted_at.len() > MAX_TEXT_LENGTH
                || !is_rfc3339(&accepted.accepted_at)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(accepted)
        }

        pub fn session_status(&mut self) -> Result<Value, ClientError> {
            self.request_body(
                Operation::SessionStatus,
                None,
                serde_json::json!({}),
                &["signed_in", "subject", "expires_at"],
            )
        }

        pub fn entitlement_snapshot(&mut self) -> Result<Value, ClientError> {
            self.request_body(
                Operation::EntitlementSnapshot,
                None,
                serde_json::json!({}),
                &["snapshot", "changed_snapshot_version"],
            )
        }

        pub fn list_devices(&mut self) -> Result<Value, ClientError> {
            self.request_body(
                Operation::DeviceList,
                None,
                serde_json::json!({}),
                &["devices"],
            )
        }

        pub fn sign_out(&mut self) -> Result<Value, ClientError> {
            self.request_body(
                Operation::SessionSignOut,
                Some(fresh_request_id()?),
                serde_json::json!({}),
                &["status"],
            )
        }

        pub fn sign_in(&mut self) -> Result<Value, ClientError> {
            let body = self
                .request_before(
                    Operation::SessionSignIn,
                    Some(fresh_request_id()?),
                    serde_json::json!({}),
                    deadline(SIGN_IN_TIMEOUT),
                )?
                .body;
            let object = body.as_object().ok_or(ClientError::UnexpectedMessage)?;
            if !object.contains_key("status") {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(body)
        }

        pub fn thread_summaries(
            &mut self,
            limit: u8,
            cursor: Option<&str>,
        ) -> Result<Value, ClientError> {
            let body = thread_read_body(limit, cursor)?;
            Ok(self.request(Operation::ThreadSummaries, None, body)?.body)
        }

        pub fn thread_history(
            &mut self,
            thread_id: &str,
            limit: u8,
            cursor: Option<&str>,
        ) -> Result<Value, ClientError> {
            if thread_id.is_empty() || thread_id.len() > MAX_THREAD_ID_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let mut body = thread_read_body(limit, cursor)?;
            body["thread_id"] = Value::String(thread_id.into());
            Ok(self.request(Operation::ThreadHistory, None, body)?.body)
        }

        pub fn subscribe_chat_events(&mut self) -> Result<String, ClientError> {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Subscription {
                subscription_id: String,
            }

            let response = self.request(Operation::RunChatEvents, None, serde_json::json!({}))?;
            let subscription: Subscription = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            let subscription_id = Id::new(subscription.subscription_id)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            let result = subscription_id.as_str().to_owned();
            self.chat_subscription_id = Some(subscription_id);
            Ok(result)
        }

        pub fn read_chat_event(&mut self) -> Result<Value, ClientError> {
            let subscription_id = self
                .chat_subscription_id
                .as_ref()
                .ok_or(ClientError::UnexpectedMessage)?;
            let authorization_remaining = Duration::from_secs(self.summary.expires_in_seconds)
                .saturating_sub(self.authorized_at.elapsed());
            let wait =
                authorization_remaining.min(Duration::from_secs(self.summary.idle_timeout_seconds));
            if wait.is_zero() {
                return Err(ClientError::AuthorizationExpired);
            }
            let value = read_value(&mut self.stream, deadline(wait)).map_err(|error| {
                if error == ClientError::ConnectionClosed {
                    ClientError::DesktopUnavailable
                } else {
                    error
                }
            })?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let event =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Event(event) => event,
                    Envelope::Error(error) => return Err(map_protocol_error(error.error.code())),
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            if event.event == EventName::CapabilityRevoked {
                AuthorizedClient::validate_capability_revocation(&event)?
                    .ok_or(ClientError::UnexpectedMessage)?;
                return Err(ClientError::CapabilityRevoked);
            }
            if &event.subscription_id != subscription_id
                || event.event != EventName::ChatEvent
                || event.run_id.is_some()
                || event.run_seq.is_some()
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(event.body)
        }

        pub fn list_companions(&mut self) -> Result<Value, ClientError> {
            self.request_body(
                Operation::CompanionList,
                None,
                serde_json::json!({}),
                &["companions"],
            )
        }

        pub fn revoke_companion(&mut self, client_identity: &str) -> Result<Value, ClientError> {
            if client_identity.is_empty() || client_identity.len() > MAX_TEXT_LENGTH {
                return Err(ClientError::UnexpectedMessage);
            }
            let body = self.request_body(
                Operation::CompanionRevoke,
                Some(fresh_request_id()?),
                serde_json::json!({"client_identity": client_identity}),
                &[],
            )?;
            if body != serde_json::json!({}) {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(body)
        }

        fn request_body(
            &mut self,
            operation: Operation,
            idempotency_key: Option<Id>,
            body: Value,
            expected_keys: &[&str],
        ) -> Result<Value, ClientError> {
            let body = self.request(operation, idempotency_key, body)?.body;
            let object = body.as_object().ok_or(ClientError::UnexpectedMessage)?;
            if !expected_keys.iter().all(|key| object.contains_key(*key)) {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(body)
        }

        pub fn into_stream(self) -> UnixStream {
            self.stream
        }
    }

    fn thread_read_body(limit: u8, cursor: Option<&str>) -> Result<Value, ClientError> {
        if limit == 0
            || limit > 100
            || cursor.is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        let mut body = serde_json::json!({"limit": limit});
        if let Some(cursor) = cursor {
            body["cursor"] = Value::String(cursor.into());
        }
        Ok(body)
    }

    impl MigrationControlClient {
        pub fn capability(&self) -> &str {
            &self.capability
        }

        pub fn authorization_summary(&self) -> AuthorizationSummary {
            self.summary.clone()
        }

        pub fn control_migration(
            &mut self,
            handoff_nonce: &str,
            deadline_ms: u64,
        ) -> Result<MigrationControlOutcome, MigrationControlFailure> {
            if handoff_nonce.is_empty()
                || handoff_nonce.len() > MAX_HANDOFF_NONCE_BYTES
                || !handoff_nonce
                    .bytes()
                    .all(|byte| (b' '..=b'~').contains(&byte))
            {
                return Err(MigrationControlFailure::InvalidNonce);
            }
            if !(1..=MAX_HANDOFF_DEADLINE_MS).contains(&deadline_ms) {
                return Err(MigrationControlFailure::InvalidDeadline);
            }

            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::MigrationControl,
                capability: self.capability.clone(),
                idempotency_key: None,
                body: serde_json::json!({
                    "handoff_nonce": handoff_nonce,
                    "deadline_ms": deadline_ms,
                }),
            };
            let request_deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, request_deadline)?;
            let envelope: Envelope =
                serde_json::from_value(read_value(&mut self.stream, request_deadline)?)
                    .map_err(|_| ClientError::UnexpectedMessage)?;
            match envelope {
                Envelope::Response(response) if response.request_id == request_id => {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Body {
                        handoff_nonce: String,
                    }
                    let body: Body = serde_json::from_value(response.body)
                        .map_err(|_| ClientError::UnexpectedMessage)?;
                    if body.handoff_nonce != handoff_nonce {
                        return Err(MigrationControlFailure::NonceMismatch);
                    }
                    Ok(MigrationControlOutcome::Accepted)
                }
                Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                    Ok(match error.error.code() {
                        ErrorCode::MigrationNotReady => {
                            MigrationControlOutcome::MigrationNotReady {
                                retryable: error.error.retryable(),
                            }
                        }
                        ErrorCode::Unauthorized => MigrationControlOutcome::Unauthorized,
                        ErrorCode::UnsupportedOperation => {
                            MigrationControlOutcome::UnsupportedOperation
                        }
                        code => return Err(map_protocol_error(code).into()),
                    })
                }
                _ => Err(ClientError::UnexpectedMessage.into()),
            }
        }

        pub fn into_stream(self) -> UnixStream {
            self.stream
        }
    }

    fn is_rfc3339(value: &str) -> bool {
        let bytes = value.as_bytes();
        if bytes.len() < 20
            || bytes.get(4) != Some(&b'-')
            || bytes.get(7) != Some(&b'-')
            || !matches!(bytes.get(10), Some(b'T' | b't'))
            || bytes.get(13) != Some(&b':')
            || bytes.get(16) != Some(&b':')
        {
            return false;
        }

        let number = |start: usize, end: usize| {
            bytes
                .get(start..end)
                .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u32>().ok())
        };
        let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
            number(0, 4),
            number(5, 7),
            number(8, 10),
            number(11, 13),
            number(14, 16),
            number(17, 19),
        ) else {
            return false;
        };
        let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap_year => 29,
            2 => 28,
            _ => return false,
        };
        if day == 0 || day > max_day || hour > 23 || minute > 59 || second > 60 {
            return false;
        }

        let mut zone = 19;
        if bytes.get(zone) == Some(&b'.') {
            zone += 1;
            let fraction_start = zone;
            while bytes.get(zone).is_some_and(u8::is_ascii_digit) {
                zone += 1;
            }
            if zone == fraction_start {
                return false;
            }
        }
        match bytes.get(zone..) {
            Some([b'Z' | b'z']) => true,
            Some([b'+' | b'-', h1, h2, b':', m1, m2]) => {
                [h1, h2, m1, m2].iter().all(|digit| digit.is_ascii_digit())
                    && (h1 - b'0') * 10 + (h2 - b'0') <= 23
                    && (m1 - b'0') * 10 + (m2 - b'0') <= 59
            }
            _ => false,
        }
    }

    pub fn handshake(
        client_version: &str,
        client_kind: &str,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        let identity = fresh_request_id()?;
        handshake_as(
            client_version,
            client_kind,
            identity.as_str(),
            pairing_pending,
        )
    }

    pub fn handshake_as(
        client_version: &str,
        client_kind: &str,
        authorized_client_id: &str,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        handshake_as_with_credential(
            client_version,
            client_kind,
            authorized_client_id,
            None,
            pairing_pending,
        )
    }

    pub fn handshake_as_with_credential(
        client_version: &str,
        client_kind: &str,
        authorized_client_id: &str,
        authorized_client_credential: Option<&str>,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        let endpoint = endpoint_from_environment()?;
        let stream = UnixStream::connect(endpoint).map_err(|_| ClientError::DesktopUnavailable)?;
        handshake_stream_with_identity(
            stream,
            client_version,
            ClientIdentity {
                kind: client_kind,
                id: authorized_client_id,
                credential: authorized_client_credential,
            },
            IO_TIMEOUT,
            APPROVAL_TIMEOUT,
            pairing_pending,
        )
    }

    pub fn connect_approval_presenter(
        client_version: &str,
    ) -> Result<ApprovalPresenterClient, ClientError> {
        let endpoint = endpoint_from_environment()?;
        connect_approval_presenter_at(&endpoint, client_version, IO_TIMEOUT)
    }

    pub fn connect_desktop_client(client_version: &str) -> Result<DesktopClient, ClientError> {
        let endpoint = endpoint_from_environment()?;
        connect_desktop_client_at(&endpoint, client_version, IO_TIMEOUT)
    }

    #[doc(hidden)]
    pub fn connect_desktop_client_at(
        endpoint: &Path,
        client_version: &str,
        io_timeout: Duration,
    ) -> Result<DesktopClient, ClientError> {
        let stream = UnixStream::connect(endpoint).map_err(|_| ClientError::DesktopUnavailable)?;
        handshake_desktop_client_stream(stream, client_version, io_timeout)
    }

    #[doc(hidden)]
    pub fn connect_approval_presenter_at(
        endpoint: &Path,
        client_version: &str,
        io_timeout: Duration,
    ) -> Result<ApprovalPresenterClient, ClientError> {
        let stream = UnixStream::connect(endpoint).map_err(|_| ClientError::DesktopUnavailable)?;
        handshake_approval_presenter_stream(stream, client_version, io_timeout)
    }

    pub fn serve_approval_presenter_at(
        endpoint: &Path,
        client_version: &str,
        io_timeout: Duration,
        retry_interval: Duration,
        stop: ApprovalPresenterStopHandle,
        mut observe: impl FnMut(bool),
        mut choose: impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
    ) {
        loop {
            let (state, wake) = &*stop.inner;
            let connected = interruptible_connect(endpoint, &stop);

            if let Some(stream) = connected {
                if let Ok(mut presenter) =
                    handshake_approval_presenter_stream(stream, client_version, io_timeout)
                {
                    observe(true);
                    let _ = presenter.serve(&mut choose);
                    observe(false);
                }
                let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                state.stream = None;
            }

            let state = state.lock().unwrap_or_else(|error| error.into_inner());
            if state.stopped {
                return;
            }
            let (state, _) = wake
                .wait_timeout_while(state, retry_interval, |state| !state.stopped)
                .unwrap_or_else(|error| error.into_inner());
            if state.stopped {
                return;
            }
        }
    }

    pub fn serve_desktop_client_at(
        endpoint: &Path,
        client_version: &str,
        io_timeout: Duration,
        retry_interval: Duration,
        stop: DesktopClientStopHandle,
        holder: DesktopClientHolder,
        mut observe: impl FnMut(bool),
    ) {
        {
            let (state, _) = &*stop.inner;
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            if state.stopped {
                return;
            }
            state.holder = Some(holder.clone());
        }
        loop {
            let connected = interruptible_desktop_connect(endpoint, &stop);
            if let Some(stream) = connected {
                if let Ok(client) =
                    handshake_desktop_client_stream(stream, client_version, io_timeout)
                {
                    let (notification_lock, notification_wake) = &*stop.notification;
                    let mut notification = notification_lock
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let (stop_state, _) = &*stop.inner;
                    let stop_state = stop_state.lock().unwrap_or_else(|error| error.into_inner());
                    if stop_state.stopped {
                        return;
                    }
                    let (held, wake) = &*holder.inner;
                    *held.lock().unwrap_or_else(|error| error.into_inner()) = Some(client);
                    *notification = Some(std::thread::current().id());
                    drop(stop_state);
                    drop(notification);
                    observe(true);
                    let mut notification = notification_lock
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    *notification = None;
                    notification_wake.notify_all();
                    drop(notification);
                    let connection = held.lock().unwrap_or_else(|error| error.into_inner());
                    let mut connection = wake
                        .wait_while(connection, |client| {
                            if client.is_none() {
                                return false;
                            }
                            let (state, _) = &*stop.inner;
                            !state
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .stopped
                        })
                        .unwrap_or_else(|error| error.into_inner());
                    *connection = None;
                    observe(false);
                }
                clear_desktop_stream(&stop);
            }

            let (state, wake) = &*stop.inner;
            let state = state.lock().unwrap_or_else(|error| error.into_inner());
            if state.stopped {
                return;
            }
            let (state, _) = wake
                .wait_timeout_while(state, retry_interval, |state| !state.stopped)
                .unwrap_or_else(|error| error.into_inner());
            if state.stopped {
                return;
            }
        }
    }

    fn interruptible_desktop_connect(
        endpoint: &Path,
        stop: &DesktopClientStopHandle,
    ) -> Option<UnixStream> {
        interruptible_connect_with_state(endpoint, &stop.inner)
    }

    fn interruptible_connect(
        endpoint: &Path,
        stop: &ApprovalPresenterStopHandle,
    ) -> Option<UnixStream> {
        interruptible_connect_with_state(endpoint, &stop.inner)
    }

    pub fn interruptible_connect_with_state<S>(
        endpoint: &Path,
        stop: &Arc<(Mutex<S>, Condvar)>,
    ) -> Option<UnixStream>
    where
        S: InterruptibleConnectState,
    {
        let path = endpoint.as_os_str().as_bytes();
        if path.is_empty() || path.len() >= 108 || path.contains(&0) {
            return None;
        }
        // SAFETY: The constants and arguments match Linux's socket(2) interface.
        let descriptor = unsafe { socket(1, 1 | 0x800 | 0x80000, 0) };
        if descriptor < 0 {
            return None;
        }
        // SAFETY: `descriptor` is a new owned descriptor from socket(2).
        let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
        let interrupt = stream.try_clone().ok()?;
        let mut address = UnixSocketAddress {
            family: 1,
            path: [0; 108],
        };
        address.path[..path.len()].copy_from_slice(path);

        let connect_result = {
            let (state, _) = &**stop;
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            if state.stopped() {
                return None;
            }
            state.set_stream(Some(interrupt));
            // SAFETY: `address` has a valid AF_UNIX family and a terminated pathname.
            unsafe {
                connect(
                    descriptor,
                    &address,
                    (std::mem::size_of::<u16>() + path.len() + 1) as u32,
                )
            }
        };
        if connect_result < 0 && io::Error::last_os_error().raw_os_error() != Some(115) {
            clear_interruptible_stream(stop);
            return None;
        }

        if connect_result < 0 {
            let mut ready = PollFd {
                fd: descriptor,
                events: POLLOUT,
                revents: 0,
            };
            loop {
                // SAFETY: `ready` points to one valid pollfd for this call.
                let result = unsafe { poll(&mut ready, 1, 50) };
                let (state, _) = &**stop;
                if state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .stopped()
                {
                    clear_interruptible_stream(stop);
                    return None;
                }
                if result > 0 {
                    break;
                }
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    clear_interruptible_stream(stop);
                    return None;
                }
            }
            let mut error = 0;
            let mut length = std::mem::size_of::<i32>() as u32;
            // SAFETY: `error` and `length` are valid output pointers for SO_ERROR.
            if unsafe { getsockopt(descriptor, 1, 4, &mut error, &mut length) } < 0 || error != 0 {
                clear_interruptible_stream(stop);
                return None;
            }
        }
        if stream.set_nonblocking(false).is_err() {
            clear_interruptible_stream(stop);
            return None;
        }
        Some(stream)
    }

    pub trait InterruptibleConnectState {
        fn stopped(&self) -> bool;
        fn set_stream(&mut self, stream: Option<UnixStream>);
    }

    impl InterruptibleConnectState for ApprovalPresenterStopState {
        fn stopped(&self) -> bool {
            self.stopped
        }
        fn set_stream(&mut self, stream: Option<UnixStream>) {
            self.stream = stream;
        }
    }

    impl InterruptibleConnectState for DesktopClientStopState {
        fn stopped(&self) -> bool {
            self.stopped
        }
        fn set_stream(&mut self, stream: Option<UnixStream>) {
            self.stream = stream;
        }
    }

    fn clear_interruptible_stream<S: InterruptibleConnectState>(stop: &Arc<(Mutex<S>, Condvar)>) {
        let (state, _) = &**stop;
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .set_stream(None);
    }

    fn clear_desktop_stream(stop: &DesktopClientStopHandle) {
        clear_interruptible_stream(&stop.inner);
    }

    fn endpoint_from_environment() -> Result<PathBuf, ClientError> {
        let runtime = env::var_os("XDG_RUNTIME_DIR")
            .ok_or(ClientError::RuntimeDirectoryMissing)
            .map(PathBuf::from)?;
        if !runtime.is_absolute() {
            return Err(ClientError::RuntimeDirectoryRelative);
        }
        Ok(runtime.join("muniment").join("attach-v1.sock"))
    }

    #[doc(hidden)]
    pub fn handshake_stream(
        stream: UnixStream,
        client_version: &str,
        io_timeout: Duration,
        approval_timeout: Duration,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        let identity = fresh_request_id()?;
        handshake_stream_as(
            stream,
            client_version,
            identity.as_str(),
            io_timeout,
            approval_timeout,
            pairing_pending,
        )
    }

    #[doc(hidden)]
    pub fn handshake_stream_as(
        stream: UnixStream,
        client_version: &str,
        authorized_client_id: &str,
        io_timeout: Duration,
        approval_timeout: Duration,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        handshake_stream_with_credential(
            stream,
            client_version,
            authorized_client_id,
            None,
            io_timeout,
            approval_timeout,
            pairing_pending,
        )
    }

    #[doc(hidden)]
    pub fn handshake_stream_with_credential(
        stream: UnixStream,
        client_version: &str,
        authorized_client_id: &str,
        authorized_client_credential: Option<&str>,
        io_timeout: Duration,
        approval_timeout: Duration,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        handshake_stream_with_identity(
            stream,
            client_version,
            ClientIdentity {
                kind: "cli",
                id: authorized_client_id,
                credential: authorized_client_credential,
            },
            io_timeout,
            approval_timeout,
            pairing_pending,
        )
    }

    #[doc(hidden)]
    pub fn handshake_migration_control_stream(
        mut stream: UnixStream,
        client_version: &str,
        io_timeout: Duration,
    ) -> Result<MigrationControlClient, ClientError> {
        let hello = Hello {
            protocol: Protocol,
            client: Client {
                kind: "runtime".into(),
                version: client_version.into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: fresh_nonce()?,
            authorized_client_id: Id::new(fresh_request_id()?.as_str())
                .map_err(|_| ClientError::UnexpectedMessage)?,
            authorized_client_credential: None,
        };
        let bytes = encode_frame(&hello).map_err(map_frame_error)?;
        write_all_before(&mut stream, &bytes, deadline(io_timeout))?;

        let welcome_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&welcome_value)?;
        let welcome: Welcome = parse_message(welcome_value)?;
        if welcome.selected != 1
            || welcome.authorization != Authorization::Authorized
            || !is_hex_secret(&welcome.server_nonce, 32)
        {
            return Err(ClientError::UnexpectedMessage);
        }

        let authorized_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&authorized_value)?;
        if authorized_value
            .get("authorized_client_credential")
            .is_some()
        {
            return Err(ClientError::UnexpectedMessage);
        }
        let authorized: PeerAuthorizedGrant = parse_message(authorized_value)?;
        if !is_hex_secret(&authorized.capability, 64)
            || authorized.expires_at == 0
            || authorized.expires_at > 8 * 60 * 60
            || authorized.idle_timeout_seconds == 0
            || authorized.idle_timeout_seconds > 15 * 60
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(MigrationControlClient {
            stream,
            capability: authorized.capability,
            summary: AuthorizationSummary {
                expires_in_seconds: authorized.expires_at,
                idle_timeout_seconds: authorized.idle_timeout_seconds,
            },
            io_timeout,
        })
    }

    #[doc(hidden)]
    pub fn handshake_desktop_client_stream(
        mut stream: UnixStream,
        client_version: &str,
        io_timeout: Duration,
    ) -> Result<DesktopClient, ClientError> {
        let hello = Hello {
            protocol: Protocol,
            client: Client {
                kind: "desktop-client".into(),
                version: client_version.into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: fresh_nonce()?,
            authorized_client_id: Id::new(fresh_request_id()?.as_str())
                .map_err(|_| ClientError::UnexpectedMessage)?,
            authorized_client_credential: None,
        };
        let bytes = encode_frame(&hello).map_err(map_frame_error)?;
        write_all_before(&mut stream, &bytes, deadline(io_timeout))?;

        let welcome_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&welcome_value)?;
        let welcome: Welcome = parse_message(welcome_value)?;
        if welcome.selected != 1
            || welcome.authorization != Authorization::Authorized
            || !is_hex_secret(&welcome.server_nonce, 32)
        {
            return Err(ClientError::UnexpectedMessage);
        }

        let authorized_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&authorized_value)?;
        if authorized_value
            .get("authorized_client_credential")
            .is_some()
        {
            return Err(ClientError::UnexpectedMessage);
        }
        let authorized: DesktopClientAuthorizedGrant = parse_message(authorized_value)?;
        if authorized.workspace_scopes.len() != 1
            || !is_hex_secret(&authorized.capability, 64)
            || authorized.expires_at == 0
            || authorized.expires_at > 8 * 60 * 60
            || authorized.idle_timeout_seconds == 0
            || authorized.idle_timeout_seconds > 15 * 60
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(DesktopClient {
            stream,
            profile_id: authorized.profile_id,
            workspace_scopes: authorized.workspace_scopes,
            capability: authorized.capability,
            summary: AuthorizationSummary {
                expires_in_seconds: authorized.expires_at,
                idle_timeout_seconds: authorized.idle_timeout_seconds,
            },
            authorized_at: Instant::now(),
            chat_subscription_id: None,
            io_timeout,
        })
    }

    #[doc(hidden)]
    pub fn handshake_approval_presenter_stream(
        mut stream: UnixStream,
        client_version: &str,
        io_timeout: Duration,
    ) -> Result<ApprovalPresenterClient, ClientError> {
        let hello = Hello {
            protocol: Protocol,
            client: Client {
                kind: "desktop".into(),
                version: client_version.into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: fresh_nonce()?,
            authorized_client_id: Id::new(fresh_request_id()?.as_str())
                .map_err(|_| ClientError::UnexpectedMessage)?,
            authorized_client_credential: None,
        };
        let bytes = encode_frame(&hello).map_err(map_frame_error)?;
        write_all_before(&mut stream, &bytes, deadline(io_timeout))?;

        let welcome_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&welcome_value)?;
        let welcome: Welcome = parse_message(welcome_value)?;
        if welcome.selected != 1
            || welcome.authorization != Authorization::Authorized
            || !is_hex_secret(&welcome.server_nonce, 32)
        {
            return Err(ClientError::UnexpectedMessage);
        }

        let authorized_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&authorized_value)?;
        if authorized_value
            .get("authorized_client_credential")
            .is_some()
        {
            return Err(ClientError::UnexpectedMessage);
        }
        let authorized: PeerAuthorizedGrant = parse_message(authorized_value)?;
        if !is_hex_secret(&authorized.capability, 64)
            || authorized.expires_at == 0
            || authorized.expires_at > 8 * 60 * 60
            || authorized.idle_timeout_seconds == 0
            || authorized.idle_timeout_seconds > 15 * 60
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(ApprovalPresenterClient {
            stream,
            capability: authorized.capability,
            summary: AuthorizationSummary {
                expires_in_seconds: authorized.expires_at,
                idle_timeout_seconds: authorized.idle_timeout_seconds,
            },
            io_timeout,
        })
    }

    fn handshake_stream_with_identity(
        mut stream: UnixStream,
        client_version: &str,
        identity: ClientIdentity<'_>,
        io_timeout: Duration,
        approval_timeout: Duration,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        let authorized_client_id =
            Id::new(identity.id).map_err(|_| ClientError::UnexpectedMessage)?;
        let hello = Hello {
            protocol: Protocol,
            client: Client {
                kind: identity.kind.into(),
                version: client_version.into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: fresh_nonce()?,
            authorized_client_id,
            authorized_client_credential: identity.credential.map(str::to_owned),
        };
        let bytes = encode_frame(&hello).map_err(map_frame_error)?;
        write_all_before(&mut stream, &bytes, deadline(io_timeout))?;

        let welcome_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&welcome_value)?;
        let welcome: Welcome = parse_message(welcome_value)?;
        if welcome.selected != 1 {
            return Err(ClientError::ProtocolIncompatible);
        }
        if !is_hex_secret(&welcome.server_nonce, 32)
            || !is_hex_secret(&welcome.approval_challenge, 32)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        if welcome.authorization == Authorization::PairingRequired {
            pairing_pending();
        }

        let authorized_value = read_value(&mut stream, deadline(approval_timeout))?;
        reject_protocol_error(&authorized_value)?;
        let authorized: Authorized = parse_message(authorized_value)?;
        if !is_hex_secret(&authorized.capability, 64)
            || !is_hex_secret(&authorized.authorized_client_credential, 64)
            || authorized.expires_at == 0
            || authorized.expires_at > 8 * 60 * 60
            || authorized.idle_timeout_seconds == 0
            || authorized.idle_timeout_seconds > 15 * 60
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(AuthorizedClient {
            stream,
            profile_id: authorized.profile_id,
            capability: authorized.capability,
            summary: AuthorizationSummary {
                expires_in_seconds: authorized.expires_at,
                idle_timeout_seconds: authorized.idle_timeout_seconds,
            },
            authorized_at: Instant::now(),
            io_timeout,
            active_run_stream: None,
            authorized_client_credential: authorized.authorized_client_credential,
        })
    }

    fn fresh_request_id() -> Result<Id, ClientError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClientError::RandomnessUnavailable)?
            .as_millis();
        if timestamp > 0xffff_ffff_ffff {
            return Err(ClientError::RandomnessUnavailable);
        }
        let mut bytes = random_bytes()?;
        bytes[..6].copy_from_slice(&(timestamp as u64).to_be_bytes()[2..]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Id::new(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
        .map_err(|_| ClientError::RandomnessUnavailable)
    }

    fn map_protocol_error(code: ErrorCode) -> ClientError {
        match code {
            ErrorCode::ProtocolIncompatible => ClientError::ProtocolIncompatible,
            ErrorCode::Unauthorized => ClientError::AuthorizationExpired,
            ErrorCode::ThreadNotFound => ClientError::ThreadNotFound,
            ErrorCode::PersistenceFailed => ClientError::DesktopFailed,
            _ => ClientError::RequestRejected,
        }
    }

    fn fresh_nonce() -> Result<String, ClientError> {
        let bytes = random_bytes()?;
        let mut nonce = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut nonce, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(nonce)
    }

    fn random_bytes() -> Result<[u8; 16], ClientError> {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| ClientError::RandomnessUnavailable)?;
        Ok(bytes)
    }

    fn is_hex_secret(value: &str, length: usize) -> bool {
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn deadline(timeout: Duration) -> Instant {
        Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now)
    }

    fn remaining(deadline: Instant) -> Result<Duration, ClientError> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ClientError::Timeout)
    }

    fn read_exact_before(
        stream: &mut UnixStream,
        mut bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), ClientError> {
        while !bytes.is_empty() {
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|_| ClientError::DesktopUnavailable)?;
            match stream.read(bytes).map_err(map_io_error)? {
                0 => return Err(ClientError::ConnectionClosed),
                read => bytes = &mut bytes[read..],
            }
        }
        Ok(())
    }

    fn write_all_before(
        stream: &mut UnixStream,
        mut bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), ClientError> {
        while !bytes.is_empty() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| ClientError::DesktopUnavailable)?;
            match stream.write(bytes).map_err(map_io_error)? {
                0 => return Err(ClientError::ConnectionClosed),
                written => bytes = &bytes[written..],
            }
        }
        Ok(())
    }

    fn read_value(stream: &mut UnixStream, deadline: Instant) -> Result<Value, ClientError> {
        let mut prefix = [0u8; 4];
        read_exact_before(stream, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_FRAME_LENGTH {
            return Err(ClientError::PayloadTooLarge);
        }
        let mut frame = vec![0u8; length + 4];
        frame[..4].copy_from_slice(&prefix);
        read_exact_before(stream, &mut frame[4..], deadline)?;
        decode_frame(&frame)
            .map_err(map_frame_error)?
            .map(|(value, _)| value)
            .ok_or(ClientError::MalformedFrame)
    }

    fn read_approval_value(
        stream: &mut UnixStream,
        deadline: Instant,
    ) -> Result<Value, ClientError> {
        let mut prefix = [0u8; 4];
        read_exact_before(stream, &mut prefix, deadline)?;
        read_approval_value_with_prefix(stream, prefix, deadline)
    }

    fn read_approval_value_with_prefix(
        stream: &mut UnixStream,
        prefix: [u8; 4],
        deadline: Instant,
    ) -> Result<Value, ClientError> {
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_FRAME_LENGTH {
            return Err(ClientError::PayloadTooLarge);
        }
        let mut frame = vec![0u8; length];
        read_exact_before(stream, &mut frame, deadline)?;
        serde_json::from_slice(&frame).map_err(|_| ClientError::MalformedFrame)
    }

    fn reject_protocol_error(value: &Value) -> Result<(), ClientError> {
        if value
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|p| p != PROTOCOL)
        {
            return Err(ClientError::ProtocolIncompatible);
        }
        if value.get("ok") == Some(&Value::Bool(false)) {
            let error: ErrorEnvelope =
                serde_json::from_value(value.clone()).map_err(|_| ClientError::MalformedFrame)?;
            return Err(if error.error.code() == ErrorCode::ProtocolIncompatible {
                ClientError::ProtocolIncompatible
            } else {
                ClientError::UnexpectedMessage
            });
        }
        Ok(())
    }

    fn parse_message<T: DeserializeOwned>(value: Value) -> Result<T, ClientError> {
        serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)
    }

    fn map_frame_error(error: FrameError) -> ClientError {
        match error {
            FrameError::PayloadTooLarge => ClientError::PayloadTooLarge,
            _ => ClientError::MalformedFrame,
        }
    }

    fn map_io_error(error: io::Error) -> ClientError {
        match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ClientError::Timeout,
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe => ClientError::ConnectionClosed,
            _ => ClientError::DesktopUnavailable,
        }
    }

    #[cfg(test)]
    mod holder_tests {
        use super::*;
        use std::sync::Barrier;

        #[test]
        fn slow_call_makes_second_caller_busy_without_clearing_client() {
            let holder = DesktopClientHolder::new();
            let (stream, _peer) = UnixStream::pair().unwrap();
            let desktop_client = DesktopClient {
                stream,
                profile_id: "profile".to_string(),
                workspace_scopes: BTreeMap::new(),
                capability: "capability".to_string(),
                summary: AuthorizationSummary {
                    expires_in_seconds: 60,
                    idle_timeout_seconds: 60,
                },
                authorized_at: Instant::now(),
                chat_subscription_id: None,
                io_timeout: IO_TIMEOUT,
            };
            let (client, _) = &*holder.inner;
            *client.lock().unwrap() = Some(desktop_client);

            let entered = Arc::new(Barrier::new(2));
            let slow_holder = holder.clone();
            let slow_entered = entered.clone();
            let slow_call = std::thread::spawn(move || {
                slow_holder.with_client(|_| {
                    slow_entered.wait();
                    std::thread::sleep(DESKTOP_CLIENT_LOCK_TIMEOUT * 3);
                    Ok(())
                })
            });
            entered.wait();

            let started = Instant::now();
            assert_eq!(holder.session_status(), Err(ClientError::DesktopBusy));
            assert!(started.elapsed() < DESKTOP_CLIENT_LOCK_TIMEOUT * 2);
            assert_eq!(slow_call.join().unwrap(), Ok(()));
            assert!(client.lock().unwrap().is_some());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    connect_approval_presenter, connect_approval_presenter_at, connect_desktop_client,
    connect_desktop_client_at, handshake_approval_presenter_stream,
    handshake_desktop_client_stream, handshake_migration_control_stream, handshake_stream,
    handshake_stream_with_credential, interruptible_connect_with_state,
    serve_approval_presenter_at, serve_desktop_client_at, ApprovalPresenterClient,
    ApprovalPresenterStopHandle, AuthorizedClient, DesktopClient, DesktopClientHolder,
    DesktopClientStopHandle, InterruptibleConnectState, MigrationControlClient,
};

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct AuthorizedClient;

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct DesktopClient;

#[cfg(not(target_os = "linux"))]
impl DesktopClient {
    pub fn run_submit(
        &mut self,
        _text: &str,
        _files: &[String],
        _thread_id: Option<&str>,
    ) -> Result<RunSubmitAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_resume(&mut self, _run_id: &str) -> Result<RunResumeAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_permission_answer(
        &mut self,
        _run_id: &str,
        _gate_id: &str,
        _answer: ChatPermissionAnswer,
    ) -> Result<RunPermissionAnswerAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_steer(
        &mut self,
        _run_id: &str,
        _text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_follow_up(
        &mut self,
        _run_id: &str,
        _text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Default)]
pub struct DesktopClientHolder;

#[cfg(not(target_os = "linux"))]
impl DesktopClientHolder {
    pub fn new() -> Self {
        Self
    }

    pub fn run_submit(
        &self,
        _text: &str,
        _files: &[String],
        _thread_id: Option<&str>,
    ) -> Result<RunSubmitAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_cancel(&self, _run_id: &str) -> Result<RunCancelAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_resume(&self, _run_id: &str) -> Result<RunResumeAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_permission_answer(
        &self,
        _run_id: &str,
        _gate_id: &str,
        _answer: ChatPermissionAnswer,
    ) -> Result<RunPermissionAnswerAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_steer(&self, _run_id: &str, _text: &str) -> Result<RunMessageAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_follow_up(
        &self,
        _run_id: &str,
        _text: &str,
    ) -> Result<RunMessageAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
}

#[cfg(not(target_os = "linux"))]
impl AuthorizedClient {
    pub fn onboard_workspace(
        &mut self,
        _opened_directory: &str,
        _memory_location: &str,
    ) -> Result<crate::WorkspaceOnboarded, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
    pub fn ensure_home(&mut self) -> Result<(), ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
    pub fn list_threads(&mut self, _cursor: Option<&str>) -> Result<ThreadListPage, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn create_thread(&mut self) -> Result<ThreadCreateAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn open_thread(
        &mut self,
        _thread_id: &str,
        _cursor: Option<&str>,
    ) -> Result<ThreadOpenPage, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn start_run(
        &mut self,
        _text: &str,
        _context: Option<serde_json::Value>,
    ) -> Result<RunStartAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
    pub fn start_run_in_workspace(
        &mut self,
        _text: &str,
        _context: Option<serde_json::Value>,
        _workspace: Option<&str>,
    ) -> Result<RunStartAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
    pub fn start_run_in_workspace_thread(
        &mut self,
        _text: &str,
        _context: Option<serde_json::Value>,
        _workspace: Option<&str>,
        _thread_id: Option<&str>,
    ) -> Result<RunStartAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn answer_permission(
        &mut self,
        _run_id: &str,
        _gate_id: &str,
        _decision: PermissionDecision,
    ) -> Result<PermissionAnswerAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn run_cancel(&mut self, _run_id: &str) -> Result<RunCancelAccepted, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn subscribe_run(
        &mut self,
        _run_id: &str,
        _after_run_seq: u64,
    ) -> Result<RunStreamSubscription, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn read_run_stream_message(&mut self) -> Result<RunStreamMessage, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn read_capability_revocation_if_ready(&mut self) -> Result<bool, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }

    pub fn acknowledge_run_cursor(&mut self, _through_run_seq: u64) -> Result<(), ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
pub fn handshake(
    client_version: &str,
    client_kind: &str,
    pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    linux::handshake(client_version, client_kind, pairing_pending)
}

#[cfg(target_os = "linux")]
pub fn handshake_as(
    client_version: &str,
    client_kind: &str,
    authorized_client_id: &str,
    pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    linux::handshake_as(
        client_version,
        client_kind,
        authorized_client_id,
        pairing_pending,
    )
}

#[cfg(target_os = "linux")]
pub fn handshake_as_with_credential(
    client_version: &str,
    client_kind: &str,
    authorized_client_id: &str,
    authorized_client_credential: Option<&str>,
    pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    linux::handshake_as_with_credential(
        client_version,
        client_kind,
        authorized_client_id,
        authorized_client_credential,
        pairing_pending,
    )
}

#[cfg(test)]
mod tests {
    use super::RunCancelAccepted;
    use serde_json::json;

    #[test]
    fn run_cancel_accepted_decode_rejects_unknown_fields() {
        let accepted: RunCancelAccepted = serde_json::from_value(json!({
            "run_id": "00000000000000000000000000000191",
            "accepted_at": "2026-07-17T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(accepted.run_id, "00000000000000000000000000000191");
        assert!(serde_json::from_value::<RunCancelAccepted>(json!({
            "run_id": accepted.run_id,
            "accepted_at": accepted.accepted_at,
            "extra": true
        }))
        .is_err());
    }
}

#[cfg(not(target_os = "linux"))]
pub fn handshake_as(
    _client_version: &str,
    _client_kind: &str,
    _authorized_client_id: &str,
    _pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn handshake(
    _client_version: &str,
    _client_kind: &str,
    _pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn handshake_as_with_credential(
    _client_version: &str,
    _client_kind: &str,
    _authorized_client_id: &str,
    _authorized_client_credential: Option<&str>,
    _pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}
