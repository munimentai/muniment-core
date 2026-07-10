//! Portable supervision for line-oriented child processes.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

const JSON_RPC_VERSION: &str = "2.0";
const DEFAULT_STDERR_CAPACITY: usize = 256;
const STDERR_DIAGNOSTIC_LINES: usize = 20;
const JSON_RPC_CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_ABANDONED_JSON_RPC_IDS: usize = 256;

/// A type-safe JSON-RPC version marker that always serializes as `"2.0"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JsonRpcVersion;

impl Serialize for JsonRpcVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(JSON_RPC_VERSION)
    }
}

impl<'de> Deserialize<'de> for JsonRpcVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = String::deserialize(deserializer)?;
        if version == JSON_RPC_VERSION {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("jsonrpc must be \"2.0\""))
        }
    }
}

/// A JSON-RPC request identifier. Numeric IDs allocated by [`JsonRpcTransport`]
/// are unsigned integers; callers may instead supply a string ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    Number(u64),
    String(String),
}

/// Typed JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest<P> {
    pub jsonrpc: JsonRpcVersion,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
    pub id: JsonRpcId,
}

impl<P> JsonRpcRequest<P> {
    pub fn new(method: impl Into<String>, params: Option<P>, id: JsonRpcId) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            method: method.into(),
            params,
            id,
        }
    }
}

/// Typed JSON-RPC 2.0 notification envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification<P> {
    pub jsonrpc: JsonRpcVersion,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
}

impl<P> JsonRpcNotification<P> {
    pub fn new(method: impl Into<String>, params: Option<P>) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            method: method.into(),
            params,
        }
    }
}

/// Typed JSON-RPC 2.0 success response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcSuccess<R> {
    pub jsonrpc: JsonRpcVersion,
    pub result: R,
    pub id: JsonRpcId,
}

impl<R> JsonRpcSuccess<R> {
    pub fn new(result: R, id: JsonRpcId) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            result,
            id,
        }
    }
}

/// The standard JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Typed JSON-RPC 2.0 error response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: JsonRpcVersion,
    pub error: JsonRpcErrorObject,
    pub id: JsonRpcId,
}

impl JsonRpcErrorResponse {
    pub fn new(error: JsonRpcErrorObject, id: JsonRpcId) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            error,
            id,
        }
    }
}

/// A bounded, synchronous JSON-RPC call failure.
#[derive(Debug)]
pub enum JsonRpcTransportError {
    Timeout,
    Cancelled,
    Disconnected,
    Io(std::io::Error),
    Serialize(serde_json::Error),
    MalformedJson(serde_json::Error),
    InvalidEnvelope(String),
    MismatchedId {
        expected: JsonRpcId,
        received: JsonRpcId,
    },
    ErrorResponse(JsonRpcErrorObject),
}

impl fmt::Display for JsonRpcTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "timed out waiting for a JSON-RPC response"),
            Self::Cancelled => write!(f, "JSON-RPC call was cancelled"),
            Self::Disconnected => write!(f, "sidecar disconnected during JSON-RPC call"),
            Self::Io(error) => write!(f, "sidecar I/O failed: {error}"),
            Self::Serialize(error) => write!(f, "could not serialize JSON-RPC request: {error}"),
            Self::MalformedJson(error) => write!(f, "malformed JSON-RPC response: {error}"),
            Self::InvalidEnvelope(reason) => write!(f, "invalid JSON-RPC response: {reason}"),
            Self::MismatchedId { expected, received } => {
                write!(
                    f,
                    "JSON-RPC response ID {received:?} did not match {expected:?}"
                )
            }
            Self::ErrorResponse(error) => {
                write!(f, "JSON-RPC error {}: {}", error.code, error.message)
            }
        }
    }
}

impl std::error::Error for JsonRpcTransportError {}

/// A cloneable signal that can cancel a JSON-RPC call from another thread.
#[derive(Clone, Default)]
pub struct JsonRpcCancellationToken(Arc<AtomicBool>);

impl JsonRpcCancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// One-request-at-a-time JSON-RPC 2.0 transport over supervised line I/O.
pub struct JsonRpcTransport {
    io: SidecarIo,
    next_id: AtomicU64,
    call_lock: Mutex<()>,
    cancel_method: Option<String>,
    abandoned: Mutex<VecDeque<(u64, JsonRpcId)>>,
}

impl JsonRpcTransport {
    pub fn new(io: SidecarIo) -> Self {
        Self {
            io,
            next_id: AtomicU64::new(1),
            call_lock: Mutex::new(()),
            cancel_method: None,
            abandoned: Mutex::new(VecDeque::new()),
        }
    }

    /// Configures the notification method used to cancel in-flight calls.
    pub fn with_cancel_method(mut self, method: impl Into<String>) -> Self {
        self.cancel_method = Some(method.into());
        self
    }

    /// Builds a supervisor health probe that calls `method` with no parameters.
    ///
    /// The returned closure shares this transport's call lock, so it cannot read
    /// a response or notification belonging to an in-flight application call.
    /// Waiting to acquire that lock is not included in `timeout`.
    pub fn health_probe(
        self: &Arc<Self>,
        method: impl Into<String> + 'static,
        timeout: Duration,
    ) -> impl Fn(&SidecarIo) -> Result<(), String> + Send + Sync + 'static {
        let transport = Arc::clone(self);
        let method = method.into();
        move |_| {
            transport
                .call::<Value, Value>(&method, None, timeout)
                .map(|_| ())
                .map_err(|error| format!("JSON-RPC health probe `{method}` failed: {error}"))
        }
    }

    /// Allocates an ID and performs one request/response exchange.
    pub fn call<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        timeout: Duration,
    ) -> Result<R, JsonRpcTransportError> {
        let id = JsonRpcId::Number(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.call_with_id(method, params, id, timeout)
    }

    /// Performs one request/response exchange with a caller-supplied ID.
    pub fn call_with_id<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        id: JsonRpcId,
        timeout: Duration,
    ) -> Result<R, JsonRpcTransportError> {
        self.call_with_notifications(method, params, id, timeout, |_| {})
    }

    /// Allocates an ID and performs a cancellable request/response exchange.
    pub fn call_with_cancellation<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        timeout: Duration,
        cancellation: &JsonRpcCancellationToken,
    ) -> Result<R, JsonRpcTransportError> {
        let id = JsonRpcId::Number(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.call_with_id_and_cancellation(method, params, id, timeout, cancellation)
    }

    /// Performs a cancellable exchange with a caller-supplied ID.
    pub fn call_with_id_and_cancellation<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        id: JsonRpcId,
        timeout: Duration,
        cancellation: &JsonRpcCancellationToken,
    ) -> Result<R, JsonRpcTransportError> {
        self.call_with_notifications_and_cancellation(
            method,
            params,
            id,
            timeout,
            cancellation,
            |_| {},
        )
    }

    /// Sends a notification, which has no request ID and expects no response.
    pub fn notify<P: Serialize>(
        &self,
        method: impl Into<String>,
        params: P,
    ) -> Result<(), JsonRpcTransportError> {
        let notification = JsonRpcNotification::new(method, Some(params));
        let line =
            serde_json::to_string(&notification).map_err(JsonRpcTransportError::Serialize)?;
        self.io.stdin.write_line(&line).map_err(map_sidecar_error)
    }

    /// Performs a call while delivering preceding server notifications in order.
    pub fn call_with_notifications<
        P: Serialize,
        R: serde::de::DeserializeOwned,
        F: FnMut(JsonRpcNotification<Value>),
    >(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        id: JsonRpcId,
        timeout: Duration,
        mut on_notification: F,
    ) -> Result<R, JsonRpcTransportError> {
        self.call_inner(method, params, id, timeout, None, &mut on_notification)
    }

    /// Performs a cancellable call while delivering preceding notifications.
    pub fn call_with_notifications_and_cancellation<
        P: Serialize,
        R: serde::de::DeserializeOwned,
        F: FnMut(JsonRpcNotification<Value>),
    >(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        id: JsonRpcId,
        timeout: Duration,
        cancellation: &JsonRpcCancellationToken,
        mut on_notification: F,
    ) -> Result<R, JsonRpcTransportError> {
        self.call_inner(
            method,
            params,
            id,
            timeout,
            Some(cancellation),
            &mut on_notification,
        )
    }

    fn call_inner<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        id: JsonRpcId,
        timeout: Duration,
        cancellation: Option<&JsonRpcCancellationToken>,
        on_notification: &mut impl FnMut(JsonRpcNotification<Value>),
    ) -> Result<R, JsonRpcTransportError> {
        // Poisoning does not make the line handles unsafe; recover the guard so
        // an earlier caller panic cannot make subsequent calls panic too.
        let _call = self
            .call_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request = JsonRpcRequest::new(method, params, id.clone());
        let line = serde_json::to_string(&request).map_err(JsonRpcTransportError::Serialize)?;
        let generation = self
            .io
            .stdin
            .write_line_in_generation(&line)
            .map_err(map_sidecar_error)?;
        let deadline = Instant::now() + timeout;
        loop {
            if cancellation.is_some_and(JsonRpcCancellationToken::is_cancelled) {
                if let Some(method) = &self.cancel_method {
                    self.notify(method, serde_json::json!({"id": id.clone()}))?;
                }
                self.abandon(generation, id);
                return Err(JsonRpcTransportError::Cancelled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.abandon(generation, id);
                return Err(JsonRpcTransportError::Timeout);
            }
            let wait = if cancellation.is_some() {
                remaining.min(JSON_RPC_CANCEL_POLL_INTERVAL)
            } else {
                remaining
            };
            let line = self
                .io
                .stdout
                .read_line_timeout_for_generation(generation, wait)
                .map_err(map_sidecar_error)?;
            let Some(line) = line else {
                continue;
            };
            match decode_frame(&line)? {
                JsonRpcFrame::Notification(notification) => on_notification(notification),
                JsonRpcFrame::Success {
                    id: received,
                    result,
                } if received == id => return Ok(result),
                JsonRpcFrame::Error {
                    id: received,
                    error,
                } if received == id => return Err(JsonRpcTransportError::ErrorResponse(error)),
                JsonRpcFrame::Success { id: received, .. }
                | JsonRpcFrame::Error { id: received, .. } => {
                    if !self.take_abandoned(generation, &received) {
                        return Err(JsonRpcTransportError::MismatchedId {
                            expected: id,
                            received,
                        });
                    }
                }
            }
        }
    }

    fn abandon(&self, generation: u64, id: JsonRpcId) {
        let mut abandoned = self
            .abandoned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        abandoned.retain(|(seen, _)| *seen >= generation);
        if abandoned.len() == MAX_ABANDONED_JSON_RPC_IDS {
            abandoned.pop_front();
        }
        abandoned.push_back((generation, id));
    }

    fn take_abandoned(&self, generation: u64, id: &JsonRpcId) -> bool {
        let mut abandoned = self
            .abandoned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        abandoned.retain(|(seen, _)| *seen >= generation);
        abandoned
            .iter()
            .position(|entry| entry == &(generation, id.clone()))
            .and_then(|index| abandoned.remove(index))
            .is_some()
    }
}

fn map_sidecar_error(error: SidecarError) -> JsonRpcTransportError {
    match error {
        SidecarError::Disconnected | SidecarError::AlreadyStopped => {
            JsonRpcTransportError::Disconnected
        }
        SidecarError::Io(error) | SidecarError::Spawn(error) => JsonRpcTransportError::Io(error),
    }
}

enum JsonRpcFrame<R> {
    Notification(JsonRpcNotification<Value>),
    Success {
        id: JsonRpcId,
        result: R,
    },
    Error {
        id: JsonRpcId,
        error: JsonRpcErrorObject,
    },
}

fn decode_frame<R: serde::de::DeserializeOwned>(
    line: &str,
) -> Result<JsonRpcFrame<R>, JsonRpcTransportError> {
    let value: Value = serde_json::from_str(line).map_err(JsonRpcTransportError::MalformedJson)?;
    let object = value.as_object().ok_or_else(|| {
        JsonRpcTransportError::InvalidEnvelope("response must be an object".into())
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some(JSON_RPC_VERSION) {
        return Err(JsonRpcTransportError::InvalidEnvelope(
            "jsonrpc must be \"2.0\"".into(),
        ));
    }
    if object.contains_key("method") && !object.contains_key("id") {
        let notification = serde_json::from_value(value).map_err(|error| {
            JsonRpcTransportError::InvalidEnvelope(format!("invalid notification: {error}"))
        })?;
        return Ok(JsonRpcFrame::Notification(notification));
    }
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        return Err(JsonRpcTransportError::InvalidEnvelope(
            "response must contain exactly one of result or error".into(),
        ));
    }
    let received_id = object
        .get("id")
        .cloned()
        .ok_or_else(|| JsonRpcTransportError::InvalidEnvelope("response is missing id".into()))
        .and_then(|id| {
            serde_json::from_value(id).map_err(|_| {
                JsonRpcTransportError::InvalidEnvelope(
                    "response id must be an unsigned integer or string".into(),
                )
            })
        })?;
    if has_error {
        let response: JsonRpcErrorResponse = serde_json::from_value(value).map_err(|error| {
            JsonRpcTransportError::InvalidEnvelope(format!("invalid error object: {error}"))
        })?;
        return Ok(JsonRpcFrame::Error {
            id: received_id,
            error: response.error,
        });
    }
    let response: JsonRpcSuccess<R> = serde_json::from_value(value).map_err(|error| {
        JsonRpcTransportError::InvalidEnvelope(format!("invalid success response: {error}"))
    })?;
    Ok(JsonRpcFrame::Success {
        id: received_id,
        result: response.result,
    })
}

#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// Number of restarts allowed during `window` (the initial start is free).
    pub max_restarts: usize,
    pub window: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 5,
            window: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub program: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub restart: RestartPolicy,
    pub health_interval: Duration,
    pub shutdown_timeout: Duration,
    /// Maximum number of recent stderr lines retained for reading and diagnostics.
    pub stderr_capacity: usize,
    /// Frequency of exit and shutdown checks. Kept configurable for bounded tests.
    pub poll_interval: Duration,
}

impl SidecarConfig {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: HashMap::new(),
            restart: RestartPolicy::default(),
            health_interval: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(2),
            stderr_capacity: DEFAULT_STDERR_CAPACITY,
            poll_interval: Duration::from_millis(20),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarStatus {
    Starting,
    Healthy,
    Restarting,
    Stopped,
    Failed,
}

/// Why a sidecar lifecycle transition occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarEventCause {
    ProcessExit {
        code: Option<i32>,
        signal: Option<i32>,
        stderr_tail: Vec<String>,
    },
    ProcessWaitError {
        message: String,
        stderr_tail: Vec<String>,
    },
    SpawnError(String),
    HealthProbeFailure {
        message: String,
        stderr_tail: Vec<String>,
    },
    Shutdown,
}

/// An ordered sidecar status transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarEvent {
    pub status: SidecarStatus,
    pub cause: Option<SidecarEventCause>,
    pub restart_attempt: Option<usize>,
    pub backoff_delay: Option<Duration>,
    pub generation: Option<u64>,
}

#[derive(Debug)]
pub enum SidecarError {
    Spawn(std::io::Error),
    Io(std::io::Error),
    Disconnected,
    AlreadyStopped,
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start sidecar: {e}"),
            Self::Io(e) => write!(f, "sidecar I/O failed: {e}"),
            Self::Disconnected => write!(f, "sidecar output disconnected"),
            Self::AlreadyStopped => write!(f, "sidecar supervisor is already stopped"),
        }
    }
}

impl std::error::Error for SidecarError {}

struct WriterState {
    generation: u64,
    writer: Option<BufWriter<ChildStdin>>,
}

#[derive(Clone)]
pub struct LineWriter(Arc<Mutex<WriterState>>);

impl LineWriter {
    pub fn write_line(&self, line: &str) -> Result<(), SidecarError> {
        self.write_line_in_generation(line).map(|_| ())
    }

    fn write_line_in_generation(&self, line: &str) -> Result<u64, SidecarError> {
        let mut guard = self.0.lock().unwrap();
        let generation = guard.generation;
        let writer = guard.writer.as_mut().ok_or(SidecarError::Disconnected)?;
        writer
            .write_all(line.as_bytes())
            .map_err(SidecarError::Io)?;
        writer.write_all(b"\n").map_err(SidecarError::Io)?;
        writer.flush().map_err(SidecarError::Io)?;
        Ok(generation)
    }
}

struct LineReceiver {
    receiver: mpsc::Receiver<(u64, String)>,
    pending: VecDeque<(u64, String)>,
    generation: Arc<AtomicU64>,
}

struct StderrState {
    lines: VecDeque<String>,
    first_sequence: u64,
    next_sequence: u64,
    read_sequence: u64,
    generation: u64,
}

struct StderrRing {
    state: Mutex<StderrState>,
    available: Condvar,
    capacity: usize,
}

impl StderrRing {
    fn begin_generation(&self, generation: u64) {
        let mut state = self.state.lock().unwrap();
        state.lines.clear();
        state.first_sequence = state.next_sequence;
        state.read_sequence = state.next_sequence;
        state.generation = generation;
    }

    fn push(&self, generation: u64, line: String) {
        let mut state = self.state.lock().unwrap();
        if self.capacity == 0 || state.generation != generation {
            return;
        }
        if state.lines.len() == self.capacity {
            state.lines.pop_front();
            state.first_sequence += 1;
        }
        state.lines.push_back(line);
        state.next_sequence += 1;
        self.available.notify_all();
    }

    fn snapshot(&self) -> Vec<String> {
        self.state.lock().unwrap().lines.iter().cloned().collect()
    }

    fn read(&self, timeout: Option<Duration>) -> Result<Option<String>, SidecarError> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.state.lock().unwrap();
        loop {
            state.read_sequence = state.read_sequence.max(state.first_sequence);
            if state.read_sequence < state.next_sequence {
                let index = (state.read_sequence - state.first_sequence) as usize;
                state.read_sequence += 1;
                return Ok(state.lines.get(index).cloned());
            }
            state = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    let (state, result) = self.available.wait_timeout(state, remaining).unwrap();
                    if result.timed_out() {
                        return Ok(None);
                    }
                    state
                }
                None => self.available.wait(state).unwrap(),
            };
        }
    }
}

#[derive(Clone)]
pub struct LineReader(LineReaderInner);

#[derive(Clone)]
enum LineReaderInner {
    Channel(Arc<Mutex<LineReceiver>>),
    Stderr(Arc<StderrRing>),
}

impl LineReader {
    pub fn read_line(&self) -> Result<String, SidecarError> {
        if let LineReaderInner::Stderr(ring) = &self.0 {
            return ring.read(None)?.ok_or(SidecarError::Disconnected);
        }
        let LineReaderInner::Channel(receiver) = &self.0 else {
            unreachable!()
        };
        let mut guard = receiver.lock().unwrap();
        if let Some((_, line)) = guard.pending.pop_front() {
            return Ok(line);
        }
        guard
            .receiver
            .recv()
            .map(|(_, line)| line)
            .map_err(|_| SidecarError::Disconnected)
    }

    pub fn read_line_timeout(&self, timeout: Duration) -> Result<Option<String>, SidecarError> {
        if let LineReaderInner::Stderr(ring) = &self.0 {
            return ring.read(Some(timeout));
        }
        let LineReaderInner::Channel(receiver) = &self.0 else {
            unreachable!()
        };
        let mut guard = receiver.lock().unwrap();
        if let Some((_, line)) = guard.pending.pop_front() {
            return Ok(Some(line));
        }
        match guard.receiver.recv_timeout(timeout) {
            Ok((_, line)) => Ok(Some(line)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SidecarError::Disconnected),
        }
    }

    fn read_line_timeout_for_generation(
        &self,
        generation: u64,
        timeout: Duration,
    ) -> Result<Option<String>, SidecarError> {
        self.read_for_generation(generation, Some(timeout))
    }

    fn read_for_generation(
        &self,
        generation: u64,
        timeout: Option<Duration>,
    ) -> Result<Option<String>, SidecarError> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let LineReaderInner::Channel(receiver) = &self.0 else {
            return Err(SidecarError::Disconnected);
        };
        let mut guard = receiver.lock().unwrap();
        loop {
            if guard.generation.load(Ordering::Acquire) != generation {
                return Err(SidecarError::Disconnected);
            }
            guard.pending.retain(|(seen, _)| *seen >= generation);
            if let Some(index) = guard
                .pending
                .iter()
                .position(|(seen, _)| *seen == generation)
            {
                return Ok(guard.pending.remove(index).map(|(_, line)| line));
            }
            let received = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    match guard.receiver.recv_timeout(remaining) {
                        Ok(line) => line,
                        Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(SidecarError::Disconnected)
                        }
                    }
                }
                None => guard
                    .receiver
                    .recv()
                    .map_err(|_| SidecarError::Disconnected)?,
            };
            match received {
                (seen, line) if seen == generation => return Ok(Some(line)),
                (seen, _) if seen < generation => continue,
                future => guard.pending.push_back(future),
            }
        }
    }
}

#[derive(Clone)]
pub struct SidecarIo {
    pub stdin: LineWriter,
    pub stdout: LineReader,
    pub stderr: LineReader,
}

type HealthProbe = dyn Fn(&SidecarIo) -> Result<(), String> + Send + Sync + 'static;

pub struct SidecarSupervisor {
    state: Arc<Mutex<SupervisorState>>,
    io: SidecarIo,
    command: mpsc::Sender<SupervisorCommand>,
    worker: Option<JoinHandle<()>>,
}

struct SupervisorState {
    status: SidecarStatus,
    events: Vec<SidecarEvent>,
    subscribers: Vec<mpsc::Sender<SidecarEvent>>,
    closed: bool,
}

enum SupervisorCommand {
    Shutdown(mpsc::Sender<()>),
}

impl SidecarSupervisor {
    pub fn spawn(
        config: SidecarConfig,
        health_probe: impl Fn(&SidecarIo) -> Result<(), String> + Send + Sync + 'static,
    ) -> Result<Self, SidecarError> {
        if config.program.is_empty() {
            return Err(SidecarError::Spawn(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "program is empty",
            )));
        }
        let (stdout_tx, stdout_rx) = mpsc::channel();
        let stderr = Arc::new(StderrRing {
            state: Mutex::new(StderrState {
                lines: VecDeque::new(),
                first_sequence: 0,
                next_sequence: 0,
                read_sequence: 0,
                generation: 0,
            }),
            available: Condvar::new(),
            capacity: config.stderr_capacity,
        });
        let generation = Arc::new(AtomicU64::new(0));
        let stdin = LineWriter(Arc::new(Mutex::new(WriterState {
            generation: 0,
            writer: None,
        })));
        let io = SidecarIo {
            stdin: stdin.clone(),
            stdout: LineReader(LineReaderInner::Channel(Arc::new(Mutex::new(
                LineReceiver {
                    receiver: stdout_rx,
                    pending: VecDeque::new(),
                    generation: generation.clone(),
                },
            )))),
            stderr: LineReader(LineReaderInner::Stderr(stderr.clone())),
        };
        let starting = SidecarEvent {
            status: SidecarStatus::Starting,
            cause: None,
            restart_attempt: None,
            backoff_delay: None,
            generation: None,
        };
        let state = Arc::new(Mutex::new(SupervisorState {
            status: SidecarStatus::Starting,
            events: vec![starting],
            subscribers: Vec::new(),
            closed: false,
        }));
        let (command, commands) = mpsc::channel();
        let worker_state = state.clone();
        let worker_io = io.clone();
        let probe: Arc<HealthProbe> = Arc::new(health_probe);
        let worker = thread::spawn(move || {
            supervise(
                config,
                worker_state,
                worker_io,
                stdout_tx,
                stderr,
                generation,
                commands,
                probe,
            )
        });
        Ok(Self {
            state,
            io,
            command,
            worker: Some(worker),
        })
    }

    pub fn status(&self) -> SidecarStatus {
        self.state.lock().unwrap().status
    }

    /// Subscribes to lifecycle transitions, replaying transitions already emitted.
    pub fn subscribe(&self) -> mpsc::Receiver<SidecarEvent> {
        let (sender, receiver) = mpsc::channel();
        let mut state = self.state.lock().unwrap();
        for event in &state.events {
            let _ = sender.send(event.clone());
        }
        if !state.closed {
            state.subscribers.push(sender);
        }
        receiver
    }

    pub fn io(&self) -> SidecarIo {
        self.io.clone()
    }

    /// Returns the retained stderr lines for the active child, oldest first.
    pub fn recent_stderr(&self) -> Vec<String> {
        let LineReaderInner::Stderr(ring) = &self.io.stderr.0 else {
            unreachable!()
        };
        ring.snapshot()
    }

    pub fn shutdown(&mut self) -> Result<(), SidecarError> {
        let Some(worker) = self.worker.take() else {
            return Err(SidecarError::AlreadyStopped);
        };
        let (done_tx, done_rx) = mpsc::channel();
        self.command
            .send(SupervisorCommand::Shutdown(done_tx))
            .map_err(|_| SidecarError::AlreadyStopped)?;
        let _ = done_rx.recv();
        let _ = worker.join();
        Ok(())
    }
}

impl Drop for SidecarSupervisor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// These independent handles make the supervisor's shared state and I/O dependencies explicit.
#[allow(clippy::too_many_arguments)]
fn supervise(
    config: SidecarConfig,
    state: Arc<Mutex<SupervisorState>>,
    io: SidecarIo,
    stdout_tx: mpsc::Sender<(u64, String)>,
    stderr: Arc<StderrRing>,
    generation: Arc<AtomicU64>,
    commands: mpsc::Receiver<SupervisorCommand>,
    probe: Arc<HealthProbe>,
) {
    let mut restarts = VecDeque::new();
    let mut consecutive_failures = 0u32;
    let mut restart_cause = None;
    let mut restart_attempt = None;
    loop {
        if consecutive_failures > 0 {
            let shift = consecutive_failures.saturating_sub(1).min(31);
            let delay = config
                .restart
                .initial_backoff
                .saturating_mul(1u32 << shift)
                .min(config.restart.max_backoff);
            emit_event(
                &state,
                SidecarEvent {
                    status: SidecarStatus::Restarting,
                    cause: restart_cause.clone(),
                    restart_attempt,
                    backoff_delay: Some(delay),
                    generation: None,
                },
            );
            if wait_or_shutdown(delay, &commands, &io, None, &config, &state) {
                return;
            }
        }
        let child_generation = generation.fetch_add(1, Ordering::AcqRel) + 1;
        let mut child = match spawn_child(
            &config,
            &io,
            stdout_tx.clone(),
            stderr.clone(),
            child_generation,
        ) {
            Ok(child) => child,
            Err(error) => {
                let cause = SidecarEventCause::SpawnError(error.to_string());
                if let Some(attempt) = allow_restart(&config.restart, &mut restarts) {
                    restart_attempt = Some(attempt);
                    restart_cause = Some(cause);
                } else {
                    emit_terminal(&state, SidecarStatus::Failed, Some(cause));
                    return;
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
                continue;
            }
        };
        emit_event(
            &state,
            SidecarEvent {
                status: SidecarStatus::Healthy,
                cause: None,
                restart_attempt: None,
                backoff_delay: None,
                generation: Some(child_generation),
            },
        );
        let mut next_probe = Instant::now() + config.health_interval;
        let cause = loop {
            match commands.recv_timeout(config.poll_interval) {
                Ok(SupervisorCommand::Shutdown(done)) => {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    emit_terminal(
                        &state,
                        SidecarStatus::Stopped,
                        Some(SidecarEventCause::Shutdown),
                    );
                    let _ = done.send(());
                    return;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    emit_terminal(
                        &state,
                        SidecarStatus::Stopped,
                        Some(SidecarEventCause::Shutdown),
                    );
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            match child.try_wait() {
                Ok(Some(exit)) => break process_exit_cause(exit, &stderr),
                Err(error) => {
                    break SidecarEventCause::ProcessWaitError {
                        message: error.to_string(),
                        stderr_tail: stderr_tail(&stderr),
                    }
                }
                Ok(None) => {}
            }
            if Instant::now() >= next_probe {
                next_probe = Instant::now() + config.health_interval;
                if let Err(message) = probe(&io) {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    break SidecarEventCause::HealthProbeFailure {
                        message,
                        stderr_tail: stderr_tail(&stderr),
                    };
                }
                consecutive_failures = 0;
            }
        };
        io.stdin.0.lock().unwrap().writer = None;
        if let Some(attempt) = allow_restart(&config.restart, &mut restarts) {
            restart_attempt = Some(attempt);
            restart_cause = Some(cause);
        } else {
            emit_terminal(&state, SidecarStatus::Failed, Some(cause));
            return;
        }
        consecutive_failures = consecutive_failures.saturating_add(1);
    }
}

fn process_exit_cause(exit: std::process::ExitStatus, stderr: &StderrRing) -> SidecarEventCause {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    SidecarEventCause::ProcessExit {
        code: exit.code(),
        #[cfg(unix)]
        signal: exit.signal(),
        #[cfg(not(unix))]
        signal: None,
        stderr_tail: stderr_tail(stderr),
    }
}

fn stderr_tail(stderr: &StderrRing) -> Vec<String> {
    let lines = stderr.snapshot();
    lines[lines.len().saturating_sub(STDERR_DIAGNOSTIC_LINES)..].to_vec()
}

fn spawn_child(
    config: &SidecarConfig,
    io: &SidecarIo,
    out: mpsc::Sender<(u64, String)>,
    err: Arc<StderrRing>,
    generation: u64,
) -> Result<Child, std::io::Error> {
    let mut child = Command::new(&config.program)
        .args(&config.args)
        .envs(&config.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    err.begin_generation(generation);
    {
        let mut stdin = io.stdin.0.lock().unwrap();
        stdin.generation = generation;
        stdin.writer = child.stdin.take().map(BufWriter::new);
    }
    pipe_lines(child.stdout.take().unwrap(), out, generation);
    pipe_error_lines(child.stderr.take().unwrap(), err, generation);
    Ok(child)
}

fn pipe_lines(pipe: ChildStdout, tx: mpsc::Sender<(u64, String)>, generation: u64) {
    thread::spawn(move || forward_lines(pipe, tx, generation));
}
fn pipe_error_lines(pipe: ChildStderr, ring: Arc<StderrRing>, generation: u64) {
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            match line {
                Ok(line) => {
                    let line = line.strip_suffix('\r').unwrap_or(&line);
                    if !line.is_empty() {
                        ring.push(generation, line.to_owned());
                    }
                }
                Err(_) => break,
            }
        }
    });
}
fn forward_lines(pipe: impl std::io::Read, tx: mpsc::Sender<(u64, String)>, generation: u64) {
    for line in BufReader::new(pipe).lines() {
        match line {
            Ok(line) => {
                let line = line.strip_suffix('\r').unwrap_or(&line);
                if line.is_empty() {
                    continue;
                }
                if tx.send((generation, line.to_owned())).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn allow_restart(policy: &RestartPolicy, history: &mut VecDeque<Instant>) -> Option<usize> {
    let now = Instant::now();
    while history
        .front()
        .is_some_and(|at| now.duration_since(*at) > policy.window)
    {
        history.pop_front();
    }
    if history.len() >= policy.max_restarts {
        return None;
    }
    history.push_back(now);
    Some(history.len())
}

fn stop_child(child: &mut Child, io: &SidecarIo, deadline: Duration, poll: Duration) {
    io.stdin.0.lock().unwrap().writer = None;
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(poll.min(until.saturating_duration_since(Instant::now())));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_or_shutdown(
    delay: Duration,
    commands: &mpsc::Receiver<SupervisorCommand>,
    io: &SidecarIo,
    child: Option<&mut Child>,
    config: &SidecarConfig,
    state: &Arc<Mutex<SupervisorState>>,
) -> bool {
    match commands.recv_timeout(delay) {
        Ok(SupervisorCommand::Shutdown(done)) => {
            if let Some(child) = child {
                stop_child(child, io, config.shutdown_timeout, config.poll_interval);
            }
            emit_terminal(
                state,
                SidecarStatus::Stopped,
                Some(SidecarEventCause::Shutdown),
            );
            let _ = done.send(());
            true
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            emit_terminal(
                state,
                SidecarStatus::Stopped,
                Some(SidecarEventCause::Shutdown),
            );
            true
        }
        Err(mpsc::RecvTimeoutError::Timeout) => false,
    }
}

fn emit_event(state: &Arc<Mutex<SupervisorState>>, event: SidecarEvent) {
    let mut state = state.lock().unwrap();
    state.status = event.status;
    state.events.push(event.clone());
    state
        .subscribers
        .retain(|sender| sender.send(event.clone()).is_ok());
}

fn emit_terminal(
    state: &Arc<Mutex<SupervisorState>>,
    status: SidecarStatus,
    cause: Option<SidecarEventCause>,
) {
    emit_event(
        state,
        SidecarEvent {
            status,
            cause,
            restart_attempt: None,
            backoff_delay: None,
            generation: None,
        },
    );
    let mut state = state.lock().unwrap();
    state.closed = true;
    state.subscribers.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn notification_envelope_has_no_id() {
        let value = serde_json::to_value(JsonRpcNotification::new(
            "cancel",
            Some(json!({"request_id": 7})),
        ))
        .unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "cancel");
        assert_eq!(value["params"], json!({"request_id": 7}));
        assert!(!value.as_object().unwrap().contains_key("id"));
    }
}
