//! Portable supervision for line-oriented child processes.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

const JSON_RPC_VERSION: &str = "2.0";

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

/// One-request-at-a-time JSON-RPC 2.0 transport over supervised line I/O.
pub struct JsonRpcTransport {
    io: SidecarIo,
    next_id: AtomicU64,
    call_lock: Mutex<()>,
}

impl JsonRpcTransport {
    pub fn new(io: SidecarIo) -> Self {
        Self {
            io,
            next_id: AtomicU64::new(1),
            call_lock: Mutex::new(()),
        }
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
        // Poisoning does not make the line handles unsafe; recover the guard so
        // an earlier caller panic cannot make subsequent calls panic too.
        let _call = self
            .call_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request = JsonRpcRequest::new(method, params, id.clone());
        let line = serde_json::to_string(&request).map_err(JsonRpcTransportError::Serialize)?;
        self.io.stdin.write_line(&line).map_err(map_sidecar_error)?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(JsonRpcTransportError::Timeout);
            }
            let line = self
                .io
                .stdout
                .read_line_timeout(remaining)
                .map_err(map_sidecar_error)?
                .ok_or(JsonRpcTransportError::Timeout)?;
            match decode_frame(&line, id.clone())? {
                JsonRpcFrame::Notification(notification) => on_notification(notification),
                JsonRpcFrame::Response(result) => return Ok(result),
            }
        }
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
    Response(R),
}

fn decode_frame<R: serde::de::DeserializeOwned>(
    line: &str,
    expected_id: JsonRpcId,
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
    if received_id != expected_id {
        return Err(JsonRpcTransportError::MismatchedId {
            expected: expected_id,
            received: received_id,
        });
    }
    if has_error {
        let response: JsonRpcErrorResponse = serde_json::from_value(value).map_err(|error| {
            JsonRpcTransportError::InvalidEnvelope(format!("invalid error object: {error}"))
        })?;
        return Err(JsonRpcTransportError::ErrorResponse(response.error));
    }
    let response: JsonRpcSuccess<R> = serde_json::from_value(value).map_err(|error| {
        JsonRpcTransportError::InvalidEnvelope(format!("invalid success response: {error}"))
    })?;
    Ok(JsonRpcFrame::Response(response.result))
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

#[derive(Clone)]
pub struct LineWriter(Arc<Mutex<Option<BufWriter<ChildStdin>>>>);

impl LineWriter {
    pub fn write_line(&self, line: &str) -> Result<(), SidecarError> {
        let mut guard = self.0.lock().unwrap();
        let writer = guard.as_mut().ok_or(SidecarError::Disconnected)?;
        writer
            .write_all(line.as_bytes())
            .map_err(SidecarError::Io)?;
        writer.write_all(b"\n").map_err(SidecarError::Io)?;
        writer.flush().map_err(SidecarError::Io)
    }
}

#[derive(Clone)]
pub struct LineReader(Arc<Mutex<mpsc::Receiver<String>>>);

impl LineReader {
    pub fn read_line(&self) -> Result<String, SidecarError> {
        self.0
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| SidecarError::Disconnected)
    }

    pub fn read_line_timeout(&self, timeout: Duration) -> Result<Option<String>, SidecarError> {
        match self.0.lock().unwrap().recv_timeout(timeout) {
            Ok(line) => Ok(Some(line)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SidecarError::Disconnected),
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
    status: Arc<Mutex<SidecarStatus>>,
    io: SidecarIo,
    command: mpsc::Sender<SupervisorCommand>,
    worker: Option<JoinHandle<()>>,
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
        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stdin = LineWriter(Arc::new(Mutex::new(None)));
        let io = SidecarIo {
            stdin: stdin.clone(),
            stdout: LineReader(Arc::new(Mutex::new(stdout_rx))),
            stderr: LineReader(Arc::new(Mutex::new(stderr_rx))),
        };
        let status = Arc::new(Mutex::new(SidecarStatus::Starting));
        let (command, commands) = mpsc::channel();
        let worker_status = status.clone();
        let worker_io = io.clone();
        let probe: Arc<HealthProbe> = Arc::new(health_probe);
        let worker = thread::spawn(move || {
            supervise(
                config,
                worker_status,
                worker_io,
                stdout_tx,
                stderr_tx,
                commands,
                probe,
            )
        });
        Ok(Self {
            status,
            io,
            command,
            worker: Some(worker),
        })
    }

    pub fn status(&self) -> SidecarStatus {
        *self.status.lock().unwrap()
    }

    pub fn io(&self) -> SidecarIo {
        self.io.clone()
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

fn supervise(
    config: SidecarConfig,
    status: Arc<Mutex<SidecarStatus>>,
    io: SidecarIo,
    stdout_tx: mpsc::Sender<String>,
    stderr_tx: mpsc::Sender<String>,
    commands: mpsc::Receiver<SupervisorCommand>,
    probe: Arc<HealthProbe>,
) {
    let mut restarts = VecDeque::new();
    let mut consecutive_failures = 0u32;
    loop {
        set_status(
            &status,
            if consecutive_failures == 0 {
                SidecarStatus::Starting
            } else {
                SidecarStatus::Restarting
            },
        );
        if consecutive_failures > 0 {
            let shift = consecutive_failures.saturating_sub(1).min(31);
            let delay = config
                .restart
                .initial_backoff
                .saturating_mul(1u32 << shift)
                .min(config.restart.max_backoff);
            if wait_or_shutdown(delay, &commands, &io, None, &config, &status) {
                return;
            }
        }
        let mut child = match spawn_child(&config, &io, stdout_tx.clone(), stderr_tx.clone()) {
            Ok(child) => child,
            Err(_) => {
                if !allow_restart(&config.restart, &mut restarts) {
                    set_status(&status, SidecarStatus::Failed);
                    return;
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
                continue;
            }
        };
        set_status(&status, SidecarStatus::Healthy);
        let mut next_probe = Instant::now() + config.health_interval;
        let restart = loop {
            match commands.recv_timeout(config.poll_interval) {
                Ok(SupervisorCommand::Shutdown(done)) => {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    set_status(&status, SidecarStatus::Stopped);
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
                    set_status(&status, SidecarStatus::Stopped);
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break true,
                Ok(None) => {}
            }
            if Instant::now() >= next_probe {
                next_probe = Instant::now() + config.health_interval;
                if probe(&io).is_err() {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    break true;
                }
                consecutive_failures = 0;
            }
        };
        if restart {
            *io.stdin.0.lock().unwrap() = None;
            if !allow_restart(&config.restart, &mut restarts) {
                set_status(&status, SidecarStatus::Failed);
                return;
            }
            consecutive_failures = consecutive_failures.saturating_add(1);
        }
    }
}

fn spawn_child(
    config: &SidecarConfig,
    io: &SidecarIo,
    out: mpsc::Sender<String>,
    err: mpsc::Sender<String>,
) -> Result<Child, std::io::Error> {
    let mut child = Command::new(&config.program)
        .args(&config.args)
        .envs(&config.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    *io.stdin.0.lock().unwrap() = child.stdin.take().map(BufWriter::new);
    pipe_lines(child.stdout.take().unwrap(), out);
    pipe_error_lines(child.stderr.take().unwrap(), err);
    Ok(child)
}

fn pipe_lines(pipe: ChildStdout, tx: mpsc::Sender<String>) {
    thread::spawn(move || forward_lines(pipe, tx));
}
fn pipe_error_lines(pipe: ChildStderr, tx: mpsc::Sender<String>) {
    thread::spawn(move || forward_lines(pipe, tx));
}
fn forward_lines(pipe: impl std::io::Read, tx: mpsc::Sender<String>) {
    for line in BufReader::new(pipe).lines() {
        match line {
            Ok(line) => {
                let line = line.strip_suffix('\r').unwrap_or(&line);
                if line.is_empty() {
                    continue;
                }
                if tx.send(line.to_owned()).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn allow_restart(policy: &RestartPolicy, history: &mut VecDeque<Instant>) -> bool {
    let now = Instant::now();
    while history
        .front()
        .is_some_and(|at| now.duration_since(*at) > policy.window)
    {
        history.pop_front();
    }
    if history.len() >= policy.max_restarts {
        return false;
    }
    history.push_back(now);
    true
}

fn stop_child(child: &mut Child, io: &SidecarIo, deadline: Duration, poll: Duration) {
    *io.stdin.0.lock().unwrap() = None;
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
    status: &Arc<Mutex<SidecarStatus>>,
) -> bool {
    match commands.recv_timeout(delay) {
        Ok(SupervisorCommand::Shutdown(done)) => {
            if let Some(child) = child {
                stop_child(child, io, config.shutdown_timeout, config.poll_interval);
            }
            set_status(status, SidecarStatus::Stopped);
            let _ = done.send(());
            true
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            set_status(status, SidecarStatus::Stopped);
            true
        }
        Err(mpsc::RecvTimeoutError::Timeout) => false,
    }
}

fn set_status(status: &Arc<Mutex<SidecarStatus>>, value: SidecarStatus) {
    *status.lock().unwrap() = value;
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
