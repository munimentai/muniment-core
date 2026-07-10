use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::{SidecarError, SidecarIo};

const JSON_RPC_VERSION: &str = "2.0";
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
    /// If that lock is busy, the probe promptly reports healthy without sending.
    pub fn health_probe(
        self: &Arc<Self>,
        method: impl Into<String> + 'static,
        timeout: Duration,
    ) -> impl Fn(&SidecarIo) -> Result<super::ProbeOutcome, String> + Send + Sync + 'static {
        let transport = Arc::clone(self);
        let method = method.into();
        move |_| {
            let call = match transport.call_lock.try_lock() {
                Ok(call) => call,
                Err(TryLockError::Poisoned(error)) => error.into_inner(),
                Err(TryLockError::WouldBlock) => return Ok(super::ProbeOutcome::Ready),
            };
            let id = JsonRpcId::Number(transport.next_id.fetch_add(1, Ordering::Relaxed));
            transport
                .call_inner_locked::<Value, Value>(
                    &method,
                    None,
                    id,
                    timeout,
                    None,
                    &mut |_| {},
                    call,
                )
                .map(|_| super::ProbeOutcome::Ready)
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
        let call_guard = self
            .call_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.call_inner_locked(
            method,
            params,
            id,
            timeout,
            cancellation,
            on_notification,
            call_guard,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn call_inner_locked<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: impl Into<String>,
        params: Option<P>,
        id: JsonRpcId,
        timeout: Duration,
        cancellation: Option<&JsonRpcCancellationToken>,
        on_notification: &mut impl FnMut(JsonRpcNotification<Value>),
        _call_guard: std::sync::MutexGuard<'_, ()>,
    ) -> Result<R, JsonRpcTransportError> {
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
