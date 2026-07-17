use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

pub const PROTOCOL: &str = "muniment.attach/1";
pub const MAX_ID_LENGTH: usize = 64;
pub const MAX_TEXT_LENGTH: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protocol;

impl Serialize for Protocol {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(PROTOCOL)
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        (value == PROTOCOL)
            .then_some(Self)
            .ok_or_else(|| de::Error::custom("unsupported attach protocol"))
    }
}

/// An opaque, UUID-shaped protocol identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        if value.len() > MAX_ID_LENGTH || Uuid::parse_str(&value).is_err() {
            return Err(IdError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdError;

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid protocol id")
    }
}
impl std::error::Error for IdError {}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub protocol: Protocol,
    pub request_id: Id,
    pub operation: Operation,
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<Id>,
    pub body: Value,
}

impl Request {
    /// Enforces the operation-level idempotency policy from ADR 0009.
    pub fn validate_idempotency_key(&self) -> Result<(), ProtocolError> {
        match (
            self.operation.requires_idempotency_key(),
            self.idempotency_key.is_some(),
        ) {
            (true, false) => Err(ProtocolError::idempotency_key_required()),
            (false, true) => Err(ProtocolError::idempotency_key_forbidden()),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub protocol: Protocol,
    pub request_id: Id,
    pub ok: Success,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Id>,
    pub ok: Failure,
    pub error: ProtocolError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub protocol: Protocol,
    pub subscription_id: Id,
    pub event: EventName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_seq: Option<u64>,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Envelope {
    Response(Response),
    Error(ErrorEnvelope),
    Request(Request),
    Event(Event),
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| de::Error::custom("attach envelope must be an object"))?;
        let has = |field: &str| object.contains_key(field);

        let kind = if has("ok") {
            if has("operation")
                || has("capability")
                || has("idempotency_key")
                || has("subscription_id")
                || has("event")
                || has("run_id")
                || has("run_seq")
            {
                return Err(de::Error::custom("conflicting attach envelope fields"));
            }
            match object.get("ok") {
                Some(Value::Bool(true)) if !has("error") => 0,
                Some(Value::Bool(false)) if has("error") && !has("body") => 1,
                _ => return Err(de::Error::custom("invalid attach envelope discriminant")),
            }
        } else if has("operation") || has("capability") || has("idempotency_key") {
            if has("error")
                || has("subscription_id")
                || has("event")
                || has("run_id")
                || has("run_seq")
            {
                return Err(de::Error::custom("conflicting attach envelope fields"));
            }
            2
        } else if has("subscription_id") || has("event") || has("run_id") || has("run_seq") {
            if has("error")
                || has("request_id")
                || has("operation")
                || has("capability")
                || has("idempotency_key")
            {
                return Err(de::Error::custom("conflicting attach envelope fields"));
            }
            3
        } else {
            return Err(de::Error::custom("unrecognized attach envelope shape"));
        };

        match kind {
            0 => serde_json::from_value(value)
                .map(Self::Response)
                .map_err(de::Error::custom),
            1 => serde_json::from_value(value)
                .map(Self::Error)
                .map_err(de::Error::custom),
            2 => serde_json::from_value(value)
                .map(Self::Request)
                .map_err(de::Error::custom),
            _ => serde_json::from_value(value)
                .map(Self::Event)
                .map_err(de::Error::custom),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ProtocolIncompatible,
    PayloadTooLarge,
    MalformedFrame,
    IdempotencyKeyRequired,
    IdempotencyKeyForbidden,
    IdempotencyConflict,
    PersistenceFailed,
    InvalidCursor,
    InvalidArtifactCursor,
    InvalidRequest,
    Unauthorized,
    UnsupportedOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    #[serde(rename = "thread.list")]
    ThreadList,
    #[serde(rename = "thread.open")]
    ThreadOpen,
    #[serde(rename = "run.open")]
    RunOpen,
    #[serde(rename = "run.start")]
    RunStart,
    #[serde(rename = "run.stream")]
    RunStream,
    #[serde(rename = "run.cursor_ack")]
    RunCursorAck,
    #[serde(rename = "run.steer")]
    RunSteer,
    #[serde(rename = "run.follow_up")]
    RunFollowUp,
    #[serde(rename = "run.cancel")]
    RunCancel,
    #[serde(rename = "permission.answer")]
    PermissionAnswer,
    #[serde(rename = "artifact.fetch")]
    ArtifactFetch,
    #[serde(rename = "artifact.window")]
    ArtifactWindow,
    #[serde(rename = "request.cancel")]
    RequestCancel,
}

impl Operation {
    pub fn requires_idempotency_key(self) -> bool {
        matches!(
            self,
            Self::RunStart
                | Self::RunSteer
                | Self::RunFollowUp
                | Self::RunCancel
                | Self::PermissionAnswer
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThreadList => "thread.list",
            Self::ThreadOpen => "thread.open",
            Self::RunOpen => "run.open",
            Self::RunStart => "run.start",
            Self::RunStream => "run.stream",
            Self::RunCursorAck => "run.cursor_ack",
            Self::RunSteer => "run.steer",
            Self::RunFollowUp => "run.follow_up",
            Self::RunCancel => "run.cancel",
            Self::PermissionAnswer => "permission.answer",
            Self::ArtifactFetch => "artifact.fetch",
            Self::ArtifactWindow => "artifact.window",
            Self::RequestCancel => "request.cancel",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventName {
    #[serde(rename = "run.event")]
    RunEvent,
    #[serde(rename = "subscription.caught_up")]
    SubscriptionCaughtUp,
    #[serde(rename = "permission.pending")]
    PermissionPending,
    #[serde(rename = "artifact.chunk")]
    ArtifactChunk,
    #[serde(rename = "artifact.complete")]
    ArtifactComplete,
    #[serde(rename = "request.cancelled")]
    RequestCancelled,
    #[serde(rename = "capability.revoked")]
    CapabilityRevoked,
    #[serde(rename = "stream.closed")]
    StreamClosed,
    #[serde(untagged)]
    Unknown(BoundedEventName),
}

/// A future v1 event name retained so a receiver can safely ignore the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedEventName(String);

impl BoundedEventName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for BoundedEventName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BoundedEventName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > MAX_TEXT_LENGTH {
            return Err(de::Error::custom("invalid event name"));
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorAction {
    UpgradeCompanion,
    UpgradeDesktop,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Success;

impl Serialize for Success {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}
impl<'de> Deserialize<'de> for Success {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        bool::deserialize(deserializer)?
            .then_some(Self)
            .ok_or_else(|| de::Error::custom("ok must be true"))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Failure;

impl Serialize for Failure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(false)
    }
}
impl<'de> Deserialize<'de> for Failure {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        (!bool::deserialize(deserializer)?)
            .then_some(Self)
            .ok_or_else(|| de::Error::custom("ok must be false"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorMessage {
    #[serde(rename = "The companion and desktop protocol versions are incompatible.")]
    ProtocolIncompatible,
    #[serde(rename = "The payload exceeds the allowed size.")]
    PayloadTooLarge,
    #[serde(rename = "The frame is malformed.")]
    MalformedFrame,
    #[serde(rename = "An idempotency key is required for this operation.")]
    IdempotencyKeyRequired,
    #[serde(rename = "An idempotency key is not valid for this operation.")]
    IdempotencyKeyForbidden,
    #[serde(rename = "The idempotency key was already used for a different request.")]
    IdempotencyConflict,
    #[serde(rename = "The request could not be committed.")]
    PersistenceFailed,
    #[serde(rename = "The stream cursor is invalid.")]
    InvalidCursor,
    #[serde(rename = "The artifact transfer cursor is invalid.")]
    InvalidArtifactCursor,
    #[serde(rename = "The request is invalid.")]
    InvalidRequest,
    #[serde(rename = "The capability is not authorized.")]
    Unauthorized,
    #[serde(rename = "The operation is not supported.")]
    UnsupportedOperation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProtocolError {
    code: ErrorCode,
    message: ErrorMessage,
    retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<ErrorAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    details: Option<ErrorDetails>,
}

impl ProtocolError {
    pub fn protocol_incompatible(supported: VersionRange, action: ErrorAction) -> Self {
        Self {
            code: ErrorCode::ProtocolIncompatible,
            message: ErrorMessage::ProtocolIncompatible,
            retryable: false,
            action: Some(action),
            details: Some(ErrorDetails::SupportedVersions { supported }),
        }
    }

    pub fn payload_too_large() -> Self {
        Self::simple(ErrorCode::PayloadTooLarge, ErrorMessage::PayloadTooLarge)
    }

    pub fn malformed_frame() -> Self {
        Self::simple(ErrorCode::MalformedFrame, ErrorMessage::MalformedFrame)
    }

    pub fn idempotency_key_required() -> Self {
        Self::simple(
            ErrorCode::IdempotencyKeyRequired,
            ErrorMessage::IdempotencyKeyRequired,
        )
    }
    pub fn idempotency_key_forbidden() -> Self {
        Self::simple(
            ErrorCode::IdempotencyKeyForbidden,
            ErrorMessage::IdempotencyKeyForbidden,
        )
    }
    pub fn idempotency_conflict() -> Self {
        Self::simple(
            ErrorCode::IdempotencyConflict,
            ErrorMessage::IdempotencyConflict,
        )
    }
    pub fn persistence_failed() -> Self {
        let mut error = Self::simple(
            ErrorCode::PersistenceFailed,
            ErrorMessage::PersistenceFailed,
        );
        error.retryable = true;
        error
    }

    pub fn invalid_cursor() -> Self {
        Self::simple(ErrorCode::InvalidCursor, ErrorMessage::InvalidCursor)
    }

    pub fn invalid_artifact_cursor() -> Self {
        Self::simple(
            ErrorCode::InvalidArtifactCursor,
            ErrorMessage::InvalidArtifactCursor,
        )
    }

    pub fn invalid_request() -> Self {
        Self::simple(ErrorCode::InvalidRequest, ErrorMessage::InvalidRequest)
    }

    pub fn unauthorized() -> Self {
        Self::simple(ErrorCode::Unauthorized, ErrorMessage::Unauthorized)
    }

    pub fn unsupported_operation() -> Self {
        Self::simple(
            ErrorCode::UnsupportedOperation,
            ErrorMessage::UnsupportedOperation,
        )
    }

    fn simple(code: ErrorCode, message: ErrorMessage) -> Self {
        Self {
            code,
            message,
            retryable: false,
            action: None,
            details: None,
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }
    pub fn message(&self) -> ErrorMessage {
        self.message
    }
    pub fn retryable(&self) -> bool {
        self.retryable
    }
    pub fn action(&self) -> Option<ErrorAction> {
        self.action
    }
    pub fn details(&self) -> Option<&ErrorDetails> {
        self.details.as_ref()
    }
}

impl<'de> Deserialize<'de> for ProtocolError {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            code: ErrorCode,
            message: ErrorMessage,
            retryable: bool,
            #[serde(default)]
            action: Option<ErrorAction>,
            #[serde(default)]
            details: Option<ErrorDetails>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let expected = match (wire.code, wire.action, wire.details) {
            (
                ErrorCode::ProtocolIncompatible,
                Some(action),
                Some(ErrorDetails::SupportedVersions { supported }),
            ) => Self::protocol_incompatible(supported, action),
            (ErrorCode::PayloadTooLarge, None, None) => Self::payload_too_large(),
            (ErrorCode::MalformedFrame, None, None) => Self::malformed_frame(),
            (ErrorCode::IdempotencyKeyRequired, None, None) => Self::idempotency_key_required(),
            (ErrorCode::IdempotencyKeyForbidden, None, None) => Self::idempotency_key_forbidden(),
            (ErrorCode::IdempotencyConflict, None, None) => Self::idempotency_conflict(),
            (ErrorCode::PersistenceFailed, None, None) => Self::persistence_failed(),
            (ErrorCode::InvalidCursor, None, None) => Self::invalid_cursor(),
            (ErrorCode::InvalidArtifactCursor, None, None) => Self::invalid_artifact_cursor(),
            (ErrorCode::InvalidRequest, None, None) => Self::invalid_request(),
            (ErrorCode::Unauthorized, None, None) => Self::unauthorized(),
            (ErrorCode::UnsupportedOperation, None, None) => Self::unsupported_operation(),
            _ => return Err(de::Error::custom("invalid error schema")),
        };
        if wire.message != expected.message || wire.retryable != expected.retryable {
            return Err(de::Error::custom("invalid error schema"));
        }
        Ok(expected)
    }
}

/// Closed, deliberately non-secret error detail vocabulary for this slice.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ErrorDetails {
    SupportedVersions { supported: VersionRange },
}

impl<'de> Deserialize<'de> for ErrorDetails {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SupportedVersions {
            supported: VersionRange,
        }

        let details = SupportedVersions::deserialize(deserializer)?;
        Ok(Self::SupportedVersions {
            supported: details.supported,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub min: u32,
    pub max: u32,
}
