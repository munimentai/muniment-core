use crate::{ClientError, ErrorCode, ErrorEnvelope, FrameError, Id, PROTOCOL};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn fresh_request_id() -> Result<Id, ClientError> {
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

pub(crate) fn map_protocol_error(code: ErrorCode) -> ClientError {
    match code {
        ErrorCode::ProtocolIncompatible => ClientError::ProtocolIncompatible,
        ErrorCode::Unauthorized => ClientError::AuthorizationExpired,
        ErrorCode::ThreadNotFound => ClientError::ThreadNotFound,
        ErrorCode::PersistenceFailed => ClientError::DesktopFailed,
        _ => ClientError::RequestRejected,
    }
}

pub(crate) fn fresh_nonce() -> Result<String, ClientError> {
    let bytes = random_bytes()?;
    let mut nonce = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut nonce, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(nonce)
}

pub(crate) fn random_bytes() -> Result<[u8; 16], ClientError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ClientError::RandomnessUnavailable)?;
    Ok(bytes)
}

pub(crate) fn is_hex_secret(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn deadline(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

pub(crate) fn reject_protocol_error(value: &Value) -> Result<(), ClientError> {
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

pub(crate) fn parse_message<T: DeserializeOwned>(value: Value) -> Result<T, ClientError> {
    serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)
}

pub(crate) fn map_frame_error(error: FrameError) -> ClientError {
    match error {
        FrameError::PayloadTooLarge => ClientError::PayloadTooLarge,
        _ => ClientError::MalformedFrame,
    }
}
