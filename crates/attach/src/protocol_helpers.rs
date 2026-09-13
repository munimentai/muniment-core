use crate::client::RunStreamMessage;
use crate::{
    ClientError, ErrorCode, ErrorEnvelope, EventName, FrameError, Id, MAX_TEXT_LENGTH, PROTOCOL,
};
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
        ErrorCode::AuthorizationFailed => ClientError::AuthorizationFailed,
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

pub(crate) fn is_rfc3339(value: &str) -> bool {
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

pub(crate) fn validate_capability_revocation(
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
    let body: Body =
        serde_json::from_value(event.body.clone()).map_err(|_| ClientError::UnexpectedMessage)?;
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
