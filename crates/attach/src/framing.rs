use std::fmt;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub const MAX_FRAME_LENGTH: usize = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_STRINGS: usize = 4096;
pub const MAX_JSON_COLLECTION_ENTRIES: usize = 4096;

#[derive(Debug)]
pub enum FrameError {
    PayloadTooLarge,
    InvalidUtf8,
    InvalidJson,
    StructureLimit,
    Serialize(serde_json::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PayloadTooLarge => "attach frame exceeds the size limit",
            Self::InvalidUtf8 => "attach frame is not UTF-8",
            Self::InvalidJson => "attach frame is not valid JSON",
            Self::StructureLimit => "attach frame exceeds a structural limit",
            Self::Serialize(_) => "attach frame could not be serialized",
        })
    }
}
impl std::error::Error for FrameError {}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value).map_err(FrameError::Serialize)?;
    validate_payload(&payload)?;
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one frame from the start of `bytes`, returning `None` when more bytes are needed.
/// The declared size is checked as soon as the four-byte prefix is available.
pub fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<Option<(T, usize)>, FrameError> {
    if bytes.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(FrameError::PayloadTooLarge);
    }
    let consumed = 4usize
        .checked_add(length)
        .ok_or(FrameError::PayloadTooLarge)?;
    if bytes.len() < consumed {
        return Ok(None);
    }
    let payload = &bytes[4..consumed];
    validate_payload(payload)?;
    let value = serde_json::from_slice(payload).map_err(|_| FrameError::InvalidJson)?;
    Ok(Some((value, consumed)))
}

fn validate_payload(payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_LENGTH {
        return Err(FrameError::PayloadTooLarge);
    }
    std::str::from_utf8(payload).map_err(|_| FrameError::InvalidUtf8)?;
    let value: Value = serde_json::from_slice(payload).map_err(|_| FrameError::InvalidJson)?;
    let artifact_data = value
        .as_object()
        .filter(|object| object.get("event").and_then(Value::as_str) == Some("artifact.chunk"))
        .and_then(|object| object.get("body"))
        .and_then(Value::as_object)
        .and_then(|body| body.get("data"))
        .and_then(Value::as_str);
    const MAX_ARTIFACT_BASE64_LENGTH: usize = (256_usize * 1024).div_ceil(3) * 4;
    let mut stack = vec![(&value, 1usize)];
    let (mut strings, mut entries) = (0usize, 0usize);
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(FrameError::StructureLimit);
        }
        match value {
            Value::String(s) => {
                strings += 1;
                let artifact_data_in_range = artifact_data
                    .is_some_and(|data| std::ptr::eq(data, s.as_str()))
                    && s.len() <= MAX_ARTIFACT_BASE64_LENGTH;
                if s.len() > crate::MAX_TEXT_LENGTH && !artifact_data_in_range {
                    return Err(FrameError::StructureLimit);
                }
            }
            Value::Array(values) => {
                entries += values.len();
                stack.extend(values.iter().map(|v| (v, depth + 1)));
            }
            Value::Object(values) => {
                entries += values.len();
                strings += values.len();
                if values.keys().any(|key| key.len() > crate::MAX_TEXT_LENGTH) {
                    return Err(FrameError::StructureLimit);
                }
                stack.extend(values.values().map(|v| (v, depth + 1)));
            }
            _ => {}
        }
        if strings > MAX_JSON_STRINGS || entries > MAX_JSON_COLLECTION_ENTRIES {
            return Err(FrameError::StructureLimit);
        }
    }
    Ok(())
}
