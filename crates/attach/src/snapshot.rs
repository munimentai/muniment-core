//! Bounded desktop snapshots span frames without changing the frame limits.
//! Only thread history responses and chat events use this transport.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{FrameError, MAX_FRAME_LENGTH, MAX_JSON_DEPTH};

const CHUNK_BYTES: usize = 16 * 1024;
const MARKER: &str = "snapshot_chunk";

/// Splits a snapshot into ordered UTF-8 chunks. The complete snapshot keeps the
/// frame byte limit. Each wire envelope still passes normal frame validation.
pub fn snapshot_chunks(body: &Value) -> Result<Vec<Value>, FrameError> {
    check_depth(body)?;
    let text = serde_json::to_string(body).map_err(FrameError::Serialize)?;
    if text.len() > MAX_FRAME_LENGTH {
        return Err(FrameError::PayloadTooLarge);
    }
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let mut end = (offset + CHUNK_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(json!({MARKER: {
            "offset": offset, "total_bytes": text.len(), "data": &text[offset..end],
        }}));
        offset = end;
    }
    Ok(chunks)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    offset: usize,
    total_bytes: usize,
    data: String,
}

/// Assembles one snapshot. Callers check the envelope identity for every chunk
/// and use one deadline for the whole snapshot. A disconnect discards this state.
#[derive(Default)]
pub struct SnapshotAssembly {
    text: String,
    total: Option<usize>,
}

impl SnapshotAssembly {
    pub fn push(&mut self, body: Value) -> Result<Option<Value>, FrameError> {
        let Some(chunk) = body.get(MARKER) else {
            return if self.total.is_none() {
                Ok(Some(body))
            } else {
                Err(FrameError::InvalidJson)
            };
        };
        if body.as_object().map(|body| body.len()) != Some(1) {
            return Err(FrameError::InvalidJson);
        }
        let chunk: Chunk =
            serde_json::from_value(chunk.clone()).map_err(|_| FrameError::InvalidJson)?;
        if chunk.total_bytes == 0 || chunk.total_bytes > MAX_FRAME_LENGTH {
            return Err(FrameError::PayloadTooLarge);
        }
        if chunk.offset != self.text.len()
            || self.total.is_some_and(|total| total != chunk.total_bytes)
            || chunk.data.is_empty()
            || chunk.data.len() > CHUNK_BYTES
            || chunk.offset > chunk.total_bytes
            || chunk.data.len() > chunk.total_bytes - chunk.offset
            || (chunk.offset + chunk.data.len() < chunk.total_bytes
                && chunk.data.len() < CHUNK_BYTES - 3)
        {
            return Err(FrameError::InvalidJson);
        }
        self.total = Some(chunk.total_bytes);
        self.text.push_str(&chunk.data);
        if self.text.len() < chunk.total_bytes {
            return Ok(None);
        }
        let value = serde_json::from_str(&self.text).map_err(|_| FrameError::InvalidJson)?;
        check_depth(&value)?;
        Ok(Some(value))
    }
}

fn check_depth(value: &Value) -> Result<(), FrameError> {
    // Reserve the same depth as a response or event envelope around the body.
    let mut stack = vec![(value, 2)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(FrameError::StructureLimit);
        }
        match value {
            Value::Array(values) => stack.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => stack.extend(values.values().map(|value| (value, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode_frame, encode_frame};

    fn long_history() -> Value {
        json!({"entries": [{
            "runId": "018f0000-0000-7000-8000-000000000201", "phase": "complete",
            "text": "Synthetic reply", "toolActivity": (0..300).map(|index| json!({
                "effectId": format!("tool-{index}"), "textOffset": 0, "displayName": "read",
                "status": "completed", "input": "synthetic input", "output": "synthetic output",
                "startedAt": "2026-01-01T00:00:00Z", "finishedAt": "2026-01-01T00:00:01Z",
            })).collect::<Vec<_>>()
        }], "nextCursor": null})
    }

    #[test]
    fn long_tool_history_exceeds_structure_not_bytes() {
        let body = long_history();
        assert!(serde_json::to_vec(&body).unwrap().len() < MAX_FRAME_LENGTH);
        assert!(matches!(
            encode_frame(&body),
            Err(FrameError::StructureLimit)
        ));
        let mut assembly = SnapshotAssembly::default();
        let chunks = snapshot_chunks(&body).unwrap();
        assert!(chunks.len() > 1);
        for (index, chunk) in chunks.iter().enumerate() {
            let frame = encode_frame(&json!({"body": chunk})).unwrap();
            let (wire, _) = decode_frame::<Value>(&frame).unwrap().unwrap();
            let restored = assembly.push(wire["body"].clone()).unwrap();
            if index + 1 == chunks.len() {
                assert_eq!(restored, Some(body.clone()));
            } else {
                assert!(restored.is_none());
            }
        }
    }

    #[test]
    fn chunks_preserve_unicode_empty_values_and_the_byte_boundary() {
        for body in [
            json!({}),
            json!([]),
            json!(""),
            json!("🦀".repeat(20_000)),
            json!("x".repeat(MAX_FRAME_LENGTH - 2)),
        ] {
            let mut assembly = SnapshotAssembly::default();
            let mut restored = None;
            for chunk in snapshot_chunks(&body).unwrap() {
                restored = assembly.push(chunk).unwrap();
            }
            assert_eq!(restored, Some(body));
        }
        assert!(matches!(
            snapshot_chunks(&json!("x".repeat(MAX_FRAME_LENGTH - 1))),
            Err(FrameError::PayloadTooLarge)
        ));
        let mut deep = json!(0);
        for _ in 0..MAX_JSON_DEPTH {
            deep = json!([deep]);
        }
        assert!(matches!(
            snapshot_chunks(&deep),
            Err(FrameError::StructureLimit)
        ));
    }

    #[test]
    fn assembly_rejects_invalid_authority_and_partial_sequences() {
        for chunk in [
            json!({"offset": 0, "total_bytes": 0, "data": "x"}),
            json!({"offset": 0, "total_bytes": MAX_FRAME_LENGTH + 1, "data": "x"}),
            json!({"offset": -1, "total_bytes": 1, "data": "x"}),
            json!({"offset": 0.5, "total_bytes": 1, "data": "x"}),
            json!({"offset": 1, "total_bytes": 1, "data": "x"}),
            json!({"offset": 0, "total_bytes": 1, "data": "xx"}),
            json!({"offset": 0, "total_bytes": 1, "data": ""}),
            json!({"offset": 0, "total_bytes": 100, "data": "x"}),
            json!({"offset": 0, "total_bytes": CHUNK_BYTES + 1, "data": "x".repeat(CHUNK_BYTES + 1)}),
            json!({"offset": 0, "total_bytes": 1, "data": "x", "extra": true}),
            json!({"offset": 0, "total_bytes": 1, "data": "x"}),
        ] {
            assert!(SnapshotAssembly::default()
                .push(json!({MARKER: chunk}))
                .is_err());
        }
        let chunks = snapshot_chunks(&long_history()).unwrap();
        for second in [
            chunks[0].clone(),
            chunks[2].clone(),
            json!({}),
            json!({MARKER: {"offset": CHUNK_BYTES, "total_bytes": 1, "data": "x"}}),
        ] {
            let mut assembly = SnapshotAssembly::default();
            assert!(assembly.push(chunks[0].clone()).unwrap().is_none());
            assert!(assembly.push(second).is_err());
        }
    }
}
