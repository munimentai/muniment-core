//! Pure backend logic for the Muniment desktop app.
//!
//! Nothing in this crate may depend on Tauri or any GUI toolkit: unit tests
//! here run on the shared CI runner, which has no display stack. The Pi
//! sidecar process manager and its RPC transport build on these pieces.

/// Incremental splitter for JSONL RPC frames read from a child process's
/// stdio. Feed raw bytes as they arrive; complete frames come back out and a
/// trailing partial line stays buffered until its newline shows up. A
/// trailing `\r` is stripped so a CRLF-emitting sidecar behaves the same on
/// every platform, and blank lines are dropped (they carry no record).
#[derive(Default)]
pub struct JsonlFrameBuffer {
    pending: Vec<u8>,
}

impl JsonlFrameBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorbs `chunk` and returns every frame it completes, in order.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.pending.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(nl) = self.pending.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.pending.drain(..=nl).collect();
            line.pop(); // the newline itself
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if !line.is_empty() {
                frames.push(String::from_utf8_lossy(&line).into_owned());
            }
        }
        frames
    }

    /// Bytes buffered while waiting for the rest of a partial frame.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_complete_frames_and_buffers_the_partial_tail() {
        let mut buf = JsonlFrameBuffer::new();
        let frames = buf.push(b"{\"id\":1}\n{\"id\":2}\n{\"id\":");
        assert_eq!(frames, vec!["{\"id\":1}", "{\"id\":2}"]);
        assert_eq!(buf.pending_len(), 6); // the dangling `{"id":` stays buffered
    }

    #[test]
    fn partial_frame_completes_across_pushes() {
        let mut buf = JsonlFrameBuffer::new();
        assert!(buf.push(b"{\"method\":\"pi").is_empty());
        let frames = buf.push(b"ng\"}\n");
        assert_eq!(frames, vec!["{\"method\":\"ping\"}"]);
        assert_eq!(buf.pending_len(), 0);
    }

    #[test]
    fn strips_crlf_and_drops_blank_keepalive_lines() {
        let mut buf = JsonlFrameBuffer::new();
        let frames = buf.push(b"{\"ok\":true}\r\n\r\n\n{\"ok\":false}\n");
        assert_eq!(frames, vec!["{\"ok\":true}", "{\"ok\":false}"]);
    }

    #[test]
    fn multibyte_utf8_split_across_chunks_survives_intact() {
        let mut buf = JsonlFrameBuffer::new();
        let bytes = "{\"name\":\"muñiment\"}\n".as_bytes();
        let (head, tail) = bytes.split_at(12); // lands between ñ's two bytes
        assert!(buf.push(head).is_empty());
        let frames = buf.push(tail);
        assert_eq!(frames, vec!["{\"name\":\"muñiment\"}"]);
    }
}
