use std::io;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use muniment_attach::{
    decode_frame, encode_frame, Envelope, Id, Operation, Protocol, Request, MAX_FRAME_LENGTH,
};
use serde::Deserialize;
use serde_json::json;

use super::deadline_io::{read_exact_before, write_all_before};
use super::ApprovalRequest;

/// A claimed presenter session used to show approval challenges.
pub struct ApprovalPresenterConnection {
    stream: UnixStream,
    capability: String,
}

impl ApprovalPresenterConnection {
    pub fn new(stream: UnixStream, capability: impl Into<String>) -> Self {
        Self {
            stream,
            capability: capability.into(),
        }
    }

    pub(crate) fn try_clone_stream(&self) -> io::Result<UnixStream> {
        self.stream.try_clone()
    }

    pub fn present(&mut self, request: &ApprovalRequest, remaining: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(remaining) else {
            return false;
        };
        let request_id = Id::new(uuid::Uuid::new_v4().to_string())
            .expect("generated approval request ID is valid");
        let envelope = Request {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::ApprovalPresent,
            capability: self.capability.clone(),
            idempotency_key: None,
            body: json!({
                "challenge": request.challenge,
                "claimed_kind": request.claimed_kind,
                "claimed_version": request.claimed_version,
                "workspace": request.workspace,
                "scopes": request.scopes,
                "deadline_ms": u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
            }),
        };
        let Ok(frame) = encode_frame(&envelope) else {
            return false;
        };
        if write_all_before(&mut self.stream, &frame, deadline).is_err() {
            return false;
        }
        let Ok(response) = read_envelope_before(&mut self.stream, deadline) else {
            return false;
        };
        let Envelope::Response(response) = response else {
            return false;
        };
        if response.request_id != request_id {
            return false;
        }
        let Ok(body) = serde_json::from_value::<ApprovalDecision>(response.body) else {
            return false;
        };
        body.challenge == request.challenge && body.decision == "approve"
    }
}

#[derive(Deserialize)]
struct ApprovalDecision {
    challenge: String,
    decision: String,
}

fn read_envelope_before(stream: &mut UnixStream, deadline: Instant) -> io::Result<Envelope> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)?;
    decode_frame(&frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid frame"))?
        .map(|(envelope, _)| envelope)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete frame"))
}
