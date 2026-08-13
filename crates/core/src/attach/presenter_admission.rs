//! Linux approval presenter admission.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use muniment_attach::{
    decode_frame, encode_frame, reconnect_welcome, ErrorEnvelope, Failure, FirstMessage,
    MigrationControlAuthorized, NegotiationError, Protocol, ProtocolError, VersionRange,
    MAX_FRAME_LENGTH,
};

use super::linux::PeerCredentials;
use super::verify_approval_presenter_peer_with_reader;
use crate::browser_control::LinuxProcReader;

const DESKTOP_PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

/// Closed outcomes from approval presenter admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalPresenterAdmissionError {
    PeerUnauthorized,
    Closed,
    Timeout,
    MalformedFrame,
    PayloadTooLarge,
    ProtocolIncompatible,
    Randomness,
}

/// Admits a verified approval presenter and returns its connection capability.
pub fn admit_approval_presenter(
    mut stream: UnixStream,
    peer_credentials: PeerCredentials,
    expected_desktop_executable: &Path,
    process_reader: &dyn LinuxProcReader,
    runtime_version: &str,
    timeout: Duration,
) -> Result<(UnixStream, String), ApprovalPresenterAdmissionError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ApprovalPresenterAdmissionError::Timeout)?;
    let peer_authorized = u32::try_from(peer_credentials.pid).is_ok_and(|peer_pid| {
        verify_approval_presenter_peer_with_reader(
            peer_pid,
            expected_desktop_executable,
            process_reader,
        )
        .is_ok()
    });
    if !peer_authorized {
        write_protocol_error(&mut stream, ProtocolError::unauthorized(), deadline);
        return Err(ApprovalPresenterAdmissionError::PeerUnauthorized);
    }

    let mut prefix = [0_u8; 4];
    read_before(&mut stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        write_protocol_error(&mut stream, ProtocolError::payload_too_large(), deadline);
        return Err(ApprovalPresenterAdmissionError::PayloadTooLarge);
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_before(&mut stream, &mut frame[4..], deadline)?;
    let message = match decode_frame::<FirstMessage>(&frame) {
        Ok(Some((message, consumed))) if consumed == frame.len() => message,
        _ => {
            write_protocol_error(&mut stream, ProtocolError::malformed_frame(), deadline);
            return Err(ApprovalPresenterAdmissionError::MalformedFrame);
        }
    };
    let selected = match muniment_attach::negotiate_first(message, DESKTOP_PROTOCOL) {
        Ok(selected) => selected,
        Err(NegotiationError::Incompatible(error)) => {
            write_protocol_error(&mut stream, error, deadline);
            return Err(ApprovalPresenterAdmissionError::ProtocolIncompatible);
        }
        Err(_) => {
            write_protocol_error(&mut stream, ProtocolError::malformed_frame(), deadline);
            return Err(ApprovalPresenterAdmissionError::MalformedFrame);
        }
    };

    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| ApprovalPresenterAdmissionError::Randomness)?;
    let welcome = reconnect_welcome(selected, runtime_version, hex(&nonce), "");
    write_before(
        &mut stream,
        &encode_frame(&welcome).map_err(|_| ApprovalPresenterAdmissionError::MalformedFrame)?,
        deadline,
    )?;

    let mut capability_bytes = [0_u8; 32];
    getrandom::fill(&mut capability_bytes)
        .map_err(|_| ApprovalPresenterAdmissionError::Randomness)?;
    let capability = hex(&capability_bytes);
    let grant = MigrationControlAuthorized {
        profile_id: String::new(),
        capability: capability.clone(),
        expires_at: timeout.as_secs(),
        idle_timeout_seconds: timeout.as_secs(),
        workspace_scopes: BTreeMap::new(),
    };
    write_before(
        &mut stream,
        &encode_frame(&grant).map_err(|_| ApprovalPresenterAdmissionError::MalformedFrame)?,
        deadline,
    )?;

    Ok((stream, capability))
}

fn read_before(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), ApprovalPresenterAdmissionError> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ApprovalPresenterAdmissionError::Closed)?;
        match stream.read(bytes) {
            Ok(0) => return Err(ApprovalPresenterAdmissionError::Closed),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if is_timeout(&error) => {
                return Err(ApprovalPresenterAdmissionError::Timeout)
            }
            Err(_) => return Err(ApprovalPresenterAdmissionError::Closed),
        }
    }
    Ok(())
}

fn write_before(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ApprovalPresenterAdmissionError> {
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| ApprovalPresenterAdmissionError::Closed)?;
    stream.write_all(bytes).map_err(|error| {
        if is_timeout(&error) {
            ApprovalPresenterAdmissionError::Timeout
        } else {
            ApprovalPresenterAdmissionError::Closed
        }
    })
}

fn write_protocol_error(stream: &mut UnixStream, error: ProtocolError, deadline: Instant) {
    let envelope = ErrorEnvelope {
        protocol: Protocol,
        request_id: None,
        ok: Failure,
        error,
    };
    if let Ok(frame) = encode_frame(&envelope) {
        let _ = write_before(stream, &frame, deadline);
    }
}

fn remaining(deadline: Instant) -> Result<Duration, ApprovalPresenterAdmissionError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ApprovalPresenterAdmissionError::Timeout)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}
