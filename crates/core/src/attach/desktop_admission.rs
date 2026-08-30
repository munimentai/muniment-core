//! Platform-neutral desktop client admission.

use std::collections::BTreeMap;
use std::io;
use std::time::Instant;

use muniment_attach::{
    decode_frame, encode_frame, reconnect_welcome, DesktopClientAuthorizedGrant, ErrorEnvelope,
    Failure, FirstMessage, NegotiationError, Protocol, ProtocolError, VersionRange,
    MAX_FRAME_LENGTH,
};

use super::deadline_io::{is_timeout, read_exact_before, write_all_before, DeadlineStream};
use super::{Approval, CAPABILITY_IDLE_LIFETIME, MAX_CAPABILITY_LIFETIME};

const DESKTOP_PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

/// Values carried by an admitted desktop client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedDesktopClient {
    pub capability: String,
    pub workspace: String,
    pub client_identity: String,
    pub companion_kind: String,
    pub companion_version: String,
}

/// Closed outcomes from desktop client admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopClientAdmissionError {
    PeerUnauthorized,
    Closed,
    Timeout,
    MalformedFrame,
    PayloadTooLarge,
    ProtocolIncompatible,
    Randomness,
}

/// Admits a desktop client over a deadline-aware stream.
pub fn admit_desktop_client_over_stream<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    runtime_version: &str,
    approval: Option<&Approval>,
    deadline: Instant,
) -> Result<AdmittedDesktopClient, DesktopClientAdmissionError> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline).map_err(map_io_error)?;
    admit_desktop_client_over_stream_with_prefix(
        stream,
        prefix,
        runtime_version,
        approval,
        deadline,
    )
}

/// Admits a desktop client after the caller has read the frame length prefix.
pub fn admit_desktop_client_over_stream_with_prefix<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    prefix: [u8; 4],
    runtime_version: &str,
    approval: Option<&Approval>,
    deadline: Instant,
) -> Result<AdmittedDesktopClient, DesktopClientAdmissionError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
        return Err(DesktopClientAdmissionError::PayloadTooLarge);
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline).map_err(map_io_error)?;
    let message = match decode_frame::<FirstMessage>(&frame) {
        Ok(Some((message, consumed))) if consumed == frame.len() => message,
        _ => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(DesktopClientAdmissionError::MalformedFrame);
        }
    };
    let (client_identity, companion_kind, companion_version) = match &message {
        FirstMessage::Hello(hello) => (
            hello.authorized_client_id.as_str().to_owned(),
            hello.client.kind.clone(),
            hello.client.version.clone(),
        ),
        FirstMessage::Other(_) => (String::new(), String::new(), String::new()),
    };
    let selected = match muniment_attach::negotiate_first(message, DESKTOP_PROTOCOL) {
        Ok(selected) => selected,
        Err(NegotiationError::Incompatible(error)) => {
            write_protocol_error(stream, error, deadline);
            return Err(DesktopClientAdmissionError::ProtocolIncompatible);
        }
        Err(_) => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(DesktopClientAdmissionError::MalformedFrame);
        }
    };

    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| DesktopClientAdmissionError::Randomness)?;
    let welcome = reconnect_welcome(selected, runtime_version, hex(&nonce), "");
    write_all_before(
        stream,
        &encode_frame(&welcome).map_err(|_| DesktopClientAdmissionError::MalformedFrame)?,
        deadline,
    )
    .map_err(map_io_error)?;

    let mut capability_bytes = [0_u8; 32];
    getrandom::fill(&mut capability_bytes).map_err(|_| DesktopClientAdmissionError::Randomness)?;
    let capability = hex(&capability_bytes);
    let mut workspace_scopes = BTreeMap::new();
    if let Some(approval) = approval.as_ref() {
        workspace_scopes.insert(approval.workspace.clone(), approval.scopes.clone());
    }
    let grant = DesktopClientAuthorizedGrant {
        profile_id: approval.as_ref().map_or_else(
            || "desktop-owner".into(),
            |approval| approval.profile.clone(),
        ),
        capability: capability.clone(),
        expires_at: approval
            .as_ref()
            .map_or(MAX_CAPABILITY_LIFETIME, |approval| approval.lifetime)
            .min(MAX_CAPABILITY_LIFETIME)
            .as_secs(),
        idle_timeout_seconds: CAPABILITY_IDLE_LIFETIME.as_secs(),
        workspace_scopes,
    };
    write_all_before(
        stream,
        &encode_frame(&grant).map_err(|_| DesktopClientAdmissionError::MalformedFrame)?,
        deadline,
    )
    .map_err(map_io_error)?;

    Ok(AdmittedDesktopClient {
        capability,
        workspace: approval.map_or_else(String::new, |approval| approval.workspace.clone()),
        client_identity,
        companion_kind,
        companion_version,
    })
}

pub(super) fn write_protocol_error<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    error: ProtocolError,
    deadline: Instant,
) {
    let envelope = ErrorEnvelope {
        protocol: Protocol,
        request_id: None,
        ok: Failure,
        error,
    };
    if let Ok(frame) = encode_frame(&envelope) {
        let _ = write_all_before(stream, &frame, deadline).map_err(map_io_error);
    }
}

fn map_io_error(error: io::Error) -> DesktopClientAdmissionError {
    if is_timeout(&error) {
        DesktopClientAdmissionError::Timeout
    } else {
        DesktopClientAdmissionError::Closed
    }
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
