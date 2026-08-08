//! Runtime service handoff readiness probe and confirmation.

use muniment_attach::Welcome;
#[cfg(target_os = "linux")]
use muniment_attach::{
    decode_frame, encode_frame, Client, Hello, Id, Protocol, VersionRange, MAX_FRAME_LENGTH,
};
use std::fmt;
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::time::Instant;

#[cfg(target_os = "linux")]
const PROBE_CLIENT_ID: &str = "018f0000-0000-7000-8000-000000000001";

/// Proof that the runtime service completed a migration handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedHandoff(());

/// A bounded reason that a probe welcome does not confirm the handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffProbeError {
    ReadinessDeadlineReached,
    ConnectionRefused,
    ConnectionFailed,
    RandomnessUnavailable,
    WriteFailed,
    ListenerClosed,
    ReadFailed,
    InvalidFrame,
    UnexpectedFirstFrame,
    MissingNonce,
    NonceMismatch,
}

impl fmt::Display for HandoffProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReadinessDeadlineReached => "runtime service readiness deadline reached",
            Self::ConnectionRefused => "runtime service readiness connection was refused",
            Self::ConnectionFailed => "runtime service readiness connection failed",
            Self::RandomnessUnavailable => "probe nonce randomness is unavailable",
            Self::WriteFailed => "probe hello write failed",
            Self::ListenerClosed => "runtime service closed before its probe welcome",
            Self::ReadFailed => "probe welcome read failed",
            Self::InvalidFrame => "runtime service sent an invalid probe frame",
            Self::UnexpectedFirstFrame => "runtime service first probe frame is not a welcome",
            Self::MissingNonce => "probe welcome has no handoff nonce",
            Self::NonceMismatch => "probe welcome handoff nonce does not match",
        })
    }
}

impl std::error::Error for HandoffProbeError {}

/// Opens the endpoint, exchanges one readiness handshake, and closes it.
#[cfg(target_os = "linux")]
pub fn read_handoff_probe_welcome(
    endpoint: impl AsRef<Path>,
    deadline: Instant,
) -> Result<Welcome, HandoffProbeError> {
    remaining(deadline)?;
    let mut stream = UnixStream::connect(endpoint).map_err(|error| match error.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => {
            HandoffProbeError::ConnectionRefused
        }
        _ => HandoffProbeError::ConnectionFailed,
    })?;

    let hello = Hello {
        protocol: Protocol,
        client: Client {
            kind: "desktop-handoff-probe".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: mint_probe_nonce()?,
        authorized_client_id: Id::new(PROBE_CLIENT_ID).expect("probe client ID is valid"),
        authorized_client_credential: None,
    };
    let frame = encode_frame(&hello).map_err(|_| HandoffProbeError::WriteFailed)?;
    write_all_before(&mut stream, &frame, deadline)?;
    read_welcome_before(&mut stream, deadline)
}

#[cfg(target_os = "linux")]
fn mint_probe_nonce() -> Result<String, HandoffProbeError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| HandoffProbeError::RandomnessUnavailable)?;
    let mut nonce = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        nonce.push(HEX[(byte >> 4) as usize] as char);
        nonce.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(nonce)
}

#[cfg(target_os = "linux")]
fn remaining(deadline: Instant) -> Result<std::time::Duration, HandoffProbeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(HandoffProbeError::ReadinessDeadlineReached)
}

#[cfg(target_os = "linux")]
fn write_all_before(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), HandoffProbeError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| HandoffProbeError::WriteFailed)?;
        match stream.write(bytes) {
            Ok(0) => return Err(HandoffProbeError::WriteFailed),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if is_timeout(&error) => {
                return Err(HandoffProbeError::ReadinessDeadlineReached)
            }
            Err(_) => return Err(HandoffProbeError::WriteFailed),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_welcome_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Welcome, HandoffProbeError> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(HandoffProbeError::InvalidFrame);
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)?;
    let value: serde_json::Value = decode_frame(&frame)
        .map_err(|_| HandoffProbeError::InvalidFrame)?
        .map(|(value, _)| value)
        .ok_or(HandoffProbeError::InvalidFrame)?;
    serde_json::from_value(value).map_err(|_| HandoffProbeError::UnexpectedFirstFrame)
}

#[cfg(target_os = "linux")]
fn read_exact_before(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), HandoffProbeError> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| HandoffProbeError::ReadFailed)?;
        match stream.read(bytes) {
            Ok(0) => return Err(HandoffProbeError::ListenerClosed),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if is_timeout(&error) => {
                return Err(HandoffProbeError::ReadinessDeadlineReached)
            }
            Err(_) => return Err(HandoffProbeError::ReadFailed),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Confirms a completed handoff from the runtime service probe welcome.
pub fn confirm_handoff_probe(
    welcome: &Welcome,
    expected_nonce: &str,
    readiness_deadline: Instant,
    now: Instant,
) -> Result<ConfirmedHandoff, HandoffProbeError> {
    if now >= readiness_deadline {
        return Err(HandoffProbeError::ReadinessDeadlineReached);
    }

    let nonce = welcome
        .handoff_nonce
        .as_deref()
        .ok_or(HandoffProbeError::MissingNonce)?;
    if nonce != expected_nonce {
        return Err(HandoffProbeError::NonceMismatch);
    }

    Ok(ConfirmedHandoff(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_attach::{Authorization, Welcome};
    use std::time::Duration;

    fn welcome(handoff_nonce: Option<&str>) -> Welcome {
        Welcome {
            selected: 1,
            desktop_version: "1.0.0".into(),
            server_nonce: "server-nonce".into(),
            authorization: Authorization::Authorized,
            approval_challenge: "challenge".into(),
            handoff_nonce: handoff_nonce.map(str::to_owned),
        }
    }

    #[test]
    fn confirms_matching_nonce_before_deadline() {
        let now = Instant::now();

        assert_eq!(
            confirm_handoff_probe(
                &welcome(Some("handoff-nonce")),
                "handoff-nonce",
                now + Duration::from_secs(1),
                now,
            ),
            Ok(ConfirmedHandoff(()))
        );
    }

    #[test]
    fn rejects_missing_nonce() {
        let now = Instant::now();

        assert_eq!(
            confirm_handoff_probe(
                &welcome(None),
                "handoff-nonce",
                now + Duration::from_secs(1),
                now
            ),
            Err(HandoffProbeError::MissingNonce)
        );
    }

    #[test]
    fn rejects_mismatched_nonce() {
        let now = Instant::now();

        assert_eq!(
            confirm_handoff_probe(
                &welcome(Some("other-nonce")),
                "handoff-nonce",
                now + Duration::from_secs(1),
                now,
            ),
            Err(HandoffProbeError::NonceMismatch)
        );
    }

    #[test]
    fn rejects_matching_nonce_at_deadline() {
        let now = Instant::now();

        assert_eq!(
            confirm_handoff_probe(&welcome(Some("handoff-nonce")), "handoff-nonce", now, now),
            Err(HandoffProbeError::ReadinessDeadlineReached)
        );
    }

    #[test]
    fn errors_have_distinct_single_line_messages() {
        let errors = [
            HandoffProbeError::ReadinessDeadlineReached,
            HandoffProbeError::ConnectionRefused,
            HandoffProbeError::ConnectionFailed,
            HandoffProbeError::RandomnessUnavailable,
            HandoffProbeError::WriteFailed,
            HandoffProbeError::ListenerClosed,
            HandoffProbeError::ReadFailed,
            HandoffProbeError::InvalidFrame,
            HandoffProbeError::UnexpectedFirstFrame,
            HandoffProbeError::MissingNonce,
            HandoffProbeError::NonceMismatch,
        ];
        let messages: std::collections::HashSet<_> =
            errors.iter().map(ToString::to_string).collect();

        assert_eq!(messages.len(), errors.len());
        assert!(messages.iter().all(|message| !message.contains('\n')));
    }
}
