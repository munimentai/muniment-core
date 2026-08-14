//! Runtime service handoff readiness probe and confirmation.

#[cfg(target_os = "linux")]
use super::handoff::mint_hex_nonce;
use muniment_attach::Welcome;
#[cfg(target_os = "linux")]
use muniment_attach::{
    decode_frame, encode_frame, Client, Hello, Id, Protocol, VersionRange, MAX_FRAME_LENGTH,
};
use std::fmt;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::Instant;

#[cfg(target_os = "linux")]
use super::deadline_io::{is_timeout, read_exact_before, remaining, write_all_before};

#[cfg(target_os = "linux")]
const PROBE_CLIENT_ID: &str = "018f0000-0000-7000-8000-000000000001";
#[cfg(target_os = "linux")]
const HANDOFF_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(10);

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

/// Probes until the runtime service confirms the handoff or the deadline passes.
#[cfg(target_os = "linux")]
pub fn probe_handoff(
    endpoint: impl AsRef<Path>,
    expected_nonce: &str,
    readiness_deadline: Instant,
) -> Result<ConfirmedHandoff, HandoffProbeError> {
    loop {
        match read_handoff_probe_welcome(endpoint.as_ref(), readiness_deadline) {
            Ok(welcome) => {
                return confirm_handoff_probe(
                    &welcome,
                    expected_nonce,
                    readiness_deadline,
                    Instant::now(),
                )
            }
            Err(HandoffProbeError::ConnectionRefused) => {
                wait_before_retry(readiness_deadline, Instant::now, thread::sleep)?;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_before_retry(
    deadline: Instant,
    now: impl FnOnce() -> Instant,
    sleep: impl FnOnce(Duration),
) -> Result<(), HandoffProbeError> {
    let delay = deadline
        .checked_duration_since(now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(HandoffProbeError::ReadinessDeadlineReached)?
        .min(HANDOFF_PROBE_RETRY_INTERVAL);
    sleep(delay);
    Ok(())
}

/// Opens the endpoint, exchanges one readiness handshake, and closes it.
#[cfg(target_os = "linux")]
pub fn read_handoff_probe_welcome(
    endpoint: impl AsRef<Path>,
    deadline: Instant,
) -> Result<Welcome, HandoffProbeError> {
    remaining(deadline).map_err(|_| HandoffProbeError::ReadinessDeadlineReached)?;
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
    write_all_before(&mut stream, &frame, deadline).map_err(map_write_error)?;
    read_welcome_before(&mut stream, deadline)
}

#[cfg(target_os = "linux")]
fn mint_probe_nonce() -> Result<String, HandoffProbeError> {
    mint_hex_nonce(16).map_err(|_| HandoffProbeError::RandomnessUnavailable)
}

#[cfg(target_os = "linux")]
fn map_write_error(error: io::Error) -> HandoffProbeError {
    if is_timeout(&error) {
        HandoffProbeError::ReadinessDeadlineReached
    } else {
        HandoffProbeError::WriteFailed
    }
}

#[cfg(target_os = "linux")]
fn read_welcome_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<Welcome, HandoffProbeError> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline).map_err(map_read_error)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(HandoffProbeError::InvalidFrame);
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline).map_err(map_read_error)?;
    let value: serde_json::Value = decode_frame(&frame)
        .map_err(|_| HandoffProbeError::InvalidFrame)?
        .map(|(value, _)| value)
        .ok_or(HandoffProbeError::InvalidFrame)?;
    serde_json::from_value(value).map_err(|_| HandoffProbeError::UnexpectedFirstFrame)
}

#[cfg(target_os = "linux")]
fn map_read_error(error: io::Error) -> HandoffProbeError {
    if is_timeout(&error) {
        HandoffProbeError::ReadinessDeadlineReached
    } else if error.kind() == io::ErrorKind::UnexpectedEof {
        HandoffProbeError::ListenerClosed
    } else {
        HandoffProbeError::ReadFailed
    }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn bounds_each_retry_wait() {
        let now = Instant::now();
        let mut waits = Vec::new();

        wait_before_retry(
            now + Duration::from_secs(1),
            || now,
            |delay| waits.push(delay),
        )
        .unwrap();
        wait_before_retry(
            now + Duration::from_millis(15),
            || now + Duration::from_millis(12),
            |delay| waits.push(delay),
        )
        .unwrap();

        assert_eq!(
            waits,
            [HANDOFF_PROBE_RETRY_INTERVAL, Duration::from_millis(3)]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn does_not_wait_after_the_deadline() {
        let now = Instant::now();
        let mut slept = false;

        assert_eq!(
            wait_before_retry(now, || now, |_| slept = true),
            Err(HandoffProbeError::ReadinessDeadlineReached)
        );
        assert!(!slept);
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
