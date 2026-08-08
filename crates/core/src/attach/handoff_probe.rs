//! Runtime service handoff probe confirmation.

use muniment_attach::Welcome;
use std::fmt;
use std::time::Instant;

/// Proof that the runtime service completed a migration handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedHandoff(());

/// A bounded reason that a probe welcome does not confirm the handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffProbeError {
    ReadinessDeadlineReached,
    MissingNonce,
    NonceMismatch,
}

impl fmt::Display for HandoffProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReadinessDeadlineReached => "runtime service readiness deadline reached",
            Self::MissingNonce => "probe welcome has no handoff nonce",
            Self::NonceMismatch => "probe welcome handoff nonce does not match",
        })
    }
}

impl std::error::Error for HandoffProbeError {}

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
}
