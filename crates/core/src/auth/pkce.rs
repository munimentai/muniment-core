//! PKCE (RFC 7636, S256 only) and the `state` parameter.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::AuthError;

/// A PKCE verifier and its S256 challenge. The verifier stays on this side
/// of the flow; only the challenge goes into the authorization URL.
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    /// 64 random bytes → 86-char base64url verifier, inside the 43..=128
    /// bounds of RFC 7636 §4.1.
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self::from_verifier(
            URL_SAFE_NO_PAD.encode(random_bytes::<64>()?),
        ))
    }

    /// Derive the S256 challenge for a known verifier (used by tests and by
    /// the mock IdP to check the proof the way a real one would).
    pub fn from_verifier(verifier: String) -> Self {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        PkcePair {
            verifier,
            challenge,
        }
    }
}

/// Random `state` binding the loopback callback to this attempt
/// (RFC 6749 §10.12).
pub fn random_state() -> Result<String, AuthError> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|e| AuthError::Config(format!("system RNG unavailable: {e}")))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_challenge_matches_rfc7636_appendix_b() {
        let pair =
            PkcePair::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string());
        assert_eq!(
            pair.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifier_is_within_rfc_bounds_and_urlsafe() {
        let pair = PkcePair::generate().unwrap();
        assert!((43..=128).contains(&pair.verifier.len()));
        assert!(pair
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn each_attempt_gets_fresh_secrets() {
        assert_ne!(
            PkcePair::generate().unwrap().verifier,
            PkcePair::generate().unwrap().verifier
        );
        assert_ne!(random_state().unwrap(), random_state().unwrap());
    }
}
