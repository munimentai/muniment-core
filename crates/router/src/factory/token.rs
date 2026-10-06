//! Run tokens: a bearer the router signs for one factory run.
//!
//! A token is `mrt1.<claims>.<signature>`, where the claims are base64url JSON
//! naming the run, task, repository, role, budget and expiry, and the
//! signature is base64url HMAC-SHA256 of `mrt1.<claims>` under the router's
//! signing key. The router checks the signature and the expiry, then checks
//! the claims against the run record, so a revoked run stops at once.

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const PREFIX: &str = "mrt1";

/// What a run token is bound to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub run_id: String,
    pub task_id: String,
    pub repo: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,
    /// Unix milliseconds the token stops serving.
    pub expires_ms: i64,
    /// A random value, so two tokens for one run differ.
    pub nonce: String,
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    BadSignature,
    Expired,
}

/// The key the router signs with: 32 bytes or more, given as hex or as text.
#[derive(Clone)]
pub struct SigningKey(Vec<u8>);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey")
    }
}

impl SigningKey {
    /// A key from configuration. An even-length hex string is read as bytes;
    /// anything else is used as written. Either way it must carry 32 bytes.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let bytes = hex(text).unwrap_or_else(|| text.as_bytes().to_vec());
        if bytes.len() < 32 {
            return Err("The run token signing key needs at least 32 bytes.".into());
        }
        Ok(Self(bytes))
    }

    fn mac(&self, message: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(message);
        mac
    }

    pub fn sign(&self, claims: &Claims) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let body = engine.encode(serde_json::to_vec(claims).expect("claims serialize"));
        let signed = format!("{PREFIX}.{body}");
        let signature = engine.encode(self.mac(signed.as_bytes()).finalize().into_bytes());
        format!("{signed}.{signature}")
    }

    /// The claims of a token this key signed that has not expired at `now_ms`.
    pub fn verify(&self, token: &str, now_ms: i64) -> Result<Claims, Refusal> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        if token.len() > 4096 {
            return Err(Refusal::Malformed);
        }
        let (signed, signature) = token.rsplit_once('.').ok_or(Refusal::Malformed)?;
        let (prefix, body) = signed.split_once('.').ok_or(Refusal::Malformed)?;
        if prefix != PREFIX {
            return Err(Refusal::Malformed);
        }
        let signature = engine.decode(signature).map_err(|_| Refusal::Malformed)?;
        self.mac(signed.as_bytes())
            .verify_slice(&signature)
            .map_err(|_| Refusal::BadSignature)?;
        let claims: Claims = engine
            .decode(body)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(Refusal::Malformed)?;
        if now_ms >= claims.expires_ms {
            return Err(Refusal::Expired);
        }
        Ok(claims)
    }
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

/// A random nonce for new claims.
pub fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(expires_ms: i64) -> Claims {
        Claims {
            run_id: "run-1".into(),
            task_id: "task-1".into(),
            repo: "factory/app".into(),
            role: "implementer".into(),
            budget_usd: Some(2.5),
            expires_ms,
            nonce: nonce(),
        }
    }

    #[test]
    fn a_signed_token_verifies_until_it_expires() {
        let key = SigningKey::parse(&"ab".repeat(32)).unwrap();
        let token = key.sign(&claims(1_000));
        assert!(token.starts_with("mrt1."));
        assert_eq!(key.verify(&token, 999).unwrap().run_id, "run-1");
        assert_eq!(key.verify(&token, 1_000), Err(Refusal::Expired));
        assert_ne!(key.sign(&claims(1_000)), token);
    }

    #[test]
    fn a_forged_or_altered_token_is_refused() {
        let key = SigningKey::parse(&"ab".repeat(32)).unwrap();
        let other = SigningKey::parse("a text key that is long enough to sign with").unwrap();
        let token = key.sign(&claims(1_000));
        assert_eq!(other.verify(&token, 0), Err(Refusal::BadSignature));
        // Raise the budget in the claims and keep the old signature.
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let (_, body) = signed.split_once('.').unwrap();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut altered: Claims = serde_json::from_slice(&engine.decode(body).unwrap()).unwrap();
        altered.budget_usd = Some(1_000.0);
        let forged = format!(
            "mrt1.{}.{signature}",
            engine.encode(serde_json::to_vec(&altered).unwrap())
        );
        assert_eq!(key.verify(&forged, 0), Err(Refusal::BadSignature));
        for junk in ["", "mrt1", "mrt1.x", "mrt2.a.b", "mrt1.a.!!"] {
            assert_eq!(key.verify(junk, 0), Err(Refusal::Malformed), "{junk}");
        }
        assert!(SigningKey::parse("short").is_err());
        assert!(SigningKey::parse(&"ab".repeat(16)).is_err());
        assert!(!format!("{key:?}").contains("ab"));
    }
}
