//! Token persistence boundary.

use std::fmt;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::AuthError;

/// Tokens held after a successful sign-in. Serialized as one JSON blob into
/// the platform keychain, never onto disk or into logs (the manual
/// `Debug` impl redacts token material; keep it that way).
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds when the access token expires (derived from
    /// `expires_in` at exchange time).
    pub expires_at: Option<u64>,
    /// OIDC subject (`sub` claim of the id_token), kept so `auth_status`
    /// can answer without a network round-trip.
    pub subject: Option<String>,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("subject", &self.subject)
            .finish()
    }
}

/// What `auth_status` reports to the webview: signed-in state only, no
/// token material.
#[derive(Debug, Clone, Serialize)]
pub struct AuthStatus {
    pub signed_in: bool,
    pub subject: Option<String>,
    pub expires_at: Option<u64>,
}

/// Where tokens live between runs. The desktop app plugs in the
/// keychain-backed implementation; tests use [`InMemoryTokenStore`].
pub trait TokenStore: Send + Sync {
    fn save(&self, tokens: &TokenSet) -> Result<(), AuthError>;
    fn load(&self) -> Result<Option<TokenSet>, AuthError>;
    fn clear(&self) -> Result<(), AuthError>;
}

/// Test/ephemeral store; nothing outlives the process.
#[derive(Default)]
pub struct InMemoryTokenStore {
    tokens: Mutex<Option<TokenSet>>,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn save(&self, tokens: &TokenSet) -> Result<(), AuthError> {
        *self.tokens.lock().unwrap() = Some(tokens.clone());
        Ok(())
    }

    fn load(&self) -> Result<Option<TokenSet>, AuthError> {
        Ok(self.tokens.lock().unwrap().clone())
    }

    fn clear(&self) -> Result<(), AuthError> {
        *self.tokens.lock().unwrap() = None;
        Ok(())
    }
}

/// Signed-in summary from whatever the store holds; no network.
pub fn status(store: &dyn TokenStore) -> Result<AuthStatus, AuthError> {
    Ok(match store.load()? {
        Some(t) => AuthStatus {
            signed_in: true,
            subject: t.subject,
            expires_at: t.expires_at,
        },
        None => AuthStatus {
            signed_in: false,
            subject: None,
            expires_at: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TokenSet {
        TokenSet {
            access_token: "top-secret-access".into(),
            refresh_token: Some("top-secret-refresh".into()),
            expires_at: Some(1_800_000_000),
            subject: Some("user-123".into()),
        }
    }

    #[test]
    fn debug_never_leaks_token_material() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("top-secret"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("user-123")); // subject is not a secret
    }

    #[test]
    fn in_memory_store_round_trips_and_clears() {
        let store = InMemoryTokenStore::new();
        assert!(store.load().unwrap().is_none());
        assert!(!status(&store).unwrap().signed_in);

        store.save(&sample()).unwrap();
        let st = status(&store).unwrap();
        assert!(st.signed_in);
        assert_eq!(st.subject.as_deref(), Some("user-123"));
        assert_eq!(st.expires_at, Some(1_800_000_000));

        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
