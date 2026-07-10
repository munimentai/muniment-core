//! OIDC authorization-code + PKCE engine for the desktop app.
//!
//! Implements the RFC 8252 native-app flow: system browser + loopback
//! redirect on 127.0.0.1, PKCE S256, `state` binding, endpoints resolved via
//! OIDC discovery. The Tauri layer (`src-tauri/src/auth/`) only wires these
//! pieces to commands and the platform keychain, so everything here stays
//! testable without a GUI stack (see `tests/oidc_flow.rs`).
//!
//! Security invariants (harness-spec §3.1/§8):
//! - Tokens are never logged and never written to plaintext disk; the only
//!   persistence path is a [`TokenStore`] implementation.
//! - [`AuthError`] values never carry token material, so they are safe to
//!   surface to the webview.

pub mod discovery;
pub mod flow;
pub mod loopback;
pub mod pkce;
pub mod store;
pub mod urlenc;

pub use discovery::{discover, ProviderMetadata};
pub use flow::{
    build_authorization_url, ensure_fresh, exchange_code, refresh_tokens, revoke_token,
    run_sign_in, sign_out, OidcConfig,
};
pub use loopback::RedirectCatcher;
pub use pkce::{random_state, PkcePair};
pub use store::{status, AuthStatus, InMemoryTokenStore, TokenSet, TokenStore};

use std::fmt;

/// Everything that can go wrong during sign-in/out. Messages describe the
/// failure only — by design they never embed token or code values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Bad or unusable client configuration / local environment.
    Config(String),
    /// Discovery document could not be fetched or failed validation.
    Discovery(String),
    /// Network-level failure talking to the provider.
    Http(String),
    /// The loopback redirect was malformed.
    Redirect(String),
    /// The callback's `state` did not match this sign-in attempt.
    StateMismatch,
    /// The provider redirected back with an error (e.g. `access_denied`).
    Denied(String),
    /// The token endpoint rejected the request.
    Token(String),
    /// The token store failed.
    Store(String),
    /// The browser round-trip did not complete in time.
    Timeout,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Config(m) => write!(f, "configuration error: {m}"),
            AuthError::Discovery(m) => write!(f, "OIDC discovery failed: {m}"),
            AuthError::Http(m) => write!(f, "network error: {m}"),
            AuthError::Redirect(m) => write!(f, "redirect error: {m}"),
            AuthError::StateMismatch => write!(f, "sign-in rejected: state mismatch"),
            AuthError::Denied(m) => write!(f, "sign-in not completed: {m}"),
            AuthError::Token(m) => write!(f, "token request failed: {m}"),
            AuthError::Store(m) => write!(f, "token store error: {m}"),
            AuthError::Timeout => write!(f, "timed out waiting for the browser sign-in"),
        }
    }
}

impl std::error::Error for AuthError {}
