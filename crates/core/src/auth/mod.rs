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
pub mod entitlement_snapshot;
pub mod flow;
pub mod loopback;
pub mod native_authorization;
pub mod native_credentials_store;
pub mod native_devices;
pub mod native_registration;
pub mod native_revocation;
pub mod native_session;
pub mod native_sign_in;
pub mod native_token;
pub mod pkce;
pub mod store;
pub mod urlenc;

pub use discovery::{discover, ProviderMetadata};
pub use entitlement_snapshot::EntitlementSnapshotTracker;
pub use flow::{
    build_authorization_url, ensure_fresh, exchange_code, refresh_tokens, revoke_token,
    run_sign_in, sign_out, OidcConfig,
};
pub use loopback::RedirectCatcher;
pub use native_authorization::{
    begin_native_authorization, run_native_browser_authorization, AuthorizationTransport,
    BrowserOpenError, BrowserOpener, NativeAuthorizationCode, NativeAuthorizationError,
    NativeAuthorizationInput, NativeAuthorizationRequest, NativeAuthorizationResponse,
    NativeAuthorizationResult, NativeBrowserAuthorizationError, NativeDeviceProof,
    UreqAuthorizationTransport,
};
pub use native_credentials_store::{
    CoherentNativeCredentialStore, NativeCredentialBackend, NativeCredentialKeys,
};
pub use native_devices::{
    list_native_devices, NativeDevice, NativeDeviceList, NativeDeviceListError,
    NativeDeviceListRequest, NativeDeviceListTransport, NativeDevicePlatform,
    UreqNativeDeviceListTransport,
};
pub use native_registration::{
    register_installation, InstallationRecord, InstallationStore, NativeDeviceRegistrationRequest,
    NativeDeviceRegistrationResponse, NativeRegistrationError, RegistrationTransport,
    UreqRegistrationTransport,
};
pub use native_revocation::{
    revoke_current_native_session, sign_out_native_session, NativeRevocationError,
    NativeRevocationRequest, NativeRevocationResponse, RevocationTransport,
    UreqRevocationTransport,
};
pub use native_session::{
    ensure_fresh_native_session, inspect_native_session, native_status,
    EntitlementSnapshotAlgorithm, EntitlementSnapshotView, FreshNativeSession,
    FreshNativeSessionError, NativeEntitlementGroup, NativeEntitlementPayload,
    NativeEntitlementSnapshot, NativeSession, NativeSessionError, NativeSessionIdentity,
    NativeSessionRequest, NativeSessionRole, SessionTransport, UreqSessionTransport,
};
pub use native_sign_in::{run_native_sign_in, NativeSignInError};
pub use native_token::{
    exchange_native_code, refresh_native_credentials, NativeAuthorizationCodeTokenRequest,
    NativeCredentialStore, NativeCredentials, NativeRefreshTokenRequest, NativeTokenError,
    NativeTokenRequest, NativeTokenResponse, TokenTransport, UreqTokenTransport,
};
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
