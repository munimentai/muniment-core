//! Composition of the production installation-bound native sign-in flow.

use std::fmt;
use std::time::Duration;

use super::{
    exchange_native_code, register_installation_with_retry, run_native_browser_authorization,
    AuthStatus, AuthorizationTransport, BrowserOpener, InstallationStore,
    NativeBrowserAuthorizationError, NativeCredentialStore, NativeRegistrationError,
    NativeTokenError, RegistrationTransport, TokenTransport,
};

#[derive(Clone, PartialEq, Eq)]
pub enum NativeSignInError {
    Registration,
    Authorization,
    TokenExchange,
    Randomness,
}

impl fmt::Debug for NativeSignInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for NativeSignInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration => write!(f, "native installation registration failed"),
            Self::Authorization => write!(f, "native browser sign-in was not completed"),
            Self::TokenExchange => write!(f, "native token exchange failed"),
            Self::Randomness => write!(f, "native sign-in could not create a secure proof"),
        }
    }
}

impl std::error::Error for NativeSignInError {}

/// Register/reuse an installation, authorize in the external browser, exchange
/// the code, and atomically publish the resulting native credentials.
#[allow(clippy::too_many_arguments)]
pub fn run_native_sign_in(
    store: &(impl InstallationStore + NativeCredentialStore),
    registration: &dyn RegistrationTransport,
    authorization: &dyn AuthorizationTransport,
    tokens: &dyn TokenTransport,
    browser: &dyn BrowserOpener,
    base_url: &str,
    clock: &dyn Fn() -> u64,
    timeout: Duration,
    registration_wait: &dyn Fn(Duration),
) -> Result<AuthStatus, NativeSignInError> {
    register_installation_with_retry(store, registration, base_url, clock(), registration_wait)
        .map_err(map_registration)?;
    let code = run_native_browser_authorization(
        store,
        authorization,
        browser,
        base_url,
        None,
        clock(),
        timeout,
    )
    .map_err(map_authorization)?;
    let mut proof_jti = [0_u8; 16];
    getrandom::fill(&mut proof_jti).map_err(|_| NativeSignInError::Randomness)?;
    let credentials = exchange_native_code(store, tokens, base_url, code, clock(), proof_jti)
        .map_err(map_token)?;
    Ok(AuthStatus {
        signed_in: true,
        subject: credentials.tokens.subject,
        expires_at: credentials.tokens.expires_at,
    })
}

fn map_registration(_: NativeRegistrationError) -> NativeSignInError {
    NativeSignInError::Registration
}

fn map_authorization(_: NativeBrowserAuthorizationError) -> NativeSignInError {
    NativeSignInError::Authorization
}

fn map_token(_: NativeTokenError) -> NativeSignInError {
    NativeSignInError::TokenExchange
}
