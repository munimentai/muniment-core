//! Composition of the production installation-bound native sign-in flow.

use std::fmt;
use std::time::Duration;

use super::{
    exchange_native_code, register_installation_with_retry, run_native_browser_authorization,
    AuthStatus, AuthorizationTransport, BrowserOpener, InstallationStore, NativeAuthorizationError,
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
    getrandom::fill(&mut proof_jti).map_err(|_| {
        failure("proof", "Randomness");
        NativeSignInError::Randomness
    })?;
    let credentials = exchange_native_code(store, tokens, base_url, code, clock(), proof_jti)
        .map_err(map_token)?;
    Ok(AuthStatus {
        signed_in: true,
        subject: credentials.tokens.subject,
        expires_at: credentials.tokens.expires_at,
    })
}

fn failure(stage: &str, cause: &str) {
    super::native_http::log(&format!(
        "muniment-runtime: native-auth failure method=RPC path=session.sign_in stage={stage} error={cause}"
    ));
}

fn map_registration(error: NativeRegistrationError) -> NativeSignInError {
    // Error strings can contain credentials. Log only fixed labels and numeric status codes.
    let cause = match error {
        NativeRegistrationError::Config(_) => "Config".into(),
        NativeRegistrationError::Transport(_) => "Transport".into(),
        NativeRegistrationError::HttpStatus(status) => format!("HttpStatus status={status}"),
        NativeRegistrationError::RateLimited(_) => "RateLimited".into(),
        NativeRegistrationError::MalformedResponse(_) => "MalformedResponse".into(),
        NativeRegistrationError::Persistence(_) => "Persistence".into(),
        NativeRegistrationError::KeyGeneration => "KeyGeneration".into(),
    };
    failure("registration", &cause);
    NativeSignInError::Registration
}

fn map_authorization(error: NativeBrowserAuthorizationError) -> NativeSignInError {
    let cause = match error {
        NativeBrowserAuthorizationError::Authorization(error) => match error {
            NativeAuthorizationError::Config(_) => "Config".into(),
            NativeAuthorizationError::InstallationMissing => "InstallationMissing".into(),
            NativeAuthorizationError::RegistrationExpired => "RegistrationExpired".into(),
            NativeAuthorizationError::Transport(_) => "Transport".into(),
            NativeAuthorizationError::HttpStatus(status) => format!("HttpStatus status={status}"),
            NativeAuthorizationError::MalformedResponse(_) => "MalformedResponse".into(),
            NativeAuthorizationError::Persistence(_) => "Persistence".into(),
        },
        NativeBrowserAuthorizationError::BrowserOpen => "BrowserOpen".into(),
        NativeBrowserAuthorizationError::StateMismatch => "StateMismatch".into(),
        NativeBrowserAuthorizationError::ProviderDenied => "ProviderDenied".into(),
        NativeBrowserAuthorizationError::Timeout => "Timeout".into(),
        NativeBrowserAuthorizationError::Callback => "Callback".into(),
    };
    failure("authorization", &cause);
    NativeSignInError::Authorization
}

fn map_token(error: NativeTokenError) -> NativeSignInError {
    // NativeTokenError's Debug implementation redacts every string field.
    failure("token_exchange", &format!("{error:?}"));
    NativeSignInError::TokenExchange
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_diagnostics_name_the_stage_and_redact_error_data() {
        let (_, lines) = super::super::native_http::capture(|| {
            for error in [
                NativeRegistrationError::Config("secret".into()),
                NativeRegistrationError::Transport("secret".into()),
                NativeRegistrationError::MalformedResponse("secret".into()),
                NativeRegistrationError::Persistence("secret".into()),
                NativeRegistrationError::RateLimited(Duration::from_secs(300)),
                NativeRegistrationError::HttpStatus(429),
                NativeRegistrationError::KeyGeneration,
            ] {
                assert_eq!(map_registration(error), NativeSignInError::Registration);
            }
            for error in [
                NativeAuthorizationError::Config("secret".into()),
                NativeAuthorizationError::Transport("secret".into()),
                NativeAuthorizationError::MalformedResponse("secret".into()),
                NativeAuthorizationError::Persistence("secret".into()),
                NativeAuthorizationError::HttpStatus(401),
                NativeAuthorizationError::InstallationMissing,
                NativeAuthorizationError::RegistrationExpired,
            ] {
                assert_eq!(
                    map_authorization(NativeBrowserAuthorizationError::Authorization(error)),
                    NativeSignInError::Authorization,
                );
            }
            for error in [
                NativeBrowserAuthorizationError::BrowserOpen,
                NativeBrowserAuthorizationError::StateMismatch,
                NativeBrowserAuthorizationError::ProviderDenied,
                NativeBrowserAuthorizationError::Timeout,
                NativeBrowserAuthorizationError::Callback,
            ] {
                assert_eq!(map_authorization(error), NativeSignInError::Authorization);
            }
            for error in [
                NativeTokenError::Config("secret".into()),
                NativeTokenError::Transport("secret".into()),
                NativeTokenError::MalformedResponse("secret".into()),
                NativeTokenError::Persistence("secret".into()),
                NativeTokenError::HttpStatus(503),
            ] {
                assert_eq!(map_token(error), NativeSignInError::TokenExchange);
            }
        });
        assert_eq!(lines.len(), 24);
        let log = lines.join("\n");
        assert!(!log.contains("secret"));
        for outcome in [
            "stage=registration error=HttpStatus status=429",
            "stage=registration error=RateLimited",
            "stage=authorization error=HttpStatus status=401",
            "stage=authorization error=Timeout",
            "stage=authorization error=StateMismatch",
            "stage=authorization error=ProviderDenied",
            "stage=token_exchange error=HttpStatus(503)",
            "stage=token_exchange error=Persistence(<redacted>)",
        ] {
            assert!(log.contains(outcome), "missing {outcome}");
        }
    }
}
