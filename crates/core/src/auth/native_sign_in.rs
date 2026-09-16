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
    Authorization(String),
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
            Self::Authorization(cause) => write!(f, "native authorization failed: {cause}"),
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
            NativeAuthorizationError::HttpFailure(status, failure) => {
                format!("HttpStatus status={status} {}", failure.diagnostic())
            }
            NativeAuthorizationError::MalformedResponse(message) => {
                malformed_authorization_cause(&message)
            }
            NativeAuthorizationError::Persistence(_) => "Persistence".into(),
        },
        NativeBrowserAuthorizationError::BrowserOpen => "BrowserOpen".into(),
        NativeBrowserAuthorizationError::StateMismatch => "StateMismatch".into(),
        NativeBrowserAuthorizationError::ProviderDenied => "ProviderDenied".into(),
        NativeBrowserAuthorizationError::Timeout => "Timeout".into(),
        NativeBrowserAuthorizationError::Callback => "Callback".into(),
    };
    failure("authorization", &cause);
    NativeSignInError::Authorization(cause)
}

// The authorize step raises a fixed message for each check it makes. The label
// carries the check and never the message itself, so a message that held
// response data stays out of the log and the card.
fn malformed_authorization_cause(message: &str) -> String {
    let check = match message {
        "response was not valid JSON" => "json",
        "response was not valid contract JSON" => "contract",
        "device challenge was not canonical contract data" => "device_challenge",
        "authorization URL is invalid" => "url_invalid",
        "authorization URL is unsafe" => "url_unsafe",
        _ => return "MalformedResponse".into(),
    };
    format!("MalformedResponse check={check}")
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
    fn authorization_failure_retains_the_safe_http_code_and_edge_id() {
        let response: ureq::Response = "HTTP/1.1 400 Bad Request\r\nCF-Ray: 0123456789abcdef-IAD\r\n\r\n{\"error\":{\"code\":\"invalid_device_proof\",\"message\":\"secret\"}}".parse().unwrap();
        let failure = super::super::native_http::NativeHttpFailure::from_response(response);
        let (error, lines) = super::super::native_http::capture(|| {
            map_authorization(NativeBrowserAuthorizationError::Authorization(
                NativeAuthorizationError::HttpFailure(400, failure),
            ))
        });
        let cause =
            "HttpStatus status=400 error_code=invalid_device_proof cf_ray=0123456789abcdef-IAD";
        assert_eq!(error, NativeSignInError::Authorization(cause.into()));
        assert_eq!(
            error.to_string(),
            format!("native authorization failed: {cause}")
        );
        assert!(lines[0].ends_with(cause));
        assert!(!lines.join("\n").contains("secret"));
    }

    #[test]
    fn malformed_authorization_names_the_check_and_never_the_message() {
        assert_eq!(
            malformed_authorization_cause("authorization URL is unsafe"),
            "MalformedResponse check=url_unsafe"
        );
        assert_eq!(
            malformed_authorization_cause("response was not valid contract JSON"),
            "MalformedResponse check=contract"
        );
        assert_eq!(
            malformed_authorization_cause("secret body text"),
            "MalformedResponse"
        );
    }

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
            for (error, cause) in [
                (NativeAuthorizationError::Config("secret".into()), "Config"),
                (
                    NativeAuthorizationError::Transport("secret".into()),
                    "Transport",
                ),
                (
                    NativeAuthorizationError::MalformedResponse("secret".into()),
                    "MalformedResponse",
                ),
                (
                    NativeAuthorizationError::Persistence("secret".into()),
                    "Persistence",
                ),
                (
                    NativeAuthorizationError::HttpStatus(401),
                    "HttpStatus status=401",
                ),
                (
                    NativeAuthorizationError::InstallationMissing,
                    "InstallationMissing",
                ),
                (
                    NativeAuthorizationError::RegistrationExpired,
                    "RegistrationExpired",
                ),
            ] {
                let result =
                    map_authorization(NativeBrowserAuthorizationError::Authorization(error));
                assert_eq!(result, NativeSignInError::Authorization(cause.into()));
                assert!(!result.to_string().contains("secret"));
            }
            for (error, cause) in [
                (NativeBrowserAuthorizationError::BrowserOpen, "BrowserOpen"),
                (
                    NativeBrowserAuthorizationError::StateMismatch,
                    "StateMismatch",
                ),
                (
                    NativeBrowserAuthorizationError::ProviderDenied,
                    "ProviderDenied",
                ),
                (NativeBrowserAuthorizationError::Timeout, "Timeout"),
                (NativeBrowserAuthorizationError::Callback, "Callback"),
            ] {
                assert_eq!(
                    map_authorization(error),
                    NativeSignInError::Authorization(cause.into())
                );
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
