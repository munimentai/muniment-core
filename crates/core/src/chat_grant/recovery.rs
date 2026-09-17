//! The core recovers grants before it maps shell errors.

#[cfg(any(feature = "keyring", test))]
use crate::chat_grant::ChatGrant;
use crate::chat_grant::FetchGrantError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantFailure {
    SessionInvalid,
    DeviceRemoved,
    NotEntitled(String),
    EntitlementChanged,
    Wait(u64),
    Other(FetchGrantError),
}

impl GrantFailure {
    pub(crate) fn shell_error(self) -> FetchGrantError {
        match self {
            Self::SessionInvalid | Self::DeviceRemoved => FetchGrantError::Unauthorized,
            Self::NotEntitled(message) => FetchGrantError::NotEntitled { message },
            Self::EntitlementChanged | Self::Wait(_) => FetchGrantError::Unavailable,
            Self::Other(error) => error,
        }
    }
}

#[cfg(any(feature = "keyring", test))]
pub(crate) trait GrantRecovery {
    fn session_needs_renewal(&self) -> bool;
    fn issue(&mut self) -> Result<ChatGrant, GrantFailure>;
    fn refresh(&mut self) -> Result<(), FetchGrantError>;
    fn inspect(&mut self) -> Result<(), GrantFailure>;
    fn clear(&mut self, installation: bool) -> Result<(), FetchGrantError>;
    fn wait(&mut self, seconds: u64, retry: bool) -> Result<(), FetchGrantError>;
}

#[cfg(any(feature = "keyring", test))]
#[derive(Default)]
struct RecoveryBudget {
    refreshed: bool,
    inspected: bool,
    waited: bool,
    stale: bool,
}

#[cfg(any(feature = "keyring", test))]
impl RecoveryBudget {
    fn recover(
        &mut self,
        recovery: &mut impl GrantRecovery,
        failure: GrantFailure,
    ) -> Result<(), FetchGrantError> {
        match failure {
            GrantFailure::SessionInvalid => {
                if self.refreshed {
                    recovery.clear(false)?;
                    return Err(FetchGrantError::Unauthorized);
                }
                self.refreshed = true;
                if let Err(error) = recovery.refresh() {
                    recovery.clear(false)?;
                    return Err(error);
                }
                Ok(())
            }
            GrantFailure::DeviceRemoved => {
                recovery.clear(true)?;
                Err(FetchGrantError::Unauthorized)
            }
            GrantFailure::EntitlementChanged if !self.inspected => {
                self.inspected = true;
                self.inspect(recovery)
            }
            GrantFailure::Wait(seconds) => {
                let retry = !self.waited;
                self.waited = true;
                recovery.wait(seconds, retry)
            }
            _ => Err(failure.shell_error()),
        }
    }

    fn inspect(&mut self, recovery: &mut impl GrantRecovery) -> Result<(), FetchGrantError> {
        match recovery.inspect() {
            Ok(()) => Ok(()),
            Err(failure @ GrantFailure::SessionInvalid) => {
                self.recover(recovery, failure)?;
                match recovery.inspect() {
                    Ok(()) => Ok(()),
                    Err(failure) => {
                        if matches!(
                            failure,
                            GrantFailure::SessionInvalid | GrantFailure::DeviceRemoved
                        ) {
                            self.recover(recovery, failure.clone())?;
                        }
                        Err(failure.shell_error())
                    }
                }
            }
            Err(failure @ GrantFailure::DeviceRemoved) => self.recover(recovery, failure),
            Err(failure) => Err(failure.shell_error()),
        }
    }
}

#[cfg(any(feature = "keyring", test))]
pub(crate) fn recover_grant(
    recovery: &mut impl GrantRecovery,
) -> Result<ChatGrant, FetchGrantError> {
    let mut budget = RecoveryBudget::default();
    loop {
        if recovery.session_needs_renewal() {
            if budget.refreshed {
                eprintln!("muniment-runtime: chat-grant recover outcome=session_refreshed_twice");
                return Err(FetchGrantError::Unavailable);
            }
            budget.recover(recovery, GrantFailure::SessionInvalid)?;
            continue;
        }
        match recovery.issue() {
            Ok(grant) if !grant.needs_renewal() => return Ok(grant),
            Ok(_) if !budget.stale => budget.stale = true,
            Ok(_) => {
                eprintln!("muniment-runtime: chat-grant recover outcome=stale_twice");
                return Err(FetchGrantError::Unavailable);
            }
            Err(failure) => {
                eprintln!("muniment-runtime: chat-grant recover failure={failure:?}");
                budget.recover(recovery, failure)?
            }
        }
    }
}

#[cfg(any(feature = "keyring", test))]
pub(super) fn session_needs_renewal(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_some_and(|expiry| expiry <= now.saturating_add(super::SAFE_LIFE_SECONDS))
}

#[cfg(any(feature = "keyring", test))]
#[derive(Clone, Copy)]
struct RetryDeadline {
    started: std::time::Instant,
    delay: std::time::Duration,
}

#[cfg(any(feature = "keyring", test))]
impl RetryDeadline {
    fn remaining(self, now: std::time::Instant) -> std::time::Duration {
        self.delay
            .saturating_sub(now.saturating_duration_since(self.started))
    }
}

#[cfg(any(feature = "keyring", test))]
fn retry_wait(
    deadline: RetryDeadline,
    now: std::time::Instant,
    retry: bool,
) -> Result<std::time::Duration, FetchGrantError> {
    let wait = deadline.remaining(now);
    if !retry || wait > std::time::Duration::from_secs(30) {
        return Err(FetchGrantError::Unavailable);
    }
    Ok(wait)
}

#[cfg(any(feature = "keyring", test))]
fn inspection_failure(status: u16, response: ureq::Response) -> GrantFailure {
    #[derive(serde::Deserialize)]
    struct Envelope {
        error: Body,
    }
    #[derive(serde::Deserialize)]
    struct Body {
        code: String,
        message: String,
    }
    let unavailable = GrantFailure::Other(FetchGrantError::Unavailable);
    let Ok(envelope) = response.into_json::<Envelope>() else {
        return unavailable;
    };
    if envelope.error.message.trim().is_empty() {
        return unavailable;
    }
    match (status, envelope.error.code.as_str()) {
        (401, "session_invalid") => GrantFailure::SessionInvalid,
        (403, "device_removed") => GrantFailure::DeviceRemoved,
        _ => unavailable,
    }
}

#[cfg(any(feature = "keyring", test))]
pub(crate) fn refresh_chat_credentials(
    store: &dyn crate::auth::NativeCredentialStore,
    transport: &dyn crate::auth::TokenTransport,
    base: &str,
    expected: &crate::auth::NativeCredentials,
    now: u64,
    proof: [u8; 16],
) -> Result<crate::auth::NativeCredentials, crate::auth::NativeTokenError> {
    use crate::auth::*;
    // The token exchange reads a frozen record and cannot publish credentials itself.
    struct Snapshot<'a>(&'a NativeCredentials);
    impl NativeCredentialStore for Snapshot<'_> {
        fn load_installation(&self) -> Result<Option<InstallationRecord>, NativeTokenError> {
            Ok(Some(self.0.installation.clone()))
        }
        fn load_credentials(&self) -> Result<Option<NativeCredentials>, NativeTokenError> {
            Ok(Some(self.0.clone()))
        }
        fn save_credentials(&self, _: &NativeCredentials) -> Result<(), NativeTokenError> {
            Ok(())
        }
        fn clear_session(&self) -> Result<(), NativeTokenError> {
            Err(NativeTokenError::CredentialsMissing)
        }
    }
    let credentials = refresh_native_credentials(&Snapshot(expected), transport, base, now, proof)?;
    store.replace_credentials(&expected.tokens.access_token, &credentials)?;
    Ok(credentials)
}

// One process serializes issuance and keeps retry deadlines across chat attempts.
#[cfg(feature = "keyring")]
mod native {
    use super::*;
    use crate::auth::*;
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};

    static RETRIES: LazyLock<Mutex<HashMap<(String, String), RetryDeadline>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    struct NativeRecovery<'a> {
        store: KeyringNativeCredentialStore,
        base: &'a str,
        credentials: NativeCredentials,
        retries: &'a mut HashMap<(String, String), RetryDeadline>,
    }

    impl NativeRecovery<'_> {
        fn current(&self) -> Result<(), FetchGrantError> {
            let current = self
                .store
                .load_credentials()
                .map_err(|_| FetchGrantError::Unavailable)?;
            if current.is_none_or(|current| {
                current.tokens.access_token != self.credentials.tokens.access_token
                    || current.installation.device_id != self.credentials.installation.device_id
            }) {
                return Err(FetchGrantError::Unauthorized);
            }
            Ok(())
        }

        fn retry_key(&self) -> (String, String) {
            (
                self.base.into(),
                self.credentials.installation.device_id.to_string(),
            )
        }
    }

    struct ChatInspectionTransport;

    impl SessionTransport for ChatInspectionTransport {
        fn inspect(
            &self,
            url: &str,
            request: &NativeSessionRequest,
        ) -> Result<NativeSession, NativeSessionError> {
            let response = ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(30))
                .build()
                .get(url)
                .set("Authorization", request.authorization())
                .call();
            match response {
                Ok(response) if response.status() == 200 => response.into_json().map_err(|_| {
                    NativeSessionError::MalformedResponse(
                        "The session inspection response is invalid.".into(),
                    )
                }),
                Err(ureq::Error::Status(status, response)) => {
                    let failure = inspection_failure(status, response);
                    Err(match failure {
                        GrantFailure::SessionInvalid => NativeSessionError::HttpStatus(401),
                        GrantFailure::DeviceRemoved => NativeSessionError::HttpStatus(403),
                        _ => NativeSessionError::Transport("The session inspection failed.".into()),
                    })
                }
                _ => Err(NativeSessionError::Transport(
                    "The session inspection failed.".into(),
                )),
            }
        }
    }

    impl GrantRecovery for NativeRecovery<'_> {
        fn session_needs_renewal(&self) -> bool {
            session_needs_renewal(
                self.credentials.tokens.expires_at,
                chrono::Utc::now().timestamp().max(0) as u64,
            )
        }
        fn issue(&mut self) -> Result<ChatGrant, GrantFailure> {
            self.current().map_err(GrantFailure::Other)?;
            if let Some(remaining) = self
                .retries
                .get(&self.retry_key())
                .map(|deadline| deadline.remaining(Instant::now()))
                .filter(|remaining| !remaining.is_zero())
            {
                eprintln!(
                    "muniment-runtime: chat-grant issue outcome=waiting remaining_ms={}",
                    remaining.as_millis()
                );
                return Err(GrantFailure::Other(FetchGrantError::Unavailable));
            }
            let result = crate::chat_grant::issue_grant(
                self.base,
                &self.credentials.tokens.access_token,
                &self.credentials.installation.device_id.to_string(),
            );
            self.current().map_err(GrantFailure::Other)?;
            result.map(|mut grant| {
                grant.native_access_token = Some(self.credentials.tokens.access_token.clone());
                grant
            })
        }

        fn refresh(&mut self) -> Result<(), FetchGrantError> {
            self.current()?;
            let mut proof = [0; 16];
            getrandom::fill(&mut proof).map_err(|_| FetchGrantError::Unavailable)?;
            self.credentials = refresh_chat_credentials(
                &self.store,
                &UreqTokenTransport::new(Duration::from_secs(30)),
                self.base,
                &self.credentials,
                chrono::Utc::now().timestamp().max(0) as u64,
                proof,
            )
            .map_err(|_| FetchGrantError::Unauthorized)?;
            self.current()
        }

        fn inspect(&mut self) -> Result<(), GrantFailure> {
            self.current().map_err(GrantFailure::Other)?;
            inspect_native_session(&self.store, &ChatInspectionTransport, self.base).map_err(
                |error| match error {
                    NativeSessionError::HttpStatus(401) => GrantFailure::SessionInvalid,
                    NativeSessionError::HttpStatus(403) => GrantFailure::DeviceRemoved,
                    _ => GrantFailure::Other(FetchGrantError::Unavailable),
                },
            )?;
            self.current().map_err(GrantFailure::Other)
        }

        fn clear(&mut self, installation: bool) -> Result<(), FetchGrantError> {
            self.store
                .clear_credentials_if_current(&self.credentials.tokens.access_token, installation)
                .map_err(|_| FetchGrantError::Unavailable)
        }

        fn wait(&mut self, seconds: u64, retry: bool) -> Result<(), FetchGrantError> {
            let now = Instant::now();
            let deadline = RetryDeadline {
                started: now,
                delay: Duration::from_secs(seconds),
            };
            self.retries.insert(self.retry_key(), deadline);
            // Keep the full deadline even when this chat cannot wait for it.
            std::thread::sleep(retry_wait(deadline, now, retry)?);
            self.current()
        }
    }

    fn with_native<T>(
        base: &str,
        token: &str,
        action: impl FnOnce(&mut NativeRecovery<'_>) -> Result<T, FetchGrantError>,
    ) -> Result<T, FetchGrantError> {
        let mut retries = RETRIES.lock().map_err(|_| FetchGrantError::Unavailable)?;
        let store = KeyringNativeCredentialStore::new();
        let credentials = store
            .load_credentials()
            .map_err(|_| FetchGrantError::Unavailable)?
            .filter(|credentials| credentials.tokens.access_token == token)
            .ok_or(FetchGrantError::Unauthorized)?;
        action(&mut NativeRecovery {
            store,
            base,
            credentials,
            retries: &mut retries,
        })
    }

    pub fn fetch_native(base: &str, token: &str) -> Result<ChatGrant, FetchGrantError> {
        let started = Instant::now();
        let result = with_native(base, token, |recovery| recover_grant(recovery));
        match &result {
            Ok(_) => eprintln!(
                "muniment-runtime: chat-grant end outcome=issued elapsed_ms={}",
                started.elapsed().as_millis()
            ),
            Err(error) => eprintln!(
                "muniment-runtime: chat-grant end outcome=refused cause={error:?} elapsed_ms={}",
                started.elapsed().as_millis()
            ),
        }
        result
    }

    pub fn inspect_native_chat_session(token: &str) -> Result<String, FetchGrantError> {
        with_native(&api_base_url(), token, |recovery| {
            RecoveryBudget::default().inspect(recovery)?;
            Ok(recovery.credentials.tokens.access_token.clone())
        })
    }
}

#[cfg(feature = "keyring")]
pub use native::{fetch_native, inspect_native_chat_session};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn session_safe_life_matches_the_grant_threshold() {
        for (expiry, expected) in [
            (None, false),
            (Some(0), true),
            (Some(1_079), true),
            (Some(1_080), true),
            (Some(1_090), true),
            (Some(1_091), false),
            (Some(u64::MAX), false),
        ] {
            assert_eq!(session_needs_renewal(expiry, 1_000), expected);
        }
        assert!(session_needs_renewal(Some(u64::MAX), u64::MAX));
    }

    #[test]
    fn a_short_refreshed_session_cannot_trigger_another_refresh() {
        struct ShortSession(usize);
        impl GrantRecovery for ShortSession {
            fn session_needs_renewal(&self) -> bool {
                true
            }
            fn refresh(&mut self) -> Result<(), FetchGrantError> {
                self.0 += 1;
                Ok(())
            }
            fn issue(&mut self) -> Result<ChatGrant, GrantFailure> {
                panic!("The session cannot support a grant.")
            }
            fn inspect(&mut self) -> Result<(), GrantFailure> {
                unreachable!()
            }
            fn clear(&mut self, _: bool) -> Result<(), FetchGrantError> {
                unreachable!()
            }
            fn wait(&mut self, _: u64, _: bool) -> Result<(), FetchGrantError> {
                unreachable!()
            }
        }
        let mut session = ShortSession(0);
        assert_eq!(
            recover_grant(&mut session).unwrap_err(),
            FetchGrantError::Unavailable
        );
        assert_eq!(session.0, 1);
    }

    #[test]
    fn inspection_recovery_requires_matching_status_and_code() {
        for (status, code, expected) in [
            (401, "session_invalid", GrantFailure::SessionInvalid),
            (403, "device_removed", GrantFailure::DeviceRemoved),
            (
                403,
                "auth_unavailable",
                GrantFailure::Other(FetchGrantError::Unavailable),
            ),
            (
                401,
                "device_removed",
                GrantFailure::Other(FetchGrantError::Unavailable),
            ),
            (
                503,
                "auth_unavailable",
                GrantFailure::Other(FetchGrantError::Unavailable),
            ),
        ] {
            let body =
                serde_json::json!({"error": {"code": code, "message": "The request failed."}});
            assert_eq!(
                inspection_failure(
                    status,
                    ureq::Response::new(status, "Error", &body.to_string()).unwrap()
                ),
                expected
            );
        }
        assert_eq!(
            inspection_failure(403, ureq::Response::new(403, "Error", "{}").unwrap()),
            GrantFailure::Other(FetchGrantError::Unavailable)
        );
    }

    #[test]
    fn retry_deadlines_preserve_server_delays_and_bound_each_chat_wait() {
        let now = Instant::now();
        for seconds in [0, 1, 30, 31, 9_007_199_254_740_991] {
            let deadline = RetryDeadline {
                started: now,
                delay: Duration::from_secs(seconds),
            };
            assert_eq!(deadline.remaining(now).as_secs(), seconds);
            assert_eq!(retry_wait(deadline, now, true).is_ok(), seconds <= 30);
            assert_eq!(
                retry_wait(deadline, now, false),
                Err(FetchGrantError::Unavailable)
            );
            if seconds > 0 {
                assert!(!deadline
                    .remaining(now + Duration::from_millis(999))
                    .is_zero());
            }
            if seconds <= 31 {
                assert_eq!(
                    retry_wait(deadline, now + Duration::from_secs(seconds), true),
                    Ok(Duration::ZERO)
                );
            }
        }
    }
}
