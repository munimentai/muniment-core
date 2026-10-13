//! What the host supplies to the runtime.
//!
//! The runtime names no desktop module. Cloud sign-in, chat grants, credential
//! storage, the OAuth clients of provider sign-in, the page a sign-in's
//! browser lands on and the paths of the host's own executables reach it
//! through one [`RuntimeHost`] value. Each default answers that the cloud is
//! unavailable, so a host without cloud accounts runs locally.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use muniment_core::account::{
    AuthStatus, EntitlementSnapshotView, NativeDeviceList, PairId, PairingChallengeView,
    PairingRevokeView, PairingStatusView, TokenSet,
};
use muniment_core::attach::{EntitlementSnapshotResult, ProtocolError, RuntimeActivityRegistry};
use muniment_core::chat_launch::{ChatGrant, FetchGrantError, FetchReceiptError};
use muniment_core::keyring::Entry;
use muniment_core::model_router::native_auth::ProviderClients;
use muniment_core::sidecar::pi_chat::Receipt;

/// The values and services one runtime process runs with.
#[derive(Clone)]
pub struct RuntimeHost {
    /// Cloud sign-in, session, device and pairing calls.
    pub account: Arc<dyn AccountService>,
    /// Cloud chat grants and receipts.
    pub chat_grants: Arc<dyn ChatGrantService>,
    /// Where the runtime keeps reader source secrets.
    pub credentials: Arc<dyn CredentialStore>,
    /// The desktop executable a same-user peer runs to reach the desktop
    /// attach routes. `None` serves companion sessions only.
    pub expected_desktop_executable: Option<PathBuf>,
    /// The reader sidecar, `muniment-reader`, that network sources run in.
    /// `MUNIMENT_READER_BIN` overrides it. `None` leaves network sources
    /// without a reader.
    pub reader_executable: Option<PathBuf>,
    /// The version the runtime announces on attach and records in the journal:
    /// the host binary's package version.
    pub runtime_version: &'static str,
    /// The OAuth clients the router's own sign-ins and refreshes use. A
    /// provider without one falls back to its environment variables.
    pub provider_clients: ProviderClients,
    /// The page a provider sign-in's browser lands on.
    pub sign_in_page: Arc<SignInPage>,
}

impl Default for RuntimeHost {
    /// No cloud account, the platform keyring, no desktop peer, no reader
    /// sidecar, this crate's version, no provider clients and a plain
    /// sign-in page.
    fn default() -> Self {
        Self {
            account: Arc::new(NoCloud),
            chat_grants: Arc::new(NoCloud),
            credentials: Arc::new(KeyringCredentialStore),
            expected_desktop_executable: None,
            reader_executable: None,
            runtime_version: env!("CARGO_PKG_VERSION"),
            provider_clients: ProviderClients::default(),
            sign_in_page: Arc::new(plain_sign_in_page),
        }
    }
}

/// Renders the page a provider sign-in's browser lands on: `Some` with the
/// provider's name after a redirect that carried a code, `None` without one.
pub type SignInPage = dyn Fn(Option<&str>) -> String + Send + Sync;

/// A sign-in page with no branding.
pub fn plain_sign_in_page(provider: Option<&str>) -> String {
    let (heading, body) = match provider {
        Some(provider) => (
            "Signed in".to_owned(),
            format!("{provider} is connected. This window can close."),
        ),
        None => (
            "Sign-in did not finish".to_owned(),
            "No code reached Muniment from this page. Return and try again.".to_owned(),
        ),
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Muniment</title>\n</head>\n<body>\n<h1>{heading}</h1>\n<p>{body}</p>\n</body>\n</html>\n"
    )
}

/// The session an account answers.
pub struct AccountSession {
    /// The bearer tokens, or `None` when no account is signed in.
    pub tokens: Option<TokenSet>,
    /// The display-only entitlement projection of the session.
    pub entitlement_snapshot: Option<EntitlementSnapshotView>,
}

/// The browser could not open a sign-in link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkOpenError;

impl std::fmt::Display for LinkOpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the browser could not open the link")
    }
}

impl std::error::Error for LinkOpenError {}

/// Shows the user a sign-in link.
pub type LinkOpener = dyn Fn(&str) -> Result<(), LinkOpenError> + Send + Sync;

/// Cloud account calls. The runtime holds the activity mark a call needs and
/// passes the registry for the host to mark its own operations.
pub trait AccountService: Send + Sync {
    /// Answers the signed-in session, refreshed when it is near expiry. The
    /// error names why no session could be read.
    fn session(
        &self,
        runtime_activity: &RuntimeActivityRegistry,
    ) -> Result<AccountSession, String> {
        let _ = runtime_activity;
        Ok(AccountSession {
            tokens: None,
            entitlement_snapshot: None,
        })
    }

    /// Reads the session status without a network call.
    fn session_status(&self) -> Result<AuthStatus, ProtocolError> {
        Ok(AuthStatus {
            signed_in: false,
            subject: None,
            expires_at: None,
        })
    }

    /// Answers the entitlement projection and whether its version changed.
    fn entitlement_snapshot(
        &self,
        runtime_activity: &RuntimeActivityRegistry,
    ) -> Result<EntitlementSnapshotResult, ProtocolError> {
        let _ = runtime_activity;
        Err(ProtocolError::persistence_failed())
    }

    /// Runs the browser sign-in while `active` answers true. `open_link`
    /// shows the user the sign-in link.
    fn sign_in(
        &self,
        active: &dyn Fn() -> bool,
        open_link: &LinkOpener,
        runtime_activity: &RuntimeActivityRegistry,
    ) -> Result<AuthStatus, ProtocolError> {
        let _ = (active, open_link, runtime_activity);
        Err(ProtocolError::unsupported_operation())
    }

    /// Revokes the session and clears it locally.
    fn sign_out(
        &self,
        runtime_activity: &RuntimeActivityRegistry,
    ) -> Result<AuthStatus, ProtocolError> {
        let _ = runtime_activity;
        Err(ProtocolError::unsupported_operation())
    }

    /// Lists the account's native installations.
    fn list_devices(&self, access_token: &str) -> Result<NativeDeviceList, ProtocolError> {
        let _ = access_token;
        Err(ProtocolError::unsupported_operation())
    }

    /// Reads the current phone pair and keeps its peer identity under the profile.
    fn pairing_status(
        &self,
        access_token: &str,
        profile_directory: &Path,
    ) -> Result<PairingStatusView, ProtocolError> {
        let _ = (access_token, profile_directory);
        Err(ProtocolError::unsupported_operation())
    }

    /// Requests a phone pairing challenge.
    fn create_pairing_challenge(
        &self,
        access_token: &str,
    ) -> Result<PairingChallengeView, ProtocolError> {
        let _ = access_token;
        Err(ProtocolError::unsupported_operation())
    }

    /// Revokes one phone pair and clears its peer identity under the profile.
    fn revoke_pairing(
        &self,
        access_token: &str,
        pair_id: PairId,
        profile_directory: &Path,
    ) -> Result<PairingRevokeView, ProtocolError> {
        let _ = (access_token, pair_id, profile_directory);
        Err(ProtocolError::unsupported_operation())
    }
}

/// Cloud chat grant calls.
pub trait ChatGrantService: Send + Sync {
    /// Fetches a chat grant for the signed-in account.
    fn fetch_grant(&self, access_token: &str) -> Result<ChatGrant, FetchGrantError> {
        let _ = access_token;
        Err(FetchGrantError::Unavailable)
    }

    /// Inspects the cloud session and answers the bearer to continue with.
    fn inspect_session(&self, access_token: &str) -> Result<String, FetchGrantError> {
        let _ = access_token;
        Err(FetchGrantError::Unavailable)
    }

    /// Fetches the receipt for a finished run on a cloud grant.
    fn fetch_receipt(
        &self,
        grant: &ChatGrant,
        access_token: &str,
        run_id: &str,
    ) -> Result<Receipt, FetchReceiptError> {
        let _ = (grant, access_token, run_id);
        Err(FetchReceiptError)
    }
}

/// A host with no cloud account.
pub struct NoCloud;

impl AccountService for NoCloud {}

impl ChatGrantService for NoCloud {}

/// Secrets the runtime keeps, each named by a service and an entry name.
pub trait CredentialStore: Send + Sync {
    /// The stored secret, or none.
    fn read(&self, service: &str, name: &str) -> Option<String>;

    /// Stores a secret, replacing the one there. The error names the store's refusal.
    fn write(&self, service: &str, name: &str, secret: &str) -> Result<(), String>;
}

/// The platform keychain through the system keyring.
pub struct KeyringCredentialStore;

impl CredentialStore for KeyringCredentialStore {
    fn read(&self, service: &str, name: &str) -> Option<String> {
        Entry::new(service, name).ok()?.get_password().ok()
    }

    fn write(&self, service: &str, name: &str, secret: &str) -> Result<(), String> {
        Entry::new(service, name)
            .and_then(|entry| entry.set_password(secret))
            .map_err(|error| format!("The keychain refused the secret: {error}."))
    }
}
