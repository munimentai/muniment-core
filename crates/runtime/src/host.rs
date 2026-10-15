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
#[cfg(feature = "keyring")]
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
    /// sign-in page. Without the `keyring` feature the credential store is
    /// [`FileCredentialStore::in_state_root`].
    fn default() -> Self {
        Self {
            account: Arc::new(NoCloud),
            chat_grants: Arc::new(NoCloud),
            #[cfg(feature = "keyring")]
            credentials: Arc::new(KeyringCredentialStore),
            #[cfg(not(feature = "keyring"))]
            credentials: Arc::new(FileCredentialStore::in_state_root()),
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
#[cfg(feature = "keyring")]
pub struct KeyringCredentialStore;

#[cfg(feature = "keyring")]
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

/// The directory under the state root that [`FileCredentialStore`] keeps
/// secrets in.
pub const CREDENTIALS_DIRECTORY_NAME: &str = "credentials";

/// The prefix of the environment variables that override stored secrets.
pub const CREDENTIAL_VARIABLE_PREFIX: &str = "MUNIMENT_SECRET_";

/// Secrets in owner-only files, with read-only overrides from the environment,
/// for a host without a keychain.
///
/// The secret `name` of `service` lives in the file `<directory>/<service>/<name>`
/// with mode 0600, under directories with mode 0700. In each of the two parts,
/// a byte other than an ASCII letter, a digit, `.`, `_` or `-` is written as
/// `%` and two hex digits, and so is a leading `.`, so a name never leaves its
/// service's directory and no file is hidden. One trailing newline in a file
/// is not part of the secret, so a file written by hand reads as typed.
///
/// The variable [`credential_variable`] names overrides the file: a read
/// answers its value, and a write refuses while it is set. An empty file or
/// an empty variable reads as no secret.
pub struct FileCredentialStore {
    directory: Option<PathBuf>,
}

impl FileCredentialStore {
    /// A store whose files live under `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: Some(directory.into()),
        }
    }

    /// A store under the `credentials` directory of the state root. When no
    /// state root resolves, the store reads the environment alone and
    /// refuses every write.
    pub fn in_state_root() -> Self {
        Self {
            directory: muniment_core::state_root::state_directory()
                .map(|state| state.join(CREDENTIALS_DIRECTORY_NAME)),
        }
    }

    fn path(&self, service: &str, name: &str) -> Option<PathBuf> {
        let directory = self.directory.as_ref()?;
        if service.is_empty() || name.is_empty() {
            return None;
        }
        Some(
            directory
                .join(file_component(service))
                .join(file_component(name)),
        )
    }
}

/// The environment variable that overrides the secret `name` of `service`:
/// `MUNIMENT_SECRET_`, then the service, `_` and the name, upper-cased, with
/// every character other than an ASCII letter or digit written as `_`. The
/// reader's `ai.muniment.reader` secret `stripe` is
/// `MUNIMENT_SECRET_AI_MUNIMENT_READER_STRIPE`.
pub fn credential_variable(service: &str, name: &str) -> String {
    let part = |value: &str| -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!(
        "{CREDENTIAL_VARIABLE_PREFIX}{}_{}",
        part(service),
        part(name)
    )
}

fn file_component(value: &str) -> String {
    let mut component = String::with_capacity(value.len());
    for (index, byte) in value.bytes().enumerate() {
        let plain = byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'-')
            || (byte == b'.' && index > 0);
        if plain {
            component.push(char::from(byte));
        } else {
            component.push_str(&format!("%{byte:02X}"));
        }
    }
    component
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        // A directory that already existed keeps its mode, so set it here.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl CredentialStore for FileCredentialStore {
    fn read(&self, service: &str, name: &str) -> Option<String> {
        if let Some(value) = std::env::var_os(credential_variable(service, name)) {
            return value.into_string().ok().filter(|value| !value.is_empty());
        }
        let mut secret = std::fs::read_to_string(self.path(service, name)?).ok()?;
        if secret.ends_with('\n') {
            secret.pop();
            if secret.ends_with('\r') {
                secret.pop();
            }
        }
        (!secret.is_empty()).then_some(secret)
    }

    fn write(&self, service: &str, name: &str, secret: &str) -> Result<(), String> {
        let variable = credential_variable(service, name);
        if std::env::var_os(&variable).is_some() {
            return Err(format!(
                "{variable} sets this secret, so the credential store keeps it."
            ));
        }
        let path = self
            .path(service, name)
            .ok_or("The credential store has no directory for this secret.")?;
        let refused =
            |error: std::io::Error| format!("The credential store refused the secret: {error}.");
        let parent = path
            .parent()
            .expect("a secret's path names its service directory");
        if let Some(directory) = &self.directory {
            create_private_directory(directory).map_err(refused)?;
        }
        create_private_directory(parent).map_err(refused)?;
        muniment_core::model_router::config::write_private(&path, secret.as_bytes())
            .map_err(refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "muniment-credentials-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_secret_round_trips_through_an_owner_only_file() {
        let root = temporary_directory("files");
        let store = FileCredentialStore::new(root.join("credentials"));
        assert_eq!(store.read("test.files", "first"), None);
        store.write("test.files", "first", "sk_old").unwrap();
        store.write("test.files", "first", "sk_new").unwrap();
        assert_eq!(store.read("test.files", "first").as_deref(), Some("sk_new"));
        let path = root.join("credentials").join("test.files").join("first");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sk_new");
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
            assert_eq!(mode(&root.join("credentials")), 0o700);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_file_written_by_hand_reads_without_its_trailing_newline() {
        let root = temporary_directory("hand");
        let store = FileCredentialStore::new(&root);
        std::fs::create_dir_all(root.join("test.hand")).unwrap();
        std::fs::write(root.join("test.hand").join("unix"), "sk_1\n").unwrap();
        std::fs::write(root.join("test.hand").join("dos"), "sk_2\r\n").unwrap();
        std::fs::write(root.join("test.hand").join("empty"), "\n").unwrap();
        assert_eq!(store.read("test.hand", "unix").as_deref(), Some("sk_1"));
        assert_eq!(store.read("test.hand", "dos").as_deref(), Some("sk_2"));
        assert_eq!(store.read("test.hand", "empty"), None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_name_never_leaves_its_service_directory() {
        let root = temporary_directory("names");
        let store = FileCredentialStore::new(root.join("credentials"));
        store.write("..", "../escape", "sk_1").unwrap();
        store.write("test.names", "a/b c", "sk_2").unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("credentials").join("%2E.").join("%2E.%2Fescape"))
                .unwrap(),
            "sk_1"
        );
        assert_eq!(store.read("test.names", "a/b c").as_deref(), Some("sk_2"));
        assert!(root
            .join("credentials")
            .join("test.names")
            .join("a%2Fb%20c")
            .is_file());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        assert!(store.write("test.names", "", "sk_3").is_err());
        assert_eq!(store.read("", "name"), None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_variable_name_upper_cases_and_replaces_other_characters() {
        assert_eq!(
            credential_variable("ai.muniment.reader", "stripe"),
            "MUNIMENT_SECRET_AI_MUNIMENT_READER_STRIPE"
        );
        assert_eq!(
            credential_variable("svc-1", "a.b/c"),
            "MUNIMENT_SECRET_SVC_1_A_B_C"
        );
    }

    #[test]
    fn the_environment_overrides_the_file_and_refuses_writes() {
        let root = temporary_directory("environment");
        let store = FileCredentialStore::new(&root);
        store.write("test.environment", "key", "from-file").unwrap();
        let variable = credential_variable("test.environment", "key");
        std::env::set_var(&variable, "from-environment");
        assert_eq!(
            store.read("test.environment", "key").as_deref(),
            Some("from-environment")
        );
        let refusal = store
            .write("test.environment", "key", "changed")
            .unwrap_err();
        assert!(refusal.contains(&variable), "{refusal}");
        assert!(!refusal.contains("from-environment"), "{refusal}");
        std::env::set_var(&variable, "");
        assert_eq!(store.read("test.environment", "key"), None);
        std::env::remove_var(&variable);
        assert_eq!(
            store.read("test.environment", "key").as_deref(),
            Some("from-file")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_store_without_a_directory_reads_the_environment_alone() {
        let store = FileCredentialStore { directory: None };
        let variable = credential_variable("test.nodirectory", "key");
        assert_eq!(store.read("test.nodirectory", "key"), None);
        assert!(store.write("test.nodirectory", "key", "sk_1").is_err());
        std::env::set_var(&variable, "sk_env");
        assert_eq!(
            store.read("test.nodirectory", "key").as_deref(),
            Some("sk_env")
        );
        std::env::remove_var(&variable);
    }
}
