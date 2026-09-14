//! Auth persistence backed by the platform keychain via the `keyring` crate:
//! macOS Keychain, Windows Credential Manager, and the Linux kernel keyring.

use keyring::Entry;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    CoherentNativeCredentialStore, InstallationRecord, InstallationStore, NativeCredentialBackend,
    NativeCredentialKeys, NativeCredentialStore, NativeCredentials, NativeRegistrationError,
    NativeTokenError,
};

const SERVICE: &str = "ai.muniment.desktop";
const NATIVE_KEYS: NativeCredentialKeys = NativeCredentialKeys {
    record: "native-credentials",
    legacy_installation: "native-installation",
};

struct PlatformKeychain;

// One refusal at the keychain prompt holds for the rest of the process: the
// saved session is unreadable here, so every later read answers signed out
// from memory instead of raising the prompt again. A write that succeeds, such
// as a new sign-in, clears it.
#[cfg(target_os = "macos")]
static ACCESS_REFUSED: AtomicBool = AtomicBool::new(false);

// errSecUserCanceled, errSecAuthFailed and errSecInteractionNotAllowed: the user,
// or a session with no user present, turned the prompt down.
#[cfg(any(target_os = "macos", test))]
fn refusal_code(code: i32) -> bool {
    matches!(code, -128 | -25293 | -25308)
}

#[cfg(target_os = "macos")]
fn refused(error: &keyring::Error) -> bool {
    match error {
        keyring::Error::PlatformFailure(inner) | keyring::Error::NoStorageAccess(inner) => inner
            .downcast_ref::<security_framework::base::Error>()
            .is_some_and(|error| refusal_code(error.code())),
        _ => false,
    }
}

impl NativeCredentialBackend for PlatformKeychain {
    fn get(&self, user: &str) -> Result<Option<String>, String> {
        #[cfg(target_os = "macos")]
        if ACCESS_REFUSED.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match Entry::new(SERVICE, user)
            .map_err(|error| error.to_string())?
            .get_password()
        {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => {
                #[cfg(target_os = "macos")]
                if refused(&error) {
                    ACCESS_REFUSED.store(true, Ordering::SeqCst);
                    crate::runtime_eprintln!(
                        "muniment-runtime: keychain access refused for {user}; the session reads as signed out until a sign-in writes a new item"
                    );
                    return Ok(None);
                }
                Err(error.to_string())
            }
        }
    }

    fn set(&self, user: &str, value: &str) -> Result<(), String> {
        let entry = Entry::new(SERVICE, user).map_err(|error| error.to_string())?;
        #[cfg(target_os = "macos")]
        let result = if entry.get_credential().is::<keyring::macos::MacCredential>() {
            set_macos_password(user, value)
        } else {
            entry.set_password(value)
        };
        #[cfg(not(target_os = "macos"))]
        let result = entry.set_password(value);
        #[cfg(target_os = "macos")]
        if result.is_ok() {
            ACCESS_REFUSED.store(false, Ordering::SeqCst);
        }
        result.map_err(|error| error.to_string())
    }

    fn delete(&self, user: &str) -> Result<(), String> {
        match Entry::new(SERVICE, user)
            .map_err(|error| error.to_string())?
            .delete_credential()
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
fn set_macos_password(user: &str, value: &str) -> keyring::Result<()> {
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

    let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
        .map_err(keyring::macos::decode_error)?;
    update_or_create(
        keychain
            .find_generic_password(SERVICE, user)
            .map_err(keyring::macos::decode_error),
        |(_, mut item)| {
            item.set_password(value.as_bytes())
                .map_err(keyring::macos::decode_error)
        },
        || {
            keychain
                .add_generic_password(SERVICE, user, value.as_bytes())
                .map_err(keyring::macos::decode_error)
        },
    )
}

// Only a missing item permits creation. Access failures never replace the item or its access list.
#[cfg(any(target_os = "macos", test))]
fn update_or_create<T>(
    found: keyring::Result<T>,
    update: impl FnOnce(T) -> keyring::Result<()>,
    create: impl FnOnce() -> keyring::Result<()>,
) -> keyring::Result<()> {
    match found {
        Ok(item) => update(item),
        Err(keyring::Error::NoEntry) => create(),
        Err(error) => Err(error),
    }
}

pub struct KeyringNativeCredentialStore(CoherentNativeCredentialStore<PlatformKeychain>);

impl KeyringNativeCredentialStore {
    pub fn new() -> Self {
        Self(CoherentNativeCredentialStore::new(
            PlatformKeychain,
            NATIVE_KEYS,
        ))
    }
}

impl Default for KeyringNativeCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InstallationStore for KeyringNativeCredentialStore {
    fn save(&self, installation: &InstallationRecord) -> Result<(), NativeRegistrationError> {
        self.0.save(installation)
    }

    fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError> {
        self.0.load()
    }
}

impl NativeCredentialStore for KeyringNativeCredentialStore {
    fn load_installation(&self) -> Result<Option<InstallationRecord>, NativeTokenError> {
        self.0.load_installation()
    }

    fn save_credentials(&self, credentials: &NativeCredentials) -> Result<(), NativeTokenError> {
        self.0.save_credentials(credentials)
    }

    fn load_credentials(&self) -> Result<Option<NativeCredentials>, NativeTokenError> {
        self.0.load_credentials()
    }

    fn clear_credentials_if_current(
        &self,
        expected_access_token: &str,
        installation: bool,
    ) -> Result<(), NativeTokenError> {
        self.0
            .clear_credentials_if_current(expected_access_token, installation)
    }

    fn replace_credentials(
        &self,
        expected_access_token: &str,
        credentials: &NativeCredentials,
    ) -> Result<(), NativeTokenError> {
        self.0
            .replace_credentials(expected_access_token, credentials)
    }

    fn clear_session(&self) -> Result<(), NativeTokenError> {
        self.0.clear_session()
    }
}

#[cfg(test)]
mod tests {
    use super::update_or_create;
    use std::cell::Cell;

    #[test]
    fn a_refusal_code_is_the_prompt_turned_down() {
        for code in [-128, -25293, -25308] {
            assert!(super::refusal_code(code), "{code}");
        }
        for code in [0, -25300, -25291, -25299] {
            assert!(!super::refusal_code(code), "{code}");
        }
    }

    #[test]
    fn renewal_updates_the_existing_item_without_creation() {
        let item = Cell::new("old-token");
        update_or_create(
            Ok(&item),
            |item| {
                item.set("new-token");
                Ok(())
            },
            || panic!("A renewal must not create an item."),
        )
        .unwrap();
        assert_eq!(item.get(), "new-token");
    }

    #[test]
    fn only_a_missing_item_allows_creation() {
        let created = Cell::new(false);
        update_or_create::<()>(
            Err(keyring::Error::NoEntry),
            |_| panic!("A missing item cannot receive an update."),
            || {
                created.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(created.get());

        let denied =
            keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("Access denied.")));
        let result = update_or_create::<()>(
            Err(denied),
            |_| panic!("A failed lookup must not update an item."),
            || panic!("A failed lookup must not create an item."),
        );
        assert!(matches!(result, Err(keyring::Error::NoStorageAccess(_))));
    }

    #[test]
    fn failed_update_and_duplicate_creation_do_not_retry() {
        let result = update_or_create(
            Ok(()),
            |_| Err(keyring::Error::NoEntry),
            || panic!("A failed update must not recreate an item."),
        );
        assert!(matches!(result, Err(keyring::Error::NoEntry)));
        let result = update_or_create::<()>(
            Err(keyring::Error::NoEntry),
            |_| unreachable!(),
            || {
                Err(keyring::Error::PlatformFailure(Box::new(
                    std::io::Error::other("Duplicate item."),
                )))
            },
        );
        assert!(matches!(result, Err(keyring::Error::PlatformFailure(_))));
    }
}
