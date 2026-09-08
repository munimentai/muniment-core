//! Platform-neutral persistence for one coherent native credential record.

use serde::{Deserialize, Serialize};

use super::{
    InstallationRecord, InstallationStore, NativeCredentialStore, NativeCredentials,
    NativeRegistrationError, NativeTokenError, TokenSet,
};

const RECORD_VERSION: u8 = 1;
// All record mutations share this lock, including sign-out and refresh publication.
static RECORD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn record_lock() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    RECORD_LOCK
        .lock()
        .map_err(|_| "The native credential lock failed.".into())
}

pub trait NativeCredentialBackend: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
    fn delete(&self, key: &str) -> Result<(), String>;
}

#[derive(Clone, Copy)]
pub struct NativeCredentialKeys {
    pub record: &'static str,
    pub legacy_installation: &'static str,
}

pub struct CoherentNativeCredentialStore<B> {
    backend: B,
    keys: NativeCredentialKeys,
}

#[derive(Serialize, Deserialize)]
struct NativeCredentialRecord {
    version: u8,
    installation: InstallationRecord,
    session: Option<NativeCredentialSession>,
}

#[derive(Serialize, Deserialize)]
struct NativeCredentialSession {
    tokens: TokenSet,
    refresh_expires_at: u64,
}

impl<B: NativeCredentialBackend> CoherentNativeCredentialStore<B> {
    pub fn new(backend: B, keys: NativeCredentialKeys) -> Self {
        Self { backend, keys }
    }

    fn save_record(&self, record: &NativeCredentialRecord) -> Result<(), String> {
        let json = serde_json::to_string(record)
            .map_err(|_| "could not serialize native credential record".to_owned())?;
        self.backend.set(self.keys.record, &json)
    }

    fn load_record(&self) -> Result<Option<NativeCredentialRecord>, String> {
        if let Some(json) = self.backend.get(self.keys.record)? {
            let record: NativeCredentialRecord = serde_json::from_str(&json)
                .map_err(|_| "stored native credential record is unreadable".to_owned())?;
            if record.version != RECORD_VERSION {
                return Err("stored native credential record has an unsupported version".into());
            }
            // Cleanup is best-effort so a transient keychain deletion failure
            // never makes the already-published coherent record unavailable.
            // Retrying on every load eventually removes the legacy value.
            let _ = self.backend.delete(self.keys.legacy_installation);
            return Ok(Some(record));
        }
        self.migrate_split_record()
    }

    fn migrate_split_record(&self) -> Result<Option<NativeCredentialRecord>, String> {
        let Some(installation_json) = self.backend.get(self.keys.legacy_installation)? else {
            return Ok(None);
        };
        let installation: InstallationRecord = serde_json::from_str(&installation_json)
            .map_err(|_| "stored installation is unreadable".to_owned())?;
        let record = NativeCredentialRecord {
            version: RECORD_VERSION,
            installation,
            session: None,
        };

        // Publish the coherent value before removing the legacy installation.
        // The generic OIDC token entry is deliberately unrelated to this record.
        self.save_record(&record)?;
        let _ = self.backend.delete(self.keys.legacy_installation);
        Ok(Some(record))
    }
}

impl<B: NativeCredentialBackend> InstallationStore for CoherentNativeCredentialStore<B> {
    fn save(&self, installation: &InstallationRecord) -> Result<(), NativeRegistrationError> {
        let _guard = record_lock().map_err(NativeRegistrationError::Persistence)?;
        self.save_record(&NativeCredentialRecord {
            version: RECORD_VERSION,
            installation: installation.clone(),
            session: None,
        })
        .map_err(NativeRegistrationError::Persistence)
    }

    fn load(&self) -> Result<Option<InstallationRecord>, NativeRegistrationError> {
        let _guard = record_lock().map_err(NativeRegistrationError::Persistence)?;
        self.load_record()
            .map(|record| record.map(|value| value.installation))
            .map_err(NativeRegistrationError::Persistence)
    }
}

impl<B: NativeCredentialBackend> NativeCredentialStore for CoherentNativeCredentialStore<B> {
    fn load_installation(&self) -> Result<Option<InstallationRecord>, NativeTokenError> {
        let _guard = record_lock().map_err(NativeTokenError::Persistence)?;
        self.load_record()
            .map(|record| record.map(|value| value.installation))
            .map_err(NativeTokenError::Persistence)
    }

    fn save_credentials(&self, credentials: &NativeCredentials) -> Result<(), NativeTokenError> {
        let _guard = record_lock().map_err(NativeTokenError::Persistence)?;
        self.save_record(&NativeCredentialRecord {
            version: RECORD_VERSION,
            installation: credentials.installation.clone(),
            session: Some(NativeCredentialSession {
                tokens: credentials.tokens.clone(),
                refresh_expires_at: credentials.refresh_expires_at,
            }),
        })
        .map_err(NativeTokenError::Persistence)
    }

    fn load_credentials(&self) -> Result<Option<NativeCredentials>, NativeTokenError> {
        let _guard = record_lock().map_err(NativeTokenError::Persistence)?;
        self.load_record()
            .map(|record| {
                record.and_then(|value| {
                    value.session.map(|session| NativeCredentials {
                        installation: value.installation,
                        tokens: session.tokens,
                        refresh_expires_at: session.refresh_expires_at,
                    })
                })
            })
            .map_err(NativeTokenError::Persistence)
    }

    fn clear_credentials_if_current(
        &self,
        expected_access_token: &str,
        installation: bool,
    ) -> Result<(), NativeTokenError> {
        let _guard = record_lock().map_err(NativeTokenError::Persistence)?;
        let record = self
            .load_record()
            .map_err(NativeTokenError::Persistence)?
            .ok_or(NativeTokenError::CredentialsMissing)?;
        if record
            .session
            .as_ref()
            .is_none_or(|session| session.tokens.access_token != expected_access_token)
        {
            return Err(NativeTokenError::CredentialsMissing);
        }
        if installation {
            self.backend
                .delete(self.keys.legacy_installation)
                .map_err(NativeTokenError::Persistence)?;
            self.backend
                .delete(self.keys.record)
                .map_err(NativeTokenError::Persistence)
        } else {
            self.save_record(&NativeCredentialRecord {
                session: None,
                ..record
            })
            .map_err(NativeTokenError::Persistence)
        }
    }

    fn replace_credentials(
        &self,
        expected_access_token: &str,
        credentials: &NativeCredentials,
    ) -> Result<(), NativeTokenError> {
        let _guard = record_lock().map_err(NativeTokenError::Persistence)?;
        let current = self.load_record().map_err(NativeTokenError::Persistence)?;
        if current.is_none_or(|record| {
            record.installation.device_id != credentials.installation.device_id
                || record
                    .session
                    .is_none_or(|session| session.tokens.access_token != expected_access_token)
        }) {
            return Err(NativeTokenError::CredentialsMissing);
        }
        self.save_record(&NativeCredentialRecord {
            version: RECORD_VERSION,
            installation: credentials.installation.clone(),
            session: Some(NativeCredentialSession {
                tokens: credentials.tokens.clone(),
                refresh_expires_at: credentials.refresh_expires_at,
            }),
        })
        .map_err(NativeTokenError::Persistence)
    }

    fn clear_session(&self) -> Result<(), NativeTokenError> {
        let _guard = record_lock().map_err(NativeTokenError::Persistence)?;
        let Some(record) = self.load_record().map_err(NativeTokenError::Persistence)? else {
            return Ok(());
        };
        if record.session.is_none() {
            return Ok(());
        }
        self.save_record(&NativeCredentialRecord {
            version: RECORD_VERSION,
            installation: record.installation,
            session: None,
        })
        .map_err(NativeTokenError::Persistence)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use uuid::Uuid;

    use super::*;

    const KEYS: NativeCredentialKeys = NativeCredentialKeys {
        record: "native-credentials",
        legacy_installation: "native-installation",
    };
    const OIDC_KEY: &str = "oidc-tokens";

    #[derive(Clone, Default)]
    struct MemoryBackend {
        values: Arc<Mutex<HashMap<String, String>>>,
        writes: Arc<Mutex<Vec<String>>>,
        fail_writes: bool,
        failed_deletes_remaining: Arc<Mutex<usize>>,
    }

    impl MemoryBackend {
        fn with_legacy_installation_and_oidc(
            installation: &InstallationRecord,
            tokens: &TokenSet,
        ) -> Self {
            Self {
                values: Arc::new(Mutex::new(HashMap::from([
                    (
                        KEYS.legacy_installation.into(),
                        serde_json::to_string(installation).unwrap(),
                    ),
                    (OIDC_KEY.into(), serde_json::to_string(tokens).unwrap()),
                ]))),
                ..Self::default()
            }
        }
    }

    impl NativeCredentialBackend for MemoryBackend {
        fn get(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &str) -> Result<(), String> {
            if self.fail_writes {
                return Err("write failed".into());
            }
            self.values.lock().unwrap().insert(key.into(), value.into());
            self.writes.lock().unwrap().push(key.into());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), String> {
            let mut failures = self.failed_deletes_remaining.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                return Err("delete failed".into());
            }
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn installation(challenge: &str) -> InstallationRecord {
        InstallationRecord {
            private_key: [7; 32],
            device_id: Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
            registration_token: "registration-secret".into(),
            device_challenge: challenge.into(),
            registration_expires_at: 1_000,
        }
    }

    fn tokens() -> TokenSet {
        TokenSet {
            access_token: "access-secret".into(),
            refresh_token: Some("refresh-secret".into()),
            expires_at: Some(2_000),
            subject: Some("user-id".into()),
        }
    }

    #[test]
    fn device_removal_clears_credentials_and_the_installation_challenge() {
        let backend =
            MemoryBackend::with_legacy_installation_and_oidc(&installation("challenge"), &tokens());
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);
        store
            .save_credentials(&NativeCredentials {
                installation: installation("challenge"),
                tokens: tokens(),
                refresh_expires_at: 9000,
            })
            .unwrap();
        store
            .clear_credentials_if_current("access-secret", true)
            .unwrap();
        assert!(store.load_credentials().unwrap().is_none());
        assert!(store.load_installation().unwrap().is_none());
        let values = backend.values.lock().unwrap();
        assert!(!values.contains_key(KEYS.record));
        assert!(!values.contains_key(KEYS.legacy_installation));
        assert!(values.contains_key(OIDC_KEY));
    }

    #[test]
    fn grant_refresh_cannot_restore_a_signed_out_or_replaced_session() {
        use crate::auth::{NativeTokenRequest, NativeTokenResponse, TokenTransport};
        struct DuringRefresh<'a> {
            store: &'a dyn NativeCredentialStore,
            mutation: u8,
        }
        impl TokenTransport for DuringRefresh<'_> {
            fn exchange(
                &self,
                _: &str,
                _: &NativeTokenRequest,
            ) -> Result<NativeTokenResponse, NativeTokenError> {
                match self.mutation {
                    1 => self.store.clear_session()?,
                    2 => self
                        .store
                        .clear_credentials_if_current("access-secret", true)?,
                    3 => {
                        let mut replacement = self.store.load_credentials()?.unwrap();
                        replacement.tokens.access_token = "concurrent-sign-in".into();
                        self.store.save_credentials(&replacement)?;
                    }
                    _ => {}
                }
                Ok(serde_json::from_value(serde_json::json!({
                    "access_token": "refreshed-secret", "token_type": "Bearer", "expires_in": 900,
                    "refresh_token": "refreshed-refresh-secret", "refresh_expires_in": 86400,
                    "session": {"org_id": "20000000-0000-4000-8000-000000000002",
                        "user_id": "30000000-0000-4000-8000-000000000003", "role": "user",
                        "device_id": "10000000-0000-4000-8000-000000000001", "client_role": "desktop"},
                    "entitlement_snapshot": {"payload": {}, "signature": "signature", "algorithm": "hmac-sha256"},
                    "device_challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                })).unwrap())
            }
        }
        for mutation in 0..4 {
            let backend = MemoryBackend::default();
            let store = CoherentNativeCredentialStore::new(backend, KEYS);
            let challenge =
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [8; 32]);
            let expected = NativeCredentials {
                installation: installation(&challenge),
                tokens: tokens(),
                refresh_expires_at: 9000,
            };
            store.save_credentials(&expected).unwrap();
            let result = crate::chat_grant::refresh_chat_credentials(
                &store,
                &DuringRefresh {
                    store: &store,
                    mutation,
                },
                "https://api.example",
                &expected,
                100,
                [1; 16],
            );
            assert_eq!(result.is_ok(), mutation == 0);
            let current = store.load_credentials().unwrap();
            match mutation {
                0 => assert_eq!(current.unwrap().tokens.access_token, "refreshed-secret"),
                3 => {
                    assert_eq!(current.unwrap().tokens.access_token, "concurrent-sign-in");
                    assert!(store
                        .clear_credentials_if_current("access-secret", false)
                        .is_err());
                    assert!(store.load_credentials().unwrap().is_some());
                }
                _ => assert!(current.is_none()),
            }
        }
    }

    #[test]
    fn credentials_replace_one_coherent_value() {
        let backend = MemoryBackend::default();
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);
        store
            .save_credentials(&NativeCredentials {
                installation: installation("rotated-challenge"),
                tokens: tokens(),
                refresh_expires_at: 9_000,
            })
            .unwrap();

        assert_eq!(*backend.writes.lock().unwrap(), [KEYS.record]);
        let loaded = store.load_credentials().unwrap().unwrap();
        assert_eq!(loaded.installation.device_challenge, "rotated-challenge");
        assert_eq!(loaded.tokens.access_token, "access-secret");
        assert_eq!(loaded.refresh_expires_at, 9_000);
    }

    #[test]
    fn clear_session_preserves_installation_and_unrelated_oidc_value() {
        let backend = MemoryBackend::default();
        backend
            .values
            .lock()
            .unwrap()
            .insert(OIDC_KEY.into(), serde_json::to_string(&tokens()).unwrap());
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);
        store
            .save_credentials(&NativeCredentials {
                installation: installation("rotated-challenge"),
                tokens: tokens(),
                refresh_expires_at: 9_000,
            })
            .unwrap();

        store.clear_session().unwrap();

        assert!(store.load_credentials().unwrap().is_none());
        assert_eq!(
            store.load_installation().unwrap().unwrap().device_challenge,
            "rotated-challenge"
        );
        let values = backend.values.lock().unwrap();
        assert!(values[KEYS.record].contains("\"session\":null"));
        assert!(!values[KEYS.record].contains("access-secret"));
        assert!(!values[KEYS.record].contains("refresh-secret"));
        assert!(!values[KEYS.record].contains("9000"));
        assert!(values.contains_key(OIDC_KEY));
    }

    #[test]
    fn clear_session_is_idempotent_for_installation_only_and_missing_records() {
        let backend = MemoryBackend::default();
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);
        store.clear_session().unwrap();
        store.save(&installation("challenge")).unwrap();
        let writes = backend.writes.lock().unwrap().len();

        store.clear_session().unwrap();
        store.clear_session().unwrap();

        assert_eq!(backend.writes.lock().unwrap().len(), writes);
        assert_eq!(
            store.load_installation().unwrap().unwrap().device_challenge,
            "challenge"
        );
    }

    #[test]
    fn failed_session_clear_keeps_credentials_and_returns_redacted_error() {
        let backend = MemoryBackend::default();
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);
        store
            .save_credentials(&NativeCredentials {
                installation: installation("challenge"),
                tokens: tokens(),
                refresh_expires_at: 9_000,
            })
            .unwrap();
        let failing_store = CoherentNativeCredentialStore::new(
            MemoryBackend {
                fail_writes: true,
                ..backend.clone()
            },
            KEYS,
        );

        let error = failing_store.clear_session().unwrap_err();

        assert_eq!(error.to_string(), "native credential persistence failed");
        assert_eq!(
            store
                .load_credentials()
                .unwrap()
                .unwrap()
                .tokens
                .access_token,
            "access-secret"
        );
    }

    #[test]
    fn legacy_installation_migrates_without_treating_oidc_as_native_session() {
        let backend = MemoryBackend::with_legacy_installation_and_oidc(
            &installation("legacy-challenge"),
            &tokens(),
        );
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);
        let loaded = store.load_installation().unwrap().unwrap();

        assert_eq!(loaded.device_challenge, "legacy-challenge");
        assert!(store.load_credentials().unwrap().is_none());
        let values = backend.values.lock().unwrap();
        assert!(values.contains_key(KEYS.record));
        assert!(!values.contains_key(KEYS.legacy_installation));
        assert!(values.contains_key(OIDC_KEY));
    }

    #[test]
    fn failed_publish_keeps_legacy_installation_and_oidc_values() {
        let mut backend = MemoryBackend::with_legacy_installation_and_oidc(
            &installation("legacy-challenge"),
            &tokens(),
        );
        backend.fail_writes = true;
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);

        assert!(store.load_credentials().is_err());
        let values = backend.values.lock().unwrap();
        assert!(values.contains_key(KEYS.legacy_installation));
        assert!(values.contains_key(OIDC_KEY));
        assert!(!values.contains_key(KEYS.record));
    }

    #[test]
    fn legacy_cleanup_retries_after_a_delete_failure() {
        let backend = MemoryBackend::with_legacy_installation_and_oidc(
            &installation("legacy-challenge"),
            &tokens(),
        );
        *backend.failed_deletes_remaining.lock().unwrap() = 1;
        let store = CoherentNativeCredentialStore::new(backend.clone(), KEYS);

        let first = store.load_installation().unwrap().unwrap();
        assert_eq!(first.device_challenge, "legacy-challenge");
        assert!(backend
            .values
            .lock()
            .unwrap()
            .contains_key(KEYS.legacy_installation));

        let second = store.load_installation().unwrap().unwrap();
        assert_eq!(second.device_challenge, "legacy-challenge");
        let values = backend.values.lock().unwrap();
        assert!(values.contains_key(KEYS.record));
        assert!(!values.contains_key(KEYS.legacy_installation));
        assert!(values.contains_key(OIDC_KEY));
    }
}
