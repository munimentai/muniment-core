#![cfg(feature = "keyring")]

use muniment_core::chat_prompt::{delete_prompt, load_prompt, prompt_user, store_prompt};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};
use uuid::Uuid;

type Secrets = Arc<Mutex<HashMap<(String, String), Vec<u8>>>>;

struct SharedCredentialBuilder(Secrets);

impl keyring::credential::CredentialBuilderApi for SharedCredentialBuilder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<keyring::Credential>> {
        Ok(Box::new(SharedCredential {
            key: (service.to_string(), user.to_string()),
            secrets: Arc::clone(&self.0),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct SharedCredential {
    key: (String, String),
    secrets: Secrets,
}

impl keyring::credential::CredentialApi for SharedCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.secrets
            .lock()
            .unwrap()
            .insert(self.key.clone(), secret.to_vec());
        Ok(())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.secrets
            .lock()
            .unwrap()
            .get(&self.key)
            .cloned()
            .ok_or(keyring::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.secrets
            .lock()
            .unwrap()
            .remove(&self.key)
            .map(|_| ())
            .ok_or(keyring::Error::NoEntry)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn use_mock_keyring() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        keyring::set_default_credential_builder(Box::new(SharedCredentialBuilder(Arc::new(
            Mutex::new(HashMap::new()),
        ))));
    });
}

#[test]
fn key_includes_subject() {
    assert_eq!(
        prompt_user(Some("subject-a"), "run-a"),
        "protected-prompts:subject-a:run-a"
    );
}

#[test]
fn key_omits_missing_subject() {
    assert_eq!(prompt_user(None, "run-a"), "protected-prompts:run-a");
}

#[test]
fn store_then_load_round_trip() {
    use_mock_keyring();
    let run_id = Uuid::now_v7().to_string();

    store_prompt(&run_id, "saved prompt", Some("subject-a")).unwrap();

    assert_eq!(
        load_prompt(&run_id, Some("subject-a")).unwrap(),
        Some("saved prompt".to_string())
    );
}

#[test]
fn missing_entry_returns_none() {
    use_mock_keyring();
    let run_id = Uuid::now_v7().to_string();

    assert_eq!(load_prompt(&run_id, None).unwrap(), None);
}

#[test]
fn delete_removes_prompt_and_accepts_missing_entry() {
    use_mock_keyring();
    let run_id = Uuid::now_v7().to_string();

    store_prompt(&run_id, "saved prompt", Some("subject-a")).unwrap();
    delete_prompt(&run_id, Some("subject-a")).unwrap();

    assert_eq!(load_prompt(&run_id, Some("subject-a")).unwrap(), None);
    delete_prompt(&run_id, Some("subject-a")).unwrap();
}
