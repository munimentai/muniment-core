use keyring::Entry;
use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const PROMPT_SERVICE: &str = "ai.muniment.desktop.chat";
const PROMPT_USER: &str = "protected-prompts";
static FAIL_NEXT_MOCK_DELETE: AtomicBool = AtomicBool::new(false);

#[doc(hidden)]
pub fn use_mock_keyring_for_tests() {
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
            if FAIL_NEXT_MOCK_DELETE.swap(false, Ordering::SeqCst) {
                return Err(keyring::Error::PlatformFailure(Box::new(
                    std::io::Error::other("injected prompt delete failure"),
                )));
            }
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

    keyring::set_default_credential_builder(Box::new(SharedCredentialBuilder(Arc::new(
        Mutex::new(HashMap::new()),
    ))));
}

#[doc(hidden)]
pub fn fail_next_mock_prompt_delete_for_tests() {
    FAIL_NEXT_MOCK_DELETE.store(true, Ordering::SeqCst);
}

#[derive(Debug)]
pub enum ChatPromptError {
    Entry(keyring::Error),
    Store(keyring::Error),
    Load(keyring::Error),
    Delete(keyring::Error),
}

pub fn prompt_user(subject: Option<&str>, run_id: &str) -> String {
    subject.filter(|value| !value.is_empty()).map_or_else(
        || format!("{PROMPT_USER}:{run_id}"),
        |value| format!("{PROMPT_USER}:{value}:{run_id}"),
    )
}

pub fn store_prompt(
    run_id: &str,
    prompt: &str,
    subject: Option<&str>,
) -> Result<(), ChatPromptError> {
    let user = prompt_user(subject, run_id);
    let entry = Entry::new(PROMPT_SERVICE, &user).map_err(ChatPromptError::Entry)?;
    entry.set_password(prompt).map_err(ChatPromptError::Store)
}

pub fn load_prompt(run_id: &str, subject: Option<&str>) -> Result<Option<String>, ChatPromptError> {
    let user = prompt_user(subject, run_id);
    let entry = Entry::new(PROMPT_SERVICE, &user).map_err(ChatPromptError::Entry)?;
    match entry.get_password() {
        Ok(prompt) => Ok(Some(prompt)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(ChatPromptError::Load(error)),
    }
}

pub fn delete_prompt(run_id: &str, subject: Option<&str>) -> Result<(), ChatPromptError> {
    let user = prompt_user(subject, run_id);
    let entry = Entry::new(PROMPT_SERVICE, &user).map_err(ChatPromptError::Entry)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(ChatPromptError::Delete(error)),
    }
}
