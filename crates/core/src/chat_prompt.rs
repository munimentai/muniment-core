use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
#[cfg(feature = "keyring")]
use std::{
    any::Any,
    collections::HashMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};

const PROMPT_USER: &str = "protected-prompts";
#[cfg(feature = "keyring")]
static FAIL_NEXT_MOCK_DELETE: AtomicBool = AtomicBool::new(false);
static LOCAL_PROMPT_ROOT: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Local mode keeps each prompt in an owner-only file beside the journal, so a
/// shell with no cloud session never opens the keychain. The runtime installs
/// its state root once, and the local-mode marker there selects the store. A
/// build without the `keyring` feature has no keychain, so it keeps every
/// prompt in the file store whether or not the marker is present.
pub fn install_local_prompt_store(config_directory: PathBuf) {
    *LOCAL_PROMPT_ROOT
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(config_directory);
}

fn local_prompt_directory() -> Option<PathBuf> {
    let root = LOCAL_PROMPT_ROOT
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    local_prompt_directory_under(root.as_deref()?)
}

fn local_prompt_directory_under(config_directory: &Path) -> Option<PathBuf> {
    (!cfg!(feature = "keyring") || crate::local_mode::is_local_mode(config_directory))
        .then(|| config_directory.join("muniment").join("prompts"))
}

fn local_prompt_path(directory: &Path, user: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    directory.join(format!("{:x}.txt", Sha256::digest(user.as_bytes())))
}

fn store_local_prompt(directory: &Path, user: &str, prompt: &str) -> io::Result<()> {
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let path = local_prompt_path(directory, user);
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(prompt.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| crate::atomic_file::replace(&temporary, &path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

fn load_local_prompt(directory: &Path, user: &str) -> io::Result<Option<String>> {
    match fs::read_to_string(local_prompt_path(directory, user)) {
        Ok(prompt) => Ok(Some(prompt)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn delete_local_prompt(directory: &Path, user: &str) -> io::Result<()> {
    match fs::remove_file(local_prompt_path(directory, user)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The prompt store's failure: the keyring's error, which also carries a file
/// store failure, or the file system's error in a build without the keyring.
#[cfg(feature = "keyring")]
pub type PromptStoreError = keyring::Error;
#[cfg(not(feature = "keyring"))]
pub type PromptStoreError = io::Error;

#[cfg(feature = "keyring")]
fn file_failure(error: io::Error) -> PromptStoreError {
    keyring::Error::PlatformFailure(Box::new(error))
}

#[cfg(not(feature = "keyring"))]
fn file_failure(error: io::Error) -> PromptStoreError {
    error
}

/// The system keyring, used when no file store is selected.
#[cfg(feature = "keyring")]
mod keychain {
    use super::ChatPromptError;
    use keyring::Entry;

    const PROMPT_SERVICE: &str = "ai.muniment.desktop.chat";

    fn entry(user: &str) -> Result<Entry, ChatPromptError> {
        Entry::new(PROMPT_SERVICE, user).map_err(ChatPromptError::Entry)
    }

    pub(super) fn store(user: &str, prompt: &str) -> Result<(), ChatPromptError> {
        entry(user)?
            .set_password(prompt)
            .map_err(ChatPromptError::Store)
    }

    pub(super) fn load(user: &str) -> Result<Option<String>, ChatPromptError> {
        match entry(user)?.get_password() {
            Ok(prompt) => Ok(Some(prompt)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(ChatPromptError::Load(error)),
        }
    }

    pub(super) fn delete(user: &str) -> Result<(), ChatPromptError> {
        match entry(user)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(ChatPromptError::Delete(error)),
        }
    }
}

/// A build without the keyring has only the file store, so a process that
/// installed no state root has no prompt store at all.
#[cfg(not(feature = "keyring"))]
mod keychain {
    use super::ChatPromptError;

    fn unavailable() -> ChatPromptError {
        ChatPromptError::Entry(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no prompt store directory is installed",
        ))
    }

    pub(super) fn store(_user: &str, _prompt: &str) -> Result<(), ChatPromptError> {
        Err(unavailable())
    }

    pub(super) fn load(_user: &str) -> Result<Option<String>, ChatPromptError> {
        Err(unavailable())
    }

    pub(super) fn delete(_user: &str) -> Result<(), ChatPromptError> {
        Err(unavailable())
    }
}

#[cfg(feature = "keyring")]
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

#[cfg(feature = "keyring")]
#[doc(hidden)]
pub fn use_refused_keyring_for_tests(
    code: i32,
    message: &'static str,
    refuse_entry: bool,
    writes: Arc<AtomicUsize>,
) {
    #[derive(Clone, Debug)]
    struct RefusedKeyring {
        code: i32,
        message: &'static str,
        refuse_entry: bool,
        writes: Arc<AtomicUsize>,
    }

    impl std::fmt::Display for RefusedKeyring {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.code, self.message)
        }
    }

    impl std::error::Error for RefusedKeyring {}

    impl RefusedKeyring {
        fn error(&self) -> keyring::Error {
            keyring::Error::PlatformFailure(Box::new(self.clone()))
        }
    }

    impl keyring::credential::CredentialBuilderApi for RefusedKeyring {
        fn build(
            &self,
            _target: Option<&str>,
            _service: &str,
            _user: &str,
        ) -> keyring::Result<Box<keyring::Credential>> {
            if self.refuse_entry {
                self.writes.fetch_add(1, Ordering::SeqCst);
                return Err(self.error());
            }
            Ok(Box::new(self.clone()))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl keyring::credential::CredentialApi for RefusedKeyring {
        fn set_secret(&self, _secret: &[u8]) -> keyring::Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(self.error())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            panic!("The runtime must not read a prompt that the keyring refused.");
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            panic!("Retention must not delete a prompt that the keyring refused.");
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    keyring::set_default_credential_builder(Box::new(RefusedKeyring {
        code,
        message,
        refuse_entry,
        writes,
    }));
}

#[cfg(feature = "keyring")]
#[doc(hidden)]
pub fn fail_next_mock_prompt_delete_for_tests() {
    FAIL_NEXT_MOCK_DELETE.store(true, Ordering::SeqCst);
}

#[derive(Debug)]
pub enum ChatPromptError {
    Entry(PromptStoreError),
    Store(PromptStoreError),
    Load(PromptStoreError),
    Delete(PromptStoreError),
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
    if let Some(directory) = local_prompt_directory() {
        return store_local_prompt(&directory, &user, prompt)
            .map_err(|error| ChatPromptError::Store(file_failure(error)));
    }
    keychain::store(&user, prompt)
}

pub fn load_prompt(run_id: &str, subject: Option<&str>) -> Result<Option<String>, ChatPromptError> {
    let user = prompt_user(subject, run_id);
    if let Some(directory) = local_prompt_directory() {
        return load_local_prompt(&directory, &user)
            .map_err(|error| ChatPromptError::Load(file_failure(error)));
    }
    keychain::load(&user)
}

pub fn delete_prompt(run_id: &str, subject: Option<&str>) -> Result<(), ChatPromptError> {
    let user = prompt_user(subject, run_id);
    if let Some(directory) = local_prompt_directory() {
        return delete_local_prompt(&directory, &user)
            .map_err(|error| ChatPromptError::Delete(file_failure(error)));
    }
    keychain::delete(&user)
}

#[cfg(test)]
mod local_store_tests {
    use super::*;

    fn temporary_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "muniment-prompt-store-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn the_marker_selects_the_file_store_under_the_state_root() {
        let root = temporary_root("marker");
        assert_eq!(local_prompt_directory_under(&root), None);
        fs::write(root.join(crate::local_mode::LOCAL_MODE_MARKER), "1").unwrap();
        assert_eq!(
            local_prompt_directory_under(&root),
            Some(root.join("muniment").join("prompts"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(not(feature = "keyring"))]
    #[test]
    fn a_build_without_the_keyring_keeps_prompts_in_files_without_the_marker() {
        let root = temporary_root("no-keyring");
        assert!(!crate::local_mode::is_local_mode(&root));
        assert_eq!(
            local_prompt_directory_under(&root),
            Some(root.join("muniment").join("prompts"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_local_prompt_round_trips_through_an_owner_only_file() {
        let root = temporary_root("files");
        let directory = root.join("muniment").join("prompts");
        let user = prompt_user(Some("user:a"), "run-1");
        assert_eq!(load_local_prompt(&directory, &user).unwrap(), None);
        store_local_prompt(&directory, &user, "first draft").unwrap();
        store_local_prompt(&directory, &user, "Plan the week").unwrap();
        assert_eq!(
            load_local_prompt(&directory, &user).unwrap().as_deref(),
            Some("Plan the week")
        );
        let path = local_prompt_path(&directory, &user);
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".txt"));
        assert_ne!(
            path,
            local_prompt_path(&directory, &prompt_user(Some("user:b"), "run-1"))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        delete_local_prompt(&directory, &user).unwrap();
        delete_local_prompt(&directory, &user).unwrap();
        assert_eq!(load_local_prompt(&directory, &user).unwrap(), None);
        fs::remove_dir_all(root).unwrap();
    }
}
