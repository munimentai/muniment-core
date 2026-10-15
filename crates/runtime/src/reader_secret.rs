//! Where a network source's secret lives: the host's credential store under
//! one service name, an entry per source. A checkout or a test sets
//! `MUNIMENT_READER_SECRET_<SOURCE>` instead, and an empty value there reads
//! as no secret, so a test can prove the unconnected path.

use crate::host::CredentialStore;

const SERVICE: &str = "ai.muniment.reader";

fn variable(source: &str) -> String {
    format!("MUNIMENT_READER_SECRET_{}", source.to_ascii_uppercase())
}

/// The secret for a source, or none.
pub fn read(store: &dyn CredentialStore, source: &str) -> Option<String> {
    if let Ok(value) = std::env::var(variable(source)) {
        return (!value.is_empty()).then_some(value);
    }
    store
        .read(SERVICE, source)
        .filter(|secret| !secret.is_empty())
}

/// Stores the secret for a source, replacing the one there.
pub fn write(store: &dyn CredentialStore, source: &str, secret: &str) -> Result<(), String> {
    if std::env::var_os(variable(source)).is_some() {
        std::env::set_var(variable(source), secret);
        return Ok(());
    }
    store.write(SERVICE, source, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FileCredentialStore;

    #[test]
    fn the_environment_stands_in_for_the_keychain() {
        let root = std::env::temp_dir().join(format!(
            "muniment-reader-secret-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let store = FileCredentialStore::new(&root);
        std::env::set_var("MUNIMENT_READER_SECRET_TESTSRC", "");
        assert_eq!(read(&store, "testsrc"), None);
        write(&store, "testsrc", "sk_1").unwrap();
        assert_eq!(read(&store, "testsrc").as_deref(), Some("sk_1"));
        write(&store, "testsrc", "").unwrap();
        assert_eq!(read(&store, "testsrc"), None);
        std::env::remove_var("MUNIMENT_READER_SECRET_TESTSRC");
        assert!(!root.exists());
    }
}
