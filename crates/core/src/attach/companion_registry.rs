//! Companion credentials and their live connection revocation state.

use super::{
    linux::LiveConnectionRegistry, save_client_credentials, ClientCredential, ProtocolError,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

type PersistCredentials =
    dyn Fn(&Path, &HashMap<String, ClientCredential>) -> Result<(), ProtocolError> + Send + Sync;

/// A companion row that excludes its secret credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionRecord {
    pub identity: String,
    pub claimed_kind: String,
    pub claimed_version: String,
    pub approved_at: Option<String>,
}

/// Manages the shared companion credential store and its live connections.
#[derive(Clone)]
pub struct CompanionRegistry {
    credentials: Arc<Mutex<HashMap<String, ClientCredential>>>,
    credential_path: PathBuf,
    live_connections: LiveConnectionRegistry,
    persist: Arc<PersistCredentials>,
}

impl CompanionRegistry {
    pub fn new(
        credentials: Arc<Mutex<HashMap<String, ClientCredential>>>,
        credential_path: impl AsRef<Path>,
        live_connections: LiveConnectionRegistry,
    ) -> Self {
        Self {
            credentials,
            credential_path: credential_path.as_ref().to_owned(),
            live_connections,
            persist: Arc::new(save_client_credentials),
        }
    }

    /// Constructs a registry with a controlled persistence operation for tests.
    #[doc(hidden)]
    pub fn new_with_persistence(
        credentials: Arc<Mutex<HashMap<String, ClientCredential>>>,
        credential_path: impl AsRef<Path>,
        live_connections: LiveConnectionRegistry,
        persist: impl Fn(&Path, &HashMap<String, ClientCredential>) -> Result<(), ProtocolError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            credentials,
            credential_path: credential_path.as_ref().to_owned(),
            live_connections,
            persist: Arc::new(persist),
        }
    }

    /// Revokes a companion after its removal reaches persistent storage.
    pub fn revoke(&self, identity: &str) -> Result<(), ProtocolError> {
        let mut credentials = self
            .credentials
            .lock()
            .map_err(|_| ProtocolError::persistence_failed())?;
        let credential = credentials
            .get(identity)
            .cloned()
            .ok_or_else(ProtocolError::unauthorized)?;

        self.live_connections.block(&credential.credential);
        credentials.remove(identity);
        if let Err(error) = (self.persist)(&self.credential_path, &credentials) {
            credentials.insert(identity.to_owned(), credential.clone());
            self.live_connections.resume(&credential.credential);
            return Err(error);
        }
        self.live_connections.revoke(&credential.credential);
        Ok(())
    }

    /// Lists companions by identity without exposing their secret credentials.
    pub fn list(&self) -> Result<Vec<CompanionRecord>, ProtocolError> {
        let credentials = self
            .credentials
            .lock()
            .map_err(|_| ProtocolError::persistence_failed())?;
        let mut companions: Vec<_> = credentials
            .iter()
            .map(|(identity, entry)| CompanionRecord {
                identity: identity.clone(),
                claimed_kind: entry.claimed_kind.clone(),
                claimed_version: entry.claimed_version.clone(),
                approved_at: entry.approved_at.clone(),
            })
            .collect();
        companions.sort_by(|left, right| left.identity.cmp(&right.identity));
        Ok(companions)
    }

    /// Returns the shared live connection registry.
    pub fn live_connections(&self) -> LiveConnectionRegistry {
        self.live_connections.clone()
    }

    /// Returns the shared companion credential map.
    pub fn credentials(&self) -> Arc<Mutex<HashMap<String, ClientCredential>>> {
        Arc::clone(&self.credentials)
    }
}
