//! Platform-neutral live attach connection registry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LiveConnectionState {
    Active,
    Blocked,
    Revoked,
}

pub(super) struct LiveConnection {
    pub(super) capability: String,
    pub(super) connection_event_id: super::Id,
    pub(super) state: Mutex<LiveConnectionState>,
}

struct CredentialConnections {
    gate: Arc<Mutex<()>>,
    state: LiveConnectionState,
    connections: HashMap<super::Id, Arc<LiveConnection>>,
}

impl Default for CredentialConnections {
    fn default() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
            state: LiveConnectionState::Active,
            connections: HashMap::new(),
        }
    }
}

type ConnectionsByCredential = HashMap<String, CredentialConnections>;

/// Tracks authorized attach connections by the client credential that authenticated them.
#[derive(Clone, Default)]
pub struct LiveConnectionRegistry {
    connections: Arc<Mutex<ConnectionsByCredential>>,
}

impl LiveConnectionRegistry {
    /// Stops request admission for every live connection authenticated by `credential`.
    pub fn block(&self, credential: &str) -> usize {
        self.set_state(credential, |state| {
            if *state == LiveConnectionState::Active {
                *state = LiveConnectionState::Blocked;
            }
        })
    }

    /// Restarts request admission for every blocked connection authenticated by `credential`.
    pub fn resume(&self, credential: &str) -> usize {
        self.set_state(credential, |state| {
            if *state == LiveConnectionState::Blocked {
                *state = LiveConnectionState::Active;
            }
        })
    }

    /// Revokes every live connection authenticated by `credential`.
    pub fn revoke(&self, credential: &str) -> usize {
        self.set_state(credential, |state| *state = LiveConnectionState::Revoked)
    }

    fn set_state(&self, credential: &str, update: impl Fn(&mut LiveConnectionState)) -> usize {
        let mut connections = self.connections.lock().expect("live connection registry");
        let entries = connections.entry(credential.to_owned()).or_default();
        let gate = Arc::clone(&entries.gate);
        let _gate = gate.lock().expect("credential admission gate");
        update(&mut entries.state);
        for connection in entries.connections.values() {
            let mut state = connection.state.lock().expect("live connection state");
            *state = entries.state;
        }
        entries.connections.len()
    }

    pub(super) fn register(
        &self,
        credential: String,
        capability: String,
        connection_event_id: super::Id,
    ) -> RegisteredConnection {
        let mut connections = self.connections.lock().expect("live connection registry");
        let entries = connections.entry(credential.clone()).or_default();
        let gate = Arc::clone(&entries.gate);
        let _gate = gate.lock().expect("credential admission gate");
        let connection = Arc::new(LiveConnection {
            capability,
            connection_event_id: connection_event_id.clone(),
            state: Mutex::new(entries.state),
        });
        entries
            .connections
            .insert(connection_event_id.clone(), Arc::clone(&connection));
        drop(_gate);
        RegisteredConnection {
            registry: self.clone(),
            credential,
            connection_event_id,
            connection,
            gate,
        }
    }
}

pub(super) struct RegisteredConnection {
    registry: LiveConnectionRegistry,
    credential: String,
    connection_event_id: super::Id,
    pub(super) connection: Arc<LiveConnection>,
    pub(super) gate: Arc<Mutex<()>>,
}

impl Drop for RegisteredConnection {
    fn drop(&mut self) {
        let mut connections = self
            .registry
            .connections
            .lock()
            .expect("live connection registry");
        if let Some(entries) = connections.get_mut(&self.credential) {
            entries.connections.remove(&self.connection_event_id);
        }
    }
}
