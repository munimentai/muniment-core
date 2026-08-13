//! Companion workspace contexts keyed by client identity and session workspace.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use super::{ProtocolError, WorkspaceOnboardRequest, WorkspaceOnboarded};

/// Canonical directories authorized for companion workspace sessions.
#[derive(Default)]
pub struct WorkspaceContextMap {
    contexts: HashMap<String, HashMap<String, HashMap<PathBuf, Option<String>>>>,
}

impl WorkspaceContextMap {
    /// Records one canonical directory for a client and session workspace.
    pub fn record(
        &mut self,
        client_identity: &str,
        session_workspace: &str,
        canonical_directory: PathBuf,
        instructions: Option<String>,
    ) {
        self.contexts
            .entry(client_identity.to_owned())
            .or_default()
            .entry(session_workspace.to_owned())
            .or_default()
            .insert(canonical_directory, instructions);
    }

    /// Returns a recorded canonical directory for the matching client and session.
    pub fn authorized_directory(
        &self,
        client_identity: &str,
        session_workspace: &str,
        canonical_directory: &Path,
    ) -> Option<PathBuf> {
        self.contexts
            .get(client_identity)?
            .get(session_workspace)?
            .contains_key(canonical_directory)
            .then(|| canonical_directory.to_owned())
    }

    /// Returns instructions recorded for the matching client, session, and directory.
    pub fn instructions(
        &self,
        client_identity: &str,
        session_workspace: &str,
        canonical_directory: &Path,
    ) -> Option<&str> {
        self.contexts
            .get(client_identity)?
            .get(session_workspace)?
            .get(canonical_directory)?
            .as_deref()
    }
}

/// Creates a companion workspace scaffold and records its authorized directories.
pub fn onboard_workspace_context(
    workspace_contexts: &Mutex<WorkspaceContextMap>,
    client_identity: &str,
    session_workspace: &str,
    request: WorkspaceOnboardRequest,
) -> Result<WorkspaceOnboarded, ProtocolError> {
    let opened = PathBuf::from(&request.opened_directory);
    let memory = PathBuf::from(&request.memory_location);
    if !opened.is_absolute() || !memory.is_absolute() {
        return Err(ProtocolError::invalid_request());
    }
    let instructions = crate::onboard_companion_workspace(&opened, &memory)
        .map_err(|_| ProtocolError::persistence_failed())?;
    let opened_canonical = opened
        .canonicalize()
        .map_err(|_| ProtocolError::persistence_failed())?;
    let memory_canonical = memory
        .canonicalize()
        .map_err(|_| ProtocolError::persistence_failed())?;
    let mut workspace_contexts = workspace_contexts
        .lock()
        .map_err(|_| ProtocolError::persistence_failed())?;
    workspace_contexts.record(
        client_identity,
        session_workspace,
        opened_canonical,
        instructions.clone(),
    );
    workspace_contexts.record(
        client_identity,
        session_workspace,
        memory_canonical,
        instructions.clone(),
    );
    Ok(WorkspaceOnboarded {
        opened_directory: opened.to_string_lossy().into_owned(),
        memory_location: memory.to_string_lossy().into_owned(),
        instructions,
    })
}
