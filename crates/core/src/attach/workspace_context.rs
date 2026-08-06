//! Companion workspace contexts keyed by client identity and session workspace.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

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
