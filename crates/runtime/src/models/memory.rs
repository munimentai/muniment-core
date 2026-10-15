//! Memory: the profile, the facts of the user or of one agent, deleted facts,
//! the recall settings and the changes the after-run pass keeps for review.
//! Settings edits are the user's own, so a fact saved here is a user fact
//! whatever trust the client sent.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use muniment_core::memory_files::{self, Fact, PendingChange, RecallSettings, Trust};
use muniment_core::serde_json::{self, Value};

/// The facts an action reads or changes: the user's, or one agent's.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    #[serde(default)]
    pub(super) agent: Option<String>,
}

/// The Home folder that holds the facts and the private folder that holds
/// deleted facts and the write lock.
fn roots(profile: &Path, scope: &Scope) -> Result<(PathBuf, PathBuf), String> {
    match &scope.agent {
        Some(agent) => muniment_core::agents::memory_paths(profile, agent),
        None => Ok((memory_files::home(profile)?, profile.to_owned())),
    }
}

pub(super) fn facts(profile: &Path, scope: Scope) -> Result<Vec<Fact>, String> {
    memory_files::facts_in(&roots(profile, &scope)?.0)
}

pub(super) fn deleted_facts(profile: &Path, scope: Scope) -> Result<Vec<Fact>, String> {
    memory_files::deleted_facts(&roots(profile, &scope)?.1)
}

pub(super) fn fact_save(profile: &Path, scope: Scope, mut fact: Fact) -> Result<Fact, String> {
    let (home, private) = roots(profile, &scope)?;
    fact.trust = Trust::User;
    memory_files::fact_save_in(&private, &home, fact)
}

pub(super) fn fact_delete(profile: &Path, scope: Scope, id: &str) -> Result<Value, String> {
    let (home, private) = roots(profile, &scope)?;
    memory_files::fact_delete_in(&private, &home, id).map(|()| Value::Null)
}

pub(super) fn fact_restore(profile: &Path, scope: Scope, id: &str) -> Result<Value, String> {
    let (home, private) = roots(profile, &scope)?;
    memory_files::fact_restore_in(&private, &home, id).map(|()| Value::Null)
}

/// The stored recall settings, or null before the user saves any.
pub(super) fn recall_settings(profile: &Path) -> Result<Value, String> {
    memory_files::recall_settings_stored(profile)
        .map(|settings| serde_json::to_value(settings).unwrap_or(Value::Null))
}

pub(super) fn recall_settings_save(
    profile: &Path,
    settings: RecallSettings,
) -> Result<RecallSettings, String> {
    memory_files::recall_settings_save(profile, settings).map(|()| settings)
}

/// The changes the after-run memory pass keeps for review, newest first.
pub(super) fn pending(profile: &Path, scope: Scope) -> Result<Vec<PendingChange>, String> {
    memory_files::pending_changes(&roots(profile, &scope)?.1)
}

/// Applies a kept change: the fact an add or update wrote, or null for a delete.
pub(super) fn pending_apply(profile: &Path, scope: Scope, id: &str) -> Result<Value, String> {
    let (home, private) = roots(profile, &scope)?;
    memory_files::pending_apply(&private, &home, id)
        .map(|fact| serde_json::to_value(fact).unwrap_or(Value::Null))
}

pub(super) fn pending_dismiss(profile: &Path, scope: Scope, id: &str) -> Result<Value, String> {
    let (_, private) = roots(profile, &scope)?;
    memory_files::pending_dismiss(&private, id).map(|()| Value::Null)
}
