//! Runtime composition for the desktop attach service.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use muniment_core::attach::{
    AttachHome, CompanionRegistry, DesktopAttachService, IdempotencyStore, ProtocolError,
    WorkspaceContextMap, COMPANION_CREDENTIAL_FILE_NAME,
};

use crate::RuntimeAttachBoundaries;

/// Composes the runtime attach boundaries into a complete desktop attach service.
pub fn compose_attach_service(
    boundaries: RuntimeAttachBoundaries,
    companion_registry: &CompanionRegistry,
    profile_directory: impl AsRef<Path>,
    config_directory: impl AsRef<Path>,
) -> Result<DesktopAttachService<RuntimeAttachBoundaries>, ProtocolError> {
    let profile_directory = profile_directory.as_ref();
    let home = AttachHome::configured(
        config_directory.as_ref().to_path_buf(),
        None,
        std::env::var_os("HOME").map(PathBuf::from),
    );

    Ok(DesktopAttachService {
        boundaries,
        idempotency: IdempotencyStore::open(profile_directory.join("attach-idempotency.sqlite3"))?,
        home,
        workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
        client_credentials: companion_registry.credentials(),
        credential_path: Some(profile_directory.join(COMPANION_CREDENTIAL_FILE_NAME)),
        client_identity: None,
        drain_state: muniment_core::attach::DrainState::new(),
    })
}
