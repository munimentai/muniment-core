use std::path::{Path, PathBuf};

use crate::chat_grant::ChatGrant;
use crate::sidecar::pi_install::{resolve_current_for, PiArtifactDescriptor, PI_ARTIFACT};
use crate::sidecar::{pi_sidecar_config, PiSessionLocator, SidecarConfig};

pub trait PiLaunchBoundaries {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError>;
    fn memory_agent_extension_path(&self) -> Option<PathBuf>;
    fn pi_artifact(&self) -> PiArtifactDescriptor {
        PI_ARTIFACT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiLaunchError {
    MissingRoot,
    UnresolvableExecutable,
    UnavailableSessionRoot,
    RejectedConfig,
}

pub fn pi_launch_config(
    boundaries: &impl PiLaunchBoundaries,
    root: Option<&Path>,
    grant: &ChatGrant,
    reopen: Option<&PiSessionLocator>,
) -> Result<SidecarConfig, PiLaunchError> {
    let root = root.ok_or(PiLaunchError::MissingRoot)?;
    let executable = resolve_current_for(root, boundaries.pi_artifact())
        .map_err(|_| PiLaunchError::UnresolvableExecutable)?;
    pi_launch_config_for_executable(boundaries, executable, grant, reopen)
}

pub fn pi_launch_config_for_executable(
    boundaries: &impl PiLaunchBoundaries,
    executable: PathBuf,
    grant: &ChatGrant,
    reopen: Option<&PiSessionLocator>,
) -> Result<SidecarConfig, PiLaunchError> {
    let session_root = boundaries.pi_session_root()?;
    let mut config = pi_sidecar_config(executable.to_string_lossy(), &session_root, reopen)
        .map_err(|_| PiLaunchError::RejectedConfig)?;
    config
        .env
        .insert("OPENAI_API_KEY".into(), grant.virtual_key.clone());
    config
        .env
        .insert("OPENAI_BASE_URL".into(), grant.gateway_url.clone());
    if let Some(model) = &grant.model {
        config.env.insert("PI_DEFAULT_MODEL".into(), model.clone());
    }
    if let Some(extension) = boundaries
        .memory_agent_extension_path()
        .filter(|path| path.is_file())
    {
        config.args.extend([
            "--extension".into(),
            extension.to_string_lossy().into_owned(),
        ]);
    }
    Ok(config)
}
