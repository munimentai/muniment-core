use std::path::{Path, PathBuf};

use crate::chat_grant::ChatGrant;
use crate::sidecar::pi_install::{resolve_current_for, PiArtifactDescriptor, PI_SELECTED_ARTIFACT};
use crate::sidecar::{pi_sidecar_config, PiSessionLocator, SidecarConfig};

const LOCAL_MODE_ENV_REMOVE: &[&str] = &[
    "AI_GATEWAY_API_KEY",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_OAUTH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_PROFILE",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_BASE_URL",
    "CEREBRAS_API_KEY",
    "CLOUDFLARE_API_KEY",
    "COPILOT_GITHUB_TOKEN",
    "DEEPSEEK_API_KEY",
    "FIREWORKS_API_KEY",
    "GCLOUD_PROJECT",
    "GEMINI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_API_KEY",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_CLOUD_PROJECT",
    "GROQ_API_KEY",
    "HF_TOKEN",
    "KIMI_API_KEY",
    "MINIMAX_API_KEY",
    "MINIMAX_CN_API_KEY",
    "MISTRAL_API_KEY",
    "MOONSHOT_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENCODE_API_KEY",
    "OPENROUTER_API_KEY",
    "PI_DEFAULT_MODEL",
    "XAI_API_KEY",
    "XIAOMI_API_KEY",
    "XIAOMI_TOKEN_PLAN_AMS_API_KEY",
    "XIAOMI_TOKEN_PLAN_CN_API_KEY",
    "XIAOMI_TOKEN_PLAN_SGP_API_KEY",
    "ZAI_API_KEY",
];

pub trait PiLaunchBoundaries {
    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError>;
    fn memory_agent_extension_path(&self) -> Option<PathBuf>;
    fn pi_artifact(&self) -> PiArtifactDescriptor {
        PI_SELECTED_ARTIFACT
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
    if grant.is_local() {
        config.env_remove = LOCAL_MODE_ENV_REMOVE
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
    } else {
        config
            .env
            .insert("OPENAI_API_KEY".into(), grant.virtual_key.clone());
        config
            .env
            .insert("OPENAI_BASE_URL".into(), grant.gateway_url.clone());
        if let Some(model) = &grant.model {
            config.env.insert("PI_DEFAULT_MODEL".into(), model.clone());
        }
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
