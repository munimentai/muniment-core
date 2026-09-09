use std::path::{Path, PathBuf};

use crate::chat_grant::ChatGrant;
use crate::sidecar::pi_install::{resolve_current_for, PiArtifactDescriptor, PI_SELECTED_ARTIFACT};
use crate::sidecar::{pi_sidecar_config, PiSessionLocator, SidecarConfig};

const CLOUD_PROVIDER_EXTENSION: &str = include_str!("muniment_cloud_provider.mjs");

const BASH_TIMEOUT_INSTRUCTIONS: &str =
    "- `bash` reads its `timeout` in SECONDS, never milliseconds, and applies
  NO timeout at all when you omit it. Pass one on every call: 60 for a
  quick command, up to 600 for a build or a test suite. A four- or
  five-digit value is a millisecond habit from another harness and leaves
  the command unbounded, so it runs until the engine kills the whole run.";

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
    fn renew_chat_grant(
        &self,
        access_token: &str,
    ) -> Result<ChatGrant, crate::chat_grant::FetchGrantError> {
        #[cfg(feature = "keyring")]
        return crate::chat_grant::renew_native_grant(access_token);
        #[cfg(not(feature = "keyring"))]
        {
            let _ = access_token;
            Err(crate::chat_grant::FetchGrantError::Unavailable)
        }
    }

    fn inspect_chat_session(
        &self,
        access_token: &str,
    ) -> Result<String, crate::chat_grant::FetchGrantError> {
        #[cfg(feature = "keyring")]
        return crate::chat_grant::inspect_native_chat_session(access_token);
        #[cfg(not(feature = "keyring"))]
        {
            let _ = access_token;
            Err(crate::chat_grant::FetchGrantError::Unavailable)
        }
    }

    fn pi_install_root(&self) -> Result<PathBuf, PiLaunchError> {
        if let Some(root) = std::env::var_os("MUNIMENT_PI_ROOT") {
            return if root.is_empty() {
                Err(PiLaunchError::MissingRoot)
            } else {
                Ok(root.into())
            };
        }
        let sessions = self.pi_session_root()?;
        let profile = sessions.parent().ok_or(PiLaunchError::MissingRoot)?;
        Ok(crate::chat_profile::ChatProfile::new(profile).pi_install_root())
    }

    fn acquire_pi(
        &self,
        root: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<PathBuf, PiLaunchError> {
        if self.pi_artifact() != PI_SELECTED_ARTIFACT {
            return Err(PiLaunchError::RejectedConfig);
        }
        crate::sidecar::pi_install::acquire_pi(root, cancelled).map_err(PiLaunchError::Acquisition)
    }

    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError>;
    fn memory_agent_extension_path(&self) -> Option<PathBuf>;
    fn prepare_pi_settings(
        &self,
        artifact: PiArtifactDescriptor,
        executable: &Path,
    ) -> Result<(), PiLaunchError> {
        crate::pi_settings::prepare_pi_settings(artifact, executable)
            .map_err(|_| PiLaunchError::RejectedConfig)
    }
    fn pi_artifact(&self) -> PiArtifactDescriptor {
        PI_SELECTED_ARTIFACT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiLaunchError {
    MissingRoot,
    UnresolvableExecutable,
    UnavailableSessionRoot,
    RejectedConfig,
    Acquisition(crate::sidecar::pi_install::CoordinatedPiInstallError),
}

fn install_cloud_provider(path: &Path) -> Result<(), PiLaunchError> {
    use std::io::Write;
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(CLOUD_PROVIDER_EXTENSION.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    let _ = std::fs::remove_file(&temporary);
    result.map_err(|_| PiLaunchError::RejectedConfig)
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
    boundaries.prepare_pi_settings(boundaries.pi_artifact(), &executable)?;
    config.env_remove.push("BUN_BE_BUN".into());
    if boundaries.pi_artifact().version == crate::sidecar::pi_install::PI_CANDIDATE_ARTIFACT.version
    {
        // Extension loading precedes the first RPC response.
        config.startup_timeout = std::time::Duration::from_secs(120);
    }
    config.args.extend([
        "--append-system-prompt".into(),
        BASH_TIMEOUT_INSTRUCTIONS.into(),
    ]);
    if grant.is_local() {
        config
            .env_remove
            .extend(LOCAL_MODE_ENV_REMOVE.iter().map(|name| (*name).to_owned()));
    } else {
        config.env_remove.push("OPENAI_API_KEY".into());
        config
            .env
            .insert("OPENAI_BASE_URL".into(), grant.gateway_url.clone());
        if let Some(model) = &grant.model {
            config.env.insert("PI_DEFAULT_MODEL".into(), model.clone());
            // Register the cloud alias without storing its key in Pi settings.
            let extension = session_root.join("muniment-cloud-provider.mjs");
            install_cloud_provider(&extension)?;
            config.args.extend([
                "--extension".into(),
                extension.to_string_lossy().into_owned(),
                "--provider".into(),
                "muniment".into(),
                "--model".into(),
                model.clone(),
                // Pi's CLI sets a runtime override on both tracks. This marker is not a credential.
                "--api-key".into(),
                "muniment-runtime-boundary".into(),
            ]);
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
