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
            return Err(PiLaunchError::rejected(
                "artifact_selection",
                "The agent runtime artifact does not match the selected artifact.",
            ));
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
    RejectedConfig { step: &'static str, cause: String },
    Acquisition(crate::sidecar::pi_install::CoordinatedPiInstallError),
}

impl PiLaunchError {
    pub fn rejected(step: &'static str, error: impl std::fmt::Display) -> Self {
        Self::RejectedConfig {
            step,
            cause: diagnostic_text(&error.to_string()),
        }
    }
}

/// Redact before truncation so a boundary cannot expose part of a credential.
pub(crate) fn diagnostic_text(text: &str) -> String {
    redact_diagnostic(text, diagnostic_secrets())
}

fn diagnostic_secrets() -> impl Iterator<Item = String> {
    std::env::vars_os().filter_map(|(name, value)| {
        let name = name.to_string_lossy().to_ascii_uppercase();
        let value = value.into_string().ok()?;
        (!value.is_empty()
            && ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "AUTH"]
                .iter()
                .any(|label| name.contains(label)))
        .then_some(value)
    })
}

fn redact_diagnostic(text: &str, secrets: impl Iterator<Item = String>) -> String {
    let mut redactor = DiagnosticRedactor::with_secrets(secrets);
    let mut text = text.to_owned();
    for secret in redactor
        .secrets
        .iter()
        .filter(|secret| secret.contains('\n'))
    {
        text = text.replace(secret, "[redacted]");
    }
    text.lines()
        .map(|line| redactor.line(line))
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(8192)
        .collect()
}

/// Keep terminal and credential state across stderr lines.
pub(crate) struct DiagnosticRedactor {
    secrets: Vec<String>,
    terminal: TerminalState,
    terminal_prefix: String,
    private_key: bool,
    value: CredentialValue,
}

#[derive(Default)]
enum TerminalState {
    #[default]
    Text,
    Escape,
    Intermediate,
    Csi,
    String,
    StringEscape,
}

#[derive(Default)]
enum CredentialValue {
    #[default]
    None,
    Pending,
    Quoted(char),
}

impl DiagnosticRedactor {
    pub(crate) fn new() -> Self {
        Self::with_secrets(diagnostic_secrets())
    }

    fn with_secrets(secrets: impl Iterator<Item = String>) -> Self {
        // Redact each component before stderr joins or bounds the lines, even when the tail contains only one component.
        let mut secrets: Vec<_> = secrets
            .flat_map(|value| {
                let mut parts = Vec::new();
                let json = serde_json::from_str::<serde_json::Value>(&value);
                let components = match &json {
                    // Credential JSON contains framing, not just secret text. Redact its string values instead of braces.
                    Ok(json @ (serde_json::Value::Object(_) | serde_json::Value::Array(_))) => {
                        let mut pending = vec![json];
                        let mut strings = Vec::new();
                        while let Some(item) = pending.pop() {
                            match item {
                                serde_json::Value::Object(fields) => {
                                    pending.extend(fields.values())
                                }
                                serde_json::Value::Array(items) => pending.extend(items),
                                serde_json::Value::String(text) => strings.push(text.as_str()),
                                _ => {}
                            }
                        }
                        strings
                    }
                    _ => vec![value.as_str()],
                };
                for component in components {
                    parts.extend(
                        component
                            .lines()
                            .filter(|part| !part.is_empty())
                            .map(str::to_owned),
                    );
                }
                if !value.is_empty() && !parts.contains(&value) {
                    parts.push(value);
                }
                parts
            })
            .collect();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self {
            secrets,
            terminal: TerminalState::default(),
            terminal_prefix: String::new(),
            private_key: false,
            value: CredentialValue::default(),
        }
    }

    fn strip_terminal(&mut self, line: &str) -> String {
        let mut text = std::mem::take(&mut self.terminal_prefix);
        for character in line.chars() {
            self.terminal = match self.terminal {
                TerminalState::Text => match character {
                    '\u{1b}' => TerminalState::Escape,
                    '\u{9b}' => TerminalState::Csi,
                    '\u{90}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => TerminalState::String,
                    _ => {
                        if !character.is_control() || character == '\t' {
                            text.push(character);
                        }
                        TerminalState::Text
                    }
                },
                TerminalState::Escape => match character {
                    '[' => TerminalState::Csi,
                    ']' | 'P' | '^' | '_' | 'X' => TerminalState::String,
                    '\u{20}'..='\u{2f}' => TerminalState::Intermediate,
                    _ => TerminalState::Text,
                },
                TerminalState::Intermediate => match character {
                    '\u{30}'..='\u{7e}' => TerminalState::Text,
                    _ => TerminalState::Intermediate,
                },
                TerminalState::Csi => match character {
                    '\u{40}'..='\u{7e}' => TerminalState::Text,
                    _ => TerminalState::Csi,
                },
                TerminalState::String | TerminalState::StringEscape => match character {
                    '\u{7}' | '\u{9c}' => TerminalState::Text,
                    '\\' if matches!(self.terminal, TerminalState::StringEscape) => {
                        TerminalState::Text
                    }
                    '\u{1b}' => TerminalState::StringEscape,
                    _ => TerminalState::String,
                },
            };
        }
        if !matches!(self.terminal, TerminalState::Text) {
            if text.len() > 65_536 {
                // Hide the continuation if the terminal prefix exceeds the stderr line bound.
                self.value = CredentialValue::Pending;
            } else {
                self.terminal_prefix = text;
            }
            return String::new();
        }
        text
    }

    fn consume_value(&mut self, value: &str) -> usize {
        let length = value.len();
        let mut value = value.trim_start();
        if matches!(self.value, CredentialValue::Pending) {
            if value.is_empty() {
                return length;
            }
            let first = value.chars().next().unwrap();
            if matches!(first, '\'' | '"' | '`') {
                self.value = CredentialValue::Quoted(first);
                value = &value[first.len_utf8()..];
            } else {
                self.value = CredentialValue::None;
            }
        }
        if let CredentialValue::Quoted(quote) = self.value {
            let mut escaped = false;
            for (index, character) in value.char_indices() {
                if character == quote && !escaped {
                    self.value = CredentialValue::None;
                    return length - value.len() + index + character.len_utf8();
                }
                escaped = character == '\\' && !escaped;
            }
        }
        length
    }

    pub(crate) fn line(&mut self, line: &str) -> String {
        let mut text = self.strip_terminal(line);
        if text.contains("-----BEGIN") && text.contains("PRIVATE KEY") {
            self.private_key = true;
        }
        let continuation = !matches!(self.value, CredentialValue::None);
        let mut offset = if continuation {
            self.consume_value(&text)
        } else {
            0
        };
        let mut first_field = None;
        while matches!(self.value, CredentialValue::None) && offset < text.len() {
            let Some((start, value)) = credential_field(&text[offset..]) else {
                break;
            };
            first_field.get_or_insert(offset + start);
            self.value = CredentialValue::Pending;
            offset = text.len() - value.len() + self.consume_value(value);
        }
        let mut redacted = if self.private_key || continuation {
            "[redacted]".to_owned()
        } else if let Some(start) = first_field {
            text[..start].to_owned() + "[redacted]"
        } else {
            text.clone()
        };
        if text.contains("-----END") && text.contains("PRIVATE KEY") {
            self.private_key = false;
        }
        for secret in &self.secrets {
            redacted = redacted.replace(secret, "[redacted]");
        }
        let scan = crate::assistant_text::scan(&redacted, true);
        if let Some(start) = scan.withhold_from {
            redacted.replace_range(start.., "[redacted]");
        }
        for matched in scan.matches.into_iter().rev() {
            redacted.replace_range(matched.range, "[redacted]");
        }
        // Registry URLs can carry credentials in userinfo, paths, or query parameters.
        text = redacted
            .split_whitespace()
            .map(|word| if word.contains("://") { "[url]" } else { word })
            .collect::<Vec<_>>()
            .join(" ");
        text.chars().take(8192).collect()
    }
}

fn credential_field(line: &str) -> Option<(usize, &str)> {
    let lower = line.to_ascii_lowercase();
    [
        "authorization",
        "bearer",
        "basic",
        "authtoken",
        "api_key",
        "apikey",
        "api-token",
        "token",
        "secret",
        "passwd",
        "password",
        "auth",
        "key",
    ]
    .into_iter()
    .flat_map(|label| {
        lower.match_indices(label).filter_map(move |(start, _)| {
            let boundary = start == 0 || !line.as_bytes()[start - 1].is_ascii_alphanumeric();
            let suffix = &line[start + label.len()..];
            let delimiter = suffix.trim_start_matches([' ', '\t', '\'', '"', '`']);
            if !boundary {
                return None;
            }
            if delimiter.starts_with([':', '=']) {
                Some((start, &delimiter[1..]))
            } else if matches!(label, "bearer" | "basic") && suffix.starts_with(char::is_whitespace)
            {
                Some((start, suffix))
            } else {
                None
            }
        })
    })
    .min_by_key(|(start, _)| *start)
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
    result.map_err(|error: std::io::Error| PiLaunchError::rejected("cloud_extension_write", error))
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
        .map_err(|error| PiLaunchError::rejected("session_root_check", error))?;
    boundaries.prepare_pi_settings(boundaries.pi_artifact(), &executable)?;
    config.env_remove.push("BUN_BE_BUN".into());
    // The harness keeps its settings, routes and keys under the app's state root.
    if let Some(agent) =
        crate::state_root::state_directory().map(|state| crate::state_root::agent_directory(&state))
    {
        config.env.insert(
            "PI_CODING_AGENT_DIR".into(),
            agent.to_string_lossy().into_owned(),
        );
    }
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
        // Cloud setup must release the run before the shell's receipt deadline.
        config.startup_timeout = std::time::Duration::from_secs(30);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiline_secret_components_preserve_json_framing_and_redact_short_values() {
        let secrets = [
            "{\n\"nested\": [{\"password\": \"opaque-one\\nopaque-two\"}]\n}".to_owned(),
            "!\n?\n".to_owned(),
            String::new(),
        ];
        let mut redactor = DiagnosticRedactor::with_secrets(secrets.into_iter());
        assert_eq!(
            redactor.line("{ registry refused }"),
            "{ registry refused }"
        );
        for secret in ["opaque-one", "opaque-two", "!", "?"] {
            assert_eq!(redactor.line(secret), "[redacted]");
        }
        assert_eq!(redactor.line(""), "");
    }

    #[test]
    fn diagnostic_redaction_precedes_bounds_and_escapes_credentials() {
        let text = format!("permission denied\nBearer opaque-credential https://user:password@registry.example/package?secret=value\napi_key={}\nlast error", "a".repeat(9000));
        let detail = redact_diagnostic(&text, ["opaque-credential".to_owned()].into_iter());
        assert!(detail.contains("permission denied"));
        assert!(detail.contains("last error"));
        for secret in [
            "opaque-credential",
            "password@",
            "secret=value",
            &"a".repeat(100),
        ] {
            assert!(!detail.contains(secret), "{detail}");
        }
        assert!(!detail.contains('\n'));
        assert!(detail.len() < 8192);
        assert_eq!(redact_diagnostic("", std::iter::empty()), "");
        assert_eq!(
            redact_diagnostic(
                "registry refused\nopaque-part-one\nopaque-part-two",
                ["opaque-part-one\nopaque-part-two".to_owned()].into_iter(),
            ),
            "registry refused [redacted]"
        );
        for text in [
            "registry refused Authorization: Bearer opaque-value",
            "registry refused password=short",
            "registry refused NPM_TOKEN=short",
            "registry refused Basic YTpi",
            "registry refused {\"_auth\":\"short\"}",
            "registry refused api_key=sh\u{1b}[31mort",
        ] {
            let detail = redact_diagnostic(text, std::iter::empty());
            assert!(detail.contains("registry refused"));
            for secret in ["opaque-value", "short", "YTpi", "31mort"] {
                assert!(!detail.contains(secret), "{detail}");
            }
        }
    }
}
