//! The server's settings: a TOML file, then environment overrides.
//!
//! Every setting has an environment variable named `MUNIMENT_ROUTER_` plus the
//! setting in upper case, with a section name joined by an underscore:
//! `listen` is `MUNIMENT_ROUTER_LISTEN`, `openbao.role_id` is
//! `MUNIMENT_ROUTER_OPENBAO_ROLE_ID`. The variable wins over the file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::config::Classifier;
use crate::policy::Mode;
use crate::store::SuccessWindow;

use super::openbao;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct File {
    listen: Option<String>,
    admin_token: Option<String>,
    run_token_signing_key: Option<String>,
    database_url: Option<String>,
    state_dir: Option<PathBuf>,
    catalog: Option<PathBuf>,
    catalog_poll_s: Option<u64>,
    policy_mode: Option<String>,
    drain_timeout_s: Option<u64>,
    quota_probe_interval_s: Option<u64>,
    metrics: Option<bool>,
    success: SuccessFile,
    openbao: OpenBaoFile,
    classifier: ClassifierFile,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SuccessFile {
    half_life_days: Option<f64>,
    min_samples: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OpenBaoFile {
    address: Option<String>,
    mount: Option<String>,
    prefix: Option<String>,
    token: Option<String>,
    role_id: Option<String>,
    secret_id: Option<String>,
    approle_mount: Option<String>,
    cache_ttl_s: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClassifierFile {
    kind: Option<String>,
    base_url: Option<String>,
    api_key: Option<String>,
    model: Option<String>,
    family: Option<String>,
}

/// Where account state lives.
#[derive(Debug, Clone, PartialEq)]
pub enum Storage {
    Postgres(String),
    /// The desktop's JSON files in one directory, for development.
    Files(PathBuf),
}

/// The settings the server runs with.
#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: String,
    pub admin_token: Option<String>,
    pub run_token_signing_key: Option<String>,
    pub storage: Option<Storage>,
    pub catalog: Option<PathBuf>,
    pub catalog_poll: Duration,
    pub policy_mode: Mode,
    pub drain_timeout: Duration,
    /// Zero turns the background quota probe off.
    pub quota_probe_interval: Duration,
    pub metrics: bool,
    pub success: SuccessWindow,
    pub openbao: Option<openbao::Settings>,
    pub classifier: Classifier,
}

/// The environment variable for one setting.
pub fn variable(name: &str) -> String {
    format!(
        "MUNIMENT_ROUTER_{}",
        name.to_ascii_uppercase().replace('.', "_")
    )
}

fn mode(text: &str) -> Result<Mode, String> {
    match text.trim() {
        "current" => Ok(Mode::Current),
        "strong" => Ok(Mode::Strong),
        "ratchet" => Ok(Mode::Ratchet),
        "adaptive" => Ok(Mode::Adaptive),
        other => Err(format!(
            "policy_mode {other:?} is not current, strong, ratchet or adaptive."
        )),
    }
}

impl Settings {
    /// Reads `path` when given, then applies `env` over it.
    pub fn load(path: Option<&Path>, env: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let file: File = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?
            }
            None => File::default(),
        };
        let get = |name: &str, value: Option<String>| -> Option<String> {
            env(&variable(name))
                .or(value)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let number = |name: &str, value: Option<u64>| -> Result<Option<u64>, String> {
            match env(&variable(name)).filter(|value| !value.trim().is_empty()) {
                Some(text) => text
                    .trim()
                    .parse()
                    .map(Some)
                    .map_err(|_| format!("{} is not a whole number.", variable(name))),
                None => Ok(value),
            }
        };
        let float = |name: &str, value: Option<f64>| -> Result<Option<f64>, String> {
            match env(&variable(name)).filter(|value| !value.trim().is_empty()) {
                Some(text) => text
                    .trim()
                    .parse()
                    .map(Some)
                    .map_err(|_| format!("{} is not a number.", variable(name))),
                None => Ok(value),
            }
        };
        let storage = match (
            get("database_url", file.database_url),
            get("state_dir", file.state_dir.map(|p| p.display().to_string())),
        ) {
            (Some(url), _) => Some(Storage::Postgres(url)),
            (None, Some(dir)) => Some(Storage::Files(dir.into())),
            (None, None) => None,
        };
        let metrics = match env(&variable("metrics")).filter(|v| !v.trim().is_empty()) {
            Some(text) => match text.trim() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => return Err(format!("{} is not true or false.", variable("metrics"))),
            },
            None => file.metrics.unwrap_or(true),
        };
        let half_life_days =
            float("success.half_life_days", file.success.half_life_days)?.unwrap_or(7.0);
        let min_samples = float("success.min_samples", file.success.min_samples)?.unwrap_or(5.0);
        if !(half_life_days.is_finite() && half_life_days > 0.0)
            || !(min_samples.is_finite() && min_samples > 0.0)
        {
            return Err("success.half_life_days and success.min_samples must be positive.".into());
        }
        let openbao = match get("openbao.address", file.openbao.address) {
            None => None,
            Some(address) => {
                let method = match (
                    get("openbao.token", file.openbao.token),
                    get("openbao.role_id", file.openbao.role_id),
                    get("openbao.secret_id", file.openbao.secret_id),
                ) {
                    (_, Some(role_id), Some(secret_id)) => openbao::Auth::AppRole {
                        mount: get("openbao.approle_mount", file.openbao.approle_mount)
                            .unwrap_or_else(|| "approle".into()),
                        role_id,
                        secret_id,
                    },
                    (Some(token), _, _) => openbao::Auth::Token(token),
                    _ => {
                        return Err(format!(
                            "OpenBao needs {} or both {} and {}.",
                            variable("openbao.token"),
                            variable("openbao.role_id"),
                            variable("openbao.secret_id")
                        ))
                    }
                };
                Some(openbao::Settings {
                    address,
                    mount: get("openbao.mount", file.openbao.mount)
                        .unwrap_or_else(|| "secret".into()),
                    prefix: get("openbao.prefix", file.openbao.prefix)
                        .unwrap_or_else(|| "muniment-router/accounts".into()),
                    method,
                    cache_ttl: Duration::from_secs(
                        number("openbao.cache_ttl_s", file.openbao.cache_ttl_s)?.unwrap_or(60),
                    ),
                    timeout: Duration::from_secs(10),
                })
            }
        };
        let classifier = match get("classifier.kind", file.classifier.kind).as_deref() {
            None | Some("none") => Classifier::None,
            Some("typesafe") => Classifier::Typesafe {
                api_key: get("classifier.api_key", file.classifier.api_key)
                    .ok_or("The typesafe classifier needs classifier.api_key.")?,
                model: get("classifier.model", file.classifier.model)
                    .unwrap_or_else(|| "jev-latest".into()),
                base_url: get("classifier.base_url", file.classifier.base_url),
            },
            Some("endpoint") => Classifier::Endpoint {
                base_url: get("classifier.base_url", file.classifier.base_url)
                    .ok_or("The endpoint classifier needs classifier.base_url.")?,
                api_key: get("classifier.api_key", file.classifier.api_key),
                model: get("classifier.model", file.classifier.model)
                    .unwrap_or_else(|| "jev-latest".into()),
            },
            Some("pooled") => Classifier::Pooled {
                family: get("classifier.family", file.classifier.family)
                    .ok_or("The pooled classifier needs classifier.family.")?,
                model: get("classifier.model", file.classifier.model)
                    .ok_or("The pooled classifier needs classifier.model.")?,
            },
            Some(other) => {
                return Err(format!(
                    "classifier.kind {other:?} is not none, typesafe, endpoint or pooled."
                ))
            }
        };
        Ok(Self {
            listen: get("listen", file.listen).unwrap_or_else(|| "127.0.0.1:8790".into()),
            admin_token: get("admin_token", file.admin_token),
            run_token_signing_key: get("run_token_signing_key", file.run_token_signing_key),
            storage,
            catalog: get("catalog", file.catalog.map(|p| p.display().to_string()))
                .map(PathBuf::from),
            catalog_poll: Duration::from_secs(
                number("catalog_poll_s", file.catalog_poll_s)?
                    .unwrap_or(5)
                    .max(1),
            ),
            policy_mode: mode(
                &get("policy_mode", file.policy_mode).unwrap_or_else(|| "adaptive".into()),
            )?,
            drain_timeout: Duration::from_secs(
                number("drain_timeout_s", file.drain_timeout_s)?.unwrap_or(100),
            ),
            quota_probe_interval: Duration::from_secs(
                number("quota_probe_interval_s", file.quota_probe_interval_s)?.unwrap_or(900),
            ),
            metrics,
            success: SuccessWindow {
                half_life_ms: (half_life_days * 86_400_000.0) as i64,
                min_samples,
            },
            openbao,
            classifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn the_environment_overrides_the_file() {
        let path = std::env::temp_dir().join(format!(
            "muniment-router-settings-{}.toml",
            uuid::Uuid::now_v7()
        ));
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:9000"
admin_token = "from-file"
database_url = "postgres://file"
policy_mode = "strong"
metrics = false

[openbao]
address = "https://bao:8200"
role_id = "role"
secret_id = "secret"
prefix = "factory/router"

[classifier]
kind = "pooled"
family = "openai"
model = "gpt-5.6-luna"

[success]
half_life_days = 2
"#,
        )
        .unwrap();
        let env: HashMap<&str, &str> = [
            ("MUNIMENT_ROUTER_ADMIN_TOKEN", "from-env"),
            ("MUNIMENT_ROUTER_OPENBAO_MOUNT", "kv"),
            ("MUNIMENT_ROUTER_METRICS", "true"),
            ("MUNIMENT_ROUTER_SUCCESS_MIN_SAMPLES", "3"),
        ]
        .into();
        let settings =
            Settings::load(Some(&path), |name| env.get(name).map(|v| v.to_string())).unwrap();
        assert_eq!(settings.listen, "0.0.0.0:9000");
        assert_eq!(settings.admin_token.as_deref(), Some("from-env"));
        assert_eq!(
            settings.storage,
            Some(Storage::Postgres("postgres://file".into()))
        );
        assert_eq!(settings.policy_mode, Mode::Strong);
        assert!(settings.metrics);
        assert_eq!(settings.success.half_life_ms, 2 * 86_400_000);
        assert_eq!(settings.success.min_samples, 3.0);
        let bao = settings.openbao.unwrap();
        assert_eq!(bao.mount, "kv");
        assert_eq!(bao.prefix, "factory/router");
        assert!(
            matches!(bao.method, openbao::Auth::AppRole { ref mount, .. } if mount == "approle")
        );
        assert!(matches!(settings.classifier, Classifier::Pooled { .. }));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn defaults_and_refusals() {
        let settings = Settings::load(None, |_| None).unwrap();
        assert_eq!(settings.listen, "127.0.0.1:8790");
        assert_eq!(settings.storage, None);
        assert!(settings.openbao.is_none());
        assert_eq!(settings.policy_mode, Mode::Adaptive);
        assert_eq!(settings.drain_timeout, Duration::from_secs(100));
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.to_string())
            }
        };
        assert!(Settings::load(None, env(&[("MUNIMENT_ROUTER_POLICY_MODE", "fast")])).is_err());
        assert!(Settings::load(None, env(&[("MUNIMENT_ROUTER_OPENBAO_ADDR", "x")])).is_ok());
        assert!(Settings::load(
            None,
            env(&[("MUNIMENT_ROUTER_OPENBAO_ADDRESS", "https://bao")])
        )
        .is_err());
        assert!(Settings::load(
            None,
            env(&[("MUNIMENT_ROUTER_CLASSIFIER_KIND", "typesafe")])
        )
        .is_err());
        assert!(Settings::load(None, env(&[("MUNIMENT_ROUTER_DRAIN_TIMEOUT_S", "soon")])).is_err());
        let files = Settings::load(None, env(&[("MUNIMENT_ROUTER_STATE_DIR", "/tmp/r")])).unwrap();
        assert_eq!(files.storage, Some(Storage::Files("/tmp/r".into())));
        assert_eq!(
            variable("openbao.role_id"),
            "MUNIMENT_ROUTER_OPENBAO_ROLE_ID"
        );
    }
}
