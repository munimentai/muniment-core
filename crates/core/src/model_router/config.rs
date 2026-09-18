//! The router's own record: the account pools, the routes, and the classifier.
//!
//! Pi's `auth.json` holds one credential per provider id, so a second account
//! of one family cannot live there. The router keeps its pools in this file
//! beside it, at the same `0600`, and serves them as one Pi provider.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::family::{family, Family};

/// The router's record in the agent directory.
pub const CONFIG_FILE: &str = "muniment-router.json";
/// The Pi provider id the router answers as.
pub const ROUTER_PROVIDER: &str = "muniment-router";
/// The model id that stands for "let the classifier pick".
pub const AUTO_MODEL: &str = "auto";
/// Below this confidence the router takes the fallback route.
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.6;

/// How an account proves itself to its upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credential {
    /// An API key the user pasted.
    ApiKey { key: String },
    /// An account sign-in: the token the harness's own flow returned.
    OAuth {
        access: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh: Option<String>,
        /// Unix milliseconds. `None` is a token that never expires.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_ms: Option<i64>,
    },
}

impl Credential {
    /// The bearer value an upstream request carries, when one is ready.
    pub fn bearer(&self) -> &str {
        match self {
            Self::ApiKey { key } => key,
            Self::OAuth { access, .. } => access,
        }
    }

    /// The tag Settings shows, `Key` or `Account`.
    pub fn source(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "key",
            Self::OAuth { .. } => "account",
        }
    }
}

/// One credential in a family's pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Stable across renames. The ledger keys its counters on it.
    pub id: String,
    /// The family this account belongs to, an id from the family table.
    pub family: String,
    /// The name Settings shows, the user's own words.
    pub label: String,
    pub credential: Credential,
    /// An upstream that replaces the family's own, for a gateway or a region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The models this account serves. Empty means every model of its family.
    #[serde(default)]
    pub models: Vec<String>,
    /// A disabled account takes no turn and keeps its counters.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The share of the round this account takes. Zero is the same as disabled.
    #[serde(default = "one")]
    pub weight: u32,
}

fn yes() -> bool {
    true
}

fn one() -> u32 {
    1
}

impl Account {
    /// The upstream this account calls.
    pub fn upstream(&self) -> Option<String> {
        let default = family(&self.family)?.base_url;
        Some(
            self.base_url
                .as_deref()
                .filter(|url| !url.trim().is_empty())
                .unwrap_or(default)
                .trim_end_matches('/')
                .to_owned(),
        )
    }

    /// The family record, when the id names one the router knows.
    pub fn family(&self) -> Option<Family> {
        family(&self.family)
    }

    /// Whether this account may answer for `model`.
    pub fn serves(&self, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|known| known == model)
    }
}

/// The query classifier that picks a route. Routing is optional, so a
/// configuration with no classifier still balances across the pool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Classifier {
    /// No classification. Every turn takes the fallback route.
    #[default]
    None,
    /// TypeSafe's System One model answers one `choice` question per turn.
    Typesafe {
        api_key: String,
        #[serde(default = "typesafe_model")]
        model: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_url: Option<String>,
    },
    /// A small model on one of the router's own accounts, asked for the same
    /// choice as one JSON answer. It spends the account, not a second bill.
    Pooled { family: String, model: String },
    /// Any endpoint that answers the same `choice` question shape.
    Endpoint {
        base_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_key: Option<String>,
        #[serde(default = "typesafe_model")]
        model: String,
    },
}

fn typesafe_model() -> String {
    "jev-latest".to_owned()
}

impl Classifier {
    /// The tag Settings shows.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Typesafe { .. } => "typesafe",
            Self::Pooled { .. } => "pooled",
            Self::Endpoint { .. } => "endpoint",
        }
    }

    /// Whether this classifier can answer a question.
    pub fn ready(&self) -> bool {
        match self {
            Self::None => false,
            Self::Typesafe { api_key, .. } => !api_key.trim().is_empty(),
            Self::Pooled { family, model } => {
                super::family::family(family).is_some() && !model.trim().is_empty()
            }
            Self::Endpoint { base_url, .. } => !base_url.trim().is_empty(),
        }
    }

    /// The model name the composer shows beside the router.
    pub fn model(&self) -> &str {
        match self {
            Self::None => "",
            Self::Typesafe { model, .. }
            | Self::Pooled { model, .. }
            | Self::Endpoint { model, .. } => model,
        }
    }
}

/// One destination the classifier may pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// The option name the classifier returns.
    pub key: String,
    /// What this route is for, in the user's words. The classifier reads it.
    pub description: String,
    /// The family that serves this route.
    pub family: String,
    /// The model that serves this route.
    pub model: String,
}

/// The whole router record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RouterConfig {
    /// Off keeps every turn on Pi's own provider and starts no listener.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub classifier: Classifier,
    #[serde(default)]
    pub routes: Vec<Route>,
    /// The route a turn takes when no classifier answers or confidence is low.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
    #[serde(default = "default_confidence")]
    pub min_confidence: f64,
}

fn default_confidence() -> f64 {
    DEFAULT_MIN_CONFIDENCE
}

impl RouterConfig {
    /// Every account of one family, in configured order.
    pub fn pool(&self, family: &str) -> Vec<&Account> {
        self.accounts
            .iter()
            .filter(|account| account.family == family)
            .collect()
    }

    /// The account with this id.
    pub fn account(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|account| account.id == id)
    }
}

/// The router record inside an agent directory.
pub fn config_path(agent: &Path) -> PathBuf {
    agent.join(CONFIG_FILE)
}

/// Reads the record, or the default when no record exists yet.
pub fn load(agent: &Path) -> io::Result<RouterConfig> {
    match fs::read(config_path(agent)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(RouterConfig::default()),
        Err(error) => Err(error),
    }
}

/// Replaces the record. The file holds credentials, so it is written `0600`
/// and only ever replaced whole.
pub fn save(agent: &Path, config: &RouterConfig) -> io::Result<()> {
    fs::create_dir_all(agent)?;
    let path = config_path(agent);
    let bytes = serde_json::to_vec_pretty(config)?;
    write_private(&path, &bytes)
}

/// Writes `bytes` to `path` through a `0600` temporary and one atomic replace.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| crate::atomic_file::replace(&temporary, path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_account(id: &str, family: &str) -> Account {
        Account {
            id: id.to_owned(),
            family: family.to_owned(),
            label: format!("{family} {id}"),
            credential: Credential::ApiKey {
                key: format!("sk-{id}"),
            },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 1,
        }
    }

    #[test]
    fn an_absent_record_reads_as_the_off_default() {
        let agent = tempdir();
        let config = load(&agent).unwrap();
        assert!(!config.enabled);
        assert!(config.accounts.is_empty());
        assert_eq!(config.classifier, Classifier::None);
        assert!(!config.classifier.ready());
    }

    #[test]
    fn a_saved_record_reads_back_whole_and_stays_private() {
        let agent = tempdir();
        let config = RouterConfig {
            enabled: true,
            accounts: vec![key_account("a1", "openai"), key_account("a2", "openai")],
            classifier: Classifier::Typesafe {
                api_key: "apikey_1".into(),
                model: "jev-latest".into(),
                base_url: None,
            },
            routes: vec![
                Route {
                    key: "fast".into(),
                    description: "A short question".into(),
                    family: "openai".into(),
                    model: "gpt-5.6-mini".into(),
                },
                Route {
                    key: "deep".into(),
                    description: "A long reasoning task".into(),
                    family: "anthropic".into(),
                    model: "claude-opus-5".into(),
                },
            ],
            fallback: Some("fast".into()),
            min_confidence: 0.6,
        };
        save(&agent, &config).unwrap();
        assert_eq!(load(&agent).unwrap(), config);
        assert!(config.classifier.ready());
        assert_eq!(config.pool("openai").len(), 2);
        assert_eq!(config.pool("kimi").len(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(config_path(&agent))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn an_account_takes_its_family_upstream_until_it_names_one() {
        let mut account = key_account("a1", "xai");
        assert_eq!(account.upstream().as_deref(), Some("https://api.x.ai/v1"));
        account.base_url = Some("http://127.0.0.1:8317/v1/".into());
        assert_eq!(
            account.upstream().as_deref(),
            Some("http://127.0.0.1:8317/v1")
        );
        account.family = "nobody".into();
        assert_eq!(account.upstream(), None);
    }

    #[test]
    fn an_empty_model_list_serves_every_model_of_the_family() {
        let mut account = key_account("a1", "openai");
        assert!(account.serves("gpt-5.6"));
        account.models = vec!["gpt-5.6-mini".into()];
        assert!(account.serves("gpt-5.6-mini"));
        assert!(!account.serves("gpt-5.6"));
    }

    #[test]
    fn a_classifier_with_no_key_is_never_ready() {
        let blank = Classifier::Typesafe {
            api_key: "  ".into(),
            model: "jev-latest".into(),
            base_url: None,
        };
        assert!(!blank.ready());
        let keyed = Classifier::Typesafe {
            api_key: "apikey_1".into(),
            model: "jev-latest".into(),
            base_url: None,
        };
        assert!(keyed.ready());
        assert!(!Classifier::Endpoint {
            base_url: " ".into(),
            api_key: None,
            model: "m".into(),
        }
        .ready());
        assert!(!Classifier::Pooled {
            family: "nobody".into(),
            model: "m".into(),
        }
        .ready());
    }

    fn tempdir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("muniment-router-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
