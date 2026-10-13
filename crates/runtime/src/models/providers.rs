//! Settings → Models, the provider half: keys and accounts in Pi's
//! `auth.json`, endpoints in Pi's `models.json`, the default model in Pi's
//! `settings.json`, the hidden and shown lists, Claude Code, and the inventory
//! the picker reads.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use muniment_core::engine::{PiModelRow, PiRpcEngine};
use muniment_core::model_router::config::ROUTER_PROVIDER;
use muniment_core::models::pi_models::{
    self, decision_models, read_record as read_models_record, saved_endpoint_key, valid_identifier,
    write_record as write_models_record,
};
use muniment_core::models::registry::{
    self, CLAUDE_BRIDGE_PROVIDER, LM_STUDIO_PROVIDER, OLLAMA_PROVIDER, STATUS_PROVIDERS,
};
use muniment_core::pi_settings::merge_pi_settings;
use muniment_core::serde_json;
use muniment_core::sidecar::pi_install::PI_SELECTED_ARTIFACT;

pub(super) const READ_SETTINGS_ERROR: &str = pi_models::READ_ERROR;
pub(super) const SAVE_SETTINGS_ERROR: &str = pi_models::SAVE_ERROR;

pub(super) type PiAuthLock = pi_models::FileLock;

#[derive(Debug, Serialize)]
pub(super) struct ProviderStatus {
    provider: &'static str,
    configured: bool,
}

const CLAUDE_BRIDGE_CONFIG_FILE: &str = "claude-bridge.json";
/// How many candidates a connect probes before it settles.
const PROBE_LIMIT: usize = 5;
const CLAUDE_STATUS_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct InventoryModel {
    id: String,
    context: String,
    max_out: String,
    thinking: bool,
    images: bool,
}

impl From<&PiModelRow> for InventoryModel {
    fn from(row: &PiModelRow) -> Self {
        Self {
            id: row.id.clone(),
            context: row.context.clone(),
            max_out: row.max_out.clone(),
            thinking: row.thinking,
            images: row.images,
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct InventoryProvider {
    id: String,
    name: String,
    /// `key`, `account`, `local`, `custom` or `claude-code`.
    source: &'static str,
    base_url: Option<String>,
    models: Vec<InventoryModel>,
    /// The decision models the server reported. They answer on its System One
    /// route, so the classifier list offers them and the chat picker does not.
    decision_models: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct ProviderInventory {
    providers: Vec<InventoryProvider>,
    default_provider: Option<String>,
    default_model: Option<String>,
    hidden: Vec<String>,
    /// The models the user turned on. The newest model of each family is on
    /// until turned off, and an older model is off until turned on here.
    shown: Vec<String>,
    /// The classifier model that picks a route per turn, when the router runs
    /// one. The composer's picker puts the router first and names it.
    router_classifier: Option<String>,
    /// Every model the router serves, with the family and model it stands for
    /// and how many accounts stand behind it. The picker lists each under its
    /// provider once and marks the ones two or more accounts serve, because
    /// picking one of those balances across them.
    router_models: Vec<RouterModel>,
}

/// One model the router serves, as the picker places it under its provider.
#[derive(Debug, Serialize, PartialEq)]
pub(super) struct RouterModel {
    /// The id the router serves it as: `family/model`, or the user's name.
    id: String,
    family: String,
    model: String,
    accounts: u32,
    /// The model's context window in tokens, when the router knows it.
    context_window: Option<u64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct ClaudeCodeStatus {
    pub(super) installed: bool,
    pub(super) logged_in: bool,
    path: Option<String>,
}

pub(super) fn lock_pi_auth_file(auth_file: &Path) -> Result<PiAuthLock, String> {
    pi_models::lock(auth_file).map_err(|_| SAVE_SETTINGS_ERROR.into())
}

pub(super) fn pi_auth_file(agent: &Path) -> PathBuf {
    agent.join("auth.json")
}

pub(super) fn pi_models_file(agent: &Path) -> PathBuf {
    pi_models::models_file(agent)
}

fn pi_settings_file(models_file: &Path) -> PathBuf {
    models_file.with_file_name("settings.json")
}

fn read_json_store(
    path: &Path,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        match parent.try_exists() {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(_) => return Err(READ_SETTINGS_ERROR.into()),
        }
    }
    let _lock = lock_pi_auth_file(path).map_err(|_| READ_SETTINGS_ERROR.to_string())?;
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(READ_SETTINGS_ERROR.into()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| READ_SETTINGS_ERROR.to_string())
}

pub(super) fn provider_status(agent: &Path) -> Result<Vec<ProviderStatus>, String> {
    provider_status_in(&pi_auth_file(agent), &pi_models_file(agent))
}

fn provider_status_in(auth_file: &Path, models_file: &Path) -> Result<Vec<ProviderStatus>, String> {
    let auth = read_json_store(auth_file)?;
    let models = read_json_store(models_file)?;
    Ok(STATUS_PROVIDERS
        .iter()
        .map(|provider| {
            let configured = if *provider == OLLAMA_PROVIDER {
                models
                    .as_ref()
                    .and_then(|root| root.get("providers"))
                    .and_then(serde_json::Value::as_object)
                    .and_then(|providers| providers.get(*provider))
                    .is_some_and(serde_json::Value::is_object)
            } else {
                auth.as_ref()
                    .and_then(|entries| entries.get(*provider))
                    .is_some_and(serde_json::Value::is_object)
            };
            ProviderStatus {
                provider,
                configured,
            }
        })
        .collect())
}

fn store_provider_key(
    auth_file: &Path,
    provider: &str,
    key: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    if registry::key_provider_name(provider).is_none()
        || key.is_empty()
        || key.len() > 16 * 1024
        || key.trim() != key
    {
        return Err("Enter a valid provider and API key.".into());
    }
    let names = registry::key_settings(provider);
    if env.keys().any(|name| !names.contains(&name.as_str()))
        || names.iter().any(|name| {
            env.get(*name).is_none_or(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            })
        })
    {
        return Err("Enter the account details this provider needs.".into());
    }
    let parent = auth_file
        .parent()
        .ok_or_else(|| SAVE_SETTINGS_ERROR.to_string())?;
    fs::create_dir_all(parent).map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
    if !auth_file.exists() {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options
            .open(auth_file)
            .and_then(|mut file| file.write_all(b"{}"))
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(SAVE_SETTINGS_ERROR.into()),
        }
    }
    let _lock = lock_pi_auth_file(auth_file)?;
    let mut auth = match fs::read(auth_file) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&bytes)
            .map_err(|_| SAVE_SETTINGS_ERROR.to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::Map::new(),
        Err(_) => return Err(SAVE_SETTINGS_ERROR.into()),
    };
    let mut credential = serde_json::json!({"type": "api_key", "key": key});
    if !env.is_empty() {
        credential["env"] = serde_json::json!(env);
    }
    auth.insert(provider.to_owned(), credential);
    let bytes = serde_json::to_vec_pretty(&auth).map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
    let temporary = auth_file.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        muniment_core::atomic_file::replace(&temporary, auth_file)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| SAVE_SETTINGS_ERROR.into())
}

/// Saves a provider key and, when Pi names no default yet, adopts the
/// provider's largest-context model.
pub(super) fn store_key(
    agent: &Path,
    engine: &PiRpcEngine,
    provider: &str,
    key: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    store_provider_key(&pi_auth_file(agent), provider, key, env)?;
    if default_model_unset(agent) {
        let _ = adopt_provider_default(agent, engine, provider, false);
    }
    Ok(())
}

/// The key saved with an endpoint, only for a URL on that endpoint, so a
/// decision model on the server receives the key its chat models use and no
/// other host does.
pub(super) fn endpoint_key_for(models_file: &Path, provider: &str, url: &str) -> Option<String> {
    let root: serde_json::Value = serde_json::from_slice(&fs::read(models_file).ok()?).ok()?;
    let base = root["providers"][provider]["baseUrl"]
        .as_str()?
        .trim_end_matches('/');
    let rest = url.strip_prefix(base)?;
    (rest.is_empty() || rest.starts_with('/'))
        .then(|| saved_endpoint_key(models_file, provider))
        .flatten()
}

/// Saves an Ollama server and makes its default model Pi's default.
pub(super) fn store_local_provider(agent: &Path, base_url: &str, key: &str) -> Result<(), String> {
    store_local_provider_in(&pi_models_file(agent), base_url, key)
}

fn store_local_provider_in(models_file: &Path, base_url: &str, key: &str) -> Result<(), String> {
    let agent = models_file
        .parent()
        .ok_or_else(|| SAVE_SETTINGS_ERROR.to_string())?;
    pi_models::store_ollama(agent, base_url, key, |model| {
        let settings_file = pi_settings_file(models_file);
        let settings_lock = muniment_core::pi_settings::lock_settings(&settings_file)
            .map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
        let mut settings = read_json_for_update(&settings_file)?;
        settings.insert("defaultProvider".to_owned(), OLLAMA_PROVIDER.into());
        settings.insert("defaultModel".to_owned(), model.into());
        merge_pi_settings(&mut settings, PI_SELECTED_ARTIFACT);
        settings_lock
            .check()
            .map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
        write_json_for_update(&settings_file, &settings)
    })
}

/// Saves a named endpoint and answers its provider id. When Pi names no
/// default yet, the endpoint's first model becomes it.
pub(super) fn store_endpoint(
    agent: &Path,
    engine: &PiRpcEngine,
    kind: &str,
    name: &str,
    base_url: &str,
    key: &str,
    models: &[String],
) -> Result<String, String> {
    let provider = pi_models::store_endpoint(agent, kind, name, base_url, key, models)?;
    if default_model_unset(agent) {
        let _ = adopt_provider_default(agent, engine, &provider, false);
    }
    Ok(provider)
}

pub(super) fn read_json_for_update(
    path: &Path,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    pi_models::read_json(path).map_err(|_| SAVE_SETTINGS_ERROR.to_string())
}

pub(super) fn write_json_for_update(
    path: &Path,
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    pi_models::write_json(path, root).map_err(|_| SAVE_SETTINGS_ERROR.to_string())
}

fn claude_bridge_config_file(agent: &Path) -> PathBuf {
    agent.join(CLAUDE_BRIDGE_CONFIG_FILE)
}

fn record_strings(record: &serde_json::Map<String, serde_json::Value>, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn provider_display_name(
    provider: &str,
    record: &serde_json::Map<String, serde_json::Value>,
) -> String {
    if let Some(name) = record
        .get("names")
        .and_then(serde_json::Value::as_object)
        .and_then(|names| names.get(provider))
        .and_then(serde_json::Value::as_str)
    {
        return name.to_owned();
    }
    registry::display_name(provider)
        .map(str::to_owned)
        .unwrap_or_else(|| provider.to_owned())
}

fn run_with_timeout(
    mut command: std::process::Command,
    timeout: Duration,
) -> Option<std::process::Output> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(command.output());
    });
    receiver.recv_timeout(timeout).ok().and_then(Result::ok)
}

/// Refresh provider catalogs under the same locks used for settings. Network
/// failures leave both the last catalog and explicit model overrides intact.
fn refresh_provider_models(
    agent: &Path,
    known: &[PiModelRow],
    force: bool,
) -> Result<bool, String> {
    use muniment_core::{
        model_router::{config::Credential, native_auth},
        provider_models,
    };
    static REFRESH: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = REFRESH.lock().unwrap_or_else(|error| error.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let mut cache = provider_models::load(agent);
    let auth_file = pi_auth_file(agent);
    let auth = read_json_store(&auth_file)?.unwrap_or_default();
    let mut discovered = Vec::new();
    for (provider, entry) in &auth {
        let oauth = entry["type"] == "oauth";
        if provider_models::endpoint(provider, oauth).is_none() {
            continue;
        }
        let cache_key = format!("provider:{provider}");
        let fresh = cache
            .get(&cache_key)
            .is_some_and(|c| now >= c.checked_ms && now - c.checked_ms < provider_models::TTL_MS);
        if force || !fresh {
            // Refresh a supported subscription before listing models. Re-read
            // and compare under the auth lock so a concurrent sign-in survives.
            let mut current = entry.clone();
            if let Some(credential) = Credential::from_pi_auth(provider, entry) {
                // A subscription copied into the pool shares its refresh token.
                // Let the pool rotate it once, then mirror it to the provider slot.
                let pooled = muniment_core::model_router::config::load(agent)
                    .ok()
                    .and_then(|config| {
                        config.accounts.into_iter().find(|account| {
                            matches!(&account.credential,
                        Credential::Subscription { provider: p, access, refresh, .. }
                        if p == provider && (entry["access"] == *access || refresh.as_deref().is_some_and(|r| entry["refresh"] == r)))
                        })
                    });
                let refreshed = if let Some(account) = pooled {
                    Some(
                        native_auth::refresh_account(agent, &account.id, now, DISCOVERY_TIMEOUT)
                            .map(|a| a.credential),
                    )
                } else {
                    native_auth::refresh_if_expiring(&credential, now, DISCOVERY_TIMEOUT)
                };
                if let Some(Ok(Credential::Subscription {
                    access,
                    refresh,
                    expires_ms,
                    ..
                })) = refreshed
                {
                    let _lock = lock_pi_auth_file(&auth_file)?;
                    let mut latest = read_json_for_update(&auth_file)?;
                    if latest.get(provider) == Some(entry) {
                        current["access"] = access.into();
                        if let Some(refresh) = refresh {
                            current["refresh"] = refresh.into();
                        }
                        if let Some(expires) = expires_ms {
                            current["expires"] = expires.into();
                        }
                        latest.insert(provider.clone(), current.clone());
                        write_json_for_update(&auth_file, &latest)?;
                    } else {
                        current = latest.get(provider).cloned().unwrap_or_default();
                    }
                }
            }
            if let Some(token) = current
                .get(if oauth { "access" } else { "key" })
                .and_then(serde_json::Value::as_str)
                .filter(|v| !v.is_empty())
            {
                if let Some(models) =
                    provider_models::discover(provider, oauth, token, DISCOVERY_TIMEOUT)
                {
                    cache.insert(
                        cache_key.clone(),
                        provider_models::Catalog {
                            checked_ms: now,
                            models,
                        },
                    );
                }
            }
        }
        if let Some(catalog) = cache.get(&cache_key) {
            let models: Vec<_> = catalog
                .models
                .iter()
                .filter(|model| {
                    !known
                        .iter()
                        .any(|row| &row.provider == provider && model["id"] == row.id)
                })
                .cloned()
                .collect();
            discovered.push((provider.clone(), models));
        }
    }
    // Pool accounts can use a different credential from the provider slot.
    if let Ok(config) = muniment_core::model_router::config::load(agent) {
        for account in config
            .accounts
            .iter()
            .filter(|a| a.enabled && a.base_url.is_none())
        {
            let oauth = matches!(account.credential, Credential::Subscription { .. });
            if provider_models::endpoint(&account.family, oauth).is_none() {
                continue;
            }
            let key = format!("account:{}", account.id);
            if !force
                && cache.get(&key).is_some_and(|c| {
                    now >= c.checked_ms && now - c.checked_ms < provider_models::TTL_MS
                })
            {
                continue;
            }
            let Ok(account) =
                native_auth::refresh_account(agent, &account.id, now, DISCOVERY_TIMEOUT)
            else {
                continue;
            };
            let token = match &account.credential {
                Credential::ApiKey { key } => key,
                Credential::Subscription { access, .. } => access,
            };
            if let Some(models) =
                provider_models::discover(&account.family, oauth, token, DISCOVERY_TIMEOUT)
            {
                cache.insert(
                    key,
                    provider_models::Catalog {
                        checked_ms: now,
                        models,
                    },
                );
            }
        }
    }
    provider_models::save(agent, &cache).map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
    pi_models::merge_discovered(agent, &discovered, |root| {
        let (Some(endpoint), Ok(config)) = (
            muniment_core::model_router::server::read_endpoint(agent),
            muniment_core::model_router::config::load(agent),
        ) else {
            return false;
        };
        if !config.enabled {
            return false;
        }
        let before = root
            .get("providers")
            .and_then(|p| p.get(ROUTER_PROVIDER))
            .cloned();
        muniment_core::model_router::pi_provider::register(root, &endpoint, &config);
        before.as_ref() != root.get("providers").and_then(|p| p.get(ROUTER_PROVIDER))
    })
}

/// Everything the picker and Settings read about providers: the endpoint
/// discovery and Pi's model list run side by side, so the page waits for the
/// slower one, not both. A changed endpoint list relists once, so the
/// inventory reads what the server serves now.
pub(super) fn inventory(
    agent: &Path,
    engine: &PiRpcEngine,
    force: bool,
) -> Result<ProviderInventory, String> {
    let discovery_agent = agent.to_path_buf();
    let discovery = std::thread::spawn(move || pi_models::refresh_endpoints(&discovery_agent));
    let mut models = engine.list_models();
    let provider_changed = refresh_provider_models(agent, &models, force).unwrap_or(false);
    if discovery.join().ok().and_then(Result::ok) == Some(true) || provider_changed {
        models = engine.list_models();
    }
    let mut inventory = provider_inventory(agent, &models)?;
    adopt_shown_default(agent, &mut inventory);
    Ok(inventory)
}

fn provider_inventory(agent: &Path, models: &[PiModelRow]) -> Result<ProviderInventory, String> {
    let auth = read_json_store(&pi_auth_file(agent))?.unwrap_or_default();
    let models_file = read_json_store(&pi_models_file(agent))?.unwrap_or_default();
    let settings = read_json_store(&pi_settings_file(&pi_models_file(agent)))?.unwrap_or_default();
    let record = read_models_record(agent)?;
    let mut providers: Vec<InventoryProvider> = Vec::new();
    for (provider, entry) in auth.iter().filter(|(_, entry)| entry.is_object()) {
        let source = if entry.get("type").and_then(serde_json::Value::as_str) == Some("oauth") {
            "account"
        } else {
            "key"
        };
        providers.push(InventoryProvider {
            id: provider.clone(),
            name: provider_display_name(provider, &record),
            source,
            base_url: None,
            models: Vec::new(),
            decision_models: Vec::new(),
        });
    }
    if let Some(endpoints) = models_file
        .get("providers")
        .and_then(serde_json::Value::as_object)
    {
        for (provider, entry) in endpoints.iter().filter(|(_, entry)| entry.is_object()) {
            if providers.iter().any(|known| known.id == *provider) {
                continue;
            }
            let source = if provider == ROUTER_PROVIDER {
                "router"
            } else if provider == OLLAMA_PROVIDER || provider == LM_STUDIO_PROVIDER {
                "local"
            } else {
                "custom"
            };
            providers.push(InventoryProvider {
                id: provider.clone(),
                name: provider_display_name(provider, &record),
                source,
                base_url: entry
                    .get("baseUrl")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                // Endpoint discovery is available before the first chat installs Pi.
                // Keep its model names available while the CLI catalog is absent.
                models: entry
                    .get("models")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|model| model.get("id").and_then(serde_json::Value::as_str))
                    .filter(|id| !id.trim().is_empty())
                    .map(|id| InventoryModel {
                        id: id.to_owned(),
                        context: String::new(),
                        max_out: String::new(),
                        thinking: false,
                        images: false,
                    })
                    .collect(),
                decision_models: decision_models(&record, provider),
            });
        }
    }
    if record
        .get("claudeCode")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        providers.push(InventoryProvider {
            id: CLAUDE_BRIDGE_PROVIDER.into(),
            name: provider_display_name(CLAUDE_BRIDGE_PROVIDER, &record),
            source: "claude-code",
            base_url: None,
            models: Vec::new(),
            decision_models: Vec::new(),
        });
    }
    for row in models {
        if let Some(known) = providers.iter_mut().find(|known| known.id == row.provider) {
            let model = InventoryModel::from(row);
            if let Some(existing) = known.models.iter_mut().find(|entry| entry.id == model.id) {
                *existing = model;
            } else {
                known.models.push(model);
            }
        }
    }
    Ok(ProviderInventory {
        providers,
        default_provider: settings
            .get("defaultProvider")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        default_model: settings
            .get("defaultModel")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        hidden: record_strings(&record, "hidden"),
        shown: record_strings(&record, "shown"),
        router_classifier: router_classifier(agent),
        router_models: router_models(agent),
    })
}

/// The models the router serves and the accounts behind each: the accounts
/// that balance together on it, its family's subscriptions while any can serve
/// it, else its keys. An overflow key never counts. Empty while the router is
/// off.
fn router_models(agent: &Path) -> Vec<RouterModel> {
    use muniment_core::model_router::all_options;
    let Ok(config) = muniment_core::model_router::config::load(agent) else {
        return Vec::new();
    };
    if !config.enabled {
        return Vec::new();
    }
    // The hidden ones too: the picker hides them, and Settings turns them back on.
    all_options(&config)
        .into_iter()
        .map(|option| {
            let accounts = muniment_core::model_router::balance::balanced(
                &config,
                &option.family,
                &option.model,
            )
            .len() as u32;
            let context_window = muniment_core::model_router::policy::model(&config, &option)
                .map(|model| model.context)
                .filter(|context| *context > 0);
            RouterModel {
                id: option.key,
                family: option.family,
                model: option.model,
                accounts,
                context_window,
            }
        })
        .collect()
}

/// The classifier the router picks routes with, when it is on and ready. A
/// router with no classifier still balances its pools, so it names none.
fn router_classifier(agent: &Path) -> Option<String> {
    use muniment_core::model_router::{classifies, options};
    let config = muniment_core::model_router::config::load(agent).ok()?;
    if !config.enabled || !classifies(&config, &options(&config)) {
        return None;
    }
    let model = config.classifier.model();
    (!model.is_empty()).then(|| model.to_owned())
}

pub(super) fn set_default_model(agent: &Path, provider: &str, model: &str) -> Result<(), String> {
    if !valid_identifier(provider, 128) || !valid_identifier(model, 512) {
        return Err("Choose a provider and a model.".into());
    }
    save_default_model(agent, provider, model).map_err(|_| SAVE_SETTINGS_ERROR.to_string())
}

fn save_default_model(agent: &Path, provider: &str, model: &str) -> std::io::Result<()> {
    let settings_file = pi_settings_file(&pi_models_file(agent));
    fs::create_dir_all(agent)?;
    let lock = muniment_core::pi_settings::lock_settings(&settings_file)?;
    let mut settings = pi_models::read_json(&settings_file)?;
    settings.insert("defaultProvider".into(), provider.into());
    settings.insert("defaultModel".into(), model.into());
    merge_pi_settings(&mut settings, PI_SELECTED_ARTIFACT);
    lock.check()?;
    pi_models::write_json(&settings_file, &settings)
}

/// Whether Pi's settings name no default model yet.
fn default_model_unset(agent: &Path) -> bool {
    read_json_store(&pi_settings_file(&pi_models_file(agent)))
        .ok()
        .flatten()
        .and_then(|settings| {
            settings
                .get("defaultProvider")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_none()
}

/// A context column from Pi's model table, `128K` or `1M`, as a token count.
fn context_tokens(context: &str) -> u64 {
    let digits: String = context
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let value: f64 = digits.parse().unwrap_or(0.0);
    let scale = match context.chars().last() {
        Some('K') | Some('k') => 1_000.0,
        Some('M') | Some('m') => 1_000_000.0,
        _ => 1.0,
    };
    (value * scale) as u64
}

/// The models a just-connected provider may start on, largest context first and
/// list order on a tie. The list is Pi's, so a narrow tuned variant that leads
/// it alphabetically never wins over the provider's general model.
fn adoption_candidates<'a>(models: &'a [PiModelRow], provider: &str) -> Vec<&'a str> {
    let mut candidates: Vec<&PiModelRow> = models
        .iter()
        .filter(|row| row.provider == provider)
        .collect();
    candidates.sort_by_key(|model| std::cmp::Reverse(context_tokens(&model.context)));
    candidates
        .into_iter()
        .map(|model| model.id.as_str())
        .collect()
}

/// Makes a just-connected provider's model the default, so the composer sends
/// to it without a second trip through Settings. With `probe`, the candidates
/// are tried in turn and the first that answers wins.
pub(super) fn adopt_provider_default(
    agent: &Path,
    engine: &PiRpcEngine,
    provider: &str,
    probe: bool,
) -> Result<(), String> {
    let models = engine.list_models();
    let candidates = adoption_candidates(&models, provider);
    let Some(first) = candidates.first() else {
        return Err("No model answers for this provider yet.".into());
    };
    let chosen = if probe {
        candidates
            .iter()
            .take(PROBE_LIMIT)
            .find(|model| engine.model_answers(provider, model))
            .unwrap_or(first)
    } else {
        first
    };
    set_default_model(agent, provider, chosen)
}

/// The chip names the saved default when it is shown, else the first shown
/// model. Pi picks its own fallback when its settings name none, so a run could
/// answer from a model the chip never named. The first shown model becomes the
/// saved default here, so the chip and the run agree.
fn adopt_shown_default(agent: &Path, inventory: &mut ProviderInventory) {
    let hidden = |provider: &str, model: &str| {
        inventory
            .hidden
            .iter()
            .any(|key| key == &format!("{provider}/{model}"))
    };
    let saved_shown =
        match (&inventory.default_provider, &inventory.default_model) {
            (Some(provider), Some(model)) => {
                inventory.providers.iter().any(|group| {
                    &group.id == provider && group.models.iter().any(|m| &m.id == model)
                }) && !hidden(provider, model)
            }
            _ => false,
        };
    if saved_shown {
        return;
    }
    let first = inventory.providers.iter().find_map(|group| {
        group
            .models
            .iter()
            .find(|model| !hidden(&group.id, &model.id))
            .map(|model| (group.id.clone(), model.id.clone()))
    });
    let Some((provider, model)) = first else {
        return;
    };
    if set_default_model(agent, &provider, &model).is_ok() {
        inventory.default_provider = Some(provider);
        inventory.default_model = Some(model);
    }
}

pub(super) fn set_model_hidden(
    agent: &Path,
    provider: &str,
    model: &str,
    hidden: bool,
) -> Result<(), String> {
    if !valid_identifier(provider, 128) || !valid_identifier(model, 512) {
        return Err("Choose a provider and a model.".into());
    }
    let key = format!("{provider}/{model}");
    let mut record = read_models_record(agent)?;
    // A model sits on one list at most: off on the hidden list, on on the shown list.
    for (name, add) in [("hidden", hidden), ("shown", !hidden)] {
        let mut list = record_strings(&record, name);
        list.retain(|entry| *entry != key);
        if add {
            list.push(key.clone());
        }
        record.insert(name.into(), list.into());
    }
    write_models_record(agent, &record)
}

fn remove_json_entry(path: &Path, key: &str) -> Result<(), String> {
    let _lock = lock_pi_auth_file(path).map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
    let mut root = read_json_for_update(path)?;
    let mut changed = root.remove(key).is_some();
    if let Some(providers) = root
        .get_mut("providers")
        .and_then(serde_json::Value::as_object_mut)
    {
        changed |= providers.remove(key).is_some();
    }
    if changed {
        write_json_for_update(path, &root)?;
    }
    Ok(())
}

pub(super) fn disconnect_provider(agent: &Path, provider: &str) -> Result<(), String> {
    if !valid_identifier(provider, 128) {
        return Err("Choose a provider.".into());
    }
    if provider == CLAUDE_BRIDGE_PROVIDER {
        let mut record = read_models_record(agent)?;
        record.insert("claudeCode".into(), false.into());
        write_models_record(agent, &record)?;
        match fs::remove_file(claude_bridge_config_file(agent)) {
            Ok(()) | Err(_) => {}
        }
    } else {
        if pi_auth_file(agent).is_file() {
            remove_json_entry(&pi_auth_file(agent), provider)?;
        }
        if pi_models_file(agent).is_file() {
            remove_json_entry(&pi_models_file(agent), provider)?;
        }
    }
    let settings_file = pi_settings_file(&pi_models_file(agent));
    if settings_file.is_file() {
        let lock = muniment_core::pi_settings::lock_settings(&settings_file)
            .map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
        let mut settings = read_json_for_update(&settings_file)?;
        if settings
            .get("defaultProvider")
            .and_then(serde_json::Value::as_str)
            == Some(provider)
        {
            settings.remove("defaultProvider");
            settings.remove("defaultModel");
            merge_pi_settings(&mut settings, PI_SELECTED_ARTIFACT);
            lock.check().map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
            write_json_for_update(&settings_file, &settings)?;
        }
    }
    Ok(())
}

fn claude_code_executable() -> Option<PathBuf> {
    let home = muniment_core::state_root::home_directory_value().map(PathBuf::from);
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(paths) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&paths).map(|dir| dir.join("claude")));
    }
    if let Some(home) = &home {
        candidates.push(home.join(".local").join("bin").join("claude"));
        candidates.push(home.join(".claude").join("local").join("claude"));
    }
    candidates.push(PathBuf::from("/opt/homebrew/bin/claude"));
    candidates.push(PathBuf::from("/usr/local/bin/claude"));
    candidates.into_iter().find(|path| path.is_file())
}

pub(super) fn claude_code_status() -> ClaudeCodeStatus {
    let Some(path) = claude_code_executable() else {
        return ClaudeCodeStatus {
            installed: false,
            logged_in: false,
            path: None,
        };
    };
    let mut command = std::process::Command::new(&path);
    command
        .args(["auth", "status"])
        .stdin(std::process::Stdio::null());
    let logged_in = run_with_timeout(command, CLAUDE_STATUS_TIMEOUT)
        .and_then(|output| serde_json::from_slice::<serde_json::Value>(&output.stdout).ok())
        .and_then(|status| status.get("loggedIn").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    ClaudeCodeStatus {
        installed: true,
        logged_in,
        path: Some(path.to_string_lossy().into_owned()),
    }
}

/// Connects Anthropic through Claude Code: the bridge reads its executable
/// path, and the inventory lists the provider.
pub(super) fn connect_claude_code(agent: &Path, executable: &str) -> Result<(), String> {
    if !valid_identifier(executable, 4096) || !Path::new(executable).is_file() {
        return Err("Install Claude Code and sign in, then retry.".into());
    }
    fs::create_dir_all(agent).map_err(|_| SAVE_SETTINGS_ERROR.to_string())?;
    let mut config = read_json_for_update(&claude_bridge_config_file(agent))?;
    let provider = config
        .entry("provider")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| SAVE_SETTINGS_ERROR.to_string())?;
    provider.insert("pathToClaudeCodeExecutable".into(), executable.into());
    write_json_for_update(&claude_bridge_config_file(agent), &config)?;
    let mut record = read_models_record(agent)?;
    record.insert("claudeCode".into(), true.into());
    write_models_record(agent, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_core::models::pi_models::{
        store_decision_models, store_endpoint as store_endpoint_provider,
        RECORD_FILE as MODELS_RECORD_FILE,
    };

    fn row(provider: &str, id: &str, context: &str) -> PiModelRow {
        PiModelRow {
            provider: provider.into(),
            id: id.into(),
            context: context.into(),
            max_out: "128K".into(),
            thinking: true,
            images: true,
        }
    }

    #[test]
    fn a_connected_provider_adopts_its_largest_context_model_first_listed_on_a_tie() {
        let table = "provider  model                context  max-out  thinking  images\n\
openai-codex  gpt-5.3-codex-spark  128K  16.4K  yes  yes\n\
openai-codex  gpt-5.4              272K  128K   yes  yes\n\
openai-codex  gpt-6-astra          272K  128K   yes  yes\n\
ollama        gemma4:12b           128K  16.4K  no   no\n\
ollama        llama3.2:3b          128K  16.4K  no   no\n\
google        gemini-3-pro         1M    64K    yes  yes\n";
        let models = muniment_core::engine::parse_model_table(table);
        assert_eq!(
            adoption_candidates(&models, "openai-codex"),
            ["gpt-5.4", "gpt-6-astra", "gpt-5.3-codex-spark"]
        );
        assert_eq!(
            adoption_candidates(&models, "ollama"),
            ["gemma4:12b", "llama3.2:3b"]
        );
        assert_eq!(adoption_candidates(&models, "google"), ["gemini-3-pro"]);
        assert!(adoption_candidates(&models, "xai").is_empty());
        assert_eq!(context_tokens("1M"), 1_000_000);
        assert_eq!(context_tokens("16.4K"), 16_400);
    }

    fn temporary_directory() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("muniment-local-mode-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn a_missing_default_becomes_the_first_shown_model_so_the_chip_and_the_run_agree() {
        let agent = temporary_directory();
        fs::write(
            agent.join("auth.json"),
            r#"{"openai-codex":{"type":"oauth","access":"a"}}"#,
        )
        .unwrap();
        fs::write(agent.join("settings.json"), r#"{"defaultTools":["read"]}"#).unwrap();
        fs::write(
            agent.join(MODELS_RECORD_FILE),
            r#"{"hidden":["openai-codex/gpt-5.5"]}"#,
        )
        .unwrap();
        let models = vec![
            row("openai-codex", "gpt-5.5", "400K"),
            row("openai-codex", "gpt-5.6-luna", "400K"),
        ];
        let mut inventory = provider_inventory(&agent, &models).unwrap();
        assert_eq!(inventory.default_model, None);
        adopt_shown_default(&agent, &mut inventory);
        assert_eq!(inventory.default_provider.as_deref(), Some("openai-codex"));
        assert_eq!(inventory.default_model.as_deref(), Some("gpt-5.6-luna"));
        let settings: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(agent.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(settings["defaultProvider"], "openai-codex");
        assert_eq!(settings["defaultModel"], "gpt-5.6-luna");

        // A shown saved default stays.
        let mut again = provider_inventory(&agent, &models).unwrap();
        adopt_shown_default(&agent, &mut again);
        assert_eq!(again.default_model.as_deref(), Some("gpt-5.6-luna"));
    }

    #[test]
    fn endpoint_models_are_selectable_before_the_first_chat_installs_pi() {
        let agent = temporary_directory();
        fs::write(agent.join("models.json"), serde_json::json!({
            "providers": {"ollama": {"baseUrl": "http://localhost:11434/v1", "models": [{"id": "local-model"}]}}
        }).to_string()).unwrap();
        let mut inventory = provider_inventory(&agent, &[]).unwrap();
        adopt_shown_default(&agent, &mut inventory);
        assert_eq!(inventory.default_provider.as_deref(), Some("ollama"));
        assert_eq!(inventory.default_model.as_deref(), Some("local-model"));
        assert_eq!(inventory.providers[0].models[0].id, "local-model");

        let detailed = PiModelRow {
            provider: "ollama".into(),
            id: "local-model".into(),
            context: "128K".into(),
            max_out: "8K".into(),
            thinking: true,
            images: true,
        };
        let inventory = provider_inventory(&agent, &[detailed]).unwrap();
        assert_eq!(inventory.providers[0].models.len(), 1);
        assert_eq!(inventory.providers[0].models[0].context, "128K");
        assert!(inventory.providers[0].models[0].images);
    }

    #[test]
    fn an_endpoint_carries_the_decision_models_its_server_reported() {
        let agent = temporary_directory();
        fs::write(agent.join("models.json"), serde_json::json!({
            "providers": {"llama": {"baseUrl": "http://localhost:8080/v1", "models": [{"id": "qwen3"}]}}
        }).to_string()).unwrap();
        store_decision_models(&agent, "llama", &["kev-4b".to_owned()]).unwrap();
        let inventory = provider_inventory(&agent, &[]).unwrap();
        assert_eq!(inventory.providers[0].decision_models, ["kev-4b"]);
        assert_eq!(inventory.providers[0].models.len(), 1);
        store_decision_models(&agent, "llama", &[]).unwrap();
        let inventory = provider_inventory(&agent, &[]).unwrap();
        assert!(inventory.providers[0].decision_models.is_empty());
    }

    #[test]
    fn a_server_key_goes_only_to_that_server() {
        let agent = temporary_directory();
        let models = agent.join("models.json");
        fs::write(&models, serde_json::json!({
            "providers": {"ollama": {"baseUrl": "https://ollama.example/v1/", "apiKey": "server-key"}}
        }).to_string()).unwrap();
        let key = |url: &str| endpoint_key_for(&models, "ollama", url);
        assert_eq!(
            key("https://ollama.example/v1/systemone").as_deref(),
            Some("server-key")
        );
        assert_eq!(key("https://ollama.example/v1evil/systemone"), None);
        assert_eq!(key("https://other.example/v1/systemone"), None);
        assert_eq!(
            endpoint_key_for(&models, "missing", "https://ollama.example/v1/systemone"),
            None
        );
    }

    #[test]
    fn the_inventory_reads_keys_accounts_endpoints_the_bridge_and_the_default() {
        let agent = temporary_directory();
        fs::write(agent.join("auth.json"), r#"{"anthropic":{"type":"api_key","key":"k"},"openai-codex":{"type":"oauth","access":"a"}}"#).unwrap();
        fs::write(agent.join("models.json"), r#"{"providers":{"ollama":{"baseUrl":"http://localhost:11434/v1","api":"openai-completions"},"custom-proxy":{"baseUrl":"http://proxy:4000/v1","api":"openai-completions"}}}"#).unwrap();
        fs::write(
            agent.join("settings.json"),
            r#"{"defaultProvider":"ollama","defaultModel":"llama3.2:3b"}"#,
        )
        .unwrap();
        fs::write(agent.join(MODELS_RECORD_FILE), r#"{"hidden":["anthropic/claude-haiku-4-5"],"names":{"custom-proxy":"My proxy"},"claudeCode":true}"#).unwrap();
        let models = vec![
            PiModelRow {
                provider: "ollama".into(),
                id: "llama3.2:3b".into(),
                context: "128K".into(),
                max_out: "16K".into(),
                thinking: false,
                images: false,
            },
            row("anthropic", "claude-sonnet-5", "1M"),
            row("unknown", "x", "1"),
        ];
        let inventory = provider_inventory(&agent, &models).unwrap();
        let ids: Vec<(&str, &str)> = inventory
            .providers
            .iter()
            .map(|p| (p.id.as_str(), p.source))
            .collect();
        // Keys first, then endpoints, then the bridge; each group in the file's key order.
        assert_eq!(
            ids,
            vec![
                ("anthropic", "key"),
                ("openai-codex", "account"),
                ("custom-proxy", "custom"),
                ("ollama", "local"),
                ("claude-bridge", "claude-code")
            ]
        );
        let names: Vec<&str> = inventory
            .providers
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["Anthropic", "OpenAI", "My proxy", "Ollama", "Anthropic"]
        );
        assert_eq!(
            inventory.providers[3].base_url.as_deref(),
            Some("http://localhost:11434/v1")
        );
        assert_eq!(inventory.providers[3].models[0].id, "llama3.2:3b");
        assert_eq!(inventory.providers[0].models.len(), 1);
        assert_eq!(inventory.default_provider.as_deref(), Some("ollama"));
        assert_eq!(inventory.default_model.as_deref(), Some("llama3.2:3b"));
        assert_eq!(inventory.hidden, vec!["anthropic/claude-haiku-4-5"]);
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn the_picker_counts_only_the_accounts_that_balance_together() {
        use muniment_core::model_router::config::{self, Account, Credential, RouterConfig};
        let account = |id: &str, subscription: bool, overflow: bool| Account {
            id: id.into(),
            family: "openai".into(),
            label: id.into(),
            credential: if subscription {
                Credential::Subscription {
                    provider: "openai-codex".into(),
                    access: "at".into(),
                    refresh: None,
                    expires_ms: None,
                    account_id: Some(id.into()),
                    email: None,
                    plan: None,
                    renews_at_ms: None,
                }
            } else {
                Credential::ApiKey { key: "sk".into() }
            },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 1,
            overflow,
        };
        let agent = temporary_directory();
        let mut saved = RouterConfig {
            enabled: true,
            accounts: vec![
                account("k1", false, false),
                account("k2", false, true),
                account("k3", false, false),
                account("s1", true, false),
                account("s2", true, false),
            ],
            ..RouterConfig::default()
        };
        let count = |saved: &RouterConfig| {
            config::save(&agent, saved).unwrap();
            router_models(&agent)
                .into_iter()
                .find(|entry| entry.id == "openai/gpt-6-astra")
                .unwrap()
                .accounts
        };
        // The subscriptions alone, never a key beside them, overflow or not.
        assert_eq!(count(&saved), 2);
        saved.accounts[3].enabled = false;
        assert_eq!(count(&saved), 1);
        // No subscription left: every key counts.
        saved.accounts[4].weight = 0;
        assert_eq!(count(&saved), 3);
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn switching_four_router_models_replaces_existing_settings() {
        let agent = temporary_directory();
        let path = agent.join("settings.json");
        fs::write(&path, r#"{"theme":"dark","compaction":{"enabled":false}}"#).unwrap();
        for model in [
            "gpt-5.6-luna",
            "gpt-5.6-terra",
            "gpt-5.6-sol",
            "gpt-5.6-astra",
        ] {
            let model = format!("openai-codex/{model}");
            set_default_model(&agent, "muniment-router", &model).unwrap();
            let settings = read_json_for_update(&path).unwrap();
            assert_eq!(settings["defaultProvider"], "muniment-router");
            assert_eq!(settings["defaultModel"], model);
            assert_eq!(settings["theme"], "dark");
            assert_eq!(settings["compaction"]["enabled"], false);
            assert!(!fs::read_dir(&agent).unwrap().any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension.to_string_lossy().starts_with("tmp-"))));
        }
        for (provider, model) in [
            ("", "x"),
            ("muniment-router", ""),
            ("muniment-router", " x"),
            ("muniment-router", "x\n"),
        ] {
            let before = fs::read(&path).unwrap();
            assert!(set_default_model(&agent, provider, model).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        fs::write(&path, b"invalid JSON").unwrap();
        assert!(
            set_default_model(&agent, "muniment-router", "openai-codex/gpt-5.6-terra").is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"invalid JSON");
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn the_default_and_the_hidden_list_persist_and_a_disconnect_clears_both() {
        let agent = temporary_directory();
        fs::write(
            agent.join("auth.json"),
            r#"{"anthropic":{"type":"api_key","key":"k"},"google":{"type":"api_key","key":"g"}}"#,
        )
        .unwrap();
        set_default_model(&agent, "anthropic", "claude-sonnet-5").unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(agent.join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["defaultProvider"], "anthropic");
        assert_eq!(settings["defaultModel"], "claude-sonnet-5");
        assert!(set_default_model(&agent, "", "x").is_err());

        set_model_hidden(&agent, "anthropic", "claude-haiku-4-5", true).unwrap();
        set_model_hidden(&agent, "google", "gemini", true).unwrap();
        set_model_hidden(&agent, "anthropic", "claude-haiku-4-5", false).unwrap();
        let record = read_models_record(&agent).unwrap();
        assert_eq!(record_strings(&record, "hidden"), vec!["google/gemini"]);
        assert_eq!(
            record_strings(&record, "shown"),
            vec!["anthropic/claude-haiku-4-5"]
        );
        set_model_hidden(&agent, "anthropic", "claude-haiku-4-5", true).unwrap();
        let record = read_models_record(&agent).unwrap();
        assert_eq!(
            record_strings(&record, "hidden"),
            vec!["google/gemini", "anthropic/claude-haiku-4-5"]
        );
        assert!(record_strings(&record, "shown").is_empty());
        set_model_hidden(&agent, "anthropic", "claude-haiku-4-5", false).unwrap();

        disconnect_provider(&agent, "anthropic").unwrap();
        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(agent.join("auth.json")).unwrap()).unwrap();
        assert!(auth.get("anthropic").is_none());
        assert!(auth.get("google").is_some());
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(agent.join("settings.json")).unwrap()).unwrap();
        assert!(settings.get("defaultProvider").is_none());
        assert!(settings.get("defaultModel").is_none());
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn endpoints_land_in_models_json_with_their_name_and_the_bridge_connects_through_the_record() {
        let agent = temporary_directory();
        assert_eq!(
            store_endpoint_provider(
                &agent,
                "lmstudio",
                "LM Studio",
                "http://localhost:1234/v1",
                "",
                &["qwen3".into()]
            )
            .unwrap(),
            "lmstudio"
        );
        let id = store_endpoint_provider(
            &agent,
            "custom",
            "My LiteLLM Proxy",
            "http://proxy:4000/v1",
            "sk-x",
            &["gpt-5.5".into(), "".into()],
        )
        .unwrap();
        assert_eq!(id, "custom-my-litellm-proxy");
        let models: serde_json::Value =
            serde_json::from_slice(&fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert_eq!(models["providers"]["lmstudio"]["apiKey"], "local");
        assert_eq!(models["providers"]["lmstudio"]["models"][0]["id"], "qwen3");
        assert_eq!(models["providers"][&id]["apiKey"], "sk-x");
        assert_eq!(
            models["providers"][&id]["models"].as_array().unwrap().len(),
            1
        );
        let record = read_models_record(&agent).unwrap();
        assert_eq!(record["names"][&id], "My LiteLLM Proxy");
        assert!(
            store_endpoint_provider(&agent, "custom", "x", "ftp://bad", "", &["m".into()]).is_err()
        );
        assert!(store_endpoint_provider(
            &agent,
            "lmstudio",
            "",
            "http://localhost:1234/v1",
            "",
            &[]
        )
        .is_err());
        assert!(store_endpoint_provider(
            &agent,
            "other",
            "x",
            "http://localhost:1234/v1",
            "",
            &["m".into()]
        )
        .is_err());

        let executable = agent.join("claude");
        fs::write(&executable, "#!/bin/sh\n").unwrap();
        connect_claude_code(&agent, executable.to_str().unwrap()).unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(agent.join(CLAUDE_BRIDGE_CONFIG_FILE)).unwrap())
                .unwrap();
        assert_eq!(
            config["provider"]["pathToClaudeCodeExecutable"],
            executable.to_str().unwrap()
        );
        assert_eq!(read_models_record(&agent).unwrap()["claudeCode"], true);
        assert!(connect_claude_code(&agent, "/nowhere/claude").is_err());
        disconnect_provider(&agent, CLAUDE_BRIDGE_PROVIDER).unwrap();
        assert_eq!(read_models_record(&agent).unwrap()["claudeCode"], false);
        assert!(!agent.join(CLAUDE_BRIDGE_CONFIG_FILE).exists());
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn every_key_provider_stores_a_key_and_an_unknown_one_does_not() {
        let agent = temporary_directory();
        let auth_file = agent.join("auth.json");
        for (provider, _) in registry::key_providers() {
            let env = registry::key_settings(provider)
                .iter()
                .map(|name| (name.to_string(), "abc123".to_string()))
                .collect();
            store_provider_key(&auth_file, provider, "k", &env).unwrap();
        }
        assert!(store_provider_key(&auth_file, "nobody", "k", &Default::default()).is_err());
        // Cloudflare needs its account beside the key, in the env Pi reads.
        assert!(store_provider_key(
            &auth_file,
            "cloudflare-workers-ai",
            "k",
            &Default::default()
        )
        .is_err());
        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_file).unwrap()).unwrap();
        assert_eq!(
            auth.as_object().unwrap().len(),
            registry::key_providers().count()
        );
        assert_eq!(
            auth["cloudflare-workers-ai"]["env"]["CLOUDFLARE_ACCOUNT_ID"],
            "abc123"
        );
        assert!(auth["openai"].get("env").is_none());
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn harness_files_sit_under_the_agent_directory() {
        let agent = Path::new("/home/tester/.muniment/agent");

        assert_eq!(
            pi_auth_file(agent),
            PathBuf::from("/home/tester/.muniment/agent/auth.json")
        );
        assert_eq!(
            pi_models_file(agent),
            PathBuf::from("/home/tester/.muniment/agent/models.json")
        );
        assert_eq!(
            pi_settings_file(&pi_models_file(agent)),
            PathBuf::from("/home/tester/.muniment/agent/settings.json")
        );
    }

    #[test]
    fn provider_status_reports_missing_store_as_not_configured() {
        let directory = temporary_directory();
        let statuses = provider_status_in(
            &directory.join("missing-auth.json"),
            &directory.join("missing-models.json"),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(statuses).unwrap(),
            serde_json::json!([
                {"provider":"anthropic","configured":false},
                {"provider":"google","configured":false},
                {"provider":"openai","configured":false},
                {"provider":"ollama","configured":false}
            ])
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_status_reports_object_entries_without_exposing_credentials() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        fs::write(
            &auth_file,
            r#"{"anthropic":{"type":"api_key","key":"secret-key"},"github-copilot":{"type":"oauth","access":"saved"}}"#,
        )
        .unwrap();

        let serialized = serde_json::to_string(
            &provider_status_in(&auth_file, &directory.join("models.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            serialized,
            r#"[{"provider":"anthropic","configured":true},{"provider":"google","configured":false},{"provider":"openai","configured":false},{"provider":"ollama","configured":false}]"#
        );
        assert!(!serialized.contains("secret-key"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_status_treats_oauth_provider_entry_as_configured() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        fs::write(
            &auth_file,
            r#"{"google":{"type":"oauth","access":"saved"}}"#,
        )
        .unwrap();

        let statuses = serde_json::to_value(
            provider_status_in(&auth_file, &directory.join("models.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(statuses[1]["configured"], true);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_status_rejects_malformed_json() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        fs::write(&auth_file, "not json").unwrap();

        assert_eq!(
            provider_status_in(&auth_file, &directory.join("models.json")).unwrap_err(),
            "Muniment cannot read provider settings. Check folder access, then retry."
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_status_rejects_unreadable_store() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        fs::create_dir(&auth_file).unwrap();

        assert_eq!(
            provider_status_in(&auth_file, &directory.join("models.json")).unwrap_err(),
            "Muniment cannot read provider settings. Check folder access, then retry."
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_key_command_writes_under_the_agent_directory() {
        let directory = temporary_directory();
        let agent = directory.join("agent");
        let auth_file = pi_auth_file(&agent);

        store_provider_key(&auth_file, "openai", "test-key", &Default::default()).unwrap();

        assert_eq!(auth_file, agent.join("auth.json"));
        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_file).unwrap()).unwrap();
        assert_eq!(auth["openai"]["key"], "test-key");
        assert!(!directory.join(".pi").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_key_command_writes_pis_auth_file_and_preserves_other_entries() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        fs::write(
            &auth_file,
            r#"{"github-copilot":{"type":"oauth","access":"saved"}}"#,
        )
        .unwrap();
        store_provider_key(&auth_file, "anthropic", "test-key", &Default::default()).unwrap();
        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_file).unwrap()).unwrap();
        assert_eq!(
            auth["anthropic"],
            serde_json::json!({"type":"api_key","key":"test-key"})
        );
        assert_eq!(auth["github-copilot"]["access"], "saved");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_key_command_waits_for_a_concurrent_pi_credential_update() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        fs::write(&auth_file, "{}").unwrap();
        let lock_path = pi_models::lock_path(&auth_file);
        fs::create_dir(&lock_path).unwrap();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer_file = auth_file.clone();
        let writer = std::thread::spawn(move || {
            let result =
                store_provider_key(&writer_file, "anthropic", "test-key", &Default::default());
            finished_tx.send(()).unwrap();
            result
        });

        assert!(finished_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err());
        fs::write(
            &auth_file,
            r#"{"github-copilot":{"type":"oauth","access":"updated"}}"#,
        )
        .unwrap();
        fs::remove_dir(lock_path).unwrap();
        writer.join().unwrap().unwrap();

        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_file).unwrap()).unwrap();
        assert_eq!(auth["github-copilot"]["access"], "updated");
        assert_eq!(auth["anthropic"]["key"], "test-key");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_key_command_rejects_unknown_providers_and_blank_keys() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        assert!(store_provider_key(&auth_file, "other", "key", &Default::default()).is_err());
        assert!(store_provider_key(&auth_file, "ollama", "key", &Default::default()).is_err());
        assert!(store_provider_key(&auth_file, "openai", " ", &Default::default()).is_err());
        assert!(!auth_file.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn local_provider_writes_models_file_and_preserves_other_providers() {
        let directory = temporary_directory();
        let models_file = directory.join("models.json");
        fs::write(
            &models_file,
            r#"{"providers":{"custom":{"baseUrl":"http://localhost:9000/v1"}}}"#,
        )
        .unwrap();

        store_local_provider_in(&models_file, "http://127.0.0.1:11434/v1", "").unwrap();

        let models: serde_json::Value =
            serde_json::from_slice(&fs::read(&models_file).unwrap()).unwrap();
        assert_eq!(
            models["providers"]["ollama"],
            serde_json::json!({
                "baseUrl": "http://127.0.0.1:11434/v1",
                "api": "openai-completions",
                "apiKey": "ollama",
                "compat": {
                    "supportsDeveloperRole": false,
                    "supportsReasoningEffort": false
                },
                "models": [{"id": "llama3.2:latest"}]
            })
        );
        assert_eq!(
            models["providers"]["custom"]["baseUrl"],
            "http://localhost:9000/v1"
        );
        let statuses = provider_status_in(&directory.join("auth.json"), &models_file).unwrap();
        assert!(statuses
            .iter()
            .any(|status| status.provider == "ollama" && status.configured));
        assert!(!directory.join("auth.json").exists());
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["defaultProvider"], "ollama");
        assert_eq!(settings["defaultModel"], "llama3.2:latest");
        // A server behind a key keeps the key Pi sends with every turn.
        store_local_provider_in(&models_file, "http://127.0.0.1:11434/v1", "sk-ollama").unwrap();
        let models: serde_json::Value =
            serde_json::from_slice(&fs::read(&models_file).unwrap()).unwrap();
        assert_eq!(models["providers"]["ollama"]["apiKey"], "sk-ollama");
        // An edit with a blank key keeps the saved one.
        store_local_provider_in(&models_file, "http://127.0.0.1:11434/v1", "").unwrap();
        let models: serde_json::Value =
            serde_json::from_slice(&fs::read(&models_file).unwrap()).unwrap();
        assert_eq!(models["providers"]["ollama"]["apiKey"], "sk-ollama");
        assert!(
            store_local_provider_in(&models_file, "http://127.0.0.1:11434/v1", " sk ").is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn local_provider_pins_ollama_when_cloud_credentials_exist() {
        let directory = temporary_directory();
        let auth_file = directory.join("auth.json");
        let models_file = directory.join("models.json");
        fs::write(
            &auth_file,
            r#"{"openai":{"type":"api_key","key":"paid-cloud-key"}}"#,
        )
        .unwrap();
        fs::write(
            directory.join("settings.json"),
            r#"{"defaultProvider":"openai","defaultModel":"gpt-5","theme":"dark"}"#,
        )
        .unwrap();

        store_local_provider_in(&models_file, "http://127.0.0.1:11434/v1", "").unwrap();

        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["defaultProvider"], "ollama");
        assert_eq!(settings["defaultModel"], "llama3.2:latest");
        assert_eq!(settings["theme"], "dark");
        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(auth_file).unwrap()).unwrap();
        assert_eq!(auth["openai"]["key"], "paid-cloud-key");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn local_provider_rejects_malformed_base_urls() {
        let directory = temporary_directory();
        let models_file = directory.join("models.json");

        for base_url in [
            "localhost:11434/v1",
            "ftp://localhost/v1",
            "http://",
            " http://localhost/v1",
            "http://user:secret@localhost/v1",
            "http://localhost/v1?token=secret",
        ] {
            assert!(store_local_provider_in(&models_file, base_url, "").is_err());
        }
        assert!(!models_file.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
