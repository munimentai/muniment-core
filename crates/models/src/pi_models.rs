//! Pi's `models.json` in an agent directory: the local servers and the
//! OpenAI-compatible endpoints Pi reaches, each with the models its server
//! serves and their windows, and the provider models discovery adds. Every
//! write holds the file's lock, and a discovery never replaces a model entry
//! the user wrote. `muniment-models.json` beside it keeps the decision models
//! each endpoint reported.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::endpoint_models::discover_endpoint_models;
use crate::registry::{
    key_providers, CUSTOM_PROVIDER_PREFIX, LM_STUDIO_PROVIDER, OLLAMA_MODEL, OLLAMA_PROVIDER,
    ROUTER_PROVIDER,
};
use crate::window::Limits;

pub const READ_ERROR: &str =
    "Muniment cannot read provider settings. Check folder access, then retry.";
pub const SAVE_ERROR: &str =
    "Muniment cannot save provider settings. Check folder access, then retry.";
/// The desktop's own record beside Pi's files: the models turned off and on,
/// endpoint names, the Claude Code connection and each endpoint's decision models.
pub const RECORD_FILE: &str = "muniment-models.json";
/// The record key that keeps each endpoint's decision models by provider.
const DECISION_MODELS: &str = "decisionModels";
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_RETRY: Duration = Duration::from_millis(20);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Pi's model file in an agent directory.
pub fn models_file(agent: &Path) -> PathBuf {
    agent.join("models.json")
}

/// The lock Pi and Muniment share on one of Pi's files: a directory beside
/// it, held until drop.
pub struct FileLock(PathBuf);

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

pub fn lock_path(file: &Path) -> PathBuf {
    let mut name = OsString::from(file.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

/// Takes the lock on `file`, waiting while another writer holds it.
pub fn lock(file: &Path) -> io::Result<FileLock> {
    let path = lock_path(file);
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match fs::create_dir(&path) {
            Ok(()) => return Ok(FileLock(path)),
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists && Instant::now() < deadline =>
            {
                std::thread::sleep(LOCK_RETRY);
            }
            Err(error) => return Err(error),
        }
    }
}

/// A JSON object file, empty when the file does not exist.
pub fn read_json(path: &Path) -> io::Result<Map<String, Value>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Map::new()),
        Err(error) => Err(error),
    }
}

/// Replaces a JSON object file atomically, readable by its owner alone.
pub fn write_json(path: &Path, root: &Map<String, Value>) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(root)?;
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
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
        // ReplaceFileW opens the replacement without sharing access.
        drop(file);
        muniment_atomic_file::replace(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_for_update(path: &Path) -> Result<Map<String, Value>, String> {
    read_json(path).map_err(|_| SAVE_ERROR.to_string())
}

fn write_for_update(path: &Path, root: &Map<String, Value>) -> Result<(), String> {
    write_json(path, root).map_err(|_| SAVE_ERROR.to_string())
}

pub fn read_record(agent: &Path) -> Result<Map<String, Value>, String> {
    match fs::read(agent.join(RECORD_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| READ_ERROR.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Map::new()),
        Err(_) => Err(READ_ERROR.into()),
    }
}

pub fn write_record(agent: &Path, record: &Map<String, Value>) -> Result<(), String> {
    fs::create_dir_all(agent).map_err(|_| SAVE_ERROR.to_string())?;
    write_for_update(&agent.join(RECORD_FILE), record)
}

/// The decision models the record keeps for one endpoint.
pub fn decision_models(record: &Map<String, Value>, provider: &str) -> Vec<String> {
    record
        .get(DECISION_MODELS)
        .and_then(|providers| providers.get(provider))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

pub fn store_decision_models(agent: &Path, provider: &str, ids: &[String]) -> Result<(), String> {
    let mut record = read_record(agent)?;
    if decision_models(&record, provider) == ids {
        return Ok(());
    }
    let providers = record.entry(DECISION_MODELS).or_insert_with(|| json!({}));
    if !providers.is_object() {
        *providers = json!({});
    }
    let providers = providers.as_object_mut().expect("an object");
    if ids.is_empty() {
        providers.remove(provider);
    } else {
        providers.insert(provider.to_owned(), json!(ids));
    }
    write_record(agent, &record)
}

/// One endpoint model as Pi reads it, with its window when the server
/// reported one. Pi assumes its own defaults for a window it is not told.
pub fn model_entry(id: &str, window: Option<&Limits>) -> Value {
    let mut entry = json!({ "id": id });
    if let Some(context) = window.and_then(|window| window.context) {
        entry["contextWindow"] = context.into();
    }
    if let Some(output) = window.and_then(|window| window.output) {
        entry["maxTokens"] = output.into();
    }
    entry
}

fn model_entries(ids: &[String], windows: &BTreeMap<String, Limits>) -> Vec<Value> {
    ids.iter()
        .map(|id| model_entry(id, windows.get(id)))
        .collect()
}

/// The key an endpoint provider already holds, never a stand-in. Settings never
/// reads a key back to show it, so an edit with a blank key keeps this one.
pub fn saved_endpoint_key(models_file: &Path, provider: &str) -> Option<String> {
    let root: Value = serde_json::from_slice(&fs::read(models_file).ok()?).ok()?;
    root["providers"][provider]["apiKey"]
        .as_str()
        .filter(|key| !matches!(*key, "ollama" | "local") && !key.is_empty())
        .map(str::to_owned)
}

pub fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.trim() == value
        && !value.contains(char::is_control)
}

/// A plain http or https server URL with no credentials, query or fragment.
pub fn endpoint_url(base_url: &str, message: &str) -> Result<url::Url, String> {
    if base_url.is_empty() || base_url.len() > 16 * 1024 || base_url.trim() != base_url {
        return Err(message.into());
    }
    let parsed = url::Url::parse(base_url).map_err(|_| message.to_owned())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(message.into());
    }
    Ok(parsed)
}

pub fn custom_provider_id(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{CUSTOM_PROVIDER_PREFIX}{}",
        if slug.is_empty() {
            "endpoint".to_owned()
        } else {
            slug
        }
    )
}

/// Saves an Ollama server. A server on another host may sit behind a key, which
/// discovery sends and Pi sends with every turn. With no key, Pi sends a
/// stand-in. `route` makes the server's default model Pi's default before the
/// model file is written, so a later write failure cannot fall back to a cloud
/// model.
pub fn store_ollama(
    agent: &Path,
    base_url: &str,
    key: &str,
    route: impl FnOnce(&str) -> Result<(), String>,
) -> Result<(), String> {
    const MESSAGE: &str = "Enter a valid Ollama server URL.";
    if base_url.is_empty() || base_url.len() > 16 * 1024 || base_url.trim() != base_url {
        return Err(MESSAGE.into());
    }
    if key.len() > 16 * 1024 || key.trim() != key {
        return Err("Enter a valid API key.".into());
    }
    let models_file = models_file(agent);
    let saved = if key.is_empty() {
        saved_endpoint_key(&models_file, OLLAMA_PROVIDER)
    } else {
        None
    };
    let key = saved.as_deref().unwrap_or(key);
    endpoint_url(base_url, MESSAGE)?;

    fs::create_dir_all(agent).map_err(|_| SAVE_ERROR.to_string())?;
    let _models_lock = lock(&models_file).map_err(|_| SAVE_ERROR.to_string())?;
    let mut models = read_for_update(&models_file)?;
    let providers = models
        .entry("providers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| SAVE_ERROR.to_string())?;
    // The server names its own models; the pinned id stands in when it does not answer.
    let discovered = discover_endpoint_models(base_url, Some(key), DISCOVERY_TIMEOUT);
    let (model_ids, decisions, windows) = match discovered {
        Some(found) => (found.chat, found.decisions, found.windows),
        None => (vec![OLLAMA_MODEL.to_owned()], Vec::new(), BTreeMap::new()),
    };
    if model_ids.is_empty() {
        return Err("The server has no chat models. Add a chat model, then try again.".into());
    }
    let default_model = if model_ids.iter().any(|id| id == OLLAMA_MODEL) {
        OLLAMA_MODEL
    } else {
        model_ids[0].as_str()
    };
    providers.insert(
        OLLAMA_PROVIDER.to_owned(),
        json!({
            "baseUrl": base_url,
            "api": "openai-completions",
            "apiKey": if key.is_empty() { OLLAMA_PROVIDER } else { key },
            "compat": {
                "supportsDeveloperRole": false,
                "supportsReasoningEffort": false
            },
            "models": model_entries(&model_ids, &windows)
        }),
    );
    route(default_model)?;
    write_for_update(&models_file, &models)?;
    store_decision_models(agent, OLLAMA_PROVIDER, &decisions)
}

/// Saves an OpenAI-compatible endpoint: LM Studio or a named custom server
/// such as a LiteLLM proxy. With no models named, the server names its own.
/// Answers the provider id.
pub fn store_endpoint(
    agent: &Path,
    kind: &str,
    name: &str,
    base_url: &str,
    key: &str,
    models: &[String],
) -> Result<String, String> {
    endpoint_url(base_url, "Enter a valid server URL.")?;
    if key.len() > 16 * 1024 || key.trim() != key {
        return Err("Enter a valid API key.".into());
    }
    let provider = match kind {
        "lmstudio" => LM_STUDIO_PROVIDER.to_owned(),
        "custom" if valid_identifier(name, 80) => custom_provider_id(name),
        _ => return Err("Name the endpoint.".into()),
    };
    let models_file = models_file(agent);
    let saved = if key.is_empty() {
        saved_endpoint_key(&models_file, &provider)
    } else {
        None
    };
    let key = saved.as_deref().unwrap_or(key);
    let mut models: Vec<String> = models
        .iter()
        .filter(|model| valid_identifier(model, 512))
        .cloned()
        .collect();
    let mut decisions = None;
    let mut windows = BTreeMap::new();
    if models.is_empty() {
        let found =
            discover_endpoint_models(base_url, Some(key), DISCOVERY_TIMEOUT).unwrap_or_default();
        models = found.chat;
        windows = found.windows;
        decisions = Some(found.decisions);
    }
    if models.is_empty() {
        return Err("The server named no models. Start it, or list its models here.".into());
    }
    fs::create_dir_all(agent).map_err(|_| SAVE_ERROR.to_string())?;
    let _models_lock = lock(&models_file).map_err(|_| SAVE_ERROR.to_string())?;
    let mut root = read_for_update(&models_file)?;
    let providers = root
        .entry("providers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| SAVE_ERROR.to_string())?;
    providers.insert(
        provider.clone(),
        json!({
            "baseUrl": base_url,
            "api": "openai-completions",
            "apiKey": if key.is_empty() { "local" } else { key },
            "models": model_entries(&models, &windows)
        }),
    );
    write_for_update(&models_file, &root)?;
    if kind == "custom" {
        let mut record = read_record(agent)?;
        let names = record
            .entry("names")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| SAVE_ERROR.to_string())?;
        names.insert(provider.clone(), name.into());
        write_record(agent, &record)?;
    }
    if let Some(ids) = decisions {
        store_decision_models(agent, &provider, &ids)?;
    }
    Ok(provider)
}

/// Rewrites each endpoint's model list from what its server serves now, with
/// each model's window, and answers whether any list changed. A model the
/// server still serves keeps the settings the user gave it.
pub fn refresh_endpoints(agent: &Path) -> Result<bool, String> {
    let models_file = models_file(agent);
    if !models_file.is_file() {
        return Ok(false);
    }
    let _lock = lock(&models_file).map_err(|_| SAVE_ERROR.to_string())?;
    let mut root = read_for_update(&models_file)?;
    let mut changed = false;
    let mut decisions = Vec::new();
    if let Some(providers) = root.get_mut("providers").and_then(Value::as_object_mut) {
        for (id, entry) in providers
            .iter_mut()
            .filter(|(id, _)| {
                id.as_str() != ROUTER_PROVIDER && !key_providers().any(|(known, _)| known == *id)
            })
            .filter_map(|(id, value)| value.as_object_mut().map(|entry| (id, entry)))
        {
            let Some(base_url) = entry.get("baseUrl").and_then(Value::as_str) else {
                continue;
            };
            // The stand-in keys Pi sends to a server with no key are not keys.
            let key = entry
                .get("apiKey")
                .and_then(Value::as_str)
                .filter(|key| !matches!(*key, "ollama" | "local"));
            let Some(found) = discover_endpoint_models(base_url, key, DISCOVERY_TIMEOUT) else {
                continue;
            };
            decisions.push((id.clone(), found.decisions));
            let current = entry
                .get("models")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let next: Vec<Value> = found
                .chat
                .iter()
                .map(|model| {
                    let mut next = current
                        .iter()
                        .find(|old| old.get("id").and_then(Value::as_str) == Some(model))
                        .filter(|old| old.is_object())
                        .cloned()
                        .unwrap_or_else(|| json!({ "id": model }));
                    if let Some(window) = found.windows.get(model) {
                        let reported = model_entry(model, Some(window));
                        for field in ["contextWindow", "maxTokens"] {
                            if let Some(value) = reported.get(field) {
                                next[field] = value.clone();
                            }
                        }
                    }
                    next
                })
                .collect();
            if current != next {
                entry.insert("models".into(), next.into());
                changed = true;
            }
        }
    }
    if changed {
        write_for_update(&models_file, &root)?;
    }
    for (provider, ids) in decisions {
        let before = decision_models(&read_record(agent)?, &provider);
        if before != ids {
            store_decision_models(agent, &provider, &ids)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Adds the models each provider's discovery found to Pi's model file without
/// replacing a model entry already there, then lets `register` change the file
/// under the same lock. Answers whether the file changed.
pub fn merge_discovered(
    agent: &Path,
    discovered: &[(String, Vec<Value>)],
    register: impl FnOnce(&mut Map<String, Value>) -> bool,
) -> Result<bool, String> {
    let models_file = models_file(agent);
    let _lock = lock(&models_file).map_err(|_| SAVE_ERROR.to_string())?;
    let mut root = read_for_update(&models_file)?;
    let mut changed = false;
    for (provider, models) in discovered {
        if !models.is_empty() {
            changed |= crate::provider_models::merge_models(&mut root, provider, models);
        }
    }
    changed |= register(&mut root);
    if changed {
        write_for_update(&models_file, &root)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve_routes;

    fn temporary_directory() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("muniment-pi-models-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn models(agent: &Path) -> Value {
        serde_json::from_slice(&fs::read(models_file(agent)).unwrap()).unwrap()
    }

    fn ollama_server() -> String {
        serve_routes(vec![
            (
                "GET /api/tags",
                json!({"models": [{"name": "qwen3:8b"}, {"name": "clef"}]}),
            ),
            (
                "POST /api/show qwen3:8b",
                json!({"model_info": {"general.architecture": "qwen3", "qwen3.context_length": 40960}}),
            ),
            (
                "POST /api/show clef",
                json!({"capabilities": ["completion"]}),
            ),
            ("GET /api/ps", json!({"models": []})),
        ])
    }

    #[test]
    fn an_ollama_server_lands_with_each_models_window_after_its_route() {
        let agent = temporary_directory();
        let url = ollama_server();
        let mut routed = None;
        store_ollama(&agent, &url, "", |model| {
            routed = Some(model.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(routed.as_deref(), Some("qwen3:8b"));
        assert_eq!(
            models(&agent)["providers"]["ollama"]["models"],
            json!([{"id": "qwen3:8b", "contextWindow": 40960}, {"id": "clef"}])
        );
        assert_eq!(models(&agent)["providers"]["ollama"]["apiKey"], "ollama");
        // A route that fails leaves the model file as it was.
        let before = fs::read(models_file(&agent)).unwrap();
        assert!(store_ollama(&agent, &url, "sk-new", |_| Err(SAVE_ERROR.into())).is_err());
        assert_eq!(fs::read(models_file(&agent)).unwrap(), before);
        assert!(!lock_path(&models_file(&agent)).exists());
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_discovered_endpoint_carries_its_windows_and_a_named_one_none() {
        let agent = temporary_directory();
        let url = serve_routes(vec![(
            "GET /v1/models",
            json!({"data": [{"id": "qwen3", "max_model_len": 32768}]}),
        )]);
        let id = store_endpoint(&agent, "custom", "vLLM", &url, "", &[]).unwrap();
        assert_eq!(id, "custom-vllm");
        assert_eq!(
            models(&agent)["providers"][&id]["models"],
            json!([{"id": "qwen3", "contextWindow": 32768}])
        );
        assert_eq!(read_record(&agent).unwrap()["names"][&id], "vLLM");
        store_endpoint(&agent, "lmstudio", "", &url, "", &["named".into()]).unwrap();
        assert_eq!(
            models(&agent)["providers"]["lmstudio"]["models"],
            json!([{"id": "named"}])
        );
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_refresh_follows_the_server_and_keeps_what_the_user_set() {
        let agent = temporary_directory();
        let url = ollama_server();
        fs::write(
            models_file(&agent),
            json!({"providers": {
                "ollama": {"baseUrl": url, "apiKey": "ollama", "models": [
                    {"id": "qwen3:8b", "reasoning": true, "contextWindow": 8192},
                    {"id": "gone"}
                ]},
                "openai": {"baseUrl": "http://127.0.0.1:9/v1", "models": [{"id": "kept"}]}
            }})
            .to_string(),
        )
        .unwrap();
        assert!(refresh_endpoints(&agent).unwrap());
        let root = models(&agent);
        assert_eq!(
            root["providers"]["ollama"]["models"],
            json!([{"id": "qwen3:8b", "reasoning": true, "contextWindow": 40960}, {"id": "clef"}])
        );
        assert_eq!(root["providers"]["openai"]["models"][0]["id"], "kept");
        assert!(!refresh_endpoints(&agent).unwrap());
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_merge_adds_discoveries_and_registers_under_one_lock() {
        let agent = temporary_directory();
        fs::write(
            models_file(&agent),
            json!({"providers": {"xai": {"models": [{"id": "grok-old", "contextWindow": 42}]}}})
                .to_string(),
        )
        .unwrap();
        let discovered = vec![(
            "xai".to_owned(),
            vec![
                json!({"id": "grok-old", "contextWindow": 100}),
                json!({"id": "grok-new"}),
            ],
        )];
        let changed = merge_discovered(&agent, &discovered, |root| {
            assert!(lock_path(&models_file(&agent)).exists());
            root.insert("registered".into(), true.into());
            true
        })
        .unwrap();
        assert!(changed);
        let root = models(&agent);
        assert_eq!(root["providers"]["xai"]["models"][0]["contextWindow"], 42);
        assert_eq!(root["providers"]["xai"]["models"][1]["id"], "grok-new");
        assert_eq!(root["registered"], true);
        assert!(!merge_discovered(&agent, &discovered, |_| false).unwrap());
        fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn decision_models_are_kept_by_endpoint_and_cleared_when_none_remain() {
        let agent = temporary_directory();
        store_decision_models(&agent, "llama", &["kev-4b".to_owned()]).unwrap();
        assert_eq!(
            decision_models(&read_record(&agent).unwrap(), "llama"),
            ["kev-4b"]
        );
        store_decision_models(&agent, "llama", &[]).unwrap();
        assert!(decision_models(&read_record(&agent).unwrap(), "llama").is_empty());
        fs::remove_dir_all(agent).unwrap();
    }
}
