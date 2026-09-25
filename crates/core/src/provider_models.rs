//! Provider APIs and Pi subscription catalogs. The cache holds model metadata only.
use std::{collections::BTreeMap, fs, io::Read, path::Path, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const CACHE_FILE: &str = "provider-models.json";
pub const TTL_MS: i64 = 10 * 60 * 1000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub checked_ms: i64,
    pub models: Vec<Value>,
}
pub type Cache = BTreeMap<String, Catalog>;

pub fn load(agent: &Path) -> Cache {
    fs::read(agent.join(CACHE_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(agent: &Path, cache: &Cache) -> std::io::Result<()> {
    fs::create_dir_all(agent)?;
    let temporary = agent.join(format!("provider-models-{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&temporary, serde_json::to_vec(cache)?)?;
    crate::atomic_file::replace(&temporary, &agent.join(CACHE_FILE))
}

/// Provider model-list routes and Pi public subscription catalogs.
/// Subscription credentials never enter the API-key discovery path.
pub fn endpoint(provider: &str, oauth: bool) -> Option<(&'static str, &'static str)> {
    if oauth {
        if let Some(endpoint) = subscription_catalog(provider) {
            return Some(endpoint);
        }
        if !matches!(provider, "xai" | "meta") {
            return None;
        }
    }
    Some(match provider {
        "xai" => ("https://api.x.ai/v1/language-models", "openai-responses"),
        "meta" => ("https://api.meta.ai/v1/models", "openai-responses"),
        "openai" => ("https://api.openai.com/v1/models", "openai-responses"),
        "anthropic" => (
            "https://api.anthropic.com/v1/models?limit=1000",
            "anthropic-messages",
        ),
        "google" => (
            "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000",
            "google-generative-ai",
        ),
        _ => return None,
    })
}

// Pi publishes the same provider catalogs its registry refreshes. These are
// public metadata, not inference endpoints. Never send account credentials.
fn subscription_catalog(provider: &str) -> Option<(&'static str, &'static str)> {
    Some(match provider {
        "anthropic" => (
            "https://pi.dev/api/models/providers/anthropic",
            "anthropic-messages",
        ),
        "openai" | "openai-codex" => (
            "https://pi.dev/api/models/providers/openai-codex",
            "openai-codex-responses",
        ),
        "kimi" => (
            "https://pi.dev/api/models/providers/kimi-coding",
            "anthropic-messages",
        ),
        _ => return None,
    })
}

fn parse_subscription_catalog(value: &Value) -> Option<Vec<Value>> {
    let entries = value
        .as_array()
        .or_else(|| value.get("models").and_then(Value::as_array))?;
    let mut models = Vec::new();
    for entry in entries {
        if entry.get("type").is_some_and(|v| v != "chat") {
            continue;
        }
        let id = entry["id"].as_str()?;
        if !valid_id(id) {
            return None;
        }
        let context = entry["contextWindow"].as_u64().filter(|n| *n > 0)?;
        let output = entry["maxTokens"].as_u64().filter(|n| *n > 0)?;
        // Only model metadata crosses this boundary. Remote base URLs, headers,
        // executable settings and credentials never enter the account config.
        let mut model = json!({"id":id,"name":entry["name"].as_str().unwrap_or(id),
            "contextWindow":context,"maxTokens":output});
        for field in ["input", "cost", "reasoning"] {
            if let Some(value) = entry.get(field) {
                model[field] = value.clone();
            }
        }
        if !models.iter().any(|m: &Value| m["id"] == id) {
            models.push(model);
        }
    }
    (!models.is_empty()).then_some(models)
}

fn discover_subscription_catalog(url: &str, timeout: Duration) -> Option<Vec<Value>> {
    let url = format!("{url}?types=chat&pi-version={}", crate::sidecar::PI_VERSION);
    let response = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build()
        .get(&url)
        .set("Accept", "application/json")
        .set("User-Agent", &format!("pi/{}", crate::sidecar::PI_VERSION))
        .call()
        .ok()?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 4 * 1024 * 1024 {
        return None;
    }
    parse_subscription_catalog(&serde_json::from_slice::<Value>(&bytes).ok()?)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.contains(char::is_whitespace)
        && !id.contains(char::is_control)
}

/// Keep conversational models only. Unknown OpenAI families stay out until the
/// provider exposes capabilities, rather than offering embeddings as chat.
pub fn parse(provider: &str, value: &Value) -> Vec<Value> {
    let entries = value
        .get(if matches!(provider, "google" | "xai") {
            "models"
        } else {
            "data"
        })
        .and_then(Value::as_array);
    let mut models = Vec::new();
    for entry in entries.into_iter().flatten() {
        let id = entry
            .get(if provider == "google" { "name" } else { "id" })
            .and_then(Value::as_str)
            .unwrap_or_default();
        let id = if provider == "google" {
            id.strip_prefix("models/").unwrap_or(id)
        } else {
            id
        };
        if !valid_id(id) || models.iter().any(|model: &Value| model["id"] == id) {
            continue;
        }
        if provider == "google"
            && !entry["supportedGenerationMethods"]
                .as_array()
                .is_some_and(|methods| methods.iter().any(|m| m == "generateContent"))
        {
            continue;
        }
        if provider == "openai"
            && (!(id.starts_with("gpt-")
                || id.starts_with("chatgpt-")
                || id.starts_with("o1")
                || id.starts_with("o3")
                || id.starts_with("o4"))
                || [
                    "audio",
                    "realtime",
                    "transcrib",
                    "tts",
                    "image",
                    "search",
                    "instruct",
                ]
                .iter()
                .any(|part| id.contains(part)))
        {
            continue;
        }
        if entry
            .get("output_modalities")
            .and_then(Value::as_array)
            .is_some_and(|m| !m.iter().any(|v| v == "text"))
        {
            continue;
        }
        let mut model = json!({"id": id, "name": entry.get("displayName").or_else(|| entry.get("display_name")).and_then(Value::as_str).unwrap_or(id)});
        for (source, target) in [
            ("inputTokenLimit", "contextWindow"),
            ("max_input_tokens", "contextWindow"),
            ("context_window", "contextWindow"),
            ("outputTokenLimit", "maxTokens"),
            ("max_tokens", "maxTokens"),
        ] {
            if let Some(n) = entry[source].as_u64().filter(|n| *n > 0) {
                model[target] = n.into();
            }
        }
        if let Some(thinking) = entry["thinking"].as_bool() {
            model["reasoning"] = thinking.into();
        }
        if let Some(input) = entry["input_modalities"].as_array() {
            model["input"] = input
                .iter()
                .filter(|v| **v == "text" || **v == "image")
                .cloned()
                .collect::<Vec<_>>()
                .into();
        }
        if provider == "xai" {
            let mut cost = json!({});
            for (field, target) in [
                ("prompt_text_token_price", "input"),
                ("completion_text_token_price", "output"),
                ("cached_prompt_text_token_price", "cacheRead"),
            ] {
                if let Some(price) = entry[field].as_f64().filter(|v| v.is_finite() && *v >= 0.0) {
                    cost[target] = (price / 10000.0).into();
                }
            }
            if cost.get("input").is_some() && cost.get("output").is_some() {
                model["cost"] = cost;
            }
        }
        models.push(model);
    }
    models
}

/// No redirects with credentials, bounded response size and request time.
/// Any incomplete or invalid response leaves the saved catalog intact.
pub fn discover(provider: &str, oauth: bool, token: &str, timeout: Duration) -> Option<Vec<Value>> {
    let (url, _) = endpoint(provider, oauth)?;
    if oauth && subscription_catalog(provider).is_some() {
        return discover_subscription_catalog(url, timeout);
    }
    discover_at(provider, url, token, timeout)
}

fn discover_at(provider: &str, url: &str, token: &str, timeout: Duration) -> Option<Vec<Value>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build();
    let mut request = agent.get(url);
    request = match provider {
        "anthropic" => request
            .set("x-api-key", token)
            .set("anthropic-version", "2023-06-01"),
        "google" => request.set("x-goog-api-key", token),
        _ => request.set("Authorization", &format!("Bearer {token}")),
    };
    let response = request.call().ok()?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 4 * 1024 * 1024 {
        return None;
    }
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    // Never replace a complete cache with a truncated page.
    if value["has_more"] == true
        || value
            .get("nextPageToken")
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
    {
        return None;
    }
    let models = parse(provider, &value);
    (!models.is_empty()).then_some(models)
}

/// Add discoveries without overwriting user model settings or bundled metadata.
pub fn merge_models(
    root: &mut serde_json::Map<String, Value>,
    provider: &str,
    models: &[Value],
) -> bool {
    let Some(providers) = root
        .entry("providers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return false;
    };
    let Some(entry) = providers
        .entry(provider.to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return false;
    };
    let Some(existing) = entry
        .entry("models")
        .or_insert_with(|| json!([]))
        .as_array_mut()
    else {
        return false;
    };
    let mut changed = false;
    for model in models {
        if !existing.iter().any(|old| old["id"] == model["id"]) {
            existing.push(model.clone());
            changed = true;
        }
    }
    // Pi rejects the entire file if a cost object omits a required field.
    // Use the uncached input price when an upstream catalog omits cache pricing.
    for model in existing {
        if let Some(cost) = model.get_mut("cost").and_then(Value::as_object_mut) {
            if let Some(input) = cost.get("input").cloned() {
                for field in ["cacheRead", "cacheWrite"] {
                    if !cost.contains_key(field) {
                        cost.insert(field.into(), input.clone());
                        changed = true;
                    }
                }
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_new_subscription_model_reaches_the_router_without_a_catalog_edit() {
        use crate::model_router::{config, options};
        let models = parse_subscription_catalog(&json!([
            {"id":"brand-new-model", "contextWindow":123456, "maxTokens":8192,
             "cost":{"input":2,"output":8}, "input":["text"], "reasoning":true,
             "baseUrl":"https://untrusted.example", "headers":{"authorization":"never-copy"}},
            {"type":"image","id":"image-only"}
        ]))
        .unwrap();
        assert_eq!(models.len(), 1);
        assert!(models[0].get("baseUrl").is_none());
        assert!(models[0].get("headers").is_none());
        let agent =
            std::env::temp_dir().join(format!("muniment-discovery-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&agent).unwrap();
        let mut settings = config::RouterConfig::default();
        settings.enabled = true;
        settings.accounts.push(
            serde_json::from_value(json!({
                "id":"claude-account","family":"anthropic","label":"Claude",
                "credential":{"type":"subscription","provider":"anthropic","access":"fixture"},
                "enabled":true,"weight":1,"models":[]
            }))
            .unwrap(),
        );
        config::save(&agent, &settings).unwrap();
        let mut cache = Cache::new();
        cache.insert(
            "account:claude-account".into(),
            Catalog {
                checked_ms: 1,
                models,
            },
        );
        save(&agent, &cache).unwrap();
        let loaded = config::load(&agent).unwrap();
        let routes = options(&loaded);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].model, "brand-new-model");
        assert!(parse_subscription_catalog(&json!([{ "id":"broken" }])).is_none());
        assert!(parse_subscription_catalog(&json!([])).is_none());
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn public_catalog_requests_never_send_credentials() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/catalog", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            assert!(headers.contains("pi-version="));
            assert!(!headers.to_lowercase().contains("authorization"));
            assert!(!headers.to_lowercase().contains("api-key"));
            let body = r#"[{"id":"new-model","contextWindow":100000,"maxTokens":8192}]"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        assert_eq!(
            discover_subscription_catalog(&url, Duration::from_secs(3)).unwrap()[0]["id"],
            "new-model"
        );
        server.join().unwrap();
    }

    #[test]
    fn discovery_filters_non_chat_models_and_keeps_metadata() {
        let google = parse(
            "google",
            &json!({"models":[{"name":"models/gemini-new","supportedGenerationMethods":["generateContent"],"inputTokenLimit":1000000,"thinking":true},{"name":"models/embed","supportedGenerationMethods":["embedContent"]}]}),
        );
        assert_eq!(google.len(), 1);
        assert_eq!(google[0]["contextWindow"], 1000000);
        assert_eq!(parse("openai", &json!({"data":[{"id":"gpt-new"},{"id":"gpt-new"},{"id":"gpt-audio"},{"id":"text-embedding-3"},{"id":"bad\nmodel"}]})).len(), 1);
        assert_eq!(
            parse(
                "xai",
                &json!({"models":[{"id":"grok-4.7","input_modalities":["text","image"],"output_modalities":["text"]}]})
            )[0]["id"],
            "grok-4.7"
        );
        assert!(endpoint("openai-codex", true)
            .unwrap()
            .0
            .starts_with("https://pi.dev/"));
    }
    #[test]
    fn discoveries_preserve_custom_settings_and_are_idempotent() {
        let mut root = json!({"providers":{"xai":{"headers":{"custom":"keep"},"models":[{"id":"grok-old","contextWindow":42}]}}}).as_object().unwrap().clone();
        let new = vec![
            json!({"id":"grok-old","contextWindow":100}),
            json!({"id":"grok-new"}),
        ];
        assert!(merge_models(&mut root, "xai", &new));
        assert!(!merge_models(&mut root, "xai", &new));
        assert_eq!(root["providers"]["xai"]["models"][0]["contextWindow"], 42);
        assert_eq!(root["providers"]["xai"]["headers"]["custom"], "keep");
    }
    #[test]
    fn authenticated_request_and_failed_refresh_keep_the_cache_usable() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/models", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            assert!(headers
                .to_lowercase()
                .contains("authorization: bearer test-token"));
            let body = r#"{"models":[{"id":"grok-new"}]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        assert_eq!(
            discover_at("xai", &url, "test-token", Duration::from_secs(2)).unwrap()[0]["id"],
            "grok-new"
        );
        server.join().unwrap();
        assert!(discover_at("xai", &url, "test-token", Duration::from_millis(50)).is_none());
    }
}

#[test]
fn cached_discovery_repairs_incomplete_prices_without_removing_other_providers() {
    let mut root = json!({"providers":{"muniment-router":{"models":[{"id":"auto"}]},"xai":{"models":[{"id":"grok","cost":{"input":2,"output":6,"cacheRead":0.2}}]}}}).as_object().unwrap().clone();
    let models = vec![json!({"id":"grok","cost":{"input":2,"output":6,"cacheRead":0.2}})];
    assert!(merge_models(&mut root, "xai", &models));
    assert_eq!(
        root["providers"]["xai"]["models"][0]["cost"],
        json!({"input":2,"output":6,"cacheRead":0.2,"cacheWrite":2})
    );
    assert_eq!(
        root["providers"]["muniment-router"]["models"][0]["id"],
        "auto"
    );
    assert!(!merge_models(&mut root, "xai", &models));
}
