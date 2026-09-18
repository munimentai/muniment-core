//! Registering the router with Pi.
//!
//! Pi reaches an OpenAI-compatible server through one entry in its
//! `models.json`. The router is one such server, so the router's whole
//! presence in Pi is that entry: the loopback base URL, the token as the key,
//! and the models the router serves. Turning the router off removes the entry
//! and nothing else, so Pi goes straight back to its own providers.

use serde_json::{json, Value};

use super::config::{RouterConfig, ROUTER_PROVIDER};
use super::served_models;
use super::server::Endpoint;

/// The `models.json` entry for the router.
pub fn provider_entry(endpoint: &Endpoint, config: &RouterConfig) -> Value {
    json!({
        "baseUrl": endpoint.base_url(),
        "api": "openai-completions",
        "apiKey": endpoint.token,
        "compat": {
            "supportsDeveloperRole": false,
            "supportsReasoningEffort": false
        },
        "models": served_models(config)
            .iter()
            .map(|id| json!({ "id": id }))
            .collect::<Vec<_>>(),
    })
}

/// Writes the router's entry into a `models.json` body, replacing any entry
/// already there.
pub fn register(
    models: &mut serde_json::Map<String, Value>,
    endpoint: &Endpoint,
    config: &RouterConfig,
) {
    let providers = models.entry("providers").or_insert_with(|| json!({}));
    if !providers.is_object() {
        *providers = json!({});
    }
    if let Some(object) = providers.as_object_mut() {
        object.insert(ROUTER_PROVIDER.to_owned(), provider_entry(endpoint, config));
    }
}

/// Removes the router's entry. Answers whether one was there.
pub fn unregister(models: &mut serde_json::Map<String, Value>) -> bool {
    models
        .get_mut("providers")
        .and_then(Value::as_object_mut)
        .is_some_and(|providers| providers.remove(ROUTER_PROVIDER).is_some())
}

/// Whether Pi's settings send turns to the router.
pub fn is_default(settings: &serde_json::Map<String, Value>) -> bool {
    settings.get("defaultProvider").and_then(Value::as_str) == Some(ROUTER_PROVIDER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_router::config::Route;

    fn endpoint() -> Endpoint {
        Endpoint {
            port: 8421,
            token: "t0ken".into(),
        }
    }

    fn routed() -> RouterConfig {
        RouterConfig {
            enabled: true,
            routes: vec![Route {
                key: "fast".into(),
                description: "A short question".into(),
                family: "openai".into(),
                model: "gpt-5.6-mini".into(),
            }],
            fallback: Some("fast".into()),
            ..RouterConfig::default()
        }
    }

    #[test]
    fn the_entry_points_pi_at_the_loopback_port_behind_the_token() {
        let entry = provider_entry(&endpoint(), &routed());
        assert_eq!(entry["baseUrl"], "http://127.0.0.1:8421/v1");
        assert_eq!(entry["api"], "openai-completions");
        assert_eq!(entry["apiKey"], "t0ken");
        assert_eq!(entry["models"][0]["id"], "auto");
        assert_eq!(entry["models"][1]["id"], "fast");
        assert_eq!(entry["models"][2]["id"], "openai/gpt-5.6-mini");
    }

    #[test]
    fn registering_leaves_every_other_provider_alone_and_unregistering_removes_only_ours() {
        let mut models: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "providers": { "ollama": { "baseUrl": "http://localhost:11434/v1" } }
        }))
        .unwrap();
        register(&mut models, &endpoint(), &routed());
        assert!(models["providers"]["ollama"].is_object());
        assert_eq!(models["providers"][ROUTER_PROVIDER]["apiKey"], "t0ken");

        assert!(unregister(&mut models));
        assert!(models["providers"]["ollama"].is_object());
        assert!(models["providers"].get(ROUTER_PROVIDER).is_none());
        assert!(!unregister(&mut models));
    }

    #[test]
    fn registering_into_an_empty_or_damaged_models_file_still_lands() {
        let mut models = serde_json::Map::new();
        register(&mut models, &endpoint(), &routed());
        assert_eq!(
            models["providers"][ROUTER_PROVIDER]["baseUrl"],
            "http://127.0.0.1:8421/v1"
        );

        let mut damaged: serde_json::Map<String, Value> =
            serde_json::from_value(json!({ "providers": "not an object" })).unwrap();
        register(&mut damaged, &endpoint(), &routed());
        assert!(damaged["providers"][ROUTER_PROVIDER].is_object());
    }

    #[test]
    fn pi_sends_turns_to_the_router_only_when_its_settings_name_it() {
        let named: serde_json::Map<String, Value> =
            serde_json::from_value(json!({ "defaultProvider": ROUTER_PROVIDER })).unwrap();
        assert!(is_default(&named));
        let other: serde_json::Map<String, Value> =
            serde_json::from_value(json!({ "defaultProvider": "openai" })).unwrap();
        assert!(!is_default(&other));
        assert!(!is_default(&serde_json::Map::new()));
    }
}
