//! A model's window: how many tokens its context holds and how many one reply
//! may use. A server's or a provider's own report wins, the catalog answers
//! next, and a model neither knows has no window.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{family, model_catalog, provider_models, registry};

/// A context window and an output limit, each when a source knows it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub context: Option<u64>,
    pub output: Option<u64>,
}

impl Limits {
    /// A known context window with no known output limit.
    pub fn context(tokens: u64) -> Self {
        Self {
            context: Some(tokens),
            output: None,
        }
    }

    /// The limits a Pi `models.json` model entry or a discovered catalog
    /// entry carries in `contextWindow` and `maxTokens`.
    pub fn of_entry(entry: &Value) -> Self {
        let tokens = |field| entry.get(field).and_then(Value::as_u64).filter(|n| *n > 0);
        Self {
            context: tokens("contextWindow"),
            output: tokens("maxTokens"),
        }
    }
}

/// Where a window came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// The server or the provider reported it.
    Discovered,
    /// The model catalog describes it.
    Catalog,
}

/// A model's window and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Window {
    pub context: u64,
    pub output: Option<u64>,
    pub source: Source,
}

/// The window of one provider's model: what discovery found first, then the
/// catalog entry of the family the provider pools into, else none.
pub fn resolve(provider: &str, model: &str, discovered: Option<Limits>) -> Option<Window> {
    if let Some(Limits {
        context: Some(context),
        output,
    }) = discovered
    {
        return Some(Window {
            context,
            output,
            source: Source::Discovered,
        });
    }
    // The router serves a catalog model as `family/model`.
    let (family_id, model) = match model.split_once('/') {
        Some((family_id, model)) if provider == registry::ROUTER_PROVIDER => (family_id, model),
        _ => (
            family::family(registry::catalog_id(provider))
                .or_else(|| family::family_for_pi_provider(provider))
                .map(|family| family.id)?,
            model,
        ),
    };
    let entry = model_catalog::entry(family_id, model)?;
    Some(Window {
        context: model_catalog::context_tokens(entry.context)?,
        output: None,
        source: Source::Catalog,
    })
}

/// The window of one provider's model as the agent directory knows it: the
/// model's entry in Pi's `models.json`, which discovery writes, then the
/// provider's discovered catalog, then the model catalog.
pub fn window(agent: &Path, provider: &str, model: &str) -> Option<Window> {
    let listed = std::fs::read(agent.join("models.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|root| {
            find(&root["providers"][provider]["models"], model)
                .map(|entry| Limits::of_entry(&entry))
        });
    let cached = || {
        provider_models::load(agent)
            .get(&format!("provider:{provider}"))
            .and_then(|catalog| {
                catalog
                    .models
                    .iter()
                    .find(|entry| entry["id"] == model)
                    .map(Limits::of_entry)
            })
    };
    let discovered = listed
        .filter(|limits| limits.context.is_some())
        .or_else(cached);
    resolve(provider, model, discovered)
}

fn find(models: &Value, id: &str) -> Option<Value> {
    models
        .as_array()?
        .iter()
        .find(|entry| entry["id"] == id)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discovery_wins_then_the_catalog_answers_and_an_unknown_model_has_no_window() {
        let found = Limits {
            context: Some(32768),
            output: Some(4096),
        };
        assert_eq!(
            resolve("ollama", "qwen3:8b", Some(found)),
            Some(Window {
                context: 32768,
                output: Some(4096),
                source: Source::Discovered
            })
        );
        assert_eq!(resolve("ollama", "qwen3:8b", None), None);
        assert_eq!(resolve("ollama", "qwen3:8b", Some(Limits::default())), None);
        let catalog = Window {
            context: 400_000,
            output: None,
            source: Source::Catalog,
        };
        assert_eq!(resolve("openai", "gpt-5.6-sol", None), Some(catalog));
        assert_eq!(resolve("openai-codex", "gpt-5.6-sol", None), Some(catalog));
        assert_eq!(
            resolve("muniment-router", "openai/gpt-5.6-sol", None),
            Some(catalog)
        );
        assert_eq!(resolve("openai", "gpt-unknown", None), None);
        assert_eq!(resolve("nobody", "gpt-5.6-sol", None), None);
    }

    #[test]
    fn the_agent_directory_answers_from_models_json_then_the_discovered_catalog() {
        let agent = std::env::temp_dir().join(format!("muniment-window-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(
            agent.join("models.json"),
            json!({"providers": {"ollama": {"models": [
                {"id": "qwen3:8b", "contextWindow": 40960},
                {"id": "bare"}
            ]}}})
            .to_string(),
        )
        .unwrap();
        let mut cache = provider_models::Cache::new();
        cache.insert(
            "provider:xai".into(),
            provider_models::Catalog {
                checked_ms: 1,
                models: vec![json!({"id": "grok-new", "contextWindow": 256000, "maxTokens": 8192})],
            },
        );
        provider_models::save(&agent, &cache).unwrap();
        assert_eq!(
            window(&agent, "ollama", "qwen3:8b").map(|window| window.context),
            Some(40960)
        );
        assert_eq!(window(&agent, "ollama", "bare"), None);
        assert_eq!(
            window(&agent, "xai", "grok-new"),
            Some(Window {
                context: 256000,
                output: Some(8192),
                source: Source::Discovered
            })
        );
        assert_eq!(
            window(&agent, "xai", "grok-4.6").map(|window| window.source),
            Some(Source::Catalog)
        );
        std::fs::remove_dir_all(agent).unwrap();
    }
}
