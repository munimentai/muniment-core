//! Model discovery for an OpenAI-compatible endpoint: Ollama's own list at
//! `/api/tags` first, then the `/models` route every compatible server answers.

use std::time::Duration;

use serde_json::Value;

/// Ollama's `/api/tags`: `models[].name`.
pub fn parse_ollama_tags(value: &Value) -> Vec<String> {
    names(value.get("models"), "name")
}

/// The OpenAI-compatible `/models`: `data[].id`.
pub fn parse_openai_models(value: &Value) -> Vec<String> {
    names(value.get("data"), "id")
}

fn names(list: Option<&Value>, field: &str) -> Vec<String> {
    let mut seen = Vec::new();
    for entry in list.and_then(Value::as_array).into_iter().flatten() {
        if let Some(name) = entry.get(field).and_then(Value::as_str) {
            let name = name.trim();
            if !name.is_empty() && !seen.iter().any(|known| known == name) {
                seen.push(name.to_owned());
            }
        }
    }
    seen
}

fn fetch(agent: &ureq::Agent, url: &str) -> Option<Value> {
    agent.get(url).call().ok()?.into_json::<Value>().ok()
}

/// Every model the server at `base_url` serves, or nothing when it does not answer.
pub fn discover_models(base_url: &str, timeout: Duration) -> Vec<String> {
    let Ok(mut origin) = url::Url::parse(base_url) else {
        return Vec::new();
    };
    if !matches!(origin.scheme(), "http" | "https") || origin.host().is_none() {
        return Vec::new();
    }
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    origin.set_path("/api/tags");
    origin.set_query(None);
    origin.set_fragment(None);
    if let Some(tags) = fetch(&agent, origin.as_str()) {
        let models = parse_ollama_tags(&tags);
        if !models.is_empty() {
            return models;
        }
    }
    let models_url = format!("{}/models", base_url.trim_end_matches('/'));
    fetch(&agent, &models_url)
        .map(|value| parse_openai_models(&value))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn both_list_shapes_parse_in_server_order_without_repeats() {
        let tags = json!({ "models": [
            { "name": "llama3.2:3b", "size": 1 },
            { "name": "hf.co/munimentai/Qwen3.5-4B-GGUF:Q4_K_M" },
            { "name": "llama3.2:3b" },
            { "name": "  " },
            { "model": "no-name" }
        ] });
        assert_eq!(
            parse_ollama_tags(&tags),
            vec!["llama3.2:3b", "hf.co/munimentai/Qwen3.5-4B-GGUF:Q4_K_M"]
        );
        let openai = json!({ "object": "list", "data": [{ "id": "qwen3", "object": "model" }, { "id": "gpt-oss:latest" }] });
        assert_eq!(
            parse_openai_models(&openai),
            vec!["qwen3", "gpt-oss:latest"]
        );
        assert!(parse_ollama_tags(&json!({})).is_empty());
        assert!(parse_openai_models(&json!({ "data": "x" })).is_empty());
    }

    #[test]
    fn a_server_that_does_not_answer_yields_nothing() {
        assert!(discover_models("http://127.0.0.1:9/v1", Duration::from_millis(300)).is_empty());
        assert!(discover_models("ftp://host/v1", Duration::from_millis(300)).is_empty());
        assert!(discover_models("not a url", Duration::from_millis(300)).is_empty());
    }
}
