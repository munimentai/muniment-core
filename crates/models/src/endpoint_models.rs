//! Model discovery for an OpenAI-compatible endpoint: Ollama's own list at
//! `/api/tags` first, then the `/models` route every compatible server answers.
//! Discovery also reads each model's context window where the server reports
//! it: Ollama's `/api/show` and `/api/ps`, llama.cpp's `/props`, LM Studio's
//! REST model list and vLLM's `max_model_len`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::window::Limits;

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

/// The JSON body, `Ok(None)` for an HTTP error or a body that is not JSON,
/// and `Err` when the host never answered: no route, a refused connection or
/// a timeout.
fn fetch(agent: &ureq::Agent, url: &str, key: Option<&str>) -> Result<Option<Value>, ()> {
    match authorized(agent.get(url), key).call() {
        Ok(response) => Ok(response.into_json::<Value>().ok()),
        Err(ureq::Error::Status(..)) => Ok(None),
        Err(ureq::Error::Transport(_)) => Err(()),
    }
}

/// A server behind a key, such as an Ollama server on another host, answers
/// only a request that carries it.
fn authorized(request: ureq::Request, key: Option<&str>) -> ureq::Request {
    match key {
        Some(key) => request.set("Authorization", &format!("Bearer {key}")),
        None => request,
    }
}

fn embedding_only(value: &Value) -> bool {
    let Some(capabilities) = value.get("capabilities").and_then(Value::as_array) else {
        return false;
    };
    capabilities.iter().any(|value| value == "embedding")
        && !capabilities.iter().any(|value| value == "completion")
}

/// What Ollama's `/api/show` says about one model: whether it only embeds, the
/// context it was trained for, and the `num_ctx` its Modelfile sets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct OllamaShow {
    embedding_only: bool,
    trained: Option<u64>,
    num_ctx: Option<u64>,
}

fn ollama_show(value: &Value) -> OllamaShow {
    let info = value.get("model_info");
    let trained = info
        .and_then(|info| info.get("general.architecture"))
        .and_then(Value::as_str)
        .and_then(|architecture| info?.get(format!("{architecture}.context_length")))
        .and_then(positive);
    let num_ctx = value
        .get("parameters")
        .and_then(Value::as_str)
        .and_then(|parameters| {
            parameters.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("num_ctx"))
                    .then(|| words.next()?.parse::<u64>().ok())
                    .flatten()
            })
        })
        .filter(|tokens| *tokens > 0);
    OllamaShow {
        embedding_only: embedding_only(value),
        trained,
        num_ctx,
    }
}

fn positive(value: &Value) -> Option<u64> {
    value.as_u64().filter(|tokens| *tokens > 0)
}

/// The window a request gets: the smaller of the trained and the served
/// length when both are known, else whichever is.
fn smaller(trained: Option<u64>, served: Option<u64>) -> Option<u64> {
    match (trained, served) {
        (Some(trained), Some(served)) => Some(trained.min(served)),
        (trained, served) => trained.or(served),
    }
}

fn chat_models(
    agent: &ureq::Agent,
    origin: &mut url::Url,
    models: Vec<String>,
    deadline: Instant,
    key: Option<&str>,
) -> (Vec<String>, BTreeMap<String, Limits>) {
    origin.set_path("/api/show");
    let url = origin.as_str();
    let next = AtomicUsize::new(0);
    let shown = Mutex::new(vec![OllamaShow::default(); models.len()]);
    // Bound both concurrent metadata requests and the whole discovery budget.
    std::thread::scope(|scope| {
        for _ in 0..models.len().min(4) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(model) = models.get(index) else {
                    break;
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                if let Ok(response) = authorized(agent.post(url), key)
                    .timeout(remaining)
                    .send_json(serde_json::json!({"model": model}))
                {
                    if let Ok(value) = response.into_json::<Value>() {
                        shown.lock().unwrap()[index] = ollama_show(&value);
                    }
                }
            });
        }
    });
    let shown = shown.into_inner().unwrap();
    let chat: Vec<(String, OllamaShow)> = models
        .into_iter()
        .zip(shown)
        .filter(|(_, show)| !show.embedding_only)
        .collect();
    // A loaded model reports the context it runs with.
    let mut loaded = BTreeMap::new();
    if !chat.is_empty() {
        origin.set_path("/api/ps");
        if let Some(Some(ps)) = remaining_fetch(origin.as_str(), key, deadline) {
            for entry in ps
                .get("models")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(context) = entry.get("context_length").and_then(positive) else {
                    continue;
                };
                for field in ["name", "model"] {
                    if let Some(name) = entry.get(field).and_then(Value::as_str) {
                        loaded.insert(name.to_owned(), context);
                    }
                }
            }
        }
    }
    let mut windows = BTreeMap::new();
    for (model, show) in &chat {
        let served = loaded.get(model).copied().or(show.num_ctx);
        if let Some(context) = smaller(show.trained, served) {
            windows.insert(model.clone(), Limits::context(context));
        }
    }
    (chat.into_iter().map(|(model, _)| model).collect(), windows)
}

/// One GET within what is left of the discovery budget. `None` when no time
/// is left or the host never answered.
fn remaining_fetch(url: &str, key: Option<&str>, deadline: Instant) -> Option<Option<Value>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let agent = crate::http::agent_builder().timeout(remaining).build();
    fetch(&agent, url, key).ok()
}

/// What an endpoint serves, by kind. A decision model answers typed
/// questions on the server's System One route and never a chat turn.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EndpointModels {
    pub chat: Vec<String>,
    pub decisions: Vec<String>,
    /// The window of each chat model whose server reports one.
    pub windows: BTreeMap<String, Limits>,
}

/// llama.cpp 0.6.0 and later list `decisions` in a decision model's
/// `architecture.output_modalities`. A model that also lists `text` chats too.
fn split_openai_models(value: &Value) -> EndpointModels {
    let mut models = EndpointModels::default();
    let ids = parse_openai_models(value);
    for id in ids {
        let modalities = entry_of(value, &id)
            .and_then(|entry| entry.pointer("/architecture/output_modalities"))
            .and_then(Value::as_array);
        let reports = |kind: &str| modalities.is_some_and(|list| list.iter().any(|v| v == kind));
        if reports("decisions") {
            models.decisions.push(id.clone());
            if !reports("text") {
                continue;
            }
        }
        if let Some(context) = entry_of(value, &id).and_then(|entry| {
            // vLLM serves `max_model_len`; llama.cpp reports the trained length.
            smaller(
                entry.pointer("/meta/n_ctx_train").and_then(positive),
                entry.get("max_model_len").and_then(positive),
            )
        }) {
            models.windows.insert(id.clone(), Limits::context(context));
        }
        models.chat.push(id);
    }
    models
}

fn entry_of<'a>(value: &'a Value, id: &str) -> Option<&'a Value> {
    value
        .get("data")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str).map(str::trim) == Some(id))
}

/// Reads the served context from the server's own routes when its model list
/// gave none it can serve with: llama.cpp's `/props`, then LM Studio's REST
/// list, current then legacy.
fn served_windows(
    origin: &mut url::Url,
    list: &Value,
    models: &mut EndpointModels,
    key: Option<&str>,
    deadline: Instant,
) {
    let llama = list
        .get("data")
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry.pointer("/meta/n_ctx_train").is_some())
        });
    if llama {
        // `/props` describes the one model a single-model server loads.
        if let [model] = models.chat.as_slice() {
            origin.set_path("/props");
            let served = remaining_fetch(origin.as_str(), key, deadline)
                .flatten()
                .and_then(|props| {
                    props
                        .pointer("/default_generation_settings/n_ctx")
                        .and_then(positive)
                });
            if let Some(served) = served {
                let trained = models.windows.get(model).and_then(|limits| limits.context);
                let context = trained.map_or(served, |trained| trained.min(served));
                models
                    .windows
                    .insert(model.clone(), Limits::context(context));
            }
        }
        return;
    }
    if !models.windows.is_empty() || models.chat.is_empty() {
        return;
    }
    origin.set_path("/api/v1/models");
    let current = remaining_fetch(origin.as_str(), key, deadline).flatten();
    let entries = current
        .as_ref()
        .and_then(|value| value.get("models"))
        .and_then(Value::as_array);
    if let Some(entries) = entries {
        for entry in entries {
            let served = entry
                .get("loaded_instances")
                .and_then(Value::as_array)
                .and_then(|instances| instances.first())
                .and_then(|instance| instance.pointer("/config/context_length"))
                .and_then(positive);
            lm_studio_window(
                models,
                entry.get("key"),
                entry.get("max_context_length"),
                served,
            );
        }
        return;
    }
    origin.set_path("/api/v0/models");
    let legacy = remaining_fetch(origin.as_str(), key, deadline).flatten();
    for entry in legacy
        .as_ref()
        .and_then(|value| value.get("data"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let served = entry.get("loaded_context_length").and_then(positive);
        lm_studio_window(
            models,
            entry.get("id"),
            entry.get("max_context_length"),
            served,
        );
    }
}

fn lm_studio_window(
    models: &mut EndpointModels,
    id: Option<&Value>,
    trained: Option<&Value>,
    served: Option<u64>,
) {
    let Some(id) = id.and_then(Value::as_str).map(str::trim) else {
        return;
    };
    if !models.chat.iter().any(|model| model == id) {
        return;
    }
    if let Some(context) = smaller(trained.and_then(positive), served) {
        models
            .windows
            .insert(id.to_owned(), Limits::context(context));
    }
}

/// Chat models the endpoint serves. `None` means discovery failed; an empty
/// list means the server answered but has no chat models.
pub fn discover_models(base_url: &str, timeout: Duration) -> Option<Vec<String>> {
    discover_models_with_key(base_url, None, timeout)
}

/// Chat models an endpoint behind a key serves. A blank key sends none.
pub fn discover_models_with_key(
    base_url: &str,
    key: Option<&str>,
    timeout: Duration,
) -> Option<Vec<String>> {
    discover_endpoint_models(base_url, key, timeout).map(|models| models.chat)
}

/// The chat and decision models an endpoint behind a key serves.
pub fn discover_endpoint_models(
    base_url: &str,
    key: Option<&str>,
    timeout: Duration,
) -> Option<EndpointModels> {
    let key = key.map(str::trim).filter(|key| !key.is_empty());
    let mut origin = url::Url::parse(base_url).ok()?;
    if !matches!(origin.scheme(), "http" | "https") || origin.host().is_none() {
        return None;
    }
    let deadline = Instant::now() + timeout;
    let agent = crate::http::agent_builder().timeout(timeout).build();
    origin.set_path("/api/tags");
    origin.set_query(None);
    origin.set_fragment(None);
    match fetch(&agent, origin.as_str(), key) {
        Ok(Some(tags)) if tags.get("models").is_some_and(Value::is_array) => {
            let (chat, windows) =
                chat_models(&agent, &mut origin, parse_ollama_tags(&tags), deadline, key);
            return Some(EndpointModels {
                chat,
                decisions: Vec::new(),
                windows,
            });
        }
        Ok(_) => {}
        Err(()) => return None,
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let agent = crate::http::agent_builder().timeout(remaining).build();
    let models_url = format!("{}/models", base_url.trim_end_matches('/'));
    let list = fetch(&agent, &models_url, key)
        .ok()
        .flatten()
        .filter(|value| value.get("data").is_some_and(Value::is_array))?;
    let mut models = split_openai_models(&list);
    served_windows(&mut origin, &list, &mut models, key, deadline);
    Some(models)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::serve_routes;
    use serde_json::json;

    #[test]
    fn decision_models_are_told_from_chat_models_by_what_the_server_reports() {
        let models = split_openai_models(&json!({"data": [
            {"id": "qwen3", "architecture": {"output_modalities": ["text"]}},
            {"id": "kev-4b", "architecture": {"output_modalities": ["decisions"]}},
            {"id": "both", "architecture": {"output_modalities": ["text", "decisions"]}},
            {"id": "older"},
        ]}));
        assert_eq!(models.chat, ["qwen3", "both", "older"]);
        assert_eq!(models.decisions, ["kev-4b", "both"]);
    }

    #[test]
    fn only_explicit_embedding_only_models_are_excluded() {
        assert!(embedding_only(&json!({"capabilities":["embedding"]})));
        assert!(!embedding_only(
            &json!({"capabilities":["completion", "embedding"]})
        ));
        assert!(!embedding_only(
            &json!({"capabilities":["completion", "vision"]})
        ));
        assert!(!embedding_only(&json!({})));
    }

    #[test]
    fn an_embedding_only_server_returns_an_empty_catalog_without_fallback() {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for (route, body) in [
                (
                    "GET /api/tags",
                    r#"{"models":[{"name":"nomic-embed-text"}]}"#,
                ),
                ("POST /api/show", r#"{"capabilities":["embedding"]}"#),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with(route));
                let mut length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut data = vec![0; length];
                reader.read_exact(&mut data).unwrap();
                if length > 0 {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&data).unwrap()["model"],
                        "nomic-embed-text"
                    );
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        assert_eq!(discover_models(&url, Duration::from_secs(3)), Some(vec![]));
        server.join().unwrap();
    }

    #[test]
    fn a_server_behind_a_key_lists_its_models_only_with_the_key() {
        use std::io::{BufRead, BufReader, Read, Write};
        // Answers each request with its models when it carries the key, else 401.
        fn serve(listener: std::net::TcpListener, requests: usize) {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let (mut line, mut route, mut keyed, mut length) =
                    (String::new(), String::new(), false, 0);
                reader.read_line(&mut route).unwrap();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    keyed |= lower.trim() == "authorization: bearer secret";
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; length]).unwrap();
                let body = match (keyed, route.split(' ').nth(1).unwrap_or_default()) {
                    (false, _) => None,
                    (true, "/api/tags") => Some(r#"{"models":[{"name":"jev-small"}]}"#),
                    (true, "/api/ps") => Some(r#"{"models":[]}"#),
                    (true, _) => Some(r#"{"capabilities":["completion"]}"#),
                };
                let (status, body) = body.map_or(("401 Unauthorized", ""), |b| ("200 OK", b));
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || serve(listener, 5));
        // Without the key, the tags and the models list both refuse. With it,
        // the tags, the model and the loaded models answer.
        assert_eq!(discover_models(&url, Duration::from_secs(3)), None);
        assert_eq!(
            discover_models_with_key(&url, Some(" secret "), Duration::from_secs(3)),
            Some(vec!["jev-small".to_owned()])
        );
        server.join().unwrap();
    }

    #[test]
    fn both_list_shapes_parse_in_server_order_without_repeats() {
        let tags = json!({ "models": [
            { "name": "llama3.2:3b", "size": 1 },
            { "name": "hf.co/munimentai/Example-4B-GGUF:Q4_K_M" },
            { "name": "llama3.2:3b" },
            { "name": "  " },
            { "model": "no-name" }
        ] });
        assert_eq!(
            parse_ollama_tags(&tags),
            vec!["llama3.2:3b", "hf.co/munimentai/Example-4B-GGUF:Q4_K_M"]
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
        assert!(discover_models("http://127.0.0.1:9/v1", Duration::from_millis(300)).is_none());
        assert!(discover_models("ftp://host/v1", Duration::from_millis(300)).is_none());
        assert!(discover_models("not a url", Duration::from_millis(300)).is_none());
    }

    fn windows(url: &str) -> Vec<(String, Option<u64>)> {
        discover_endpoint_models(url, None, Duration::from_secs(3))
            .unwrap()
            .windows
            .into_iter()
            .map(|(id, limits)| (id, limits.context))
            .collect()
    }

    #[test]
    fn ollama_windows_take_the_smaller_of_the_trained_and_the_served_context() {
        let url = serve_routes(vec![
            (
                "GET /api/tags",
                json!({"models": [{"name": "set"}, {"name": "loaded"}, {"name": "trained"}, {"name": "bare"}]}),
            ),
            (
                "POST /api/show set",
                json!({"parameters": "num_ctx                        8192\nstop \"<end>\"",
                    "model_info": {"general.architecture": "qwen3", "qwen3.context_length": 40960}}),
            ),
            (
                "POST /api/show loaded",
                json!({"model_info": {"general.architecture": "llama", "llama.context_length": 131072}}),
            ),
            (
                "POST /api/show trained",
                json!({"model_info": {"general.architecture": "gemma3", "gemma3.context_length": 32768}}),
            ),
            (
                "POST /api/show bare",
                json!({"capabilities": ["completion"]}),
            ),
            (
                "GET /api/ps",
                json!({"models": [{"name": "loaded", "model": "loaded", "context_length": 4096}]}),
            ),
        ]);
        assert_eq!(
            windows(&url),
            [
                ("loaded".to_owned(), Some(4096)),
                ("set".to_owned(), Some(8192)),
                ("trained".to_owned(), Some(32768)),
            ]
        );
    }

    #[test]
    fn llama_cpp_and_vllm_windows_come_from_their_own_fields() {
        let llama = serve_routes(vec![
            (
                "GET /v1/models",
                json!({"data": [{"id": "gemma", "meta": {"n_ctx_train": 131072}}]}),
            ),
            (
                "GET /props",
                json!({"default_generation_settings": {"n_ctx": 4096}}),
            ),
        ]);
        assert_eq!(windows(&llama), [("gemma".to_owned(), Some(4096))]);
        let vllm = serve_routes(vec![(
            "GET /v1/models",
            json!({"data": [{"id": "qwen3", "max_model_len": 32768}, {"id": "lora"}]}),
        )]);
        assert_eq!(windows(&vllm), [("qwen3".to_owned(), Some(32768))]);
    }

    #[test]
    fn lm_studio_windows_come_from_its_rest_list_current_then_legacy() {
        let models = json!({"data": [{"id": "qwen3"}, {"id": "gemma"}]});
        let current = serve_routes(vec![
            ("GET /v1/models", models.clone()),
            (
                "GET /api/v1/models",
                json!({"models": [
                    {"type": "llm", "key": "qwen3", "max_context_length": 262144,
                     "loaded_instances": [{"id": "qwen3", "config": {"context_length": 4096}}]},
                    {"type": "llm", "key": "gemma", "max_context_length": 131072, "loaded_instances": []},
                    {"type": "llm", "key": "unlisted", "max_context_length": 8192}
                ]}),
            ),
        ]);
        assert_eq!(
            windows(&current),
            [
                ("gemma".to_owned(), Some(131072)),
                ("qwen3".to_owned(), Some(4096))
            ]
        );
        let legacy = serve_routes(vec![
            ("GET /v1/models", models),
            (
                "GET /api/v0/models",
                json!({"data": [{"id": "qwen3", "state": "loaded", "max_context_length": 32768,
                    "loaded_context_length": 8192}]}),
            ),
        ]);
        assert_eq!(windows(&legacy), [("qwen3".to_owned(), Some(8192))]);
    }

    #[test]
    fn a_server_that_reports_no_window_leaves_it_unknown() {
        let url = serve_routes(vec![("GET /v1/models", json!({"data": [{"id": "plain"}]}))]);
        let found = discover_endpoint_models(&url, None, Duration::from_secs(3)).unwrap();
        assert_eq!(found.chat, ["plain"]);
        assert!(found.windows.is_empty());
    }
}
