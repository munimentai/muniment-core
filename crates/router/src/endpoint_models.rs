//! Model discovery for an OpenAI-compatible endpoint: Ollama's own list at
//! `/api/tags` first, then the `/models` route every compatible server answers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

fn chat_models(
    agent: &ureq::Agent,
    origin: &mut url::Url,
    models: Vec<String>,
    deadline: Instant,
    key: Option<&str>,
) -> Vec<String> {
    origin.set_path("/api/show");
    let url = origin.as_str();
    let next = AtomicUsize::new(0);
    let excluded = Mutex::new(vec![false; models.len()]);
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
                    if response
                        .into_json::<Value>()
                        .is_ok_and(|value| embedding_only(&value))
                    {
                        excluded.lock().unwrap()[index] = true;
                    }
                }
            });
        }
    });
    let excluded = excluded.into_inner().unwrap();
    models
        .into_iter()
        .enumerate()
        .filter_map(|(index, model)| (!excluded[index]).then_some(model))
        .collect()
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
            return Some(chat_models(
                &agent,
                &mut origin,
                parse_ollama_tags(&tags),
                deadline,
                key,
            ));
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
    fetch(&agent, &models_url, key)
        .ok()
        .flatten()
        .filter(|value| value.get("data").is_some_and(Value::is_array))
        .map(|value| parse_openai_models(&value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
                let body = match (keyed, route.starts_with("GET /api/tags")) {
                    (false, _) => None,
                    (true, true) => Some(r#"{"models":[{"name":"jev-small"}]}"#),
                    (true, false) => Some(r#"{"capabilities":["completion"]}"#),
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
        let server = std::thread::spawn(move || serve(listener, 4));
        // Without the key, the tags and the models list both refuse.
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
}
