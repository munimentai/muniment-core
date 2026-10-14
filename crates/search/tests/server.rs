//! The loopback server's contract: the SearXNG JSON shape, the token, and
//! the endpoint file.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use common::{Answer, Engines};
use muniment_search::server::{self, read_endpoint, ENDPOINT_FILE};
use muniment_search::EngineId;
use serde_json::Value;

/// Sends one raw GET and returns the status and body.
fn get(port: u16, target: &str, token: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: application/json\r\n{auth}\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert!(head
        .to_lowercase()
        .contains("content-type: application/json"));
    (status, body.to_owned())
}

fn start(engines: &Engines) -> (tempdir::Dir, server::Handle) {
    let dir = tempdir::Dir::new();
    let search = Arc::new(engines.metasearch(&[EngineId::Brave, EngineId::Bing]));
    let handle = server::start(&dir.path().join(ENDPOINT_FILE), search).unwrap();
    (dir, handle)
}

#[test]
fn search_answers_searxng_json_behind_the_token() {
    let engines = Engines::default()
        .answer(
            EngineId::Brave,
            Answer::Results(vec!["https://a.example/", "https://b.example/"]),
        )
        .answer(EngineId::Bing, Answer::Results(vec!["https://a.example"]));
    let (dir, handle) = start(&engines);
    let endpoint = handle.endpoint().clone();
    assert_eq!(
        read_endpoint(&dir.path().join(ENDPOINT_FILE)),
        Some(endpoint.clone())
    );
    assert_eq!(endpoint.token.len(), 64);
    assert_eq!(
        endpoint.base_url(),
        format!("http://127.0.0.1:{}", endpoint.port)
    );
    let port = endpoint.port;
    let token = endpoint.token.as_str();

    let (status, body) = get(port, "/healthz", None);
    assert_eq!((status, body.as_str()), (200, r#"{"ok":true}"#));

    let target = "/search?q=rust%20lang&format=json";
    assert_eq!(get(port, target, None).0, 401);
    assert_eq!(get(port, target, Some("wrong")).0, 401);
    assert!(engines.searches(EngineId::Brave).is_empty());

    let (status, body) = get(port, target, Some(token));
    assert_eq!(status, 200);
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["query"], "rust lang");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["url"], "https://a.example/");
    assert_eq!(results[0]["title"], "Title 1");
    assert_eq!(results[0]["content"], "About https://a.example/");
    assert_eq!(results[0]["engines"], serde_json::json!(["brave", "bing"]));
    assert_eq!(results[1]["url"], "https://b.example/");
    assert_eq!(body["unresponsive_engines"], serde_json::json!([]));
    assert_eq!(
        engines.searches(EngineId::Brave),
        ["https://search.brave.com/search?q=rust+lang&source=web"]
    );
}

#[test]
fn requests_outside_the_contract_are_refused() {
    let engines =
        Engines::default().answer(EngineId::Brave, Answer::Results(vec!["https://a.example/"]));
    let (_dir, handle) = start(&engines);
    let (port, token) = (handle.endpoint().port, handle.endpoint().token.clone());
    let token = Some(token.as_str());
    assert_eq!(get(port, "/search?q=rust&format=html", token).0, 400);
    assert_eq!(get(port, "/search?q=rust", token).0, 400);
    assert_eq!(get(port, "/search?format=json", token).0, 400);
    assert_eq!(
        get(port, "/search?q=rust&format=json&time_range=decade", token).0,
        400
    );
    assert_eq!(get(port, "/other", token).0, 404);
    let (status, body) = get(port, "/search?q=rust&format=json&time_range=week", token);
    assert_eq!(status, 200);
    assert!(serde_json::from_str::<Value>(&body).is_ok());
    assert_eq!(
        engines.searches(EngineId::Brave),
        ["https://search.brave.com/search?q=rust&source=web&tf=pw"]
    );
}

#[test]
fn every_engine_failing_answers_service_unavailable() {
    let engines = Engines::default()
        .answer(EngineId::Brave, Answer::Status(429))
        .answer(EngineId::Bing, Answer::Status(403));
    let (_dir, handle) = start(&engines);
    let endpoint = handle.endpoint().clone();
    let (status, body) = get(
        endpoint.port,
        "/search?q=rust&format=json",
        Some(&endpoint.token),
    );
    assert_eq!(status, 503);
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["results"], serde_json::json!([]));
    assert_eq!(
        body["unresponsive_engines"],
        serde_json::json!([
            ["brave", "blocked: HTTP 429"],
            ["bing", "blocked: HTTP 403"]
        ])
    );
}

#[test]
fn a_replaced_metasearch_answers_later_searches_on_the_same_endpoint() {
    let engines = Engines::default()
        .answer(EngineId::Brave, Answer::Results(vec!["https://a.example/"]))
        .answer(EngineId::Bing, Answer::Results(vec!["https://b.example/"]));
    let (_dir, handle) = start(&engines);
    let endpoint = handle.endpoint().clone();
    handle.replace_search(Arc::new(engines.metasearch(&[EngineId::Bing])));
    assert_eq!(handle.search().engines(), [EngineId::Bing]);
    let (status, body) = get(
        endpoint.port,
        "/search?q=rust&format=json",
        Some(&endpoint.token),
    );
    assert_eq!(status, 200);
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["results"][0]["url"], "https://b.example/");
    assert!(engines.searches(EngineId::Brave).is_empty());
    assert_eq!(handle.endpoint(), &endpoint);
}

#[test]
fn a_stopped_server_accepts_no_more_connections() {
    let (_dir, handle) = start(&Engines::default());
    let port = handle.endpoint().port;
    assert_eq!(get(port, "/healthz", None).0, 200);
    drop(handle);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "the listener still accepts"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// A temporary directory removed on drop.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new() -> Self {
            let mut bytes = [0_u8; 8];
            getrandom::fill(&mut bytes).unwrap();
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("muniment-search-{name}"));
            std::fs::create_dir_all(&path).unwrap();
            Dir(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
