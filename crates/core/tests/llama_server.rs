use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use muniment_core::llama::{
    ChatCompletionRequest, ChatMessage, LlamaChatClient, LlamaChatError, LlamaHealthClient,
    LlamaServerConfig, LoopbackHost,
};
use muniment_core::sidecar::{ProbeOutcome, RestartPolicy, SidecarStatus, SidecarSupervisor};

fn fixture(responses: Vec<String>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let worker = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let count = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..count]).starts_with("GET /health "));
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (url, worker)
}

fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn chat_fixture(response: String) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            request.extend_from_slice(&buffer[..count]);
            let headers_end = request.windows(4).position(|part| part == b"\r\n\r\n");
            if let Some(end) = headers_end {
                let headers = String::from_utf8_lossy(&request[..end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::parse::<usize>)
                    })
                    .transpose()
                    .unwrap()
                    .unwrap();
                if request.len() >= end + 4 + content_length {
                    break;
                }
            }
        }
        sender.send(String::from_utf8(request).unwrap()).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
    });
    (url, receiver, worker)
}

fn chat_request() -> ChatCompletionRequest {
    ChatCompletionRequest::new(
        "local-model",
        vec![
            ChatMessage::system("private-system"),
            ChatMessage::user("private-user"),
        ],
        42,
        0.25,
    )
}

fn temp_marker(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("muniment-llama-{name}-{}", std::process::id()))
}

#[test]
fn launch_arguments_are_separate_and_always_loopback() {
    let config = LlamaServerConfig::new("llama server", "models/a model.gguf", 32123);
    let sidecar = config.sidecar_config();
    assert_eq!(sidecar.program, "llama server");
    assert_eq!(
        sidecar.args,
        [
            "--model",
            "models/a model.gguf",
            "--host",
            "127.0.0.1",
            "--port",
            "32123"
        ]
    );
    assert_eq!(config.base_url(), "http://127.0.0.1:32123");

    let ipv6 = config.with_host(LoopbackHost::Ipv6);
    assert_eq!(ipv6.sidecar_config().args[3], "::1");
    assert_eq!(ipv6.base_url(), "http://[::1]:32123");
}

#[test]
fn health_client_rejects_non_loopback_urls() {
    for url in [
        "http://0.0.0.0:8080",
        "http://192.168.1.2:8080",
        "http://localhost:8080",
        "https://127.0.0.1:8080",
        "http://127.0.0.1:8080/path",
    ] {
        assert!(
            LlamaHealthClient::new(url, Duration::from_secs(1)).is_err(),
            "{url}"
        );
    }
}

#[test]
fn chat_client_posts_typed_non_streaming_request_and_returns_usage() {
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"answer"}}],"usage":{"prompt_tokens":7,"completion_tokens":2,"total_tokens":9}}"#;
    let (url, request, worker) = chat_fixture(response("200 OK", body));
    let client = LlamaChatClient::new(url, Duration::from_secs(1)).unwrap();
    let result = client.complete(&chat_request()).unwrap();
    assert_eq!(result.text, "answer");
    assert_eq!(result.usage.unwrap().total_tokens, Some(9));
    let request = request.recv().unwrap();
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let json: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(json["model"], "local-model");
    assert_eq!(json["messages"][0]["role"], "system");
    assert_eq!(json["messages"][1]["role"], "user");
    assert_eq!(json["max_tokens"], 42);
    assert_eq!(json["temperature"], 0.25);
    assert_eq!(json["stream"], false);
    worker.join().unwrap();
}

#[test]
fn chat_errors_are_typed_bounded_and_redacted() {
    let secret = "private-response-content";
    for (wire, expected) in [
        (response("500 Internal Server Error", secret), "HTTP 500"),
        (response("200 OK", secret), "invalid JSON"),
        (
            response("200 OK", r#"{"choices":[]}"#),
            "exactly one choice",
        ),
    ] {
        let (url, request, worker) = chat_fixture(wire);
        let error = LlamaChatClient::new(url, Duration::from_secs(1))
            .unwrap()
            .complete(&chat_request())
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains(expected));
        assert!(!message.contains(secret));
        assert!(!message.contains("private-user"));
        request.recv().unwrap();
        worker.join().unwrap();
    }

    let (url, request, worker) = chat_fixture(response("200 OK", "123456789"));
    let error = LlamaChatClient::new(url, Duration::from_secs(1))
        .unwrap()
        .with_max_response_bytes(8)
        .complete(&chat_request())
        .unwrap_err();
    assert!(matches!(error, LlamaChatError::BodyTooLarge { limit: 8 }));
    request.recv().unwrap();
    worker.join().unwrap();
}

#[test]
fn chat_maximum_response_limit_does_not_overflow() {
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"answer"}}]}"#;
    let (url, request, worker) = chat_fixture(response("200 OK", body));
    let result = LlamaChatClient::new(url, Duration::from_secs(1))
        .unwrap()
        .with_max_response_bytes(u64::MAX)
        .complete(&chat_request())
        .unwrap();
    assert_eq!(result.text, "answer");
    request.recv().unwrap();
    worker.join().unwrap();
}

#[test]
fn documented_loading_transitions_to_ready() {
    let loading = response(
        "503 Service Unavailable",
        r#"{"error":{"code":503,"message":"Loading model","type":"unavailable_error"}}"#,
    );
    let ready = response("200 OK", r#"{"status":"ok"}"#);
    let (url, worker) = fixture(vec![loading, ready]);
    let client = LlamaHealthClient::new(url, Duration::from_secs(1)).unwrap();
    assert_eq!(client.probe().unwrap(), ProbeOutcome::Loading);
    assert_eq!(client.probe().unwrap(), ProbeOutcome::Ready);
    worker.join().unwrap();
}

#[test]
fn unhealthy_and_malformed_responses_are_descriptive_without_body_content() {
    let secret = "private-user-content";
    let bad_status = response("500 Internal Server Error", secret);
    let malformed = response("200 OK", secret);
    let (url, worker) = fixture(vec![bad_status, malformed]);
    let client = LlamaHealthClient::new(url, Duration::from_secs(1)).unwrap();
    let status_error = client.probe().unwrap_err();
    let malformed_error = client.probe().unwrap_err();
    assert!(status_error.contains("HTTP 500"));
    assert!(malformed_error.contains("invalid llama health response"));
    assert!(!status_error.contains(secret));
    assert!(!malformed_error.contains(secret));
    worker.join().unwrap();
}

#[test]
fn supervisor_restarts_stub_and_shutdown_cleans_up_child() {
    let ready = response("200 OK", r#"{"status":"ok"}"#);
    let (url, worker) = fixture(vec![ready]);
    let health = LlamaHealthClient::new(url, Duration::from_secs(1)).unwrap();
    let marker = temp_marker("restart");
    let _ = std::fs::remove_dir(&marker);
    let mut config = LlamaServerConfig::new(
        env!("CARGO_BIN_EXE_sidecar-test-stub"),
        "model with spaces.gguf",
        1,
    )
    .sidecar_config();
    config.env.insert(
        "LLAMA_STUB_EXIT_ONCE".into(),
        marker.to_string_lossy().into_owned(),
    );
    config.restart = RestartPolicy {
        max_restarts: 2,
        window: Duration::from_secs(2),
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(10),
    };
    config.health_interval = Duration::from_millis(10);
    config.poll_interval = Duration::from_millis(5);
    config.shutdown_timeout = Duration::from_millis(100);
    let probe = health.clone();
    let mut supervisor = SidecarSupervisor::spawn(config, move |_| probe.probe()).unwrap();
    let events = supervisor.subscribe();
    let mut healthy_generation = None;
    while let Ok(event) = events.recv_timeout(Duration::from_secs(5)) {
        if event.status == SidecarStatus::Healthy {
            healthy_generation = event.generation;
            break;
        }
    }
    assert_eq!(healthy_generation, Some(2));
    supervisor.shutdown().unwrap();
    assert_eq!(
        events.recv_timeout(Duration::from_secs(1)).unwrap().status,
        SidecarStatus::Stopped
    );
    worker.join().unwrap();
    let _ = std::fs::remove_dir(marker);
}
