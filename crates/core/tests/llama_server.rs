use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use muniment_core::llama::{LlamaHealthClient, LlamaServerConfig, LoopbackHost};
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
