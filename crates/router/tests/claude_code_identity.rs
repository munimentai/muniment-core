//! The router sends an Anthropic subscription turn with the Claude Code client
//! identity from `pins/pins.toml`, and relays the streamed reply.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use muniment_router::config::{self, RouterConfig};
use serde_json::{json, Value};

/// One captured request: the lowercase header lines and the JSON body.
struct Seen {
    path: String,
    headers: Vec<(String, String)>,
    body: Value,
}

/// A stand-in Messages API that answers one streamed text reply.
fn anthropic_upstream() -> (String, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, seen) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .map(|(_, value)| value.parse().unwrap())
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let usage = json!({"input_tokens": 100, "output_tokens": 2, "cache_read_input_tokens": 50, "cache_creation_input_tokens": 0});
        let events = [
            (
                "message_start",
                json!({"type": "message_start", "message": {"id": "msg_fixture", "type": "message", "role": "assistant", "model": "claude-opus-5", "content": [], "stop_reason": null, "usage": usage}}),
            ),
            (
                "content_block_start",
                json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ),
            (
                "content_block_delta",
                json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "12"}}),
            ),
            (
                "content_block_stop",
                json!({"type": "content_block_stop", "index": 0}),
            ),
            (
                "message_delta",
                json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
            ),
            ("message_stop", json!({"type": "message_stop"})),
        ];
        let payload: String = events
            .iter()
            .map(|(name, data)| format!("event: {name}\ndata: {data}\n\n"))
            .collect();
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        )
        .unwrap();
        stream.flush().unwrap();
        let _ = sender.send(Seen {
            path: request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_owned(),
            headers,
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
        });
    });
    (format!("http://127.0.0.1:{port}/v1"), seen)
}

#[test]
fn subscription_turns_carry_the_pinned_claude_code_identity() {
    let agent =
        std::env::temp_dir().join(format!("muniment-claude-identity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&agent);
    let (url, seen) = anthropic_upstream();
    let config: RouterConfig = serde_json::from_value(json!({
        "enabled": true,
        "accounts": [{
            "id": "claude", "family": "anthropic", "label": "Claude", "enabled": true, "weight": 1,
            "base_url": url, "models": ["claude-opus-5"],
            "credential": {"type": "subscription", "provider": "anthropic", "access": "fixture-token",
                "refresh": "fixture-refresh", "expires_ms": 9_999_999_999_999_i64}
        }],
    }))
    .unwrap();
    config::save(&agent, &config).unwrap();
    let handle = muniment_router::server::start(agent.clone()).unwrap();
    let endpoint = handle.endpoint();
    let reply = ureq::post(&format!("{}/chat/completions", endpoint.base_url()))
        .set("authorization", &format!("Bearer {}", endpoint.token))
        .send_json(json!({
            "model": "auto",
            "stream": true,
            "messages": [{"role": "user", "content": "What is 6 + 6?"}]
        }))
        .unwrap()
        .into_string()
        .unwrap();
    let request = seen
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap();
    handle.stop();
    let _ = std::fs::remove_dir_all(&agent);

    assert_eq!(request.path, "/v1/messages");
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(
        header("user-agent"),
        Some(format!("claude-cli/{}", muniment_pins::CLAUDE_CODE.version).as_str())
    );
    assert_eq!(header("x-app"), Some("cli"));
    assert_eq!(header("authorization"), Some("Bearer fixture-token"));
    assert!(header("anthropic-beta").is_some_and(|beta| beta.contains("claude-code-20250219")));
    assert_eq!(
        request.body["system"][0]["text"],
        "You are Claude Code, Anthropic's official CLI for Claude."
    );
    assert!(reply.contains("12"), "{reply}");
}
