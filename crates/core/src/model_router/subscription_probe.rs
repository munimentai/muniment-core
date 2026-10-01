//! The installed subscription probe writes bounded metadata.
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

static WRITER: Mutex<()> = Mutex::new(());
const LIMIT: u64 = 32_768;

pub fn record(
    root: &Path,
    stage: &str,
    turn: Option<usize>,
    outcome: &str,
    error_class: &str,
) -> Result<(), &'static str> {
    record_progress(root, stage, turn, outcome, error_class, None)
}

fn record_progress(
    root: &Path,
    stage: &str,
    turn: Option<usize>,
    outcome: &str,
    error_class: &str,
    failure: Option<&TransportFailure>,
) -> Result<(), &'static str> {
    if !matches!(
        stage,
        "composer"
            | "runtime"
            | "selection"
            | "inventory"
            | "send"
            | "reply"
            | "render"
            | "complete"
            | "restore"
            | "features"
            | "result"
            | "transport"
    ) || !matches!(
        outcome,
        "not-started" | "pending" | "accepted" | "complete" | "failed"
    ) || !matches!(
        error_class,
        "none"
            | "timeout"
            | "command-timeout"
            | "command-failed"
            | "reply-failed"
            | "context-mismatch"
            | "auth"
            | "quota"
            | "http"
            | "network"
            | "stream"
            | "update-profile"
            | "update-plan"
            | "update-phase"
            | "update-state"
            | "update-address"
            | "update-builder"
            | "update-check"
            | "update-download"
            | "update-unavailable"
            | "update-not-prepared"
            | "update-package-digest"
            | "update-tamper-rejection"
            | "update-version-rejection"
            | "update-active-work-refusal"
            | "update-checkpoint-encode"
            | "update-checkpoint-write"
            | "update-busy"
            | "update-install-task"
            | "update-install"
            | "update-restart"
    ) {
        return Err("The probe progress is invalid.");
    }
    let plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("subscription-probe.json"))
            .map_err(|_| "The probe plan is missing.")?,
    )
    .map_err(|_| "The probe plan is invalid.")?;
    let phase = plan["phase"].as_str().unwrap_or("");
    if !matches!(
        phase,
        "chat" | "features" | "restart" | "update" | "update-restart"
    ) {
        return Err("The probe phase is invalid.");
    }
    let requested = match turn {
        Some(index) if index < 4 => {
            let model = plan["models"][index]["id"].as_str().unwrap_or("");
            if model.is_empty()
                || model.len() > 128
                || !model
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
            {
                return Err("The probe model is invalid.");
            }
            Some(model)
        }
        Some(_) => return Err("The probe turn is invalid."),
        None => None,
    };
    let mut row = serde_json::json!({
        "phase": phase, "stage": stage, "turn": turn, "requested": requested,
        "transport": outcome, "error_class": error_class,
    });
    if let Some(failure) = failure {
        row["transport_kind"] = failure.kind.into();
        row["host"] = serde_json::json!(failure.host);
    }
    let line = format!("{row}\n");
    let _guard = WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let file = root.join(if stage == "transport" {
        "subscription-probe-transport-progress.jsonl"
    } else {
        "subscription-probe-progress.jsonl"
    });
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(file)
        .map_err(|_| "The probe could not open its progress file.")?;
    if file
        .metadata()
        .map_err(|_| "The probe could not read its progress file.")?
        .len()
        + line.len() as u64
        > LIMIT
    {
        return Err("The probe progress reached its size limit.");
    }
    file.write_all(line.as_bytes())
        .map_err(|_| "The probe could not save its progress.")
}

pub fn transport(agent: &Path, model: &str, outcome: &str, error_class: &str) {
    transport_progress(agent, model, outcome, error_class, None);
}

pub fn transport_failed(agent: &Path, model: &str, url: &str, error: &ureq::Transport) {
    transport_progress(
        agent,
        model,
        "failed",
        "network",
        Some(&TransportFailure::new(url, error)),
    );
}

struct TransportFailure {
    kind: &'static str,
    host: Option<String>,
}

impl TransportFailure {
    fn new(request_url: &str, error: &ureq::Transport) -> Self {
        // Prefer the failed redirect host. Never export the URL or error text.
        let url = error.url().cloned().or_else(|| request_url.parse().ok());
        Self {
            kind: transport_kind(error.kind(), error.message(), error.source()),
            host: url.as_ref().and_then(transport_host),
        }
    }
}

fn transport_host(url: &url::Url) -> Option<String> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host()?;
    if let url::Host::Domain(domain) = host {
        if domain.len() > 253
            || !domain
                .strip_suffix('.')
                .unwrap_or(domain)
                .split('.')
                .all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        {
            return None;
        }
    }
    Some(host.to_string())
}

fn transport_kind(
    kind: ureq::ErrorKind,
    message: Option<&str>,
    mut source: Option<&(dyn Error + 'static)>,
) -> &'static str {
    // Timeouts can wrap connect, proxy, or TLS failures. Bound the source walk.
    for _ in 0..16 {
        let Some(error) = source else { break };
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                return "timeout";
            }
            source = io.get_ref().map(|inner| inner as &(dyn Error + 'static));
        } else {
            source = error.source();
        }
    }
    match kind {
        ureq::ErrorKind::Dns => "dns",
        ureq::ErrorKind::InvalidProxyUrl
        | ureq::ErrorKind::ProxyConnect
        | ureq::ErrorKind::ProxyUnauthorized => "proxy",
        // ureq 2 wraps rustls failures in these two fixed messages.
        ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::Io
            if matches!(
                message,
                Some("tls connection init failed" | "tls connection creation failed")
            ) =>
        {
            "tls"
        }
        ureq::ErrorKind::UnknownScheme
            if message
                == Some("cannot make HTTPS request because no TLS backend is configured") =>
        {
            "tls"
        }
        ureq::ErrorKind::ConnectionFailed => "connect",
        // Protocol and unclassified I/O failures must not masquerade as connect failures.
        _ => "other",
    }
}

fn transport_progress(
    agent: &Path,
    model: &str,
    outcome: &str,
    error_class: &str,
    failure: Option<&TransportFailure>,
) {
    if std::env::var("MUNIMENT_SUBSCRIPTION_PROBE").as_deref() != Ok("1") {
        return;
    }
    let Some(root) = agent.parent() else { return };
    let Ok(bytes) = std::fs::read(root.join("subscription-probe.json")) else {
        return;
    };
    let Ok(plan) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return;
    };
    let turn = plan["models"].as_array().and_then(|models| {
        models
            .iter()
            .position(|entry| entry["id"].as_str() == Some(model))
    });
    if turn.is_some() {
        let _ = record_progress(root, "transport", turn, outcome, error_class, failure);
    }
}

pub fn http_error(status: u16) -> &'static str {
    match status {
        401 | 403 => "auth",
        402 | 429 => "quota",
        _ => "http",
    }
}

// Read structured codes only. Provider messages can contain credentials or reply text.
pub fn event_error(event: &serde_json::Value) -> &'static str {
    let error = match event["type"].as_str() {
        Some("error") => event.get("error").unwrap_or(event),
        Some("response.failed") => &event["response"]["error"],
        _ => return "stream",
    };
    // A specific code takes precedence over a generic error type.
    for field in ["code", "type"] {
        match error[field].as_str().unwrap_or("") {
            "authentication_error"
            | "invalid_api_key"
            | "invalid_token"
            | "token_expired"
            | "permission_error"
            | "access_denied" => return "auth",
            "rate_limit_error"
            | "rate_limit_exceeded"
            | "usage_limit_reached"
            | "insufficient_quota"
            | "quota_exceeded"
            | "billing_hard_limit_reached" => {
                return "quota";
            }
            _ => {}
        }
    }
    "stream"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_kinds_use_structured_errors_and_fixed_tls_markers() {
        use ureq::ErrorKind::*;
        for (kind, message, expected) in [
            (Dns, None, "dns"),
            (ConnectionFailed, Some("Connect error"), "connect"),
            (InvalidProxyUrl, None, "proxy"),
            (ProxyConnect, None, "proxy"),
            (ProxyUnauthorized, None, "proxy"),
            (ConnectionFailed, Some("tls connection init failed"), "tls"),
            (Io, Some("tls connection creation failed"), "tls"),
            (
                UnknownScheme,
                Some("cannot make HTTPS request because no TLS backend is configured"),
                "tls",
            ),
            (Io, Some("PRIVATE tls timeout proxy"), "other"),
            (BadHeader, None, "other"),
            (BadStatus, None, "other"),
            (InvalidUrl, None, "other"),
            (TooManyRedirects, None, "other"),
        ] {
            assert_eq!(transport_kind(kind, message, None), expected);
            // A timed-out handshake is a timeout, not a certificate failure.
            for io_kind in [std::io::ErrorKind::TimedOut, std::io::ErrorKind::WouldBlock] {
                let timeout = std::io::Error::new(io_kind, "PRIVATE TOKEN");
                let wrapped = std::io::Error::other(timeout);
                assert_eq!(transport_kind(kind, message, Some(&wrapped)), "timeout");
            }
        }
        let text = std::io::Error::other("tls connection init failed: timeout PRIVATE");
        assert_eq!(transport_kind(Io, None, Some(&text)), "other");
    }

    #[test]
    fn transport_failures_export_only_the_kind_and_host() {
        let directory =
            std::env::temp_dir().join(format!("subscription-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("subscription-probe.json"),
            r#"{"phase":"chat","models":[{"id":"model-one"}]}"#,
        )
        .unwrap();
        let error = ureq::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Authorization: Bearer PRIVATE TOKEN",
        ))
        .into_transport()
        .unwrap();
        for (url, host) in [
            (
                "https://user:PRIVATE@example.com:8443/PRIVATE?token=PRIVATE#PRIVATE",
                Some("example.com"),
            ),
            ("http://127.0.0.1:1234/PRIVATE", Some("127.0.0.1")),
            ("https://[::1]:443/?PRIVATE", Some("[::1]")),
            ("https://example.com./PRIVATE", Some("example.com.")),
            ("https://example.com../PRIVATE", None),
            ("https://-example.com/PRIVATE", None),
            ("https://PRIVATE!example.com/", None),
            ("file:///PRIVATE", None),
            ("", None),
            ("not a URL PRIVATE", None),
        ] {
            let failure = TransportFailure::new(url, &error);
            assert_eq!(failure.host.as_deref(), host);
            record_progress(
                &directory,
                "transport",
                Some(0),
                "failed",
                "network",
                Some(&failure),
            )
            .unwrap();
            let text = std::fs::read_to_string(
                directory.join("subscription-probe-transport-progress.jsonl"),
            )
            .unwrap();
            assert!(!text.contains("PRIVATE"));
            assert!(!text.contains("Authorization"));
            let row: serde_json::Value =
                serde_json::from_str(text.lines().last().unwrap()).unwrap();
            assert_eq!(row["transport_kind"], "timeout");
            assert_eq!(row["host"], serde_json::json!(host));
            assert_eq!(row["error_class"], "network");
            assert_eq!(row["turn"], 0);
        }
        for domain in [
            format!("{}.com", "x".repeat(64)),
            format!("{}.com", "a.".repeat(126)),
        ] {
            assert!(TransportFailure::new(&format!("https://{domain}/"), &error)
                .host
                .is_none());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ureq_dns_errors_keep_the_failed_host_without_request_secrets() {
        let agent = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .resolver(|_: &str| Err(std::io::Error::other("PRIVATE DNS detail")))
            .build();
        let error = agent
            .get("https://user:PRIVATE@example.invalid/PRIVATE?token=PRIVATE")
            .set("authorization", "Bearer PRIVATE")
            .call()
            .unwrap_err()
            .into_transport()
            .unwrap();
        let failure = TransportFailure::new("https://original.invalid", &error);
        assert_eq!(failure.kind, "dns");
        assert_eq!(failure.host.as_deref(), Some("example.invalid"));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn ureq_tls_handshake_errors_are_not_connect_errors() {
        use std::io::Read;
        use std::net::TcpListener;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = stream.read(&mut [0; 4096]);
            // Plain HTTP cannot complete a TLS handshake.
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        });
        let error = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .timeout(Duration::from_secs(5))
            .build()
            .get(&format!("https://{address}/?token=PRIVATE"))
            .call()
            .unwrap_err()
            .into_transport()
            .unwrap();
        server.join().unwrap();
        let failure = TransportFailure::new("", &error);
        assert_eq!(failure.kind, "tls");
        assert_eq!(failure.host.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn progress_exports_only_bounded_metadata() {
        let directory =
            std::env::temp_dir().join(format!("subscription-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let root = directory.as_path();
        std::fs::write(root.join("subscription-probe.json"), r#"{"phase":"chat","models":[{"id":"model-one"}],"nonce":"PRIVATE REPLY","access":"PRIVATE TOKEN"}"#).unwrap();
        record(root, "reply", Some(0), "pending", "none").unwrap();
        let file = root.join("subscription-probe-progress.jsonl");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("PRIVATE"));
        let row: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(row["requested"], "model-one");
        assert_eq!(row["turn"], 0);
        for (stage, turn, outcome, error) in [
            ("secret", Some(0), "pending", "none"),
            ("reply", Some(4), "pending", "none"),
            ("reply", Some(1), "pending", "none"),
            ("reply", Some(0), "secret", "none"),
            ("reply", Some(0), "pending", "secret"),
        ] {
            assert!(record(root, stage, turn, outcome, error).is_err());
        }
        while record(root, "reply", Some(0), "pending", "none").is_ok() {}
        assert!(std::fs::metadata(file).unwrap().len() <= LIMIT);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn update_failures_survive_the_restart_checkpoint() {
        let directory =
            std::env::temp_dir().join(format!("subscription-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        for phase in ["update", "update-restart"] {
            std::fs::write(
                directory.join("subscription-probe.json"),
                serde_json::json!({"phase": phase}).to_string(),
            )
            .unwrap();
            for code in [
                "update-profile",
                "update-plan",
                "update-phase",
                "update-state",
                "update-address",
                "update-builder",
                "update-check",
                "update-download",
                "update-unavailable",
                "update-not-prepared",
                "update-package-digest",
                "update-tamper-rejection",
                "update-version-rejection",
                "update-active-work-refusal",
                "update-checkpoint-encode",
                "update-checkpoint-write",
                "update-busy",
                "update-install-task",
                "update-install",
                "update-restart",
            ] {
                record(&directory, "features", None, "not-started", code).unwrap();
                let text =
                    std::fs::read_to_string(directory.join("subscription-probe-progress.jsonl"))
                        .unwrap();
                let row: serde_json::Value =
                    serde_json::from_str(text.lines().last().unwrap()).unwrap();
                assert_eq!(row["error_class"], code);
                assert_eq!(row["phase"], phase);
            }
            assert!(record(
                &directory,
                "features",
                None,
                "not-started",
                "update-PRIVATE"
            )
            .is_err());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn http_200_error_events_separate_access_from_product_errors() {
        use serde_json::json;
        for (code, class) in [
            ("invalid_api_key", "auth"),
            ("authentication_error", "auth"),
            ("permission_error", "auth"),
            ("rate_limit_error", "quota"),
            ("rate_limit_exceeded", "quota"),
            ("usage_limit_reached", "quota"),
            ("insufficient_quota", "quota"),
            ("server_error", "stream"),
            ("PRIVATE TOKEN", "stream"),
        ] {
            for event in [
                json!({"type":"error","code":code,"message":"PRIVATE REPLY"}),
                json!({"type":"error","error":{"type":code,"message":"PRIVATE REPLY"}}),
                json!({"type":"response.failed","response":{"error":{"code":code,"message":"PRIVATE REPLY"}}}),
            ] {
                let body = format!("data: {event}\n\n");
                let response = ureq::Response::new(200, "OK", &body).unwrap();
                let text = response.into_string().unwrap();
                let parsed: serde_json::Value =
                    serde_json::from_str(text.trim().strip_prefix("data: ").unwrap()).unwrap();
                let mut decoder = super::super::transport::Decoder::new("test-model");
                assert!(decoder.event(&parsed).is_err());
                assert_eq!(event_error(&parsed), class);
            }
        }
        for event in [
            json!({"type":"error","error":{"message":"rate_limit_exceeded"}}),
            json!({"type":"response.incomplete","response":{"error":{"code":"insufficient_quota"}}}),
            json!({"type":"response.output_text.delta","code":"invalid_api_key"}),
            json!({"type":"error","error":{"code":429}}),
            json!({}),
        ] {
            assert_eq!(event_error(&event), "stream");
        }
    }

    #[test]
    fn http_failures_separate_access_from_product_errors() {
        for status in [401, 403] {
            assert_eq!(http_error(status), "auth");
        }
        for status in [402, 429] {
            assert_eq!(http_error(status), "quota");
        }
        for status in [400, 404, 408, 500, 502, 503] {
            assert_eq!(http_error(status), "http");
        }
    }
}
