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
    record_progress(root, stage, turn, outcome, error_class, None, None)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFailure {
    pub command: String,
    pub kind: String,
}

impl CommandFailure {
    fn valid(&self) -> bool {
        matches!(
            self.command.as_str(),
            "attach_listener_status"
                | "local_mode_provider_inventory"
                | "chat_current_thread"
                | "chat_thread_open"
                | "chat_answer_permission"
                | "subscription_probe_progress"
                | "subscription_probe_observed"
                | "subscription_probe_update"
                | "workspace_read_text"
                | "workspace_save_text"
                | "workspace_folders"
                | "workspace_file_action"
                | "model_router_settings"
                | "model_router_update_account"
                | "model_router_save_routes"
                | "model_router_test_route"
                | "project_create"
                | "project_list"
                | "project_rename"
                | "memory_profile_read"
                | "memory_profile_save"
                | "agent_save"
                | "agent_list"
                | "agent_delete"
                | "artifact_from_file"
                | "artifact_read"
                | "artifact_edit"
                | "artifact_list"
                | "browser_view"
                | "browser_command"
                | "terminal_start"
                | "terminal_write"
                | "terminal_read"
                | "terminal_close"
                | "extend_command"
        ) && matches!(
            self.kind.as_str(),
            "busy" | "unavailable" | "unauthorized" | "timeout" | "rejected"
        )
    }
}

pub fn record_command(
    root: &Path,
    stage: &str,
    turn: Option<usize>,
    outcome: &str,
    error_class: &str,
    command: Option<&CommandFailure>,
) -> Result<(), &'static str> {
    record_progress_with_detail(
        root,
        stage,
        turn,
        outcome,
        error_class,
        command.map(FailureDetail::Command),
        None,
    )
}

pub fn record_model_save(
    root: &Path,
    provider: &str,
    model: &str,
    outcome: &str,
    os_error: Option<i32>,
) -> Result<(), &'static str> {
    if provider != "muniment-router" || !matches!(outcome, "pending" | "complete" | "failed") {
        return Err("The probe model save is invalid.");
    }
    let plan: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("subscription-probe.json"))
            .map_err(|_| "The probe plan is missing.")?,
    )
    .map_err(|_| "The probe plan is invalid.")?;
    let turn = plan["models"]
        .as_array()
        .and_then(|models| {
            models.iter().position(|entry| {
                model
                    == format!(
                        "{}/{}",
                        entry["family"].as_str().unwrap_or(""),
                        entry["id"].as_str().unwrap_or("")
                    )
            })
        })
        .ok_or("The probe model save is invalid.")?;
    record_progress(
        root,
        "model-save",
        Some(turn),
        outcome,
        "none",
        None,
        os_error,
    )
}

fn saved_default(
    value: &serde_json::Value,
    plan: &serde_json::Value,
    provider: bool,
) -> serde_json::Value {
    if value.is_null() {
        return serde_json::Value::Null;
    }
    let allowed = value.as_str().is_some_and(|value| {
        if provider && value == "muniment-router" {
            return true;
        }
        plan["models"].as_array().is_some_and(|models| {
            models.iter().any(|entry| {
                let family = entry["family"].as_str().unwrap_or("");
                let id = entry["id"].as_str().unwrap_or("");
                let identifier = |text: &str, model: bool| {
                    text.len() <= 128
                        && text
                            .bytes()
                            .next()
                            .is_some_and(|byte| byte.is_ascii_alphanumeric())
                        && text.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || b"._-".contains(&byte)
                                || (model && byte == b':')
                        })
                };
                identifier(family, false)
                    && identifier(id, true)
                    && if provider {
                        value == family
                    } else {
                        value == id || value == format!("{family}/{id}")
                    }
            })
        })
    });
    if allowed {
        value.clone()
    } else {
        "[redacted]".into()
    }
}

fn record_progress(
    root: &Path,
    stage: &str,
    turn: Option<usize>,
    outcome: &str,
    error_class: &str,
    failure: Option<&TransportFailure>,
    os_error: Option<i32>,
) -> Result<(), &'static str> {
    record_progress_with_detail(
        root,
        stage,
        turn,
        outcome,
        error_class,
        failure.map(FailureDetail::Transport),
        os_error,
    )
}

enum FailureDetail<'a> {
    Transport(&'a TransportFailure),
    Command(&'a CommandFailure),
}

fn record_progress_with_detail(
    root: &Path,
    stage: &str,
    turn: Option<usize>,
    outcome: &str,
    error_class: &str,
    detail: Option<FailureDetail<'_>>,
    os_error: Option<i32>,
) -> Result<(), &'static str> {
    let (failure, command) = match detail {
        Some(FailureDetail::Transport(failure)) => (Some(failure), None),
        Some(FailureDetail::Command(command)) => (None, Some(command)),
        None => (None, None),
    };
    if command
        .is_some_and(|command| !command.valid() || error_class == "none" || stage == "transport")
    {
        return Err("The probe command failure is invalid.");
    }
    if !matches!(
        stage,
        "composer"
            | "runtime"
            | "selection"
            | "model-save"
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
            | "update-check-network"
            | "update-check-target-not-found"
            | "update-check-manifest-parse"
            | "update-check-release-not-found"
            | "update-check-version"
            | "update-check-address"
            | "update-check-other"
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
    if let Some(command) = command {
        row["command"] = command.command.clone().into();
        row["command_error_class"] = command.kind.clone().into();
    }
    if stage == "model-save" {
        row["model_save_rejected"] = match outcome {
            "complete" => false.into(),
            "failed" => true.into(),
            _ => serde_json::Value::Null,
        };
        row["os_error"] = serde_json::json!(os_error.filter(|_| outcome == "failed"));
    }
    if stage == "inventory" {
        // Read the file without inventory adoption so diagnostics cannot change the saved choice.
        let settings = std::fs::read(root.join("agent/settings.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(serde_json::Value::is_object);
        row["settings_read"] = settings.is_some().into();
        let settings = settings.unwrap_or_default();
        row["defaultProvider"] = saved_default(&settings["defaultProvider"], &plan, true);
        row["defaultModel"] = saved_default(&settings["defaultModel"], &plan, false);
    }
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

pub fn transport_failed(
    agent: &Path,
    model: &str,
    request: &TransportRequest,
    error: &ureq::Transport,
) {
    transport_progress(
        agent,
        model,
        "failed",
        "network",
        Some(&request.failure(error)),
    );
}

// ureq attaches the original URL to redirect errors. Keep the current target ourselves.
// Each router attempt owns this context and its agent.
pub struct TransportRequest {
    agent: ureq::Agent,
    url: String,
    proxy_host: Option<Option<String>>,
}

impl TransportRequest {
    pub fn new(builder: ureq::AgentBuilder, url: &str) -> Self {
        let mut builder = builder.try_proxy_from_env(false).redirects(0);
        let mut proxy_host = None;
        if cfg!(feature = "tls") {
            // Match ureq 2's environment precedence and parser, including scheme-free proxies.
            for name in [
                "ALL_PROXY",
                "all_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
            ] {
                let Ok(value) = std::env::var(name) else {
                    continue;
                };
                let Ok(proxy) = ureq::Proxy::new(&value) else {
                    continue;
                };
                let authority = value
                    .trim_end_matches('/')
                    .split_once("://")
                    .map_or(value.trim_end_matches('/'), |(_, rest)| rest);
                let host = authority
                    .rsplit('@')
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("");
                proxy_host = Some(
                    url::Url::parse(&format!("http://{host}/"))
                        .ok()
                        .filter(|url| {
                            url.host_str()
                                .is_some_and(|parsed| parsed.eq_ignore_ascii_case(host))
                        })
                        .as_ref()
                        .and_then(transport_host),
                );
                builder = builder.proxy(proxy);
                break;
            }
        }
        Self {
            agent: builder.build(),
            url: url.into(),
            proxy_host,
        }
    }

    pub fn send_json(
        &mut self,
        headers: &[(&str, String)],
        body: &serde_json::Value,
    ) -> Result<ureq::Response, Box<ureq::Error>> {
        let mut method = "POST";
        for hop in 0..5 {
            let mut call = self
                .agent
                .request(method, &self.url)
                .set("content-type", "application/json");
            for (name, value) in headers {
                // Drop explicit authorization and cookies on redirects, as ureq does.
                if hop > 0
                    && ["authorization", "cookie", "content-length"]
                        .iter()
                        .any(|header| name.eq_ignore_ascii_case(header))
                {
                    continue;
                }
                call = call.set(name, value);
            }
            let response = if hop == 0 {
                call.send_json(body)
            } else {
                call.call()
            }?;
            if !(300..399).contains(&response.status()) {
                return Ok(response);
            }
            if hop == 4 {
                return Err(ureq::Error::from(std::io::Error::other(
                    "The provider reached the redirect limit.",
                ))
                .into());
            }
            let Some(location) = response.header("location") else {
                return Ok(response);
            };
            let next = url::Url::parse(&self.url)
                .map_err(ureq::Error::from)?
                .join(location)
                .map_err(ureq::Error::from)?;
            match response.status() {
                301..=303 => method = "GET",
                307 | 308 if method == "GET" => {}
                _ => return Ok(response),
            }
            self.url = next.into();
        }
        unreachable!()
    }

    fn failure(&self, error: &ureq::Transport) -> TransportFailure {
        let mut failure = TransportFailure::new(&self.url, error);
        if let Some(host) = &self.proxy_host {
            if matches!(failure.kind, "dns" | "connect" | "proxy")
                || (failure.kind == "timeout"
                    && matches!(
                        error.kind(),
                        ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed
                    )
                    && error.message() != Some("tls connection init failed"))
            {
                if failure.kind != "timeout" {
                    failure.kind = "proxy";
                }
                failure.host = host.clone();
            }
        }
        failure
    }
}

struct TransportFailure {
    kind: &'static str,
    host: Option<String>,
}

impl TransportFailure {
    fn new(request_url: &str, error: &ureq::Transport) -> Self {
        // Never export the URL or error text.
        let url = request_url.parse().ok();
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

pub(crate) fn transport_kind(
    kind: ureq::ErrorKind,
    message: Option<&str>,
    mut source: Option<&(dyn Error + 'static)>,
) -> &'static str {
    let mut tls_kind = None;
    // Timeouts can wrap connect, proxy, or TLS failures. Bound the source walk.
    for _ in 0..16 {
        let Some(error) = source else { break };
        #[cfg(feature = "tls")]
        let detected = error.downcast_ref::<rustls::Error>().map(|error| {
            if matches!(
                error,
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
            ) {
                "tls_certificate"
            } else {
                "tls"
            }
        });
        #[cfg(not(feature = "tls"))]
        let detected: Option<&'static str> = None;
        tls_kind = tls_kind.or(detected);
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
    if let Some(kind) = tls_kind {
        return kind;
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
        let _ = record_progress(root, "transport", turn, outcome, error_class, failure, None);
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
    fn command_progress_keeps_only_allowed_names_and_classes() {
        let directory =
            std::env::temp_dir().join(format!("subscription-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("subscription-probe.json"),
            r#"{"phase":"chat","models":[{"id":"one"},{"id":"two"},{"id":"three"}]}"#,
        )
        .unwrap();
        for command in ["chat_current_thread", "chat_thread_open"] {
            for kind in ["busy", "unavailable", "unauthorized", "timeout", "rejected"] {
                record_command(
                    &directory,
                    "reply",
                    Some(2),
                    "pending",
                    "command-failed",
                    Some(&CommandFailure {
                        command: command.into(),
                        kind: kind.into(),
                    }),
                )
                .unwrap();
            }
        }
        let path = directory.join("subscription-probe-progress.jsonl");
        let before = std::fs::read_to_string(&path).unwrap();
        for (command, kind) in [
            ("PRIVATE", "busy"),
            ("chat_thread_open", "PRIVATE"),
            ("", "rejected"),
            ("chat_thread_open\nPRIVATE", "busy"),
        ] {
            assert!(record_command(
                &directory,
                "reply",
                Some(2),
                "pending",
                "command-failed",
                Some(&CommandFailure {
                    command: command.into(),
                    kind: kind.into()
                }),
            )
            .is_err());
        }
        for (stage, error_class) in [("transport", "command-failed"), ("reply", "none")] {
            assert!(record_command(
                &directory,
                stage,
                Some(2),
                "pending",
                error_class,
                Some(&CommandFailure {
                    command: "chat_thread_open".into(),
                    kind: "busy".into()
                }),
            )
            .is_err());
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        let rows = before
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 10);
        assert_eq!(rows[0]["command"], "chat_current_thread");
        assert_eq!(rows[0]["command_error_class"], "busy");
        assert_eq!(rows[5]["command"], "chat_thread_open");
        assert_eq!(rows[5]["turn"], 2);
        assert_eq!(rows[5]["requested"], "three");
        assert!(!before.contains("PRIVATE"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn assert_artifact(failure: &TransportFailure, kind: &str, host: Option<&str>) {
        let directory =
            std::env::temp_dir().join(format!("subscription-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("subscription-probe.json"),
            r#"{"phase":"chat","models":[{"id":"model-one"}]}"#,
        )
        .unwrap();
        record_progress(
            &directory,
            "transport",
            Some(0),
            "failed",
            "network",
            Some(failure),
            None,
        )
        .unwrap();
        let text =
            std::fs::read_to_string(directory.join("subscription-probe-transport-progress.jsonl"))
                .unwrap();
        for secret in [
            "PRIVATE",
            "Authorization",
            "authorization",
            "user",
            "dXNlcjpQUklWQVRF",
            "://",
            "?",
            "#",
        ] {
            assert!(
                !text.contains(secret),
                "The artifact contains a secret or URL component."
            );
        }
        let row: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(row["transport_kind"], kind);
        assert_eq!(row["host"], serde_json::json!(host));
        assert_eq!(row["phase"], "chat");
        assert_eq!(row["error_class"], "network");
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn direct_request(builder: ureq::AgentBuilder, url: &str) -> TransportRequest {
        TransportRequest {
            agent: builder
                .try_proxy_from_env(false)
                .redirects(0)
                .timeout(std::time::Duration::from_secs(5))
                .build(),
            url: url.into(),
            proxy_host: None,
        }
    }

    // Child processes isolate real proxy variables from parallel router tests.
    #[cfg(feature = "tls")]
    #[test]
    fn environment_proxy_failures_name_the_proxy_without_credentials() {
        use std::net::ToSocketAddrs;
        const CASE: &str = "MUNIMENT_TEST_PROXY_CASE";
        let Ok(case) = std::env::var(CASE) else {
            for (case, proxy) in [
                ("connect", "http://user:PRIVATE@127.0.0.1:0"),
                ("dns", "http://user:PRIVATE@proxy.example:80"),
                ("scheme-free", "user:PRIVATE@proxy.example:80"),
                ("precedence", "http://user:PRIVATE@unused.example:80"),
                ("invalid-precedence", "http://user:PRIVATE@proxy.example:80"),
                (
                    "unsafe-host",
                    "http://user:PRIVATE@proxy.example/PRIVATE?token=PRIVATE",
                ),
            ] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap());
                child.args(["--exact", "subscription_probe::tests::environment_proxy_failures_name_the_proxy_without_credentials", "--nocapture"]);
                for name in [
                    "ALL_PROXY",
                    "all_proxy",
                    "HTTPS_PROXY",
                    "https_proxy",
                    "HTTP_PROXY",
                    "http_proxy",
                ] {
                    child.env_remove(name);
                }
                child.env(CASE, case).env("HTTPS_PROXY", proxy);
                if case == "precedence" {
                    child.env("ALL_PROXY", "http://user:PRIVATE@proxy.example:80");
                } else if case == "invalid-precedence" {
                    child.env("ALL_PROXY", "invalid://PRIVATE");
                }
                let output = child.output().unwrap();
                assert!(
                    output.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        let connect = case == "connect";
        let unsafe_host = case == "unsafe-host";
        let builder = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(5))
            .resolver(move |netloc: &str| {
                if connect {
                    assert_eq!(netloc, "127.0.0.1:0");
                    netloc.to_socket_addrs().map(Iterator::collect)
                } else {
                    assert_eq!(
                        netloc,
                        if unsafe_host {
                            "proxy.example/PRIVATE?token=PRIVATE:80"
                        } else {
                            "proxy.example:80"
                        }
                    );
                    Err(std::io::Error::other("PRIVATE DNS detail"))
                }
            });
        let mut request = TransportRequest::new(
            builder,
            "https://provider.example/PRIVATE?token=PRIVATE#PRIVATE",
        );
        let error = request
            .send_json(
                &[("authorization", "Bearer PRIVATE".into())],
                &serde_json::json!({"secret":"PRIVATE"}),
            )
            .unwrap_err()
            .into_transport()
            .unwrap();
        assert_eq!(
            error.kind(),
            if connect {
                ureq::ErrorKind::ConnectionFailed
            } else {
                ureq::ErrorKind::Dns
            }
        );
        assert_artifact(
            &request.failure(&error),
            "proxy",
            if connect {
                Some("127.0.0.1")
            } else if unsafe_host {
                None
            } else {
                Some("proxy.example")
            },
        );
    }

    fn http_server(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{BufRead, BufReader, Read};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        });
        (url, server)
    }

    fn redirect(status: u16, location: &str) -> String {
        format!("HTTP/1.1 {status} Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
    }

    #[test]
    fn redirect_failures_name_the_current_endpoint_without_url_secrets() {
        use std::net::ToSocketAddrs;
        for connect in [false, true] {
            let (url, server) = http_server(vec![redirect(
                302,
                "http://user:PRIVATE@redirect.example:80/PRIVATE?token=PRIVATE#PRIVATE",
            )]);
            let builder = ureq::AgentBuilder::new().resolver(move |netloc: &str| {
                if netloc == "redirect.example:80" {
                    if connect {
                        Ok(vec!["127.0.0.1:0".parse().unwrap()])
                    } else {
                        Err(std::io::Error::other("PRIVATE DNS detail"))
                    }
                } else {
                    netloc.to_socket_addrs().map(Iterator::collect)
                }
            });
            let mut request = direct_request(builder, &format!("{url}/PRIVATE?token=PRIVATE"));
            let error = request
                .send_json(
                    &[("authorization", "Bearer PRIVATE".into())],
                    &serde_json::json!({"secret":"PRIVATE"}),
                )
                .unwrap_err()
                .into_transport()
                .unwrap();
            assert!(server.join().unwrap()[0].starts_with("POST "));
            assert_artifact(
                &request.failure(&error),
                if connect { "connect" } else { "dns" },
                Some("redirect.example"),
            );
        }
    }

    #[test]
    fn redirects_keep_the_ureq_method_credential_and_limit_rules() {
        for status in [301, 302, 303, 307, 308] {
            let follows = status <= 303;
            let mut responses = vec![redirect(status, "/next")];
            if follows {
                responses.push(
                    "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into(),
                );
            }
            let (url, server) = http_server(responses);
            let mut request = direct_request(ureq::AgentBuilder::new(), &url);
            let response = request
                .send_json(
                    &[
                        ("authorization", "Bearer PRIVATE".into()),
                        ("cookie", "PRIVATE".into()),
                    ],
                    &serde_json::json!({"secret":"PRIVATE"}),
                )
                .unwrap();
            assert_eq!(response.status(), if follows { 200 } else { status });
            let requests = server.join().unwrap();
            assert!(requests[0].starts_with("POST "));
            assert!(requests[0].contains("PRIVATE"));
            if follows {
                assert!(requests[1].starts_with("GET /next "));
                assert!(!requests[1].contains("PRIVATE"));
                assert!(!requests[1].to_ascii_lowercase().contains("content-length"));
            }
        }
        let (url, server) = http_server(vec![redirect(302, "/next"); 5]);
        let mut request = direct_request(ureq::AgentBuilder::new(), &url);
        assert!(request.send_json(&[], &serde_json::json!({})).is_err());
        assert_eq!(server.join().unwrap().len(), 5);
    }

    #[test]
    fn boxed_http_errors_keep_the_status_and_response() {
        for status in [401, 429, 503] {
            let (url, server) = http_server(vec![format!(
                "HTTP/1.1 {status} Error\r\ncontent-length: 6\r\nconnection: close\r\n\r\nfailed"
            )]);
            let mut request = direct_request(ureq::AgentBuilder::new(), &url);
            let error = request.send_json(&[], &serde_json::json!({})).unwrap_err();
            match *error {
                ureq::Error::Status(code, response) => {
                    assert_eq!(code, status);
                    assert_eq!(response.status(), status);
                    assert_eq!(response.into_string().unwrap(), "failed");
                }
                ureq::Error::Transport(error) => panic!("Expected an HTTP status error: {error}"),
            }
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_failures_through_a_proxy_name_the_provider() {
        let (proxy, server) = http_server(vec!["HTTP/1.1 200 OK\r\n\r\n".into()]);
        let mut request = direct_request(
            ureq::AgentBuilder::new().proxy(ureq::Proxy::new(proxy).unwrap()),
            "https://provider.example/PRIVATE?token=PRIVATE",
        );
        request.proxy_host = Some(Some("127.0.0.1".into()));
        let error = request
            .send_json(&[], &serde_json::json!({}))
            .unwrap_err()
            .into_transport()
            .unwrap();
        assert!(server.join().unwrap()[0].starts_with("CONNECT provider.example:443 "));
        assert_artifact(&request.failure(&error), "tls", Some("provider.example"));
    }

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

    #[cfg(feature = "tls")]
    #[test]
    fn certificate_failures_use_types_not_error_text() {
        use rustls::{CertificateError, Error as TlsError};
        for error in [
            CertificateError::UnknownIssuer,
            CertificateError::Expired,
            CertificateError::NotValidForName,
            CertificateError::Revoked,
            CertificateError::BadSignature,
            CertificateError::BadEncoding,
            CertificateError::InvalidPurpose,
            CertificateError::Other(rustls::OtherError(std::sync::Arc::new(
                std::io::Error::other("PRIVATE certificate details"),
            ))),
        ] {
            let wrapped =
                std::io::Error::other(std::io::Error::other(TlsError::InvalidCertificate(error)));
            let transport = ureq::Error::from(wrapped).into_transport().unwrap();
            let failure = TransportFailure::new(
                "https://user:PRIVATE@chatgpt.com/PRIVATE?token=PRIVATE#PRIVATE",
                &transport,
            );
            assert_artifact(&failure, "tls_certificate", Some("chatgpt.com"));
        }
        for (error, expected) in [
            (TlsError::NoCertificatesPresented, "tls_certificate"),
            (
                TlsError::General("PRIVATE certificate UnknownIssuer".into()),
                "tls",
            ),
        ] {
            assert_eq!(
                transport_kind(ureq::ErrorKind::Io, None, Some(&error)),
                expected
            );
            let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, error);
            assert_eq!(
                transport_kind(ureq::ErrorKind::Io, None, Some(&timeout)),
                "timeout"
            );
        }
        let text = std::io::Error::other("InvalidCertificate(UnknownIssuer) PRIVATE");
        assert_eq!(
            transport_kind(ureq::ErrorKind::Io, None, Some(&text)),
            "other"
        );
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
                None,
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
        let failure = TransportFailure::new(
            "https://user:PRIVATE@example.invalid/PRIVATE?token=PRIVATE",
            &error,
        );
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
        let error = crate::http::agent_builder()
            .try_proxy_from_env(false)
            .timeout(Duration::from_secs(5))
            .build()
            .get(&format!("https://{address}/?token=PRIVATE"))
            .call()
            .unwrap_err()
            .into_transport()
            .unwrap();
        server.join().unwrap();
        let failure = TransportFailure::new(&format!("https://{address}/?token=PRIVATE"), &error);
        assert_eq!(failure.kind, "tls");
        assert_eq!(failure.host.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn model_save_and_inventory_diagnostics_keep_codes_and_saved_defaults() {
        let root =
            std::env::temp_dir().join(format!("subscription-probe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("agent")).unwrap();
        std::fs::write(root.join("subscription-probe.json"), r#"{"phase":"chat","models":[{"family":"openai-codex","id":"luna"},{"family":"openai-codex","id":"terra"}]}"#).unwrap();
        let settings = root.join("agent/settings.json");
        let bytes = br#"{"defaultProvider":"muniment-router","defaultModel":"openai-codex/luna","token":"PRIVATE"}"#;
        std::fs::write(&settings, bytes).unwrap();
        let last = || {
            let text =
                std::fs::read_to_string(root.join("subscription-probe-progress.jsonl")).unwrap();
            assert!(!text.contains("PRIVATE"));
            serde_json::from_str::<serde_json::Value>(text.lines().last().unwrap()).unwrap()
        };
        for (outcome, code, rejected) in [
            ("pending", None, serde_json::Value::Null),
            ("failed", Some(32), true.into()),
            ("failed", Some(1175), true.into()),
            ("failed", None, true.into()),
            ("complete", None, false.into()),
        ] {
            record_model_save(
                &root,
                "muniment-router",
                "openai-codex/terra",
                outcome,
                code,
            )
            .unwrap();
            let row = last();
            assert_eq!(row["turn"], 1);
            assert_eq!(row["requested"], "terra");
            assert_eq!(row["model_save_rejected"], rejected);
            assert_eq!(row["os_error"], serde_json::json!(code));
        }
        record(&root, "inventory", Some(1), "not-started", "timeout").unwrap();
        let row = last();
        assert_eq!(row["settings_read"], true);
        assert_eq!(row["defaultProvider"], "muniment-router");
        assert_eq!(row["defaultModel"], "openai-codex/luna");
        assert_eq!(std::fs::read(&settings).unwrap(), bytes);
        for value in [
            serde_json::json!("C:/PRIVATE"),
            serde_json::json!("/PRIVATE"),
            serde_json::json!("PRIVATE"),
            serde_json::json!({"token":"PRIVATE"}),
        ] {
            std::fs::write(
                &settings,
                serde_json::json!({"defaultProvider":value, "defaultModel":value}).to_string(),
            )
            .unwrap();
            record(&root, "inventory", Some(1), "not-started", "timeout").unwrap();
            assert_eq!(last()["defaultProvider"], "[redacted]");
            assert_eq!(last()["defaultModel"], "[redacted]");
        }
        std::fs::write(&settings, b"{}").unwrap();
        record(&root, "inventory", Some(1), "not-started", "timeout").unwrap();
        assert_eq!(last()["settings_read"], true);
        assert!(last()["defaultModel"].is_null());
        for bytes in [b"invalid".as_slice(), b"null".as_slice()] {
            std::fs::write(&settings, bytes).unwrap();
            record(&root, "inventory", Some(1), "not-started", "timeout").unwrap();
            assert_eq!(last()["settings_read"], false);
        }
        std::fs::remove_file(&settings).unwrap();
        record(&root, "inventory", Some(1), "not-started", "timeout").unwrap();
        assert_eq!(last()["settings_read"], false);
        assert!(record_model_save(&root, "PRIVATE", "openai-codex/terra", "failed", None).is_err());
        assert!(record_model_save(&root, "muniment-router", "PRIVATE", "failed", None).is_err());
        assert!(record_model_save(
            &root,
            "muniment-router",
            "openai-codex/terra",
            "PRIVATE",
            None
        )
        .is_err());
        std::fs::remove_dir_all(root).unwrap();
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
                "update-check-network",
                "update-check-target-not-found",
                "update-check-manifest-parse",
                "update-check-release-not-found",
                "update-check-version",
                "update-check-address",
                "update-check-other",
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
            for code in [
                "update-PRIVATE",
                "update-check-PRIVATE",
                "update-check-network https://PRIVATE/path?token=SECRET",
            ] {
                assert!(record(&directory, "features", None, "not-started", code).is_err());
            }
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
