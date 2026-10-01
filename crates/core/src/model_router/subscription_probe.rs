//! The installed subscription probe writes bounded metadata.
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
    let row = serde_json::json!({
        "phase": phase, "stage": stage, "turn": turn, "requested": requested,
        "transport": outcome, "error_class": error_class,
    });
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
        let _ = record(root, "transport", turn, outcome, error_class);
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
