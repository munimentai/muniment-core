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
