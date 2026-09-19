//! What a run tells the model about where it is running. The prompt itself is
//! a constant. These facts change with every launch: the model that answers,
//! the models that answered earlier in the thread, the host and its shell,
//! and the working directory. Each user message also opens with the time it
//! was sent, so the model reads the clock from the message and not from its
//! training data.

use std::path::{Path, PathBuf};

use chrono::SecondsFormat;

/// The host the runtime was built for, in the words the model reads.
pub const PLATFORM: &str = if cfg!(target_os = "macos") {
    "macOS"
} else if cfg!(target_os = "windows") {
    "Windows"
} else {
    "Linux"
};

/// The shell the agent's command tool runs on this host.
pub const SHELL: &str = if cfg!(target_os = "windows") {
    "powershell"
} else {
    "bash"
};

/// The cloud alias the agent registers for the app's gateway. It names the
/// product, so a model name that carries it loses the prefix before it reaches
/// the prompt.
const CLOUD_ALIAS_PREFIX: &str = "muniment/";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaunchFacts {
    /// The model answering this run as `provider/model`, or the bare model
    /// name a cloud grant carries.
    pub model: Option<String>,
    /// Models that wrote earlier replies in this thread, once each, in order,
    /// without the one answering now.
    pub earlier_models: Vec<String>,
    /// The folder the agent works in: the user's Home.
    pub working_directory: Option<PathBuf>,
}

impl LaunchFacts {
    /// The facts block appended to the system prompt.
    pub fn render(&self) -> String {
        let mut lines = vec!["Facts:".to_owned()];
        match &self.model {
            Some(model) => lines.push(format!(
                "- You are running as the model {model}. When asked what you are, say so. You are no other model."
            )),
            None => lines.push(
                "- The app has not recorded which model is answering. When asked what you are, say that you do not know rather than name one."
                    .to_owned(),
            ),
        }
        if !self.earlier_models.is_empty() {
            lines.push(format!(
                "- Earlier replies in this thread came from other models: {}. You did not write them.",
                self.earlier_models.join(", ")
            ));
        }
        lines.push(format!(
            "- The host runs {PLATFORM}. Shell commands run in {SHELL}."
        ));
        match &self.working_directory {
            Some(directory) => lines.push(format!(
                "- The working directory is {}. Create generated files inside this working directory. Read or write elsewhere only at a path the user names.",
                directory.display()
            )),
            None => lines.push(
                "- No working directory is configured. Read or write only at a path the user names."
                    .to_owned(),
            ),
        }
        lines.push(
            "- Each user message opens with a line that says when it was sent: a timestamp with its offset and zone."
                .to_owned(),
        );
        lines.join("\n")
    }
}

/// The prompt the agent receives: the constant prompt, then the facts.
pub fn system_prompt_with_facts(prompt: &str, facts: &LaunchFacts) -> String {
    format!("{prompt}\n\n{}", facts.render())
}

/// A model name as the prompt shows it. The cloud alias prefix goes.
pub fn shown_model(name: &str) -> String {
    name.strip_prefix(CLOUD_ALIAS_PREFIX)
        .unwrap_or(name)
        .to_owned()
}

/// Earlier models once each, in order, without the current one.
pub fn earlier_models(
    receipt_models: impl IntoIterator<Item = String>,
    current: Option<&str>,
) -> Vec<String> {
    let current = current.map(shown_model);
    let mut seen = Vec::new();
    for model in receipt_models {
        let model = shown_model(&model);
        if model.is_empty() || Some(&model) == current.as_ref() || seen.contains(&model) {
            continue;
        }
        seen.push(model);
    }
    seen
}

/// The local default model from the agent's settings, as `provider/model`.
pub fn local_default_model(settings: &serde_json::Value) -> Option<String> {
    let provider = settings.get("defaultProvider")?.as_str()?.trim();
    let model = settings.get("defaultModel")?.as_str()?.trim();
    if provider.is_empty() || model.is_empty() {
        return None;
    }
    Some(format!("{provider}/{model}"))
}

/// Reads the local default model from `<agent directory>/settings.json`.
pub fn read_local_default_model(agent_directory: &Path) -> Option<String> {
    let bytes = std::fs::read(agent_directory.join("settings.json")).ok()?;
    let settings: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    local_default_model(&settings)
}

/// The agent's working directory: the configured Home, else the default Home
/// for this user, else nothing.
pub fn working_directory(config_directory: &Path) -> Option<PathBuf> {
    if let Ok(Some(home)) = crate::home::configured_home(config_directory) {
        return Some(home);
    }
    let home = PathBuf::from(crate::state_root::home_directory_value()?);
    crate::home::choose_default_home(Some(home.join("Documents")), Some(home)).ok()
}

/// The zone name behind a `zoneinfo` link such as
/// `/var/db/timezone/zoneinfo/America/New_York`.
pub fn zone_name_from_link(target: &Path) -> Option<String> {
    let text = target.to_str()?;
    let (_, zone) = text.rsplit_once("zoneinfo/")?;
    let zone = zone.trim_matches('/');
    (!zone.is_empty()).then(|| zone.to_owned())
}

/// The IANA zone name: `TZ` when set, else the system's local time link.
pub fn zone_name() -> Option<String> {
    if let Some(zone) = std::env::var_os("TZ").filter(|value| !value.is_empty()) {
        return zone.into_string().ok();
    }
    if cfg!(unix) {
        std::fs::read_link("/etc/localtime")
            .ok()
            .and_then(|target| zone_name_from_link(&target))
    } else {
        None
    }
}

/// The line that opens a user message: when it was sent, with offset and zone.
pub fn message_timestamp() -> String {
    timestamp_line(
        &chrono::Local::now().to_rfc3339_opts(SecondsFormat::Secs, false),
        zone_name().as_deref(),
    )
}

pub fn timestamp_line(local_time: &str, zone: Option<&str>) -> String {
    match zone {
        Some(zone) => format!("[sent {local_time} {zone}]"),
        None => format!("[sent {local_time}]"),
    }
}

/// A user message with its timestamp line in front.
pub fn stamp_message(message: &str) -> String {
    format!("{}\n{message}", message_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_fact_and_names_the_model_once() {
        let facts = LaunchFacts {
            model: Some("xai/grok-4.6".into()),
            earlier_models: vec!["openai/gpt-5.5".into()],
            working_directory: Some(PathBuf::from("/Users/a/Documents/Muniment")),
        };
        let block = facts.render();
        assert!(block.starts_with("Facts:\n"));
        assert!(block.contains("running as the model xai/grok-4.6"));
        assert!(block.contains("other models: openai/gpt-5.5. You did not write them."));
        assert!(block.contains(&format!(
            "The host runs {PLATFORM}. Shell commands run in {SHELL}."
        )));
        assert!(block.contains("The working directory is /Users/a/Documents/Muniment."));
        assert!(block.contains("opens with a line that says when it was sent"));
        let prompt = system_prompt_with_facts("You are the assistant.", &facts);
        assert!(prompt.starts_with("You are the assistant.\n\nFacts:"));
    }

    #[test]
    fn an_unknown_model_asks_for_honesty_and_no_earlier_line_appears() {
        let block = LaunchFacts::default().render();
        assert!(block.contains("has not recorded which model is answering"));
        assert!(block.contains("say that you do not know rather than name one"));
        assert!(!block.contains("Earlier replies"));
        assert!(block.contains("No working directory is configured."));
    }

    #[test]
    fn earlier_models_are_distinct_ordered_and_exclude_the_current_one() {
        let models = [
            "openai/gpt-5.5",
            "xai/grok-4.6",
            "openai/gpt-5.5",
            "muniment/claude-sonnet-5",
            "",
        ]
        .map(String::from);
        assert_eq!(
            earlier_models(models, Some("xai/grok-4.6")),
            ["openai/gpt-5.5", "claude-sonnet-5"]
        );
        assert_eq!(shown_model("muniment/gpt-5.5"), "gpt-5.5");
        assert_eq!(shown_model("xai/grok-4.6"), "xai/grok-4.6");
    }

    #[test]
    fn reads_the_local_default_as_provider_and_model() {
        let settings = serde_json::json!({"defaultProvider": "xai", "defaultModel": "grok-4.6"});
        assert_eq!(
            local_default_model(&settings).as_deref(),
            Some("xai/grok-4.6")
        );
        assert_eq!(
            local_default_model(&serde_json::json!({"defaultProvider": "xai"})),
            None
        );
        assert_eq!(
            local_default_model(&serde_json::json!({"defaultProvider": " ", "defaultModel": "m"})),
            None
        );
        let directory =
            std::env::temp_dir().join(format!("muniment-launch-facts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("settings.json"),
            br#"{"defaultProvider":"ollama","defaultModel":"llama3.2:3b"}"#,
        )
        .unwrap();
        assert_eq!(
            read_local_default_model(&directory).as_deref(),
            Some("ollama/llama3.2:3b")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reads_the_zone_from_a_localtime_link_and_stamps_a_message() {
        assert_eq!(
            zone_name_from_link(Path::new("/var/db/timezone/zoneinfo/America/New_York")).as_deref(),
            Some("America/New_York")
        );
        assert_eq!(
            zone_name_from_link(Path::new("/usr/share/zoneinfo/UTC")).as_deref(),
            Some("UTC")
        );
        assert_eq!(zone_name_from_link(Path::new("/etc/localtime")), None);
        assert_eq!(
            timestamp_line("2026-09-16T08:41:03-04:00", Some("America/New_York")),
            "[sent 2026-09-16T08:41:03-04:00 America/New_York]"
        );
        assert_eq!(
            timestamp_line("2026-09-16T08:41:03-04:00", None),
            "[sent 2026-09-16T08:41:03-04:00]"
        );
        let stamped = stamp_message("what time is it");
        let (first, rest) = stamped.split_once('\n').unwrap();
        assert!(
            first.starts_with("[sent 20") && first.ends_with(']'),
            "{first}"
        );
        assert_eq!(rest, "what time is it");
    }
}
