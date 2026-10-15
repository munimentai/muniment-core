//! The engine adapter for the Pi coding agent in RPC mode.

use crate::runtime_eprintln as eprintln;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::{
    clamp_thinking_level, startup_thinking_level, supported_thinking_levels, AgentEngine,
    CompactionSettings, Configuration, ContextUsage, EngineEvent, OpenError, Opened, Submission,
    Thinking,
};
use crate::active_run::ChatDelivery;
use crate::pi_execution::{PiRuntime, RPC_TIMEOUT};
use crate::sidecar::pi_chat::{ExtensionUiAnswer, ExtensionUiRequest, PiRunAdapter};
use crate::sidecar::{
    PiRpcTransport, PiRpcWiring, PiSessionLocator, SidecarConfig, SidecarStatus, SidecarSupervisor,
};

/// The bound on a queued steer or follow-up message.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(2);
/// The bound on a state read, such as the context usage.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const READ_SETTINGS_ERROR: &str =
    "Muniment cannot read provider settings. Check folder access, then retry.";
const SAVE_SETTINGS_ERROR: &str =
    "Muniment cannot save provider settings. Check folder access, then retry.";

/// A step of `open` the caller observes, such as for run diagnostics.
pub enum OpenStage<'a> {
    /// The Pi process started and has not answered its readiness probe yet.
    Spawned(&'a SidecarSupervisor),
    /// One poll of the readiness wait.
    Waiting,
}

/// What the Pi adapter opens a conversation with: the launch the `pi_launch`
/// module builds, a cancel flag the readiness wait reads, and an observer.
pub struct PiOpen<'a> {
    pub config: SidecarConfig,
    pub cancelled: &'a AtomicBool,
    pub observe: &'a mut dyn FnMut(OpenStage<'_>),
}

/// The Pi RPC adapter. Conversations live as Pi session files under the
/// session root, and the agent directory holds Pi's `settings.json` and
/// `models.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PiRpcEngine {
    session_root: Option<PathBuf>,
    pub(super) agent_directory: Option<PathBuf>,
    /// The root the pinned Pi installs under.
    pub(super) harness_root: Option<PathBuf>,
}

impl PiRpcEngine {
    /// An adapter for the session root given, and the agent directory and Pi
    /// install root under the state root, the ones Pi reads at launch.
    pub fn new(session_root: Option<PathBuf>) -> Self {
        let state = crate::state_root::state_directory();
        Self {
            session_root,
            agent_directory: state.as_deref().map(crate::state_root::agent_directory),
            harness_root: state.map(|state| state.join(crate::state_root::HARNESS_DIRECTORY_NAME)),
        }
    }

    /// Replaces the agent directory, for a host with another state root.
    pub fn with_agent_directory(mut self, agent_directory: impl Into<PathBuf>) -> Self {
        self.agent_directory = Some(agent_directory.into());
        self
    }

    fn agent(&self, error: &str) -> Result<&Path, String> {
        self.agent_directory
            .as_deref()
            .ok_or_else(|| error.to_owned())
    }

    fn settings_path(&self, error: &str) -> Result<PathBuf, String> {
        Ok(self.agent(error)?.join("settings.json"))
    }

    fn read_settings(&self) -> Result<Map<String, Value>, String> {
        let path = self.settings_path(READ_SETTINGS_ERROR)?;
        match path.parent().map(Path::try_exists) {
            Some(Ok(false)) => return Ok(Map::new()),
            Some(Err(_)) => return Err(READ_SETTINGS_ERROR.into()),
            _ => {}
        }
        let _lock = crate::pi_settings::lock_settings(&path)
            .map_err(|_| READ_SETTINGS_ERROR.to_string())?;
        read_object(&path).map_err(|_| READ_SETTINGS_ERROR.to_string())
    }

    /// The context usage in Pi's `get_session_stats` and `get_state` answers.
    fn usage_from(&self, stats: &Value, state: &Value) -> Result<ContextUsage, String> {
        let usage = stats.get("contextUsage");
        let count = |value: Option<&Value>| {
            value
                .and_then(Value::as_f64)
                .filter(|count| count.is_finite())
                .map(|count| count.max(0.0) as u64)
        };
        let provider = state
            .pointer("/model/provider")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let model = state
            .pointer("/model/id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        // Pi reports no window before a model's first reply and while a turn
        // runs. The model knowledge in core answers for the active model then.
        let reported = count(usage.and_then(|usage| usage.get("contextWindow")))
            .or_else(|| count(state.pointer("/model/contextWindow")))
            .filter(|window| *window > 0);
        let looked_up = || {
            let agent = self.agent_directory.as_deref()?;
            let (provider, model) = provider.as_deref().zip(model.as_deref())?;
            crate::models::window::window(agent, provider, model).map(|window| window.context)
        };
        let context_window = reported.or_else(looked_up).filter(|window| *window > 0);
        let mut tokens = count(usage.and_then(|usage| usage.get("tokens")));
        let mut percent = usage
            .and_then(|usage| usage.get("percent"))
            .and_then(Value::as_f64)
            .filter(|percent| percent.is_finite());
        let mut estimated = false;
        if tokens.is_none() {
            let session = stats
                .get("sessionFile")
                .and_then(Value::as_str)
                .and_then(|file| Path::new(file).file_name())
                .and_then(|name| name.to_str());
            if let Some(after) = session
                .and_then(super::last_compaction)
                .and_then(|outcome| outcome.estimated_tokens_after)
            {
                tokens = Some(after);
                percent = context_window.map(|window| after as f64 * 100.0 / window as f64);
                estimated = true;
            }
        }
        if percent.is_none() {
            percent = tokens
                .zip(context_window)
                .map(|(tokens, window)| tokens as f64 * 100.0 / window as f64);
        }
        let active = provider.as_deref().zip(model.as_deref());
        let settings = compaction_settings_for(&self.read_settings()?, active);
        Ok(ContextUsage {
            tokens,
            context_window,
            percent,
            estimated,
            window_known: context_window.is_some()
                && active.is_none_or(|(provider, model)| self.window_known(provider, model)),
            provider,
            model,
            auto_compact: settings.enabled,
            compact_at: context_window.map(|window| window.saturating_sub(settings.reserve_tokens)),
        })
    }

    /// Sends Pi the level a turn runs at, only when it differs from the
    /// level the conversation runs at now. Each read and command waits until
    /// `deadline` at most.
    fn apply_thinking(
        &self,
        transport: &PiRpcTransport,
        thinking: Thinking<'_>,
        deadline: Instant,
    ) -> Result<(), String> {
        let wait = || READ_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        let state = read_within(transport, "get_state", wait())?;
        let current = state.get("thinkingLevel").and_then(Value::as_str);
        let Some(level) = self.thinking_level_for(&state, thinking)? else {
            return Ok(());
        };
        if current == Some(level) {
            return Ok(());
        }
        let response = transport.call(
            json!({"type": "set_thinking_level", "level": level}),
            wait(),
        )?;
        require_success(&response, "set_thinking_level")
    }

    /// The level the active model in a `get_state` answer runs a turn at:
    /// the choice, or the level Pi starts the model at, clamped to the levels
    /// the model supports. A state with no model, or a model without
    /// reasoning, answers none, because Pi runs it without thinking.
    fn thinking_level_for(
        &self,
        state: &Value,
        thinking: Thinking<'_>,
    ) -> Result<Option<&'static str>, String> {
        let Some(model) = state.get("model").filter(|model| model.is_object()) else {
            return Ok(None);
        };
        if model.get("reasoning").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }
        let available = supported_thinking_levels(model);
        let level = match thinking {
            Thinking::Level(level) => clamp_thinking_level(level, &available),
            Thinking::Default => {
                let settings = self.read_settings()?;
                let provider = model.get("provider").and_then(Value::as_str);
                let id = model.get("id").and_then(Value::as_str);
                let wanted = provider
                    .zip(id)
                    .map_or(super::DEFAULT_THINKING_LEVEL, |(provider, id)| {
                        startup_thinking_level(&settings, provider, id)
                    });
                clamp_thinking_level(wanted, &available)
            }
        };
        Ok(Some(level))
    }

    /// Answers whether the model's window is a known value. A model that
    /// `models.json` defines without a `contextWindow` runs on Pi's default
    /// window. Any other model is in Pi's built-in catalog.
    fn window_known(&self, provider: &str, model: &str) -> bool {
        let Some(agent) = self.agent_directory.as_deref() else {
            return true;
        };
        let Ok(models) = read_object(&agent.join("models.json")) else {
            return true;
        };
        !models
            .get("providers")
            .and_then(|providers| providers.get(provider))
            .and_then(|provider| provider.get("models"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|entry| {
                entry.get("id").and_then(Value::as_str) == Some(model)
                    && entry
                        .get("contextWindow")
                        .and_then(Value::as_u64)
                        .is_none_or(|window| window == 0)
            })
    }
}

fn read_object(path: &Path) -> std::io::Result<Map<String, Value>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(error) => Err(error),
    }
}

/// Reads the compaction settings Pi applies to one model: the ordinary
/// settings, with the model's `modelOverrides` entry over its token counts.
fn compaction_settings_for(
    settings: &Map<String, Value>,
    model: Option<(&str, &str)>,
) -> CompactionSettings {
    let defaults = CompactionSettings::default();
    let compaction = settings.get("compaction");
    let field = |name: &str| {
        let ordinary = compaction.and_then(|value| value.get(name));
        model
            .and_then(|(provider, model)| {
                compaction?
                    .get("modelOverrides")?
                    .get(format!("{provider}/{model}"))?
                    .get(name)
            })
            .or(ordinary)
    };
    CompactionSettings {
        enabled: compaction
            .and_then(|value| value.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(defaults.enabled),
        reserve_tokens: field("reserveTokens")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.reserve_tokens),
        keep_recent_tokens: field("keepRecentTokens")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.keep_recent_tokens),
    }
}

/// Sends one Pi command and answers its `data` when Pi reports success.
fn read(transport: &PiRpcTransport, command: &str) -> Result<Value, String> {
    read_within(transport, command, READ_TIMEOUT)
}

/// Sends one Pi command, waits `timeout` at most, and answers its `data`
/// when Pi reports success.
fn read_within(
    transport: &PiRpcTransport,
    command: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let response = transport.call(json!({"type": command}), timeout)?;
    if response.get("type").and_then(Value::as_str) != Some("response")
        || response.get("command").and_then(Value::as_str) != Some(command)
        || response.get("success").and_then(Value::as_bool) != Some(true)
    {
        return Err("The agent runtime did not answer the context read.".into());
    }
    Ok(response.get("data").cloned().unwrap_or(Value::Null))
}

fn require_success(response: &Value, command: &str) -> Result<(), String> {
    if response.get("type").and_then(Value::as_str) == Some("response")
        && response.get("command").and_then(Value::as_str) == Some(command)
        && response.get("success").and_then(Value::as_bool) == Some(true)
    {
        Ok(())
    } else {
        Err("The agent runtime refused the setting.".into())
    }
}

impl AgentEngine for PiRpcEngine {
    type Launch<'a> = PiOpen<'a>;
    type Process = PiRuntime;
    type Conversation = Arc<PiRpcTransport>;
    type Turn = PiRunAdapter;
    type Locator = PiSessionLocator;

    fn open(&self, launch: PiOpen<'_>) -> Opened<Self> {
        let PiOpen {
            config,
            cancelled,
            observe,
        } = launch;
        let startup_timeout = config.startup_timeout;
        let wiring = PiRpcWiring::new();
        let supervisor = SidecarSupervisor::spawn(
            config,
            wiring.readiness_probe_with_startup_timeout(startup_timeout, Duration::from_secs(10)),
        )
        .map_err(|error| OpenError::Spawn(format!("{error:?}")))?;
        observe(OpenStage::Spawned(&supervisor));
        let process = PiRuntime { supervisor, wiring };
        let deadline = Instant::now() + startup_timeout;
        while process.supervisor.status() == SidecarStatus::Starting && Instant::now() < deadline {
            observe(OpenStage::Waiting);
            if cancelled.load(Ordering::SeqCst) {
                return Err(OpenError::Cancelled(process));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        observe(OpenStage::Waiting);
        let status = process.supervisor.status();
        if status != SidecarStatus::Healthy {
            return Err(OpenError::NotReady(process, status));
        }
        match process.wiring.transport() {
            Some(transport) => Ok((process, transport)),
            None => Err(OpenError::Unavailable(process)),
        }
    }

    fn submit(
        &self,
        conversation: &Arc<PiRpcTransport>,
        run_id: &str,
        submission: Submission<'_>,
        intercept: &mut dyn FnMut(&PiRunAdapter, &EngineEvent) -> bool,
    ) -> Result<PiRunAdapter, String> {
        let thinking = submission.thinking;
        PiRunAdapter::start_prepared(
            run_id,
            conversation,
            submission.message,
            submission.images,
            RPC_TIMEOUT,
            |transport, deadline| {
                let Some(thinking) = thinking else {
                    return;
                };
                // A level Pi does not take leaves the turn at the level it runs at now.
                if let Err(error) = self.apply_thinking(transport, thinking, deadline) {
                    eprintln!("muniment-runtime: run_id={run_id} thinking_level error={error:?}");
                }
            },
            |turn, event| intercept(turn, event),
        )
        .map(|(turn, _)| turn)
    }

    fn bind(
        &self,
        conversation: &Arc<PiRpcTransport>,
        turn: &PiRunAdapter,
        intercept: &mut dyn FnMut(&EngineEvent) -> Result<bool, String>,
    ) -> Result<(PiSessionLocator, Vec<EngineEvent>), String> {
        let root = self
            .session_root
            .as_deref()
            .ok_or("The agent runtime session directory is unavailable.")?;
        turn.await_session_binding_with_handler(conversation, root, RPC_TIMEOUT, |event| {
            intercept(event)
        })
    }

    fn resume(
        &self,
        conversation: &Arc<PiRpcTransport>,
        run_id: &str,
        locator: &PiSessionLocator,
        continuation: &str,
    ) -> Result<PiRunAdapter, String> {
        let (turn, _) = PiRunAdapter::start(run_id, conversation, continuation, RPC_TIMEOUT)?;
        turn.bind_session(locator);
        Ok(turn)
    }

    fn steer(
        &self,
        conversation: &Arc<PiRpcTransport>,
        turn: &PiRunAdapter,
        delivery: ChatDelivery,
        message: &str,
    ) -> Result<(), String> {
        match delivery {
            ChatDelivery::Steer => turn.steer(conversation, message, QUEUE_TIMEOUT),
            ChatDelivery::FollowUp => turn.follow_up(conversation, message, QUEUE_TIMEOUT),
        }
    }

    fn cancel(
        &self,
        conversation: &Arc<PiRpcTransport>,
        turn: &PiRunAdapter,
        timeout: Duration,
    ) -> Result<(), String> {
        turn.cancel_and_drain(conversation, timeout)
    }

    fn answer(
        &self,
        conversation: &Arc<PiRpcTransport>,
        turn: &PiRunAdapter,
        request: &ExtensionUiRequest,
        answer: ExtensionUiAnswer,
    ) -> Result<(), String> {
        turn.answer_extension_ui(conversation, request, answer)
    }

    fn next_event(
        &self,
        conversation: &Arc<PiRpcTransport>,
        turn: &PiRunAdapter,
        timeout: Duration,
    ) -> Result<EngineEvent, String> {
        turn.next_settled(conversation, timeout)
    }

    fn compact(
        &self,
        conversation: &Arc<PiRpcTransport>,
        run_id: &str,
        locator: &PiSessionLocator,
        instructions: Option<&str>,
    ) -> Result<PiRunAdapter, String> {
        let turn = PiRunAdapter::compact(run_id, conversation, instructions)?;
        turn.bind_session(locator);
        Ok(turn)
    }

    fn context_usage(&self, conversation: &Arc<PiRpcTransport>) -> Result<ContextUsage, String> {
        let stats = read(conversation, "get_session_stats")?;
        let state = read(conversation, "get_state")?;
        self.usage_from(&stats, &state)
    }

    fn configure(
        &self,
        conversation: &Arc<PiRpcTransport>,
        configuration: &Configuration<'_>,
    ) -> Result<(), String> {
        if configuration.tools.is_some() {
            return Err("The agent runtime sets its tools when a conversation opens.".into());
        }
        if let Some((provider, model)) = configuration.model {
            let response = conversation.call(
                json!({"type": "set_model", "provider": provider, "modelId": model}),
                READ_TIMEOUT,
            )?;
            require_success(&response, "set_model")?;
        }
        if let Some(enabled) = configuration.auto_compaction {
            let response = conversation.call(
                json!({"type": "set_auto_compaction", "enabled": enabled}),
                READ_TIMEOUT,
            )?;
            require_success(&response, "set_auto_compaction")?;
        }
        if let Some(thinking) = configuration.thinking {
            self.apply_thinking(conversation, thinking, Instant::now() + READ_TIMEOUT)?;
        }
        Ok(())
    }

    fn compaction_settings(&self) -> Result<CompactionSettings, String> {
        Ok(compaction_settings_for(&self.read_settings()?, None))
    }

    fn save_compaction_settings(
        &self,
        settings: CompactionSettings,
    ) -> Result<CompactionSettings, String> {
        settings.validate()?;
        let path = self.settings_path(SAVE_SETTINGS_ERROR)?;
        let save = || -> std::io::Result<()> {
            std::fs::create_dir_all(
                self.agent(SAVE_SETTINGS_ERROR)
                    .map_err(std::io::Error::other)?,
            )?;
            let lock = crate::pi_settings::lock_settings(&path)?;
            let mut root = read_object(&path)?;
            let compaction = root
                .entry("compaction")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("The compaction settings are invalid."))?;
            compaction.insert("enabled".into(), settings.enabled.into());
            compaction.insert("reserveTokens".into(), settings.reserve_tokens.into());
            compaction.insert(
                "keepRecentTokens".into(),
                settings.keep_recent_tokens.into(),
            );
            lock.check()?;
            crate::model_router::config::write_private(&path, &serde_json::to_vec_pretty(&root)?)
        };
        save().map_err(|error| {
            if error.to_string() == "The compaction settings are invalid." {
                error.to_string()
            } else {
                SAVE_SETTINGS_ERROR.to_string()
            }
        })?;
        self.compaction_settings()
    }

    fn stopped(&self, process: &PiRuntime) -> bool {
        matches!(
            process.supervisor.status(),
            SidecarStatus::Failed | SidecarStatus::Stopped
        )
    }

    fn stop(&self, process: &mut PiRuntime) {
        let _ = process.supervisor.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("muniment-engine-pi-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn compaction_settings_save_keeps_other_settings_and_answers_what_it_saved() {
        let agent = agent();
        std::fs::write(
            agent.join("settings.json"),
            r#"{"defaultModel":"audit-model"}"#,
        )
        .unwrap();
        let engine = PiRpcEngine::new(None).with_agent_directory(&agent);
        let wanted = CompactionSettings {
            enabled: false,
            reserve_tokens: 8192,
            keep_recent_tokens: 12000,
        };
        let saved = engine.save_compaction_settings(wanted).unwrap();
        assert_eq!(saved, wanted);
        assert_eq!(engine.compaction_settings().unwrap(), saved);
        let root = read_object(&agent.join("settings.json")).unwrap();
        assert_eq!(root["defaultModel"], "audit-model");
        assert_eq!(
            root["compaction"],
            json!({"enabled": false, "reserveTokens": 8192, "keepRecentTokens": 12000})
        );
        assert_eq!(
            engine
                .save_compaction_settings(CompactionSettings {
                    reserve_tokens: 0,
                    ..wanted
                })
                .unwrap_err(),
            "Choose token counts between 4,096 and 131,072."
        );
        assert_eq!(engine.compaction_settings().unwrap(), saved);
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn missing_settings_read_as_pi_defaults() {
        let agent = agent();
        let engine = PiRpcEngine::new(None).with_agent_directory(agent.join("absent"));
        assert_eq!(
            engine.compaction_settings().unwrap(),
            CompactionSettings::default()
        );
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_model_override_replaces_the_ordinary_reserve() {
        let settings = json!({"compaction": {
            "enabled": true,
            "reserveTokens": 16384,
            "modelOverrides": {"local/big": {"reserveTokens": 400000}}
        }});
        let settings = settings.as_object().unwrap();
        assert_eq!(
            compaction_settings_for(settings, Some(("local", "big"))).reserve_tokens,
            400000
        );
        assert_eq!(
            compaction_settings_for(settings, Some(("local", "small"))).reserve_tokens,
            16384
        );
        assert_eq!(
            compaction_settings_for(settings, Some(("local", "big"))).keep_recent_tokens,
            20000
        );
    }

    #[test]
    fn a_window_pi_does_not_report_comes_from_the_model_knowledge() {
        let agent = agent();
        std::fs::write(
            agent.join("models.json"),
            json!({"providers": {"muniment-router": {"models": [{"id": "openai/sized", "contextWindow": 272000}]}}}).to_string(),
        )
        .unwrap();
        let engine = PiRpcEngine::new(None).with_agent_directory(&agent);
        let stats =
            json!({"contextUsage": {"tokens": 68000, "contextWindow": null, "percent": null}});
        let state = json!({"model": {"provider": "muniment-router", "id": "openai/sized"}});
        let usage = engine.usage_from(&stats, &state).unwrap();
        assert_eq!(usage.context_window, Some(272000));
        assert!(usage.window_known);
        assert_eq!(usage.percent, Some(25.0));
        // A model nothing knows keeps an unknown window.
        let state = json!({"model": {"provider": "local", "id": "nameless"}});
        let usage = engine.usage_from(&stats, &state).unwrap();
        assert_eq!(usage.context_window, None);
        assert!(!usage.window_known);
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_custom_model_without_a_window_is_unknown() {
        let agent = agent();
        std::fs::write(
            agent.join("models.json"),
            json!({"providers": {"local": {"models": [
                {"id": "sized", "contextWindow": 32768},
                {"id": "unsized"}
            ]}}})
            .to_string(),
        )
        .unwrap();
        let engine = PiRpcEngine::new(None).with_agent_directory(&agent);
        assert!(engine.window_known("local", "sized"));
        assert!(!engine.window_known("local", "unsized"));
        assert!(engine.window_known("anthropic", "catalog-model"));
        std::fs::remove_dir_all(agent).unwrap();
    }
}
