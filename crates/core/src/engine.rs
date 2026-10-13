//! The runtime's one boundary to its agent engine.
//!
//! The runtime reaches the engine through [`AgentEngine`] alone. An adapter
//! implements it for one engine. [`PiRpcEngine`] is the adapter for the Pi
//! coding agent in RPC mode. It wraps the `sidecar`, `pi_launch`,
//! `pi_execution` and `pi_settings` modules, and only the adapter reads Pi RPC
//! frames, Pi session files and Pi settings files.

mod pi_rpc;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::active_run::ChatDelivery;
use crate::sidecar::pi_chat::{ExtensionUiAnswer, ExtensionUiRequest};
use crate::sidecar::SidecarStatus;

pub use pi_rpc::{OpenStage, PiOpen, PiRpcEngine};

/// One event of a turn: a reply's text, a tool's activity, a permission
/// request, a compaction's outcome or the turn's end.
pub type EngineEvent = crate::sidecar::pi_chat::PiChatEvent;

/// An image a prompt carries.
pub type EngineImage = crate::sidecar::pi_chat::PiImageContent;

/// One prompt for the engine: its text and the images it carries.
pub struct Submission<'a> {
    pub message: &'a str,
    pub images: Vec<EngineImage>,
}

/// Why a conversation did not open. Each case after `Spawn` hands back the
/// started process, so the caller decides when it stops.
pub enum OpenError<P> {
    /// The engine process did not start.
    Spawn(String),
    /// The caller cancelled before the engine was ready.
    Cancelled(P),
    /// The engine did not become ready. The status is the last one seen.
    NotReady(P, SidecarStatus),
    /// The engine became ready without a conversation handle.
    Unavailable(P),
}

/// The context window of one conversation, as the engine counts it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContextUsage {
    /// The tokens in the context. `None` means the engine has no count.
    pub tokens: Option<u64>,
    pub context_window: Option<u64>,
    pub percent: Option<f64>,
    /// True when `tokens` is the last compaction's estimate, because the
    /// engine has no count between a compaction and the next reply.
    pub estimated: bool,
    /// False when the active model's window is a default, not a known value.
    pub window_known: bool,
    pub provider: Option<String>,
    pub model: Option<String>,
    /// Whether the engine compacts on its own near the window's end.
    pub auto_compact: bool,
    /// The token count at which automatic compaction starts.
    pub compact_at: Option<u64>,
}

/// The token counts of one finished compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionOutcome {
    pub tokens_before: u64,
    pub estimated_tokens_after: Option<u64>,
}

/// The engine-wide compaction settings. They apply when a conversation opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactionSettings {
    pub enabled: bool,
    pub reserve_tokens: u64,
    pub keep_recent_tokens: u64,
}

impl Default for CompactionSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            reserve_tokens: 16_384,
            keep_recent_tokens: 20_000,
        }
    }
}

impl CompactionSettings {
    /// The token counts a user may choose.
    pub const TOKEN_RANGE: std::ops::RangeInclusive<u64> = 4_096..=131_072;

    pub fn validate(&self) -> Result<(), String> {
        if !Self::TOKEN_RANGE.contains(&self.reserve_tokens)
            || !Self::TOKEN_RANGE.contains(&self.keep_recent_tokens)
        {
            return Err("Choose token counts between 4,096 and 131,072.".into());
        }
        Ok(())
    }
}

/// What `configure` changes on an open conversation. `None` keeps a value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Configuration<'a> {
    /// The provider and model that answer the next turn.
    pub model: Option<(&'a str, &'a str)>,
    /// Whether the conversation compacts on its own.
    pub auto_compaction: Option<bool>,
    /// The tools the conversation may call. An engine that fixes its tools
    /// when it opens refuses a change.
    pub tools: Option<&'a [&'a str]>,
}

/// What `open` answers: the process with a conversation handle, or why the
/// conversation did not open.
pub type Opened<E> = Result<
    (
        <E as AgentEngine>::Process,
        <E as AgentEngine>::Conversation,
    ),
    OpenError<<E as AgentEngine>::Process>,
>;

/// The runtime's one interface to the agent engine.
///
/// `open` starts the engine on a new or a saved conversation and answers the
/// process that keeps it alive with a handle to the conversation. Each turn
/// is a prompt, a resumed reply or a compaction, and `next_event` reads its
/// events until it ends.
pub trait AgentEngine {
    /// What `open` starts the engine with.
    type Launch<'a>;
    /// What keeps the engine running.
    type Process;
    /// The handle every conversation operation takes.
    type Conversation;
    /// One submitted turn and its event stream.
    type Turn;
    /// The engine's durable name for a conversation, kept in the run journal.
    type Locator;

    /// Opens a conversation: a new one, or the saved one the launch names.
    fn open(&self, launch: Self::Launch<'_>) -> Opened<Self>;

    /// Submits a prompt. `intercept` sees each event that arrives before the
    /// engine accepts the prompt and answers whether it handled the event.
    fn submit(
        &self,
        conversation: &Self::Conversation,
        run_id: &str,
        submission: Submission<'_>,
        intercept: &mut dyn FnMut(&Self::Turn, &EngineEvent) -> bool,
    ) -> Result<Self::Turn, String>;

    /// Waits until the engine names the conversation's durable locator.
    /// Events that `intercept` does not handle return in order.
    fn bind(
        &self,
        conversation: &Self::Conversation,
        turn: &Self::Turn,
        intercept: &mut dyn FnMut(&EngineEvent) -> Result<bool, String>,
    ) -> Result<(Self::Locator, Vec<EngineEvent>), String>;

    /// Continues a reply that a crash interrupted, in the conversation the
    /// journal names.
    fn resume(
        &self,
        conversation: &Self::Conversation,
        run_id: &str,
        locator: &Self::Locator,
        continuation: &str,
    ) -> Result<Self::Turn, String>;

    /// Delivers a message to the running turn now, or after it ends.
    fn steer(
        &self,
        conversation: &Self::Conversation,
        turn: &Self::Turn,
        delivery: ChatDelivery,
        message: &str,
    ) -> Result<(), String>;

    /// Stops the running turn and waits until the engine reports its end.
    fn cancel(
        &self,
        conversation: &Self::Conversation,
        turn: &Self::Turn,
        timeout: Duration,
    ) -> Result<(), String>;

    /// Answers a permission or extension request the turn raised.
    fn answer(
        &self,
        conversation: &Self::Conversation,
        turn: &Self::Turn,
        request: &ExtensionUiRequest,
        answer: ExtensionUiAnswer,
    ) -> Result<(), String>;

    /// Reads the turn's next event.
    fn next_event(
        &self,
        conversation: &Self::Conversation,
        turn: &Self::Turn,
        timeout: Duration,
    ) -> Result<EngineEvent, String>;

    /// Compacts the conversation, with optional instructions for the summary.
    /// The turn reports the compaction's activity and ends with
    /// [`EngineEvent::Compacted`].
    fn compact(
        &self,
        conversation: &Self::Conversation,
        run_id: &str,
        locator: &Self::Locator,
        instructions: Option<&str>,
    ) -> Result<Self::Turn, String>;

    /// Reads how much of the context window the conversation fills.
    fn context_usage(&self, conversation: &Self::Conversation) -> Result<ContextUsage, String>;

    /// Changes the model or the tools of an open conversation.
    fn configure(
        &self,
        conversation: &Self::Conversation,
        configuration: &Configuration<'_>,
    ) -> Result<(), String>;

    /// Reads the engine-wide compaction settings.
    fn compaction_settings(&self) -> Result<CompactionSettings, String>;

    /// Saves the engine-wide compaction settings and answers what it saved.
    fn save_compaction_settings(
        &self,
        settings: CompactionSettings,
    ) -> Result<CompactionSettings, String>;

    /// Whether the engine process has stopped.
    fn stopped(&self, process: &Self::Process) -> bool;

    /// Stops the engine process.
    fn stop(&self, process: &mut Self::Process);
}

/// The last compaction each conversation reported, by locator. The engine
/// counts no tokens between a compaction and the next reply, so the usage
/// read answers this estimate until then.
static COMPACTIONS: Mutex<BTreeMap<String, CompactionOutcome>> = Mutex::new(BTreeMap::new());

/// Keeps the last compaction a conversation reported.
pub(crate) fn record_compaction(locator: &str, outcome: CompactionOutcome) {
    COMPACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(locator.to_owned(), outcome);
}

/// The last compaction a conversation reported in this process.
pub fn last_compaction(locator: &str) -> Option<CompactionOutcome> {
    COMPACTIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(locator)
        .copied()
}
