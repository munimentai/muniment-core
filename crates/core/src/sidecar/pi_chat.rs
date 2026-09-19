//! Typed projection of the Pi 0.73.1 chat event stream.
//!
//! Pi has one active agent stream. Muniment nevertheless tags every projected
//! event with the locally-owned run id; callers must create a fresh adapter for
//! each accepted prompt and discard unrelated frames.

use crate::runtime_eprintln as eprintln;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::PiRpcTransport;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptCommand<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub message: &'a str,
    pub streaming_behavior: StreamingBehavior,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<PiImageContent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PiImageContent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub data: String,
    pub mime_type: String,
}

impl PiImageContent {
    pub fn new(data: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self {
            kind: "image",
            data: data.into(),
            mime_type: mime_type.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum StreamingBehavior {
    #[serde(rename = "steer")]
    Steer,
    #[serde(rename = "followUp")]
    FollowUp,
}

impl<'a> PromptCommand<'a> {
    pub fn new(message: &'a str) -> Self {
        Self {
            kind: "prompt",
            message,
            streaming_behavior: StreamingBehavior::Steer,
            images: Vec::new(),
        }
    }

    pub fn with_images(message: &'a str, images: Vec<PiImageContent>) -> Self {
        Self {
            images,
            ..Self::new(message)
        }
    }

    pub fn into_value(self) -> Value {
        serde_json::to_value(self).expect("PromptCommand is JSON serializable")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<CapabilityReceipt>,
    /// The tokens the reply's turns used, summed from Pi's usage on each assistant message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenUsage>,
    /// How many assistant messages the run took.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turns: Option<u32>,
    /// One tally per tool name: calls made and calls that failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReceipt {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub reasoning: u64,
    pub total: u64,
}

impl TokenUsage {
    pub fn add(&mut self, other: &TokenUsage) {
        self.input += other.input;
        self.output += other.output;
        self.cache_read += other.cache_read;
        self.cache_write += other.cache_write;
        self.reasoning += other.reasoning;
        self.total += other.total;
    }

    fn from_frame(usage: &Value) -> Option<Self> {
        let count = |field: &str| {
            usage
                .get(field)
                .and_then(Value::as_f64)
                .map(|n| n.max(0.0) as u64)
        };
        Some(Self {
            input: count("input")?,
            output: count("output")?,
            cache_read: count("cacheRead").unwrap_or(0),
            cache_write: count("cacheWrite").unwrap_or(0),
            reasoning: count("reasoning").unwrap_or(0),
            total: count("totalTokens").unwrap_or(0),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolReceipt {
    pub name: String,
    pub calls: u32,
    pub failed: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PiChatEvent {
    PromptAccepted,
    /// Pi's agent loop started on the accepted prompt: the model is thinking.
    TurnStarted,
    /// An assistant message ended: one turn, with the provider and model that
    /// wrote it, its token usage, and the cost Pi's catalog puts on that usage.
    ModelReported {
        provider: String,
        model: String,
        usage: Option<TokenUsage>,
        cost: Option<f64>,
    },
    TextDelta(String),
    ToolStarted {
        tool_call_id: String,
        tool_name: String,
        input: Option<String>,
    },
    ToolFinished {
        tool_call_id: String,
        failed: bool,
        output: Option<String>,
    },
    ExtensionUiRequest(ExtensionUiRequest),
    Completed,
    Cancelled,
    Failed,
    /// A valid Pi event for another part of the agent lifecycle.
    Interleaved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionUiRequest {
    pub id: String,
    pub dialog: ExtensionUiDialog,
    pub timeout: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionUiDialog {
    Select {
        title: String,
        options: Vec<String>,
    },
    Confirm {
        title: String,
        message: String,
    },
    Input {
        title: String,
        placeholder: Option<String>,
    },
    Editor {
        title: String,
        prefill: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionUiAnswer {
    Selection(String),
    Confirmation(bool),
    Input(String),
    Editor(String),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionUiResponse {
    id: String,
    answer: ExtensionUiAnswer,
}

impl ExtensionUiResponse {
    pub fn new(
        request: &ExtensionUiRequest,
        answer: ExtensionUiAnswer,
    ) -> Result<Self, &'static str> {
        let matches = match (&request.dialog, &answer) {
            (_, ExtensionUiAnswer::Cancelled) => true,
            (ExtensionUiDialog::Select { options, .. }, ExtensionUiAnswer::Selection(value)) => {
                options.contains(value)
            }
            (ExtensionUiDialog::Confirm { .. }, ExtensionUiAnswer::Confirmation(_)) => true,
            (ExtensionUiDialog::Input { .. }, ExtensionUiAnswer::Input(_)) => true,
            (ExtensionUiDialog::Editor { .. }, ExtensionUiAnswer::Editor(_)) => true,
            _ => false,
        };
        if !matches {
            return Err("answer kind does not match extension UI request");
        }
        Ok(Self {
            id: request.id.clone(),
            answer,
        })
    }

    pub fn into_value(self) -> Value {
        match self.answer {
            ExtensionUiAnswer::Selection(value)
            | ExtensionUiAnswer::Input(value)
            | ExtensionUiAnswer::Editor(value) => {
                json!({"type": "extension_ui_response", "id": self.id, "value": value})
            }
            ExtensionUiAnswer::Confirmation(confirmed) => {
                json!({"type": "extension_ui_response", "id": self.id, "confirmed": confirmed})
            }
            ExtensionUiAnswer::Cancelled => {
                json!({"type": "extension_ui_response", "id": self.id, "cancelled": true})
            }
        }
    }
}

/// Parse only the documented fields needed by the UI. Error details and raw
/// assistant messages deliberately do not cross this boundary.
pub fn parse_frame(frame: &Value) -> Result<PiChatEvent, &'static str> {
    match frame.get("type").and_then(Value::as_str) {
        Some("response") if frame.get("command").and_then(Value::as_str) == Some("prompt") => {
            if frame.get("success").and_then(Value::as_bool) == Some(true) {
                Ok(PiChatEvent::PromptAccepted)
            } else {
                Ok(PiChatEvent::Failed)
            }
        }
        Some("message_update") => {
            let event = frame.get("assistantMessageEvent").unwrap_or(frame);
            match event.get("type").and_then(Value::as_str) {
                Some("text_delta") => event
                    .get("delta")
                    .and_then(Value::as_str)
                    .map(|text| PiChatEvent::TextDelta(text.to_owned()))
                    .ok_or("text delta is missing delta"),
                _ => Ok(PiChatEvent::Interleaved),
            }
        }
        Some("compaction_start" | "auto_compaction_start") => Ok(PiChatEvent::ToolStarted {
            tool_call_id: "muniment:context-compaction".into(),
            tool_name: "compact_context".into(),
            input: Some(serde_json::json!({"reason": frame.get("reason").and_then(Value::as_str).unwrap_or("threshold")}).to_string()),
        }),
        Some("compaction_end" | "auto_compaction_end") => {
            let failed = frame.get("aborted").and_then(Value::as_bool) == Some(true)
                || frame.get("errorMessage").and_then(Value::as_str).is_some()
                || !frame.get("result").is_some_and(Value::is_object);
            let detail = if frame.get("aborted").and_then(Value::as_bool) == Some(true) {
                "Context compaction was cancelled. The conversation remains available.".to_owned()
            } else if failed {
                frame.get("errorMessage").and_then(Value::as_str).unwrap_or("Context compaction did not finish.").to_owned()
            } else {
                let tokens = frame.pointer("/result/tokensBefore").and_then(Value::as_u64);
                let summary = frame.pointer("/result/summary").and_then(Value::as_str).unwrap_or("");
                format!("Context compacted. Earlier messages remain in the conversation.\n{}\n{summary}", tokens.map(|n| format!("Context before compaction: {n} tokens.")).unwrap_or_default())
            };
            Ok(PiChatEvent::ToolFinished {
                tool_call_id: "muniment:context-compaction".into(), failed,
                output: activity_detail(Some(&Value::String(detail))),
            })
        }
        Some("agent_start") => Ok(PiChatEvent::TurnStarted),
        Some("message_end")
            if frame.pointer("/message/role").and_then(Value::as_str) == Some("assistant") =>
        {
            match (
                frame.pointer("/message/provider").and_then(Value::as_str),
                frame.pointer("/message/model").and_then(Value::as_str),
            ) {
                (Some(provider), Some(model)) if !provider.is_empty() && !model.is_empty() => {
                    let usage = frame.pointer("/message/usage");
                    let routed = (provider == crate::model_router::config::ROUTER_PROVIDER)
                        .then(|| {
                            frame
                                .pointer("/message/responseId")
                                .and_then(Value::as_str)
                                .and_then(crate::model_router::wire::response_model)
                        })
                        .flatten();
                    let tokens = usage.and_then(TokenUsage::from_frame);
                    // The router alias has no Pi catalog price. Estimate each turn
                    // against its selected model, never the alias or the final model
                    // of a multi-model run. Cached input uses the standard input rate.
                    let cost = if provider == crate::model_router::config::ROUTER_PROVIDER {
                        routed.as_ref().and_then(|(family, model)| {
                            let price = crate::model_router::model_catalog::entry(family, model)?;
                            let tokens = tokens.as_ref()?;
                            Some(((tokens.input as f64 + tokens.cache_read as f64
                                + tokens.cache_write as f64) * price.price
                                + tokens.output as f64 * price.output) / 1_000_000.0)
                        })
                    } else {
                        usage.and_then(|usage| usage.pointer("/cost/total"))
                            .and_then(Value::as_f64)
                    };
                    let (provider, model) =
                        routed.unwrap_or_else(|| (provider.to_owned(), model.to_owned()));
                    Ok(PiChatEvent::ModelReported {
                        provider,
                        model,
                        usage: tokens,
                        cost,
                    })
                }
                _ => Ok(PiChatEvent::Interleaved),
            }
        }
        Some("tool_execution_start") => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct ToolStart {
                tool_call_id: String,
                tool_name: String,
            }

            let Ok(event) = serde_json::from_value::<ToolStart>(frame.clone()) else {
                return Ok(PiChatEvent::Interleaved);
            };
            if event.tool_call_id.is_empty() || event.tool_name.is_empty() {
                return Ok(PiChatEvent::Interleaved);
            }
            Ok(PiChatEvent::ToolStarted {
                tool_call_id: event.tool_call_id,
                tool_name: event.tool_name,
                input: activity_detail(frame.get("args")),
            })
        }
        Some("tool_execution_end") => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct ToolEnd {
                tool_call_id: String,
                is_error: bool,
            }

            let Ok(event) = serde_json::from_value::<ToolEnd>(frame.clone()) else {
                return Ok(PiChatEvent::Interleaved);
            };
            if event.tool_call_id.is_empty() {
                return Ok(PiChatEvent::Interleaved);
            }
            Ok(PiChatEvent::ToolFinished {
                tool_call_id: event.tool_call_id,
                failed: event.is_error,
                output: activity_detail(frame.get("result")),
            })
        }
        Some("extension_ui_request") => parse_extension_ui_request(frame),
        // Pi owns generation, not billing/routing provenance. Any similarly
        // named member is deliberately ignored; the control plane supplies it.
        Some("agent_end") => {
            let stop_reason = frame
                .get("messages")
                .and_then(Value::as_array)
                .and_then(|messages| {
                    messages.iter().rev().find(|message| {
                        message.get("role").and_then(Value::as_str) == Some("assistant")
                    })
                })
                .and_then(|message| message.get("stopReason"))
                .and_then(Value::as_str);
            match stop_reason {
                Some("error") => Ok(PiChatEvent::Failed),
                Some("aborted") => Ok(PiChatEvent::Cancelled),
                _ => Ok(PiChatEvent::Completed),
            }
        }
        Some("cancelled") => Ok(PiChatEvent::Cancelled),
        Some("error") => Ok(PiChatEvent::Failed),
        Some(_) => Ok(PiChatEvent::Interleaved),
        None => Err("Pi frame is missing type"),
    }
}

fn parse_extension_ui_request(frame: &Value) -> Result<PiChatEvent, &'static str> {
    let Some(method) = frame.get("method").and_then(Value::as_str) else {
        return Ok(PiChatEvent::Interleaved);
    };
    if !matches!(method, "select" | "confirm" | "input" | "editor") {
        return Ok(PiChatEvent::Interleaved);
    }
    let id = frame
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or("blocking extension UI request is missing id")?;
    let title = frame
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.trim().is_empty())
        .ok_or("blocking extension UI request is missing title")?;
    let timeout = match frame.get("timeout") {
        Some(value) => Some(
            value
                .as_u64()
                .ok_or("blocking extension UI request has invalid timeout")?,
        ),
        None => None,
    };

    let dialog = match method {
        "select" => {
            let options = frame
                .get("options")
                .and_then(Value::as_array)
                .filter(|options| !options.is_empty())
                .ok_or("select extension UI request has invalid options")?
                .iter()
                .map(|option| {
                    option
                        .as_str()
                        .filter(|option| !option.is_empty())
                        .map(str::to_owned)
                        .ok_or("select extension UI request has invalid options")
                })
                .collect::<Result<Vec<_>, _>>()?;
            ExtensionUiDialog::Select {
                title: title.into(),
                options,
            }
        }
        "confirm" => ExtensionUiDialog::Confirm {
            title: title.into(),
            message: frame
                .get("message")
                .and_then(Value::as_str)
                .ok_or("confirm extension UI request is missing message")?
                .into(),
        },
        "input" => ExtensionUiDialog::Input {
            title: title.into(),
            placeholder: optional_string(frame, "placeholder")?,
        },
        "editor" => ExtensionUiDialog::Editor {
            title: title.into(),
            prefill: optional_string(frame, "prefill")?,
        },
        _ => unreachable!(),
    };
    Ok(PiChatEvent::ExtensionUiRequest(ExtensionUiRequest {
        id: id.into(),
        dialog,
        timeout,
    }))
}

fn optional_string(frame: &Value, field: &str) -> Result<Option<String>, &'static str> {
    match frame.get(field) {
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or("blocking extension UI request has invalid optional field"),
        None => Ok(None),
    }
}

pub fn cancel_command() -> Value {
    json!({"type": "abort"})
}

const EMPTY_QUEUE_MESSAGE: &str = "Pi queued message must not be empty";
const QUEUE_COMMAND_FAILED: &str = "Pi queue command failed";

macro_rules! queue_command {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        pub struct $name<'a> {
            #[serde(rename = "type")]
            kind: &'static str,
            message: &'a str,
        }

        impl<'a> $name<'a> {
            pub fn new(message: &'a str) -> Result<Self, &'static str> {
                if message.trim().is_empty() {
                    return Err(EMPTY_QUEUE_MESSAGE);
                }
                Ok(Self {
                    kind: $kind,
                    message,
                })
            }

            pub fn into_value(self) -> Value {
                serde_json::to_value(self).expect("Pi queue command is JSON serializable")
            }
        }
    };
}

queue_command!(SteerCommand, "steer");
queue_command!(FollowUpCommand, "follow_up");

fn require_queue_ack(response: &Value, command: &str) -> Result<(), String> {
    if response.get("type").and_then(Value::as_str) == Some("response")
        && response.get("command").and_then(Value::as_str) == Some(command)
        && response.get("success").and_then(Value::as_bool) == Some(true)
    {
        Ok(())
    } else {
        Err(QUEUE_COMMAND_FAILED.into())
    }
}

/// Pi must produce a reply event within 30 seconds of prompt submission.
/// Prompt acknowledgments and unrelated lifecycle frames do not count.
pub const FIRST_EVENT_TIMEOUT: Duration = Duration::from_secs(30);
pub const FIRST_EVENT_TIMEOUT_REASON: &str = "No reply arrived within 30 seconds. Try again.";

/// Binds Pi's single active stream to a locally-owned run. Construct this
/// before sending the prompt so no post-ack frame can be lost.
pub struct PiRunAdapter {
    run_id: String,
    frames: Mutex<mpsc::Receiver<Value>>,
    buffered: Mutex<VecDeque<Value>>,
    first_event_deadline: Mutex<Option<Instant>>,
    compaction_id: Mutex<Option<String>>,
    pending_terminal: Mutex<Option<PiChatEvent>>,
}

impl PiRunAdapter {
    pub fn start(
        run_id: impl Into<String>,
        transport: &PiRpcTransport,
        prompt: &str,
        timeout: Duration,
    ) -> Result<(Self, PiChatEvent), String> {
        Self::start_with_images(run_id, transport, prompt, Vec::new(), timeout)
    }

    pub fn start_with_images(
        run_id: impl Into<String>,
        transport: &PiRpcTransport,
        prompt: &str,
        images: Vec<PiImageContent>,
        timeout: Duration,
    ) -> Result<(Self, PiChatEvent), String> {
        Self::start_with_images_and_handler(run_id, transport, prompt, images, timeout, |_, _| {
            false
        })
    }

    /// Services extension requests while Pi prepares a prompt, before its acknowledgement.
    pub fn start_with_images_and_handler(
        run_id: impl Into<String>,
        transport: &PiRpcTransport,
        prompt: &str,
        images: Vec<PiImageContent>,
        timeout: Duration,
        mut consume: impl FnMut(&Self, &PiChatEvent) -> bool,
    ) -> Result<(Self, PiChatEvent), String> {
        let run_id = run_id.into();
        let deadline = Instant::now() + FIRST_EVENT_TIMEOUT;
        let adapter = Self {
            run_id: run_id.clone(),
            frames: Mutex::new(transport.subscribe()),
            buffered: Mutex::new(VecDeque::new()),
            compaction_id: Mutex::new(None),
            pending_terminal: Mutex::new(None),
            first_event_deadline: Mutex::new(Some(deadline)),
        };
        let response = std::thread::scope(|scope| {
            let (sender, response) = mpsc::channel();
            scope.spawn(move || {
                let result = transport.call(
                    PromptCommand::with_images(prompt, images).into_value(),
                    timeout.min(deadline.saturating_duration_since(Instant::now())),
                );
                let _ = sender.send(result);
            });
            loop {
                match response.try_recv() {
                    Ok(result) => return result,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err("The prompt dispatcher stopped.".into())
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                let frame = adapter
                    .frames
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv_timeout(Duration::from_millis(5));
                match frame {
                    Ok(frame) => {
                        let handled =
                            parse_frame(&frame).is_ok_and(|event| consume(&adapter, &event));
                        if !handled {
                            adapter
                                .buffered
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push_back(frame);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return response
                            .recv()
                            .unwrap_or_else(|_| Err("The prompt dispatcher stopped.".into()))
                    }
                }
            }
        })
        .map_err(|error| {
            if Instant::now() >= deadline {
                format!("Pi did not acknowledge the prompt within 30 seconds. {error}")
            } else {
                error
            }
        })?;
        let accepted = parse_frame(&response).map_err(str::to_owned)?;
        if accepted != PiChatEvent::PromptAccepted {
            let detail: String = response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Pi rejected the prompt")
                .chars()
                .take(4096)
                .collect();
            eprintln!("muniment-runtime: run_id={run_id} provider_request outcome=not_started prompt_error={detail:?}");
            return Err("Pi rejected the prompt".into());
        }
        Ok((adapter, accepted))
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Answers a pending extension UI request without waiting for an RPC response.
    pub fn answer_extension_ui(
        &self,
        transport: &PiRpcTransport,
        request: &ExtensionUiRequest,
        answer: ExtensionUiAnswer,
    ) -> Result<(), String> {
        let response = ExtensionUiResponse::new(request, answer).map_err(str::to_owned)?;
        transport.send(response.into_value())
    }

    /// Waits for Pi to materialize the persistent session after accepting a
    /// prompt. Stream frames arriving while the file is being created are
    /// returned in order. If the binding cannot be validated, the accepted
    /// turn is cancelled and drained to a terminal event before returning.
    pub fn await_session_binding(
        &self,
        transport: &PiRpcTransport,
        session_root: &Path,
        timeout: Duration,
    ) -> Result<(super::PiSessionLocator, Vec<PiChatEvent>), String> {
        self.await_session_binding_with_handler(transport, session_root, timeout, |_| false)
    }

    pub fn await_session_binding_with_handler(
        &self,
        transport: &PiRpcTransport,
        session_root: &Path,
        timeout: Duration,
        mut consume: impl FnMut(&PiChatEvent) -> bool,
    ) -> Result<(super::PiSessionLocator, Vec<PiChatEvent>), String> {
        let mut deadline = std::time::Instant::now() + timeout;
        let mut buffered = Vec::new();
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let call_timeout = remaining.min(Duration::from_millis(100));
            if let Ok(locator) = transport.session_locator(session_root, call_timeout) {
                return Ok((locator, buffered));
            }
            match self.next(Duration::from_millis(10).min(remaining)) {
                Ok(event) => {
                    let started = std::time::Instant::now();
                    if consume(&event) {
                        // Native recovery has its own timeout. Keep Pi's binding wait separate.
                        deadline += started.elapsed();
                    } else {
                        buffered.push(event);
                    }
                }
                Err(error) if error == "timed out waiting for Pi stream" => {}
                Err(error) if error == FIRST_EVENT_TIMEOUT_REASON => return Err(error),
                Err(_) => break,
            }
        }
        if self
            .first_event_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(FIRST_EVENT_TIMEOUT_REASON.into());
        }
        let _ = self.cancel_and_drain(transport, Duration::from_secs(2));
        Err("Pi session binding failed".into())
    }

    /// Cancels an already-submitted prompt and waits until Pi reports that no
    /// agent work remains active.
    pub fn cancel_and_drain(
        &self,
        transport: &PiRpcTransport,
        timeout: Duration,
    ) -> Result<(), String> {
        transport.call(cancel_command(), timeout.min(Duration::from_millis(500)))?;
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.next(remaining) {
                Ok(PiChatEvent::Completed | PiChatEvent::Cancelled | PiChatEvent::Failed) => {
                    return Ok(())
                }
                Ok(_) => {}
                Err(error) => return Err(error),
            }
        }
        Err("Pi cancellation did not finish".into())
    }

    /// Queues a message for delivery during the active turn. Success only
    /// confirms that Pi queued it; stream completion continues through `next`.
    pub fn steer(
        &self,
        transport: &PiRpcTransport,
        message: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let command = SteerCommand::new(message).map_err(str::to_owned)?;
        let response = transport
            .call(command.into_value(), timeout)
            .map_err(|_| QUEUE_COMMAND_FAILED.to_string())?;
        require_queue_ack(&response, "steer")
    }

    /// Queues a message for delivery after the active turn finishes.
    pub fn follow_up(
        &self,
        transport: &PiRpcTransport,
        message: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let command = FollowUpCommand::new(message).map_err(str::to_owned)?;
        let response = transport
            .call(command.into_value(), timeout)
            .map_err(|_| QUEUE_COMMAND_FAILED.to_string())?;
        require_queue_ack(&response, "follow_up")
    }

    /// Pi emits agent_end before automatic compaction. A state RPC is a
    /// protocol barrier: drain the following lifecycle events before settling.
    pub fn next_settled(
        &self,
        transport: &PiRpcTransport,
        timeout: Duration,
    ) -> Result<PiChatEvent, String> {
        self.next_with_settlement(timeout, || {
            transport.call(json!({"type": "get_state"}), Duration::from_secs(5))
        })
    }

    fn next_with_settlement(
        &self,
        timeout: Duration,
        state: impl FnOnce() -> Result<Value, String>,
    ) -> Result<PiChatEvent, String> {
        let result = self.next(timeout);
        let mut pending = self
            .pending_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match result {
            Ok(event @ (PiChatEvent::Completed | PiChatEvent::Failed | PiChatEvent::Cancelled)) => {
                *pending = Some(event);
                Ok(PiChatEvent::Interleaved)
            }
            Err(ref error) if error == "timed out waiting for Pi stream" && pending.is_some() => {
                let snapshot = state()?;
                if snapshot
                    .pointer("/data/isCompacting")
                    .and_then(Value::as_bool)
                    == Some(true)
                    || snapshot
                        .pointer("/data/isStreaming")
                        .and_then(Value::as_bool)
                        == Some(true)
                {
                    return Ok(PiChatEvent::Interleaved);
                }
                // The barrier may have delivered compaction events to the subscriber.
                if let Ok(frame) = self
                    .frames
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .try_recv()
                {
                    self.buffered
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push_back(frame);
                    return Ok(PiChatEvent::Interleaved);
                }
                if self
                    .compaction_id
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some()
                {
                    return Ok(PiChatEvent::Interleaved);
                }
                Ok(pending.take().unwrap())
            }
            other => other,
        }
    }

    pub fn next(&self, timeout: Duration) -> Result<PiChatEvent, String> {
        let mut deadline = self
            .first_event_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timeout = if let Some(deadline) = *deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(FIRST_EVENT_TIMEOUT_REASON.into());
            }
            timeout.min(remaining)
        } else {
            timeout
        };
        let buffered = self
            .buffered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        let frame = match buffered {
            Some(frame) => Ok(frame),
            None => self
                .frames
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv_timeout(timeout),
        }
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) =>
            {
                FIRST_EVENT_TIMEOUT_REASON.to_string()
            }
            mpsc::RecvTimeoutError::Timeout => "timed out waiting for Pi stream".to_string(),
            mpsc::RecvTimeoutError::Disconnected => "Pi process stream ended".to_string(),
        })?;
        let mut event = parse_frame(&frame).map_err(str::to_owned)?;
        if frame.get("type").and_then(Value::as_str) == Some("agent_start")
            || (matches!(
                frame.get("type").and_then(Value::as_str),
                Some("compaction_end" | "auto_compaction_end")
            ) && frame.get("willRetry").and_then(Value::as_bool) == Some(true))
        {
            self.pending_terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
        match &mut event {
            PiChatEvent::ToolStarted { tool_call_id, .. }
                if tool_call_id == "muniment:context-compaction" =>
            {
                *tool_call_id = format!("muniment:context-compaction:{}", uuid::Uuid::now_v7());
                *self
                    .compaction_id
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(tool_call_id.clone());
            }
            PiChatEvent::ToolFinished { tool_call_id, .. }
                if tool_call_id == "muniment:context-compaction" =>
            {
                if let Some(id) = self
                    .compaction_id
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    *tool_call_id = id;
                }
            }
            _ => {}
        }
        if frame.get("type").and_then(Value::as_str) == Some("message_end")
            && frame.pointer("/message/role").and_then(Value::as_str) == Some("assistant")
        {
            let outcome = match frame.pointer("/message/stopReason").and_then(Value::as_str) {
                Some("stop" | "length" | "toolUse") => "completed",
                Some("error") => "failed",
                Some("aborted") => "cancelled",
                _ => "unknown",
            };
            eprintln!("muniment-runtime: run_id={} provider_request outcome={outcome} source=pi_message_end", self.run_id);
        }
        let kind = match &event {
            PiChatEvent::TextDelta(_) => Some("text_delta"),
            PiChatEvent::ToolStarted { .. } => Some("tool_start"),
            PiChatEvent::ToolFinished { .. } => Some("tool_end"),
            PiChatEvent::ExtensionUiRequest(_) => Some("extension_ui_request"),
            PiChatEvent::Completed => Some("completed"),
            PiChatEvent::Cancelled => Some("cancelled"),
            PiChatEvent::Failed => Some("failed"),
            _ => match frame.get("type").and_then(Value::as_str) {
                Some(
                    kind @ ("agent_start" | "turn_start" | "turn_end" | "message_start"
                    | "message_update" | "message_end"),
                ) => Some(kind),
                _ => None,
            },
        };
        if let Some(kind) = kind.filter(|_| deadline.take().is_some()) {
            eprintln!(
                "muniment-runtime: run_id={} first_event {kind}",
                self.run_id
            );
        }
        Ok(event)
    }
}

impl Drop for PiRunAdapter {
    fn drop(&mut self) {
        if self
            .first_event_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
        {
            eprintln!(
                "muniment-runtime: run_id={} first_event absent",
                self.run_id
            );
        }
    }
}

// Activity details are bounded plain text. The same secret gate as memory
// prevents credentials from entering the journal or the webview.
fn activity_detail(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let text = if let Some(text) = value.as_str() {
        text.to_owned()
    } else if let Some(content) = value.get("content").and_then(Value::as_array) {
        content
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        serde_json::to_string_pretty(value).ok()?
    };
    if crate::memory_secret::reject_memory_secret(&text).is_err() {
        return Some("Details withheld because they may contain a secret.".into());
    }
    let mut clipped: String = text.chars().take(8000).collect();
    if text.chars().count() > 8000 {
        clipped.push_str("\n[Output shortened]");
    }
    Some(clipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_stream_reports_process_death_without_upstream_details() {
        let (sender, frames) = mpsc::channel();
        let adapter = PiRunAdapter {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            frames: Mutex::new(frames),
            buffered: Mutex::new(VecDeque::new()),
            compaction_id: Mutex::new(None),
            pending_terminal: Mutex::new(None),
            first_event_deadline: Mutex::new(Some(Instant::now() + Duration::from_secs(1))),
        };
        drop(sender);

        assert_eq!(
            adapter.next(Duration::from_millis(1)).unwrap_err(),
            "Pi process stream ended"
        );
    }

    fn bounded_adapter(timeout: Duration) -> (mpsc::Sender<Value>, PiRunAdapter) {
        let (sender, frames) = mpsc::channel();
        (
            sender,
            PiRunAdapter {
                run_id: "run-bound".into(),
                frames: Mutex::new(frames),
                buffered: Mutex::new(VecDeque::new()),
                compaction_id: Mutex::new(None),
                pending_terminal: Mutex::new(None),
                first_event_deadline: Mutex::new(Some(Instant::now() + timeout)),
            },
        )
    }

    #[test]
    fn completion_waits_for_post_reply_compaction_and_overflow_retry() {
        let (sender, adapter) = bounded_adapter(Duration::from_secs(1));
        let next = || {
            adapter
                .next_with_settlement(Duration::from_millis(1), || {
                    Ok(json!({"success":true,"data":{"isStreaming":false,"isCompacting":false}}))
                })
                .unwrap()
        };
        sender.send(json!({"type":"agent_end"})).unwrap();
        assert_eq!(next(), PiChatEvent::Interleaved);
        sender
            .send(json!({"type":"compaction_start","reason":"threshold"}))
            .unwrap();
        assert!(matches!(next(), PiChatEvent::ToolStarted { .. }));
        assert_eq!(next(), PiChatEvent::Interleaved);
        sender.send(json!({"type":"compaction_end","result":{"summary":"Keep the goal"},"willRetry":false})).unwrap();
        assert!(matches!(
            next(),
            PiChatEvent::ToolFinished { failed: false, .. }
        ));
        assert_eq!(next(), PiChatEvent::Completed);

        sender
            .send(
                json!({"type":"agent_end","messages":[{"role":"assistant","stopReason":"error"}]}),
            )
            .unwrap();
        assert_eq!(next(), PiChatEvent::Interleaved);
        sender
            .send(json!({"type":"compaction_start","reason":"overflow"}))
            .unwrap();
        assert!(matches!(next(), PiChatEvent::ToolStarted { .. }));
        sender.send(json!({"type":"compaction_end","result":{"summary":"Keep the goal"},"willRetry":true})).unwrap();
        assert!(matches!(next(), PiChatEvent::ToolFinished { .. }));
        assert!(adapter.pending_terminal.lock().unwrap().is_none());
        sender.send(json!({"type":"agent_end"})).unwrap();
        assert_eq!(next(), PiChatEvent::Interleaved);
        assert_eq!(next(), PiChatEvent::Completed);
    }

    #[test]
    fn compaction_cycles_have_distinct_ids_and_failed_endings_are_visible() {
        let (sender, adapter) = bounded_adapter(Duration::from_secs(1));
        let mut ids = Vec::new();
        for prefix in ["compaction", "auto_compaction"] {
            sender
                .send(json!({"type": format!("{prefix}_start"), "reason": "threshold"}))
                .unwrap();
            let PiChatEvent::ToolStarted {
                tool_call_id,
                tool_name,
                ..
            } = adapter.next(Duration::from_secs(1)).unwrap()
            else {
                panic!("missing start")
            };
            assert_eq!(tool_name, "compact_context");
            sender.send(json!({"type": format!("{prefix}_end"), "result": {"summary":"Keep the user goal", "tokensBefore":50000}})).unwrap();
            let PiChatEvent::ToolFinished {
                tool_call_id: ended,
                failed,
                output,
            } = adapter.next(Duration::from_secs(1)).unwrap()
            else {
                panic!("missing end")
            };
            assert_eq!(tool_call_id, ended);
            assert!(!failed);
            assert!(output.unwrap().contains("50000"));
            ids.push(tool_call_id);
        }
        assert_ne!(ids[0], ids[1]);
        assert!(matches!(
            parse_frame(&json!({"type":"compaction_end","aborted":true,"result":null})).unwrap(),
            PiChatEvent::ToolFinished { failed: true, .. }
        ));
    }

    #[test]
    fn silence_ends_at_the_first_event_bound() {
        let (_sender, adapter) = bounded_adapter(Duration::from_millis(20));
        let started = Instant::now();
        assert_eq!(
            adapter.next(Duration::from_secs(1)).unwrap_err(),
            "No reply arrived within 30 seconds. Try again."
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(
            adapter.next(Duration::ZERO).unwrap_err(),
            "No reply arrived within 30 seconds. Try again."
        );
    }

    #[test]
    fn acknowledgments_and_unrelated_frames_do_not_extend_the_bound() {
        let (sender, adapter) = bounded_adapter(Duration::from_millis(20));
        for frame in [
            json!({"type":"queue_update"}),
            json!({"type":"response", "command":"prompt", "success":true}),
        ] {
            sender.send(frame).unwrap();
            adapter.next(Duration::ZERO).unwrap();
        }
        assert_eq!(
            adapter.next(Duration::from_secs(1)).unwrap_err(),
            "No reply arrived within 30 seconds. Try again."
        );
    }

    #[test]
    fn a_reply_event_disarms_the_bound_but_a_late_event_does_not() {
        let (sender, adapter) = bounded_adapter(Duration::from_secs(1));
        sender
            .send(json!({"type":"message_update", "assistantMessageEvent":{
                "type":"text_delta", "delta":"hello"
            }}))
            .unwrap();
        assert_eq!(
            adapter.next(Duration::ZERO).unwrap(),
            PiChatEvent::TextDelta("hello".into())
        );
        assert!(adapter.first_event_deadline.lock().unwrap().is_none());
        assert_eq!(
            adapter.next(Duration::ZERO).unwrap_err(),
            "timed out waiting for Pi stream"
        );

        let (sender, adapter) = bounded_adapter(Duration::ZERO);
        sender.send(json!({"type":"agent_end"})).unwrap();
        assert_eq!(
            adapter.next(Duration::ZERO).unwrap_err(),
            "No reply arrived within 30 seconds. Try again."
        );
    }

    #[test]
    fn run_lifecycle_events_disarm_the_bound_before_text_arrives() {
        for (kind, event) in [
            ("agent_start", PiChatEvent::TurnStarted),
            ("turn_start", PiChatEvent::Interleaved),
            ("message_start", PiChatEvent::Interleaved),
            ("message_update", PiChatEvent::Interleaved),
        ] {
            let (sender, adapter) = bounded_adapter(Duration::from_secs(1));
            sender.send(json!({"type":kind})).unwrap();
            assert_eq!(adapter.next(Duration::ZERO).unwrap(), event);
            assert!(adapter.first_event_deadline.lock().unwrap().is_none());
        }
    }

    #[test]
    fn routed_messages_report_their_own_selected_model() {
        let fast = crate::model_router::wire::routed_response_id("openai", "gpt-5.6-luna");
        let deep = crate::model_router::wire::routed_response_id("anthropic", "claude-opus-5");
        for (id, provider, model) in [
            (deep, "anthropic", "claude-opus-5"),
            (fast, "openai", "gpt-5.6-luna"),
        ] {
            let frame = json!({"type":"message_end","message":{"role":"assistant","provider":"muniment-router","model":"auto","responseId":id}});
            assert_eq!(
                parse_frame(&frame).unwrap(),
                PiChatEvent::ModelReported {
                    provider: provider.into(),
                    model: model.into(),
                    usage: None,
                    cost: None
                }
            );
            // Another provider cannot accidentally consume router metadata.
            let mut direct = frame;
            direct["message"]["provider"] = json!("ollama");
            assert_eq!(
                parse_frame(&direct).unwrap(),
                PiChatEvent::ModelReported {
                    provider: "ollama".into(),
                    model: "auto".into(),
                    usage: None,
                    cost: None
                }
            );
        }
        let frame = json!({"type":"message_end","message":{"role":"assistant","provider":"muniment-router","model":"auto","responseId":"muniment-route-v1.invalid"}});
        assert_eq!(
            parse_frame(&frame).unwrap(),
            PiChatEvent::ModelReported {
                provider: "muniment-router".into(),
                model: "auto".into(),
                usage: None,
                cost: None
            }
        );
    }

    #[test]
    fn routed_cost_uses_the_selected_model_and_unknown_prices_are_unavailable() {
        for (model, expected) in [("claude-sonnet-5", Some(0.018)), ("private-model", None)] {
            let id = crate::model_router::wire::routed_response_id("anthropic", model);
            let frame = json!({"type":"message_end","message":{
                "role":"assistant","provider":"muniment-router","model":"auto","responseId":id,
                "usage":{"input":1000,"output":1000,"cost":{"total":0}}
            }});
            let PiChatEvent::ModelReported { cost, .. } = parse_frame(&frame).unwrap() else {
                panic!("expected model usage");
            };
            assert_eq!(cost, expected);
        }
    }

    #[test]
    fn an_assistant_message_end_reports_its_provider_and_model() {
        assert_eq!(
            parse_frame(&json!({"type":"message_end", "message":{
                "role":"assistant", "provider":"ollama", "model":"llama3.2:3b", "stopReason":"stop"
            }}))
            .unwrap(),
            PiChatEvent::ModelReported {
                provider: "ollama".into(),
                model: "llama3.2:3b".into(),
                usage: None,
                cost: None,
            }
        );
        assert_eq!(
            parse_frame(&json!({"type":"message_end", "message":{
                "role":"assistant", "provider":"openai-codex", "model":"gpt-5.5",
                "usage":{"input":11414,"output":64,"cacheRead":0,"cacheWrite":0,"reasoning":0,"totalTokens":11478,
                         "cost":{"input":0.05707,"output":0.00192,"cacheRead":0,"cacheWrite":0,"total":0.05899}}
            }}))
            .unwrap(),
            PiChatEvent::ModelReported {
                provider: "openai-codex".into(),
                model: "gpt-5.5".into(),
                usage: Some(TokenUsage {
                    input: 11414,
                    output: 64,
                    cache_read: 0,
                    cache_write: 0,
                    reasoning: 0,
                    total: 11478
                }),
                cost: Some(0.05899),
            }
        );
        assert_eq!(
            parse_frame(&json!({"type":"message_end", "message":{
                "role":"user", "provider":"ollama", "model":"llama3.2:3b"
            }}))
            .unwrap(),
            PiChatEvent::Interleaved
        );
    }

    #[test]
    fn agent_start_is_the_turn_start_and_the_other_lifecycle_frames_interleave() {
        assert_eq!(
            parse_frame(&json!({"type":"agent_start"})).unwrap(),
            PiChatEvent::TurnStarted
        );
        for kind in ["turn_start", "turn_end", "message_start", "message_end"] {
            assert_eq!(
                parse_frame(&json!({"type": kind})).unwrap(),
                PiChatEvent::Interleaved
            );
        }
    }

    #[test]
    fn provider_error_and_abort_do_not_become_success_at_agent_end() {
        for (reason, expected) in [
            ("error", PiChatEvent::Failed),
            ("aborted", PiChatEvent::Cancelled),
        ] {
            assert_eq!(
                parse_frame(&json!({"type":"agent_end", "messages":[{
                    "role":"assistant", "stopReason":reason, "errorMessage":"private detail"
                }]}))
                .unwrap(),
                expected
            );
        }
        assert_eq!(
            parse_frame(&json!({"type":"message_end", "message":{
                "role":"assistant", "stopReason":"error"
            }}))
            .unwrap(),
            PiChatEvent::Interleaved
        );
        assert_eq!(
            parse_frame(&json!({"type":"agent_end", "messages":[
                {"role":"assistant", "stopReason":"error"},
                {"role":"assistant", "stopReason":"stop"}
            ]}))
            .unwrap(),
            PiChatEvent::Completed
        );
        for role in ["user", "toolResult"] {
            assert_eq!(
                parse_frame(&json!({"type":"message_end", "message":{
                    "role":role, "stopReason":"error"
                }}))
                .unwrap(),
                PiChatEvent::Interleaved
            );
        }
    }

    #[test]
    fn queue_acknowledgements_are_exact_and_non_sensitive() {
        assert!(require_queue_ack(
            &json!({"type":"response", "command":"steer", "success":true}),
            "steer"
        )
        .is_ok());
        for response in [
            json!({"type":"response", "command":"follow_up", "success":true}),
            json!({"type":"response", "command":"steer", "success":false, "message":"secret"}),
            json!({"type":"agent_end"}),
            json!({"command":"steer", "success":true}),
        ] {
            assert_eq!(
                require_queue_ack(&response, "steer").unwrap_err(),
                QUEUE_COMMAND_FAILED
            );
        }
    }
}
