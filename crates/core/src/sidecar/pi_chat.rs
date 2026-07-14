//! Typed projection of the Pi 0.73.1 chat event stream.
//!
//! Pi has one active agent stream. Muniment nevertheless tags every projected
//! event with the locally-owned run id; callers must create a fresh adapter for
//! each accepted prompt and discard unrelated frames.

use serde::{Deserialize, Serialize};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use super::PiRpcTransport;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptCommand<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub message: &'a str,
    pub streaming_behavior: StreamingBehavior,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReceipt {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PiChatEvent {
    PromptAccepted,
    TextDelta(String),
    ToolStarted {
        tool_call_id: String,
        tool_name: String,
    },
    ToolFinished {
        tool_call_id: String,
        failed: bool,
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
            })
        }
        Some("extension_ui_request") => parse_extension_ui_request(frame),
        // Pi owns generation, not billing/routing provenance. Any similarly
        // named member is deliberately ignored; the control plane supplies it.
        Some("agent_end") => Ok(PiChatEvent::Completed),
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

/// Binds Pi's single active stream to a locally-owned run. Construct this
/// before sending the prompt so no post-ack frame can be lost.
pub struct PiRunAdapter {
    run_id: String,
    frames: Mutex<mpsc::Receiver<Value>>,
}

impl PiRunAdapter {
    pub fn start(
        run_id: impl Into<String>,
        transport: &PiRpcTransport,
        prompt: &str,
        timeout: Duration,
    ) -> Result<(Self, PiChatEvent), String> {
        let frames = transport.subscribe();
        let response = transport.call(PromptCommand::new(prompt).into_value(), timeout)?;
        let accepted = parse_frame(&response).map_err(str::to_owned)?;
        if accepted != PiChatEvent::PromptAccepted {
            return Err("Pi rejected the prompt".into());
        }
        Ok((
            Self {
                run_id: run_id.into(),
                frames: Mutex::new(frames),
            },
            accepted,
        ))
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
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

    pub fn next(&self, timeout: Duration) -> Result<PiChatEvent, String> {
        let frame = self
            .frames
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => "timed out waiting for Pi stream".to_string(),
                mpsc::RecvTimeoutError::Disconnected => "Pi process stream ended".to_string(),
            })?;
        parse_frame(&frame).map_err(str::to_owned)
    }
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
        };
        drop(sender);

        assert_eq!(
            adapter.next(Duration::from_millis(1)).unwrap_err(),
            "Pi process stream ended"
        );
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
