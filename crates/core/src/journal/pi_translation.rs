use super::reducer::{PermissionGate, PermissionRequest};
use crate::sidecar::pi_chat::{ExtensionUiDialog, ExtensionUiRequest, PiChatEvent};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub fn model_stream_delta_payload(text: &str) -> Value {
    json!({"text": text, "content_disclosure": "released"})
}

pub fn tool_journal_entry(
    event: &PiChatEvent,
    open_effects: &mut BTreeSet<String>,
) -> Option<(&'static str, Value)> {
    match event {
        PiChatEvent::ToolStarted {
            tool_call_id,
            tool_name,
        } if open_effects.insert(tool_call_id.clone()) => Some((
            "tool.effect.started",
            json!({"effect_id": tool_call_id, "display_name": tool_name}),
        )),
        PiChatEvent::ToolFinished {
            tool_call_id,
            failed,
        } if open_effects.remove(tool_call_id) => Some((
            if *failed {
                "tool.effect.failed"
            } else {
                "tool.effect.completed"
            },
            json!({"effect_id": tool_call_id}),
        )),
        _ => None,
    }
}

pub fn permission_journal_payload(request: &ExtensionUiRequest) -> Value {
    let gate_id = request.id.clone();
    let timeout = request.timeout;
    let request = match &request.dialog {
        ExtensionUiDialog::Select { title, options } => PermissionRequest::Select {
            title: title.clone(),
            options: options.clone(),
            timeout,
        },
        ExtensionUiDialog::Confirm { title, message } => PermissionRequest::Confirm {
            title: title.clone(),
            message: message.clone(),
            timeout,
        },
        ExtensionUiDialog::Input { title, placeholder } => PermissionRequest::Input {
            title: title.clone(),
            placeholder: placeholder.clone(),
            timeout,
        },
        ExtensionUiDialog::Editor { title, prefill } => PermissionRequest::Editor {
            title: title.clone(),
            prefill: prefill.clone(),
            timeout,
        },
    };
    serde_json::to_value(PermissionGate { gate_id, request })
        .expect("permission gate is serializable")
}

pub fn close_open_effects<E>(
    open_effects: &mut BTreeSet<String>,
    mut append: impl FnMut(&str, Value) -> Result<(), E>,
) -> Result<(), E> {
    for effect_id in open_effects.clone() {
        append("tool.effect.failed", json!({"effect_id": effect_id}))?;
        open_effects.remove(&effect_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_stream_delta_has_released_disclosure() {
        assert_eq!(
            model_stream_delta_payload("hello"),
            json!({"text": "hello", "content_disclosure": "released"})
        );
    }

    #[test]
    fn tool_frames_track_started_and_finished_effects() {
        let mut open_effects = BTreeSet::new();
        let started = PiChatEvent::ToolStarted {
            tool_call_id: "tool-1".into(),
            tool_name: "Read file".into(),
        };
        let unmatched = PiChatEvent::ToolFinished {
            tool_call_id: "missing".into(),
            failed: false,
        };

        assert_eq!(
            tool_journal_entry(&started, &mut open_effects),
            Some((
                "tool.effect.started",
                json!({"effect_id": "tool-1", "display_name": "Read file"})
            ))
        );
        assert!(tool_journal_entry(&started, &mut open_effects).is_none());
        assert!(tool_journal_entry(&unmatched, &mut open_effects).is_none());

        let finished = PiChatEvent::ToolFinished {
            tool_call_id: "tool-1".into(),
            failed: false,
        };
        assert_eq!(
            tool_journal_entry(&finished, &mut open_effects),
            Some(("tool.effect.completed", json!({"effect_id": "tool-1"})))
        );
        assert!(tool_journal_entry(&finished, &mut open_effects).is_none());

        let failed = PiChatEvent::ToolFinished {
            tool_call_id: "tool-2".into(),
            failed: true,
        };
        assert!(open_effects.insert("tool-2".into()));
        assert_eq!(
            tool_journal_entry(&failed, &mut open_effects),
            Some(("tool.effect.failed", json!({"effect_id": "tool-2"})))
        );
    }

    #[test]
    fn dialogs_translate_to_permission_journal_payloads() {
        let cases = [
            (
                ExtensionUiDialog::Select {
                    title: "Choose".into(),
                    options: vec!["A".into(), "B".into()],
                },
                json!({"gate_id":"gate","kind":"select","title":"Choose","options":["A","B"],"timeout":5000}),
            ),
            (
                ExtensionUiDialog::Confirm {
                    title: "Allow?".into(),
                    message: "Proceed?".into(),
                },
                json!({"gate_id":"gate","kind":"confirm","title":"Allow?","message":"Proceed?","timeout":5000}),
            ),
            (
                ExtensionUiDialog::Input {
                    title: "Value".into(),
                    placeholder: Some("Type".into()),
                },
                json!({"gate_id":"gate","kind":"input","title":"Value","placeholder":"Type","timeout":5000}),
            ),
            (
                ExtensionUiDialog::Editor {
                    title: "Edit".into(),
                    prefill: Some("draft".into()),
                },
                json!({"gate_id":"gate","kind":"editor","title":"Edit","prefill":"draft","timeout":5000}),
            ),
        ];
        for (dialog, expected) in cases {
            assert_eq!(
                permission_journal_payload(&ExtensionUiRequest {
                    id: "gate".into(),
                    dialog,
                    timeout: Some(5000),
                }),
                expected
            );
        }
    }

    #[test]
    fn closes_each_open_effect() {
        let mut open_effects = BTreeSet::from(["tool-2".to_string(), "tool-1".to_string()]);
        let mut appended = Vec::new();

        close_open_effects(&mut open_effects, |kind, payload| {
            appended.push((kind.to_string(), payload));
            Ok::<(), ()>(())
        })
        .unwrap();

        assert!(open_effects.is_empty());
        assert_eq!(
            appended,
            [
                ("tool.effect.failed".into(), json!({"effect_id": "tool-1"})),
                ("tool.effect.failed".into(), json!({"effect_id": "tool-2"})),
            ]
        );
    }

    #[test]
    fn close_stops_after_an_append_error() {
        let mut open_effects = BTreeSet::from(["tool-1".to_string(), "tool-2".to_string()]);

        assert_eq!(
            close_open_effects(&mut open_effects, |_, payload| {
                if payload == json!({"effect_id": "tool-2"}) {
                    Err("append failed")
                } else {
                    Ok(())
                }
            }),
            Err("append failed")
        );
        assert_eq!(open_effects, BTreeSet::from(["tool-2".to_string()]));
    }
}
