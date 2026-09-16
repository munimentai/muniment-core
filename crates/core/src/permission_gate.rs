//! Permission gate coordination for a chat run.
//!
//! A Pi extension-UI request opens a gate. The gate stays open until an answer
//! arrives for its id and matches its dialog shape. ADR 0012 phase one makes
//! this state runtime-service state, so the rules live here rather than in the
//! desktop shell.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;

use crate::journal::pi_translation::permission_journal_payload;
use crate::sidecar::pi_chat::{
    ExtensionUiAnswer, ExtensionUiRequest, ExtensionUiResponse, PiChatEvent,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum ChatPermissionAnswer {
    Select(String),
    Confirm(bool),
    Input(String),
    Editor(String),
    Cancelled,
    CodeDiff {
        gate_id: String,
        effect_id: String,
        code_diff_id: String,
        diff_sha256: String,
        write_plan_sha256: String,
    },
}

impl ChatPermissionAnswer {
    pub fn pi_answer(&self) -> Option<ExtensionUiAnswer> {
        Some(match self {
            Self::Select(value) => ExtensionUiAnswer::Selection(value.clone()),
            Self::Confirm(value) => ExtensionUiAnswer::Confirmation(*value),
            Self::Input(value) => ExtensionUiAnswer::Input(value.clone()),
            Self::Editor(value) => ExtensionUiAnswer::Editor(value.clone()),
            Self::Cancelled => ExtensionUiAnswer::Cancelled,
            Self::CodeDiff { .. } => return None,
        })
    }

    pub fn decision(&self) -> Value {
        serde_json::to_value(self).expect("permission answers serialize")
    }
}

#[derive(Clone, Debug)]
pub struct PendingPermissionAnswer {
    pub gate_id: String,
    pub answer: ChatPermissionAnswer,
    pub resolved: Option<std::sync::mpsc::SyncSender<Option<u64>>>,
}

/// The caller could not journal a gate event. The run stops, and the gate keeps
/// the state the failed append found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalAppendFailed;

/// Opens a gate for a Pi extension-UI request. The caller journals the request
/// through `append` before the gate becomes the pending one. The journal holds
/// one open gate per run, so a request that arrives while another waits, as
/// two parallel tool calls each asking a question do, joins `waiting` and
/// opens when the pending one resolves.
pub fn coordinate_extension_ui_request(
    event: PiChatEvent,
    pending: &mut Option<ExtensionUiRequest>,
    waiting: &mut VecDeque<ExtensionUiRequest>,
    append: impl FnOnce(&str, Value) -> Result<(), ()>,
) -> Result<(), JournalAppendFailed> {
    let PiChatEvent::ExtensionUiRequest(request) = event else {
        return Ok(());
    };
    if pending.is_some() {
        waiting.push_back(request);
        return Ok(());
    }
    append("permission.requested", permission_journal_payload(&request))
        .map_err(|()| JournalAppendFailed)?;
    *pending = Some(request);
    Ok(())
}

/// Opens the next waiting request once no gate is pending.
pub fn open_waiting_request(
    pending: &mut Option<ExtensionUiRequest>,
    waiting: &mut VecDeque<ExtensionUiRequest>,
    append: impl FnOnce(&str, Value) -> Result<(), ()>,
) -> Result<(), JournalAppendFailed> {
    if pending.is_some() {
        return Ok(());
    }
    let Some(next) = waiting.pop_front() else {
        return Ok(());
    };
    coordinate_extension_ui_request(
        PiChatEvent::ExtensionUiRequest(next),
        pending,
        waiting,
        append,
    )
}

/// Closes the open gate when the queued answer names it and fits its dialog.
/// A stale gate id, a rejected answer shape, or a failed send leaves the gate
/// open. Each of those three cases resolves the waiting caller with no
/// committed sequence number.
pub fn coordinate_permission_answer(
    pending: &mut Option<ExtensionUiRequest>,
    queued: PendingPermissionAnswer,
    send: impl FnOnce(&ExtensionUiRequest, ExtensionUiAnswer) -> Result<(), String>,
    append: impl FnOnce(&str, Value) -> Result<u64, ()>,
) -> Result<(), JournalAppendFailed> {
    let resolved = queued.resolved;
    let Some(request) = pending
        .as_ref()
        .filter(|request| request.id == queued.gate_id)
    else {
        if let Some(resolved) = resolved {
            let _ = resolved.send(None);
        }
        return Ok(());
    };
    let Some(answer) = queued.answer.pi_answer() else {
        if let Some(resolved) = resolved {
            let _ = resolved.send(None);
        }
        return Ok(());
    };
    if ExtensionUiResponse::new(request, answer.clone()).is_err() {
        if let Some(resolved) = resolved {
            let _ = resolved.send(None);
        }
        return Ok(());
    }
    if send(request, answer).is_err() {
        if let Some(resolved) = resolved {
            let _ = resolved.send(None);
        }
        return Ok(());
    }
    let committed_seq = append(
        "permission.resolved",
        json!({"gate_id": queued.gate_id, "decision": queued.answer.decision()}),
    )
    .map_err(|()| JournalAppendFailed)?;
    if let Some(resolved) = resolved {
        let _ = resolved.send(Some(committed_seq));
    }
    *pending = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::pi_chat::ExtensionUiDialog;

    fn select(id: &str) -> ExtensionUiRequest {
        ExtensionUiRequest {
            id: id.into(),
            dialog: ExtensionUiDialog::Select {
                title: "MCP Input Request".into(),
                options: vec!["Continue".into(), "Decline".into()],
            },
            timeout: None,
        }
    }

    #[test]
    fn a_second_request_waits_for_the_first_gate_and_opens_after_its_answer() {
        let mut pending = None;
        let mut waiting = VecDeque::new();
        let mut journaled = Vec::new();
        for id in ["gate-1", "gate-2"] {
            coordinate_extension_ui_request(
                PiChatEvent::ExtensionUiRequest(select(id)),
                &mut pending,
                &mut waiting,
                |kind, payload| {
                    journaled.push((kind.to_owned(), payload["gate_id"].clone()));
                    Ok(())
                },
            )
            .unwrap();
        }
        assert_eq!(
            pending.as_ref().map(|request| request.id.as_str()),
            Some("gate-1")
        );
        assert_eq!(waiting.len(), 1);
        assert_eq!(
            journaled,
            [("permission.requested".to_owned(), json!("gate-1"))]
        );

        // The card names gate-1, so its answer lands, and gate-2 opens next.
        let mut sent = Vec::new();
        coordinate_permission_answer(
            &mut pending,
            PendingPermissionAnswer {
                gate_id: "gate-1".into(),
                answer: ChatPermissionAnswer::Select("Continue".into()),
                resolved: None,
            },
            |request, _| {
                sent.push(request.id.clone());
                Ok(())
            },
            |_, _| Ok(9),
        )
        .unwrap();
        assert!(pending.is_none());
        assert_eq!(sent, ["gate-1"]);
        open_waiting_request(&mut pending, &mut waiting, |kind, payload| {
            journaled.push((kind.to_owned(), payload["gate_id"].clone()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            pending.as_ref().map(|request| request.id.as_str()),
            Some("gate-2")
        );
        assert!(waiting.is_empty());
        assert_eq!(
            journaled[1],
            ("permission.requested".to_owned(), json!("gate-2"))
        );

        // With a gate open, the next opener does nothing.
        open_waiting_request(&mut pending, &mut waiting, |_, _| panic!("no append")).unwrap();
        assert_eq!(
            pending.as_ref().map(|request| request.id.as_str()),
            Some("gate-2")
        );
    }
}
