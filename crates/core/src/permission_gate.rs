//! Permission gate coordination for a chat run.
//!
//! A Pi extension-UI request opens a gate. The gate stays open until an answer
//! arrives for its id and matches its dialog shape. ADR 0012 phase one makes
//! this state runtime-service state, so the rules live here rather than in the
//! desktop shell.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
}

impl ChatPermissionAnswer {
    pub fn pi_answer(&self) -> ExtensionUiAnswer {
        match self {
            Self::Select(value) => ExtensionUiAnswer::Selection(value.clone()),
            Self::Confirm(value) => ExtensionUiAnswer::Confirmation(*value),
            Self::Input(value) => ExtensionUiAnswer::Input(value.clone()),
            Self::Editor(value) => ExtensionUiAnswer::Editor(value.clone()),
            Self::Cancelled => ExtensionUiAnswer::Cancelled,
        }
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
/// through `append` before the gate becomes the pending one.
pub fn coordinate_extension_ui_request(
    event: PiChatEvent,
    pending: &mut Option<ExtensionUiRequest>,
    append: impl FnOnce(&str, Value) -> Result<(), ()>,
) -> Result<(), JournalAppendFailed> {
    let PiChatEvent::ExtensionUiRequest(request) = event else {
        return Ok(());
    };
    append("permission.requested", permission_journal_payload(&request))
        .map_err(|()| JournalAppendFailed)?;
    *pending = Some(request);
    Ok(())
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
    let answer = queued.answer.pi_answer();
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
