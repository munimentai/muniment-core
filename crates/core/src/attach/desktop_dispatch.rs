//! Platform-neutral desktop client request dispatch.

use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::TryRecvError;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

use super::desktop_service_message::{
    CompanionProvenance, MigrationControlRequest, PermissionAnswerRequest, PermissionDecision,
    RunCancelRequest, RunMessageRequest, RunPermissionAnswerRequest, RunResumeRequest,
    RunStreamPage, RunSubmitRequest,
};
use super::desktop_session::{
    DesktopDispatchFailure, DesktopDispatchResult, DesktopSessionService,
};
use super::thread_service::{
    RunStartRequest, ThreadListRequest, ThreadListService, ThreadOpenRequest,
};
use super::{
    encode_frame, ArtifactMetadata, ArtifactTransfer, ArtifactTransferRegistry,
    ArtifactTransferRegistryError, AttachSessionError, Event, EventName, Operation, Protocol,
    ProtocolError, Request, RunEventAdmission, RunStreamCursor, WorkspaceOnboardRequest,
    ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT, MAX_ARTIFACT_CHUNK_BYTES, MAX_FRAME_LENGTH,
    MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS, MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
    MAX_TEXT_LENGTH, MAX_UNACKNOWLEDGED_ARTIFACT_BYTES,
};
use crate::journal::MAX_THREAD_TITLE_CHARS;

const MAX_THREAD_ID_LENGTH: usize = 36;
const MAX_CURSOR_LENGTH: usize = 1024;
const MAX_RESPONSE_BODY_LENGTH: usize = MAX_FRAME_LENGTH - 4096;
const MAX_HANDOFF_NONCE_BYTES: usize = 128;
const MAX_HANDOFF_DEADLINE_MS: u64 = 60_000;
pub const MAX_RUN_START_TEXT_LENGTH: usize = 32 * 1024;
pub const MAX_RUN_MESSAGE_TEXT_LENGTH: usize = 32 * 1024;
pub const MAX_RUN_START_CONTEXT_LENGTH: usize = 64 * 1024;
pub const MAX_PERMISSION_GATE_ID_LENGTH: usize = 256;

fn invalid_permission_answer(answer: &crate::permission_gate::ChatPermissionAnswer) -> bool {
    use crate::permission_gate::ChatPermissionAnswer;
    match answer {
        ChatPermissionAnswer::Select(value)
        | ChatPermissionAnswer::Input(value)
        | ChatPermissionAnswer::Editor(value) => value.trim().is_empty(),
        ChatPermissionAnswer::CodeDiff {
            gate_id,
            effect_id,
            code_diff_id,
            diff_sha256,
            write_plan_sha256,
        } => {
            [gate_id, effect_id, code_diff_id]
                .into_iter()
                .any(|value| value.trim().is_empty() || value.len() > MAX_PERMISSION_GATE_ID_LENGTH)
                || [diff_sha256, write_plan_sha256].into_iter().any(|value| {
                    value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        }
        ChatPermissionAnswer::Confirm(_) | ChatPermissionAnswer::Cancelled => false,
    }
}

fn permission_answer_gate_mismatch(
    gate_id: &str,
    answer: &crate::permission_gate::ChatPermissionAnswer,
) -> bool {
    matches!(
        answer,
        crate::permission_gate::ChatPermissionAnswer::CodeDiff {
            gate_id: answer_gate_id,
            ..
        } if answer_gate_id != gate_id
    )
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    encoded
}

pub(super) struct DispatchResult {
    pub(super) body: serde_json::Value,
    pub(super) events: Vec<Event>,
}

#[derive(Debug, Default)]
pub(super) struct SessionRegistries {
    cancelled_subscriptions: HashSet<super::Id>,
    pub(super) artifact_transfers: ArtifactTransferRegistry,
    pub(super) artifact_now: Option<Instant>,
}

pub(super) struct DispatchFailure {
    pub(super) error: ProtocolError,
    pub(super) events: Vec<Event>,
}

impl From<ProtocolError> for DispatchFailure {
    fn from(error: ProtocolError) -> Self {
        Self {
            error,
            events: Vec::new(),
        }
    }
}

const MAX_ACTIVE_RUN_STREAMS: usize = 64;
const MAX_CHAT_EVENTS_PER_POLL: usize = 64;

pub(super) struct ActiveRunStream {
    cursor: RunStreamCursor,
    pending: VecDeque<Event>,
    workspace: String,
    snapshot_run_seq: u64,
    fetched_through_run_seq: u64,
    exhausted: bool,
    caught_up: bool,
    commit_hints: Option<crate::journal::CommitSubscription>,
}

pub(super) struct ActiveChatSubscription {
    subscription_id: super::Id,
    receiver: crate::run_events::ChatEventSubscription,
}

pub(super) struct DesktopSessionState {
    subscriptions: Vec<ActiveRunStream>,
    chat_subscription: Option<ActiveChatSubscription>,
    registries: SessionRegistries,
}

impl<S: ThreadListService> DesktopSessionService for S {
    type State = DesktopSessionState;
    type Provenance = CompanionProvenance;

    fn new_session_state(&self) -> Self::State {
        DesktopSessionState {
            subscriptions: Vec::new(),
            chat_subscription: None,
            registries: SessionRegistries::default(),
        }
    }

    fn poll_run_streams(&mut self, state: &mut Self::State) -> Result<Vec<Event>, ProtocolError> {
        poll_run_streams(self, &mut state.subscriptions)
    }

    fn has_chat_subscription(&self, state: &Self::State) -> bool {
        state.chat_subscription.is_some()
    }

    #[cfg(target_os = "linux")]
    fn record_chat_delivery_failure(&mut self, run_id: &str, cause: &str) {
        ThreadListService::record_chat_delivery_failure(self, run_id, cause);
    }

    fn drain_chat_events(
        &mut self,
        state: &mut Self::State,
    ) -> Result<(Vec<Event>, bool), AttachSessionError> {
        state
            .chat_subscription
            .as_ref()
            .map_or(Ok((Vec::new(), false)), drain_chat_events)
    }

    fn dispatch_request(
        &mut self,
        request: Request,
        workspace: &str,
        provenance: Self::Provenance,
        state: &mut Self::State,
    ) -> Result<DesktopDispatchResult, DesktopDispatchFailure> {
        dispatch_request(
            request,
            workspace,
            provenance,
            self,
            &mut state.subscriptions,
            &mut state.chat_subscription,
            &mut state.registries,
        )
        .map(|result| DesktopDispatchResult {
            body: result.body,
            events: result.events,
        })
        .map_err(|failure| DesktopDispatchFailure {
            error: failure.error,
            events: failure.events,
        })
    }
}

fn drain_chat_events(
    subscription: &ActiveChatSubscription,
) -> Result<(Vec<Event>, bool), AttachSessionError> {
    let mut events = Vec::new();
    for _ in 0..MAX_CHAT_EVENTS_PER_POLL {
        match subscription.receiver.try_recv() {
            Ok(event) => events.push(Event {
                protocol: Protocol,
                subscription_id: subscription.subscription_id.clone(),
                event: EventName::ChatEvent,
                run_id: None,
                run_seq: None,
                body: serde_json::to_value(event)
                    .map_err(|_| AttachSessionError::MalformedFrame)?,
            }),
            Err(TryRecvError::Empty) => return Ok((events, false)),
            Err(TryRecvError::Disconnected) => return Ok((events, true)),
        }
    }
    Ok((events, false))
}

pub(super) fn poll_run_streams<S: ThreadListService>(
    service: &mut S,
    subscriptions: &mut [ActiveRunStream],
) -> Result<Vec<Event>, ProtocolError> {
    let mut events = Vec::new();
    for stream in subscriptions {
        let window = stream.cursor.window();
        if !stream.pending.is_empty()
            || stream.cursor.outstanding_events() == window.max_events
            || stream.cursor.outstanding_bytes() == window.max_bytes
            || stream.cursor.outstanding_text_bytes() == window.max_text_bytes
        {
            continue;
        }
        let mut wake = false;
        if let Some(receiver) = stream.commit_hints.as_ref() {
            loop {
                match receiver.try_recv() {
                    Ok(hint) => {
                        if hint.run_id == stream.cursor.run_id().as_str() {
                            wake = true;
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        stream.commit_hints = None;
                        break;
                    }
                }
            }
        }
        if !wake {
            continue;
        }
        let page = service.stream_run(
            &stream.workspace,
            stream.cursor.run_id().as_str(),
            stream.fetched_through_run_seq,
        )?;
        stream.snapshot_run_seq = page.current_run_seq;
        append_run_stream_page(stream, page)?;
        events.extend(drain_run_stream(stream)?);
    }
    Ok(events)
}

fn append_run_stream_page(
    stream: &mut ActiveRunStream,
    page: RunStreamPage,
) -> Result<(), ProtocolError> {
    let expected = stream.fetched_through_run_seq.saturating_add(1);
    if page.run_id != stream.cursor.run_id().as_str()
        || page.first_available_run_seq != stream.cursor.first_available_run_seq()
        || page.current_run_seq < stream.snapshot_run_seq
        || page.events.iter().enumerate().any(|(index, event)| {
            event.run_id != page.run_id || event.run_seq != expected.saturating_add(index as u64)
        })
    {
        return Err(ProtocolError::persistence_failed());
    }
    for journal_event in page.events {
        if journal_event.run_seq > stream.snapshot_run_seq {
            break;
        }
        let (event_name, body) = if journal_event.event_type == "permission.requested" {
            let projection = journal_event
                .pending_permission
                .as_ref()
                .filter(|projection| projection.valid)
                .ok_or_else(ProtocolError::persistence_failed)?;
            if projection.gate_id.trim().is_empty()
                || projection.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH
                || projection.kind != "confirm"
                || projection.title.trim().is_empty()
                || projection.title.len() > 1_024
                || projection
                    .message
                    .as_ref()
                    .is_some_and(|message| message.len() > 4_096)
            {
                return Err(ProtocolError::persistence_failed());
            }
            let mut body = serde_json::json!({
                "gate_id": projection.gate_id,
                "kind": projection.kind,
                "title": projection.title,
            });
            if let Some(message) = &projection.message {
                body["message"] = serde_json::json!(message);
            }
            (EventName::PermissionPending, body)
        } else {
            let mut payload = serde_json::json!({ "withheld": true });
            match journal_event.event_type.as_str() {
                "model.stream.delta" => {
                    if let Some(text) = &journal_event.text {
                        payload = serde_json::json!({ "text": text });
                    }
                }
                "tool.effect.started" | "tool.effect.completed" | "tool.effect.failed" => {
                    let effect_id = journal_event
                        .effect_id
                        .as_ref()
                        .filter(|effect_id| !effect_id.is_empty() && effect_id.len() <= 65_536)
                        .filter(|_| journal_event.tool_effect_valid)
                        .ok_or_else(ProtocolError::persistence_failed)?;
                    if journal_event
                        .display_name
                        .as_ref()
                        .is_some_and(|display_name| display_name.len() > 65_536)
                        || (journal_event.event_type != "tool.effect.started"
                            && journal_event.display_name.is_some())
                    {
                        return Err(ProtocolError::persistence_failed());
                    }
                    payload = serde_json::json!({ "effect_id": effect_id });
                    if let Some(display_name) = &journal_event.display_name {
                        payload["display_name"] = serde_json::json!(display_name);
                    }
                }
                _ => {}
            }
            if let Some(receipt) = &journal_event.receipt {
                payload["receipt"] = serde_json::to_value(receipt)
                    .map_err(|_| ProtocolError::persistence_failed())?;
            }
            (
                EventName::RunEvent,
                serde_json::json!({
                    "event_type": journal_event.event_type,
                    "event_version": journal_event.event_version,
                    "recorded_at": journal_event.recorded_at,
                    "payload": payload
                }),
            )
        };
        let event = Event {
            protocol: Protocol,
            subscription_id: stream.cursor.subscription_id().clone(),
            event: event_name,
            run_id: Some(stream.cursor.run_id().clone()),
            run_seq: Some(journal_event.run_seq),
            body,
        };
        if encode_frame(&event)
            .map_err(|_| ProtocolError::persistence_failed())?
            .len()
            > MAX_RUN_STREAM_WINDOW_BYTES
        {
            return Err(ProtocolError::persistence_failed());
        }
        stream.fetched_through_run_seq = journal_event.run_seq;
        stream.pending.push_back(event);
    }
    stream.exhausted = stream.fetched_through_run_seq == stream.snapshot_run_seq;
    Ok(())
}

fn drain_run_stream(stream: &mut ActiveRunStream) -> Result<Vec<Event>, ProtocolError> {
    let mut events = Vec::new();
    while let Some(event) = stream.pending.front() {
        let run_seq = event
            .run_seq
            .ok_or_else(ProtocolError::persistence_failed)?;
        let bytes = encode_frame(event)
            .map_err(|_| ProtocolError::persistence_failed())?
            .len();
        let text_bytes = event.body["payload"]["text"].as_str().map_or(0, str::len);
        match stream
            .cursor
            .admit_event(
                event
                    .run_id
                    .as_ref()
                    .ok_or_else(ProtocolError::persistence_failed)?,
                run_seq,
                bytes,
                text_bytes,
            )
            .map_err(|_| ProtocolError::invalid_cursor())?
        {
            RunEventAdmission::Sent => {
                events.push(stream.pending.pop_front().expect("front existed"))
            }
            RunEventAdmission::Paused => break,
        }
    }
    if stream.exhausted && stream.pending.is_empty() && !stream.caught_up {
        stream.caught_up = true;
        events.push(Event {
            protocol: Protocol,
            subscription_id: stream.cursor.subscription_id().clone(),
            event: EventName::SubscriptionCaughtUp,
            run_id: Some(stream.cursor.run_id().clone()),
            run_seq: Some(stream.cursor.current_run_seq()),
            body: serde_json::json!({}),
        });
    }
    Ok(events)
}

fn response_only(body: serde_json::Value) -> DispatchResult {
    DispatchResult {
        body,
        events: Vec::new(),
    }
}

fn bounded_response(body: serde_json::Value) -> Result<DispatchResult, DispatchFailure> {
    if serde_json::to_vec(&body)
        .map_err(|_| ProtocolError::persistence_failed())?
        .len()
        > MAX_RESPONSE_BODY_LENGTH
    {
        return Err(ProtocolError::persistence_failed().into());
    }
    Ok(response_only(body))
}

fn redacted_run_open_event(
    event: &crate::journal::RunEventProjection,
) -> Result<serde_json::Value, ProtocolError> {
    if event.event_type.is_empty()
        || event.event_type.len() > MAX_TEXT_LENGTH
        || event.event_version == 0
        || event.recorded_at.is_empty()
        || event.recorded_at.len() > MAX_TEXT_LENGTH
        || chrono::DateTime::parse_from_rfc3339(&event.recorded_at).is_err()
        || event
            .text
            .as_ref()
            .is_some_and(|text| text.is_empty() || text.len() > 65_536)
        || event
            .effect_id
            .as_ref()
            .is_some_and(|effect_id| effect_id.is_empty() || effect_id.len() > 65_536)
        || event
            .display_name
            .as_ref()
            .is_some_and(|display_name| display_name.is_empty() || display_name.len() > 65_536)
    {
        return Err(ProtocolError::persistence_failed());
    }
    let mut body = serde_json::json!({
        "run_seq": event.run_seq,
        "event_type": event.event_type,
        "event_version": event.event_version,
        "recorded_at": event.recorded_at,
    });
    if let Some(text) = &event.text {
        body["text"] = serde_json::json!(text);
    }
    if let Some(effect_id) = &event.effect_id {
        body["effect_id"] = serde_json::json!(effect_id);
    }
    if let Some(display_name) = &event.display_name {
        body["display_name"] = serde_json::json!(display_name);
    }
    if let Some(receipt) = &event.receipt {
        body["receipt"] = serde_json::json!({
            "route": receipt.route,
            "model": receipt.model,
            "cost": receipt.cost,
            "time": receipt.time,
            "capabilities": receipt.capabilities,
        });
    }
    Ok(body)
}

pub(super) fn dispatch_request<S: ThreadListService>(
    request: Request,
    workspace: &str,
    provenance: CompanionProvenance,
    service: &mut S,
    subscriptions: &mut Vec<ActiveRunStream>,
    chat_subscription: &mut Option<ActiveChatSubscription>,
    registries: &mut SessionRegistries,
) -> Result<DispatchResult, DispatchFailure> {
    let now = registries.artifact_now.unwrap_or_else(Instant::now);
    let _drain_admission = service
        .drain_state()
        .map(|drain| drain.admit(request.operation))
        .transpose()
        .map_err(|_| ProtocolError::runtime_draining())?;
    if chat_subscription.is_some() {
        return Err(if request.operation == Operation::RunChatEvents {
            ProtocolError::invalid_request().into()
        } else {
            ProtocolError::unsupported_operation().into()
        });
    }
    request.validate_idempotency_key()?;
    if request.operation == Operation::ArtifactWindow {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            transfer_id: String,
            ack_through_chunk: i64,
            max_chunks: u32,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let transfer_id =
            super::Id::new(body.transfer_id).map_err(|_| ProtocolError::invalid_request())?;
        let transfer = registries
            .artifact_transfers
            .get_mut(&transfer_id)
            .map_err(|_| ProtocolError::transfer_not_found())?;
        let granted_chunks = match transfer.accept_window_at(
            &transfer_id,
            body.ack_through_chunk,
            body.max_chunks,
            now,
        ) {
            Ok(granted_chunks) => granted_chunks,
            Err(error) => {
                let close = error.close();
                let code = close.code.as_str();
                registries
                    .artifact_transfers
                    .remove(&transfer_id)
                    .map_err(|_| ProtocolError::transfer_not_found())?;
                return Err(DispatchFailure {
                    error: error.error().clone(),
                    events: vec![Event {
                        protocol: Protocol,
                        subscription_id: transfer_id,
                        event: EventName::StreamClosed,
                        run_id: None,
                        run_seq: None,
                        body: serde_json::json!({
                            "code": code,
                            "resumable": close.resumable,
                        }),
                    }],
                });
            }
        };
        let metadata = transfer.metadata().clone();
        let first_chunk = u64::try_from(transfer.highest_emitted() + 1)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let end_chunk = first_chunk
            .checked_add(u64::from(granted_chunks))
            .map(|end| end.min(metadata.chunk_count))
            .ok_or_else(ProtocolError::persistence_failed)?;
        let mut events = Vec::new();
        for chunk_index in first_chunk..end_chunk {
            let offset = chunk_index
                .checked_mul(metadata.chunk_bytes)
                .ok_or_else(ProtocolError::persistence_failed)?;
            let byte_length = metadata
                .total_bytes
                .checked_sub(offset)
                .map(|remaining| remaining.min(metadata.chunk_bytes))
                .ok_or_else(ProtocolError::persistence_failed)?;
            let data = match service.read_artifact_range(
                workspace,
                &metadata.artifact_id,
                offset,
                byte_length,
            ) {
                Ok(data) => data,
                Err(error) => {
                    registries.artifact_transfers.remove(&transfer_id).ok();
                    let code = serde_json::to_value(error.code())
                        .unwrap_or_else(|_| serde_json::json!("persistence_failed"));
                    return Err(DispatchFailure {
                        error,
                        events: vec![Event {
                            protocol: Protocol,
                            subscription_id: transfer_id,
                            event: EventName::StreamClosed,
                            run_id: None,
                            run_seq: None,
                            body: serde_json::json!({"code": code, "resumable": true}),
                        }],
                    });
                }
            };
            let chunk_sha256 = format!("{:x}", Sha256::digest(&data));
            let admission = registries
                .artifact_transfers
                .get_mut(&transfer_id)
                .map_err(|_| ProtocolError::transfer_not_found())?
                .admit_chunk_at(
                    &metadata.artifact_id,
                    chunk_index,
                    offset,
                    byte_length,
                    &chunk_sha256,
                    &data,
                    now,
                );
            if let Err(error) = admission {
                let close = error.close();
                let code = close.code.as_str();
                registries.artifact_transfers.remove(&transfer_id).ok();
                return Err(DispatchFailure {
                    error: error.error().clone(),
                    events: vec![Event {
                        protocol: Protocol,
                        subscription_id: transfer_id,
                        event: EventName::StreamClosed,
                        run_id: None,
                        run_seq: None,
                        body: serde_json::json!({
                            "code": code,
                            "resumable": close.resumable,
                        }),
                    }],
                });
            }
            events.push(Event {
                protocol: Protocol,
                subscription_id: transfer_id.clone(),
                event: EventName::ArtifactChunk,
                run_id: None,
                run_seq: None,
                body: serde_json::json!({
                    "artifact_id": metadata.artifact_id,
                    "chunk_index": chunk_index,
                    "offset": offset,
                    "byte_length": byte_length,
                    "chunk_sha256": chunk_sha256,
                    "data": STANDARD.encode(data),
                }),
            });
        }
        if let Some(completion) = registries
            .artifact_transfers
            .get(&transfer_id)
            .map_err(|_| ProtocolError::transfer_not_found())?
            .completion()
        {
            registries
                .artifact_transfers
                .remove(&transfer_id)
                .map_err(|_| ProtocolError::transfer_not_found())?;
            events.push(Event {
                protocol: Protocol,
                subscription_id: transfer_id,
                event: EventName::ArtifactComplete,
                run_id: None,
                run_seq: None,
                body: serde_json::json!({
                    "transfer_id": completion.transfer_id,
                    "artifact_id": completion.artifact_id,
                    "total_bytes": completion.total_bytes,
                    "sha256": completion.sha256,
                }),
            });
        }
        return Ok(DispatchResult {
            body: serde_json::json!({
                "ack_through_chunk": body.ack_through_chunk,
                "granted_chunks": granted_chunks,
            }),
            events,
        });
    }
    if request.operation == Operation::ArtifactFetch {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            artifact_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let artifact_id =
            super::Id::new(body.artifact_id).map_err(|_| ProtocolError::invalid_request())?;
        let artifact = service.fetch_artifact(workspace, &artifact_id)?;
        let chunk_bytes = MAX_ARTIFACT_CHUNK_BYTES;
        let chunk_count = artifact.total_bytes.div_ceil(chunk_bytes);
        let mut transfer_random = [0u8; 16];
        getrandom::fill(&mut transfer_random).map_err(|_| ProtocolError::persistence_failed())?;
        let transfer_id = super::Id::new(hex(&transfer_random))
            .map_err(|_| ProtocolError::persistence_failed())?;
        let metadata = ArtifactMetadata {
            transfer_id: transfer_id.clone(),
            artifact_id: artifact_id.clone(),
            total_bytes: artifact.total_bytes,
            sha256: artifact.sha256,
            chunk_bytes,
            chunk_count,
        };
        let transfer = ArtifactTransfer::new(metadata.clone())
            .map_err(|_| ProtocolError::persistence_failed())?;
        registries
            .artifact_transfers
            .insert(transfer)
            .map_err(|error| match error {
                ArtifactTransferRegistryError::BoundReached => ProtocolError::invalid_request(),
                ArtifactTransferRegistryError::NotFound => ProtocolError::persistence_failed(),
            })?;
        return Ok(response_only(serde_json::json!({
            "transfer_id": transfer_id,
            "artifact_id": artifact_id,
            "total_bytes": metadata.total_bytes,
            "sha256": metadata.sha256,
            "chunk_bytes": metadata.chunk_bytes,
            "chunk_count": metadata.chunk_count,
            "max_unacknowledged_bytes": MAX_UNACKNOWLEDGED_ARTIFACT_BYTES,
            "acknowledgement_timeout_ms": ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT.as_millis(),
        })));
    }
    if request.operation == Operation::RunChatEvents {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        let receiver = service.subscribe_chat_events()?;
        let mut subscription_random = [0u8; 16];
        getrandom::fill(&mut subscription_random)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let subscription_id = super::Id::new(hex(&subscription_random))
            .map_err(|_| ProtocolError::persistence_failed())?;
        *chat_subscription = Some(ActiveChatSubscription {
            subscription_id: subscription_id.clone(),
            receiver,
        });
        return Ok(response_only(serde_json::json!({
            "subscription_id": subscription_id,
        })));
    }
    if matches!(
        request.operation,
        Operation::SessionStatus
            | Operation::EntitlementSnapshot
            | Operation::DeviceList
            | Operation::SessionSignIn
            | Operation::SessionSignOut
            | Operation::CompanionList
    ) {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        let body = match request.operation {
            Operation::SessionStatus => serde_json::to_value(service.session_status()?),
            Operation::EntitlementSnapshot => {
                let result = service.entitlement_snapshot()?;
                Ok(serde_json::json!({
                    "snapshot": result.snapshot,
                    "changed_snapshot_version": result.changed_snapshot_version,
                }))
            }
            Operation::DeviceList => serde_json::to_value(service.list_devices()?),
            Operation::CompanionList => {
                let companions = service.list_companions()?;
                Ok(serde_json::json!({
                    "companions": companions.into_iter().map(|companion| serde_json::json!({
                        "identity": companion.identity,
                        "claimed_kind": companion.claimed_kind,
                        "claimed_version": companion.claimed_version,
                        "approved_at": companion.approved_at,
                    })).collect::<Vec<_>>(),
                }))
            }
            Operation::SessionSignIn => {
                let idempotency_key = request
                    .idempotency_key
                    .as_ref()
                    .ok_or_else(ProtocolError::idempotency_key_required)?;
                Ok(serde_json::json!({
                    "status": service.sign_in(
                        &request.request_id,
                        idempotency_key,
                        provenance,
                    )?,
                }))
            }
            Operation::SessionSignOut => {
                let idempotency_key = request
                    .idempotency_key
                    .as_ref()
                    .ok_or_else(ProtocolError::idempotency_key_required)?;
                Ok(serde_json::json!({
                    "status": service.sign_out(
                        &request.request_id,
                        idempotency_key,
                        provenance,
                    )?,
                }))
            }
            _ => unreachable!(),
        }
        .map_err(|_| ProtocolError::persistence_failed())?;
        return bounded_response(body);
    }
    if request.operation == Operation::CompanionRevoke {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            client_identity: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.client_identity.is_empty() || body.client_identity.len() > MAX_TEXT_LENGTH {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        service.revoke_companion(
            &body.client_identity,
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        return bounded_response(serde_json::json!({}));
    }
    if request.operation == Operation::WorkspaceOnboard {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            opened_directory: String,
            memory_location: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.opened_directory.is_empty()
            || body.memory_location.is_empty()
            || body.opened_directory.len() > MAX_TEXT_LENGTH
            || body.memory_location.len() > MAX_TEXT_LENGTH
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let result = service.onboard_workspace(
            workspace,
            WorkspaceOnboardRequest {
                opened_directory: body.opened_directory,
                memory_location: body.memory_location,
            },
        )?;
        if result.opened_directory.len() > MAX_TEXT_LENGTH
            || result.memory_location.len() > MAX_TEXT_LENGTH
            || result
                .instructions
                .as_ref()
                .is_some_and(|value| value.len() > MAX_TEXT_LENGTH)
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "opened_directory": result.opened_directory,
            "memory_location": result.memory_location,
            "instructions": result.instructions,
        })));
    }
    if request.operation == Operation::HomeEnsure {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        service.ensure_home()?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::MigrationControl {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            handoff_nonce: String,
            deadline_ms: u64,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.handoff_nonce.is_empty()
            || body.handoff_nonce.len() > MAX_HANDOFF_NONCE_BYTES
            || !body
                .handoff_nonce
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            || !(1..=MAX_HANDOFF_DEADLINE_MS).contains(&body.deadline_ms)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let handoff_nonce = body.handoff_nonce.clone();
        service.control_migration(
            MigrationControlRequest {
                handoff_nonce: body.handoff_nonce,
                deadline_ms: body.deadline_ms,
            },
            provenance,
        )?;
        return Ok(response_only(serde_json::json!({
            "handoff_nonce": handoff_nonce,
        })));
    }
    if request.operation == Operation::ThreadCreate {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let accepted =
            service.create_thread(workspace, &request.request_id, idempotency_key, provenance)?;
        if super::Id::new(accepted.thread_id.clone()).is_err() {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "thread_id": accepted.thread_id,
        })));
    }
    if request.operation == Operation::ThreadRename {
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
            title: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let thread_id =
            super::Id::new(body.thread_id).map_err(|_| ProtocolError::invalid_request())?;
        if body.title.is_empty() || body.title.chars().count() > MAX_THREAD_TITLE_CHARS {
            return Err(ProtocolError::invalid_request().into());
        }
        service.rename_thread(
            workspace,
            &thread_id,
            &body.title,
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::ThreadDelete {
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let thread_id =
            super::Id::new(body.thread_id).map_err(|_| ProtocolError::invalid_request())?;
        service.delete_thread(
            workspace,
            &thread_id,
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::RunCursorAck {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            subscription_id: String,
            through_run_seq: u64,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let subscription_id =
            super::Id::new(body.subscription_id).map_err(|_| ProtocolError::invalid_request())?;
        let Some(index) = subscriptions
            .iter()
            .position(|stream| stream.cursor.subscription_id() == &subscription_id)
        else {
            return Err(ProtocolError::invalid_cursor().into());
        };
        if subscriptions[index]
            .cursor
            .acknowledge(body.through_run_seq)
            .is_err()
        {
            let stream = subscriptions.remove(index);
            return Err(DispatchFailure {
                error: ProtocolError::invalid_cursor(),
                events: vec![Event {
                    protocol: Protocol,
                    subscription_id: stream.cursor.subscription_id().clone(),
                    event: EventName::StreamClosed,
                    run_id: Some(stream.cursor.run_id().clone()),
                    run_seq: Some(stream.cursor.highest_sent_run_seq()),
                    body: serde_json::json!({"code": "invalid_cursor", "resumable": true}),
                }],
            });
        }
        while subscriptions[index].pending.is_empty() && !subscriptions[index].exhausted {
            let fetched_through_run_seq = subscriptions[index].fetched_through_run_seq;
            let page = service.stream_run(
                &subscriptions[index].workspace,
                subscriptions[index].cursor.run_id().as_str(),
                subscriptions[index].fetched_through_run_seq,
            )?;
            append_run_stream_page(&mut subscriptions[index], page)?;
            if subscriptions[index].fetched_through_run_seq == fetched_through_run_seq {
                break;
            }
        }
        let events = drain_run_stream(&mut subscriptions[index])?;
        return Ok(DispatchResult {
            body: serde_json::json!({
                "subscription_id": subscription_id.as_str(),
                "through_run_seq": body.through_run_seq,
            }),
            events,
        });
    }
    if request.operation == Operation::RequestCancel {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            kind: String,
            #[serde(default)]
            subscription_id: Option<String>,
            #[serde(default)]
            request_id: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        match (body.kind.as_str(), body.subscription_id, body.request_id) {
            ("request", None, Some(_)) => {
                return Err(ProtocolError::unsupported_operation().into());
            }
            ("subscription", Some(subscription_id), None) => {
                let subscription_id = super::Id::new(subscription_id)
                    .map_err(|_| ProtocolError::invalid_request())?;
                if registries
                    .artifact_transfers
                    .remove(&subscription_id)
                    .is_ok()
                {
                    registries
                        .cancelled_subscriptions
                        .insert(subscription_id.clone());
                    return Ok(DispatchResult {
                        body: serde_json::json!({
                            "subscription_id": subscription_id,
                        }),
                        events: vec![
                            Event {
                                protocol: Protocol,
                                subscription_id: subscription_id.clone(),
                                event: EventName::RequestCancelled,
                                run_id: None,
                                run_seq: None,
                                body: serde_json::json!({}),
                            },
                            Event {
                                protocol: Protocol,
                                subscription_id,
                                event: EventName::StreamClosed,
                                run_id: None,
                                run_seq: None,
                                body: serde_json::json!({"code": "cancelled", "resumable": true}),
                            },
                        ],
                    });
                }
                let Some(index) = subscriptions
                    .iter()
                    .position(|stream| stream.cursor.subscription_id() == &subscription_id)
                else {
                    return Err(if registries
                        .cancelled_subscriptions
                        .contains(&subscription_id)
                    {
                        ProtocolError::already_completed()
                    } else {
                        ProtocolError::subscription_not_found()
                    }
                    .into());
                };
                let stream = subscriptions.remove(index);
                registries
                    .cancelled_subscriptions
                    .insert(subscription_id.clone());
                let run_id = stream.cursor.run_id().clone();
                let run_seq = stream.cursor.highest_sent_run_seq();
                return Ok(DispatchResult {
                    body: serde_json::json!({
                        "subscription_id": subscription_id,
                    }),
                    events: vec![
                        Event {
                            protocol: Protocol,
                            subscription_id: subscription_id.clone(),
                            event: EventName::RequestCancelled,
                            run_id: Some(run_id.clone()),
                            run_seq: Some(run_seq),
                            body: serde_json::json!({}),
                        },
                        Event {
                            protocol: Protocol,
                            subscription_id,
                            event: EventName::StreamClosed,
                            run_id: Some(run_id),
                            run_seq: Some(run_seq),
                            body: serde_json::json!({"code": "cancelled", "resumable": true}),
                        },
                    ],
                });
            }
            _ => return Err(ProtocolError::invalid_request().into()),
        }
    }
    if request.operation == Operation::RunStart {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            text: String,
            #[serde(default)]
            workspace: Option<String>,
            #[serde(default)]
            context: Option<serde_json::Value>,
            #[serde(default)]
            thread_id: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let context_length = body
            .context
            .as_ref()
            .map(|context| serde_json::to_vec(context).map(|bytes| bytes.len()))
            .transpose()
            .map_err(|_| ProtocolError::invalid_request())?
            .unwrap_or(0);
        if body.text.trim().is_empty()
            || body.text.len() > MAX_RUN_START_TEXT_LENGTH
            || body
                .workspace
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_TEXT_LENGTH)
            || body
                .thread_id
                .as_ref()
                .is_some_and(|value| value.len() > 36 || super::Id::new(value.clone()).is_err())
            || context_length > MAX_RUN_START_CONTEXT_LENGTH
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let execution_root = match body.workspace.as_deref() {
            Some(requested_workspace) => service
                .authorized_workspace(workspace, requested_workspace)
                .ok_or_else(ProtocolError::unauthorized)?,
            None => workspace.to_owned(),
        };
        let accepted = service.start_run(
            workspace,
            &execution_root,
            RunStartRequest {
                text: body.text,
                context: body.context,
                thread_id: body.thread_id,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if super::Id::new(accepted.run_id.clone()).is_err()
            || super::Id::new(accepted.thread_id.clone()).is_err()
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "thread_id": accepted.thread_id,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::RunSubmit {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            text: String,
            files: Vec<String>,
            thread_id: Option<String>,
        }
        let body: Body = serde_json::from_value(request.body).map_err(|_| {
            ProtocolError::invalid_request_with_reason("The run request body is invalid.")
        })?;
        let reason = if body.text.trim().is_empty() {
            Some("Enter a message before sending.")
        } else if body.text.len() > MAX_RUN_START_TEXT_LENGTH {
            Some("The message exceeds the allowed size.")
        } else if body
            .files
            .iter()
            .any(|path| path.is_empty() || path.len() > MAX_TEXT_LENGTH)
        {
            Some("A selected file path is invalid.")
        } else if body
            .thread_id
            .as_ref()
            .is_some_and(|value| super::Id::new(value.clone()).is_err())
        {
            Some("The thread ID is invalid.")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(ProtocolError::invalid_request_with_reason(reason).into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let requested_thread_id = body.thread_id.clone();
        let requested_attachment_count = body.files.len();
        let accepted = service.submit_run(
            workspace,
            RunSubmitRequest {
                text: body.text,
                files: body.files,
                thread_id: body.thread_id,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if super::Id::new(accepted.run_id.clone()).is_err()
            || super::Id::new(accepted.thread_id.clone()).is_err()
            || requested_thread_id
                .as_ref()
                .is_some_and(|thread_id| thread_id != &accepted.thread_id)
            || accepted.committed_seq == 0
            || accepted.attachments.len() != requested_attachment_count
            || accepted.attachments.iter().any(|attachment| {
                attachment.display_name.trim().is_empty()
                    || attachment.display_name.len() > MAX_TEXT_LENGTH
                    || attachment.media_type.as_ref().is_some_and(|value| {
                        value.trim().is_empty() || value.len() > MAX_TEXT_LENGTH
                    })
            })
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return bounded_response(serde_json::json!({
            "run_id": accepted.run_id,
            "thread_id": accepted.thread_id,
            "attachments": accepted.attachments,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        }));
    }
    if request.operation == Operation::RunResume {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let requested_run_id = body.run_id.clone();
        let accepted = service.resume_run(
            workspace,
            RunResumeRequest {
                run_id: body.run_id,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if accepted.run_id != requested_run_id
            || super::Id::new(accepted.run_id.clone()).is_err()
            || super::Id::new(accepted.thread_id.clone()).is_err()
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "thread_id": accepted.thread_id,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::RunCancel {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let requested_run_id = body.run_id.clone();
        let accepted = service.cancel_run(
            workspace,
            RunCancelRequest {
                run_id: body.run_id,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if accepted.run_id != requested_run_id
            || super::Id::new(accepted.run_id.clone()).is_err()
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if matches!(
        request.operation,
        Operation::RunSteer | Operation::RunFollowUp
    ) {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
            text: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        if body.text.trim().is_empty() || body.text.len() > MAX_RUN_MESSAGE_TEXT_LENGTH {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let requested_run_id = body.run_id.clone();
        let operation = request.operation;
        let mutation = RunMessageRequest {
            run_id: body.run_id,
            text: body.text,
        };
        let accepted = if operation == Operation::RunSteer {
            service.steer_run(
                workspace,
                mutation,
                &request.request_id,
                idempotency_key,
                provenance,
            )?
        } else {
            service.follow_up_run(
                workspace,
                mutation,
                &request.request_id,
                idempotency_key,
                provenance,
            )?
        };
        if accepted.run_id != requested_run_id
            || super::Id::new(accepted.run_id.clone()).is_err()
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::RunPermissionAnswer {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
            gate_id: String,
            answer: crate::permission_gate::ChatPermissionAnswer,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        let answer_length = serde_json::to_vec(&body.answer)
            .map_err(|_| ProtocolError::invalid_request())?
            .len();
        if body.gate_id.trim().is_empty()
            || body.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH
            || answer_length > MAX_RUN_MESSAGE_TEXT_LENGTH
            || invalid_permission_answer(&body.answer)
            || permission_answer_gate_mismatch(&body.gate_id, &body.answer)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let requested_run_id = body.run_id.clone();
        let requested_gate_id = body.gate_id.clone();
        let requested_answer =
            serde_json::to_value(&body.answer).map_err(|_| ProtocolError::invalid_request())?;
        let accepted = service.answer_run_permission(
            workspace,
            RunPermissionAnswerRequest {
                run_id: body.run_id,
                gate_id: body.gate_id,
                answer: body.answer,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if accepted.run_id != requested_run_id
            || accepted.gate_id != requested_gate_id
            || super::Id::new(accepted.run_id.clone()).is_err()
            || accepted.committed_seq == 0
            || serde_json::to_value(&accepted.answer)
                .map_or(true, |answer| answer != requested_answer)
            || invalid_permission_answer(&accepted.answer)
            || permission_answer_gate_mismatch(&accepted.gate_id, &accepted.answer)
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "gate_id": accepted.gate_id,
            "answer": accepted.answer,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::PermissionAnswer {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
            gate_id: String,
            decision: PermissionDecision,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        if body.gate_id.trim().is_empty() || body.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH {
            return Err(ProtocolError::invalid_request().into());
        }
        let idempotency_key = request
            .idempotency_key
            .as_ref()
            .ok_or_else(ProtocolError::idempotency_key_required)?;
        let accepted = service.answer_permission(
            workspace,
            PermissionAnswerRequest {
                run_id: body.run_id,
                gate_id: body.gate_id,
                decision: body.decision,
            },
            &request.request_id,
            idempotency_key,
            provenance,
        )?;
        if super::Id::new(accepted.run_id.clone()).is_err()
            || accepted.gate_id.trim().is_empty()
            || accepted.gate_id.len() > MAX_PERMISSION_GATE_ID_LENGTH
            || accepted.committed_seq == 0
            || accepted.accepted_at.is_empty()
            || accepted.accepted_at.len() > MAX_TEXT_LENGTH
            || chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_err()
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(serde_json::json!({
            "run_id": accepted.run_id,
            "gate_id": accepted.gate_id,
            "decision": accepted.decision,
            "committed_seq": accepted.committed_seq,
            "accepted_at": accepted.accepted_at,
        })));
    }
    if request.operation == Operation::RunOpen {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let run_id = super::Id::new(body.run_id).map_err(|_| ProtocolError::invalid_request())?;
        let page = service.stream_run(workspace, run_id.as_str(), 0)?;
        if page.run_id != run_id.as_str()
            || page.first_available_run_seq == 0
            || (page.first_available_run_seq > page.current_run_seq
                && page.first_available_run_seq != page.current_run_seq.saturating_add(1))
            || (page.exhausted && page.events.len() as u64 != page.current_run_seq)
            || page.events.len() > MAX_RUN_STREAM_WINDOW_EVENTS
            || page.events.iter().enumerate().any(|(index, event)| {
                event.run_id != page.run_id
                    || event.run_seq != index as u64 + 1
                    || event.run_seq > page.current_run_seq
            })
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        let mut events = page
            .events
            .iter()
            .map(redacted_run_open_event)
            .collect::<Result<Vec<_>, _>>()?;
        let mut exhausted = page.exhausted;
        loop {
            let body = serde_json::json!({
                "run_id": page.run_id,
                "first_available_run_seq": page.first_available_run_seq,
                "current_run_seq": page.current_run_seq,
                "events": &events,
                "exhausted": exhausted,
            });
            if serde_json::to_vec(&body)
                .map_err(|_| ProtocolError::persistence_failed())?
                .len()
                <= MAX_RESPONSE_BODY_LENGTH
            {
                return Ok(response_only(body));
            }
            if events.len() <= 1 {
                return Err(ProtocolError::persistence_failed().into());
            }
            events.pop();
            exhausted = false;
        }
    }
    if request.operation == Operation::RunStream {
        if subscriptions.len() >= MAX_ACTIVE_RUN_STREAMS {
            return Err(ProtocolError::invalid_request().into());
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            run_id: String,
            after_run_seq: u64,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        let run_id =
            super::Id::new(body.run_id.clone()).map_err(|_| ProtocolError::invalid_request())?;
        let subscription = service.subscribe_run_commits(run_id.as_str())?;
        let page = service.stream_run(workspace, run_id.as_str(), body.after_run_seq)?;
        if let Some(subscription) = subscription.as_ref() {
            if page.current_run_seq < subscription.committed_high_water {
                return Err(ProtocolError::persistence_failed().into());
            }
        }
        if page.run_id != run_id.as_str()
            || page.first_available_run_seq == 0
            || (page.first_available_run_seq > page.current_run_seq
                && page.first_available_run_seq != page.current_run_seq.saturating_add(1))
            || (page.exhausted
                && body.after_run_seq.saturating_add(page.events.len() as u64)
                    != page.current_run_seq)
            || page.events.iter().enumerate().any(|(index, event)| {
                event.run_id != page.run_id
                    || event.run_seq != body.after_run_seq.saturating_add(index as u64 + 1)
                    || event.run_seq > page.current_run_seq
            })
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        let mut subscription_random = [0u8; 16];
        getrandom::fill(&mut subscription_random)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let subscription_id = super::Id::new(hex(&subscription_random))
            .map_err(|_| ProtocolError::persistence_failed())?;
        let cursor = RunStreamCursor::new(
            subscription_id.clone(),
            run_id.clone(),
            page.first_available_run_seq,
            page.current_run_seq,
            body.after_run_seq,
            MAX_RUN_STREAM_WINDOW_EVENTS,
            MAX_RUN_STREAM_WINDOW_BYTES,
            MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
        )
        .map_err(|_| ProtocolError::invalid_cursor())?;
        let snapshot_run_seq = page.current_run_seq;
        let first_available_run_seq = page.first_available_run_seq;
        let mut active = ActiveRunStream {
            cursor,
            pending: VecDeque::new(),
            workspace: workspace.to_owned(),
            snapshot_run_seq,
            fetched_through_run_seq: body.after_run_seq,
            exhausted: false,
            caught_up: false,
            commit_hints: subscription,
        };
        append_run_stream_page(&mut active, page)?;
        let events = drain_run_stream(&mut active)?;
        subscriptions.push(active);
        return Ok(DispatchResult {
            body: serde_json::json!({
                "subscription_id": subscription_id,
                "run_id": run_id,
                "first_available_run_seq": first_available_run_seq,
                "current_run_seq": snapshot_run_seq,
                "window": {
                    "max_events": MAX_RUN_STREAM_WINDOW_EVENTS,
                    "max_bytes": MAX_RUN_STREAM_WINDOW_BYTES,
                    "max_text_bytes": MAX_RUN_STREAM_WINDOW_TEXT_BYTES
                }
            }),
            events,
        });
    }
    if request.operation == Operation::ThreadOpen {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
            limit: u8,
            #[serde(default)]
            cursor: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.thread_id.is_empty()
            || body.thread_id.len() > MAX_THREAD_ID_LENGTH
            || body.limit == 0
            || body.limit > 100
            || body
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let limit = body.limit;
        let requested_thread_id = body.thread_id.clone();
        let page = service.open_thread(
            workspace,
            ThreadOpenRequest {
                thread_id: body.thread_id,
                limit,
                cursor: body.cursor,
            },
        )?;
        if page.entries.len() > usize::from(limit)
            || page.thread_id != requested_thread_id
            || page.thread_id.is_empty()
            || page.thread_id.len() > MAX_TEXT_LENGTH
            || page.entries.iter().any(|entry| {
                entry.run_seq == 0
                    || entry.kind.is_empty()
                    || entry.kind.len() > MAX_TEXT_LENGTH
                    || entry
                        .text
                        .as_ref()
                        .is_some_and(|text| text.len() > MAX_TEXT_LENGTH)
            })
            || page
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        let value = serde_json::to_value(page).map_err(|_| ProtocolError::persistence_failed())?;
        if serde_json::to_vec(&value)
            .map_err(|_| ProtocolError::persistence_failed())?
            .len()
            > MAX_RESPONSE_BODY_LENGTH
        {
            return Err(ProtocolError::persistence_failed().into());
        }
        return Ok(response_only(value));
    }
    if request.operation == Operation::ThreadSummaries {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            limit: u8,
            #[serde(default)]
            cursor: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.limit == 0
            || body.limit > 100
            || body
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let mut limit = body.limit;
        loop {
            let value = service.thread_summaries(ThreadListRequest {
                limit,
                cursor: body.cursor.clone(),
            })?;
            if serde_json::to_vec(&value)
                .map_err(|_| ProtocolError::persistence_failed())?
                .len()
                <= MAX_RESPONSE_BODY_LENGTH
            {
                return Ok(response_only(value));
            }
            if limit == 1 {
                return Err(ProtocolError::persistence_failed().into());
            }
            limit /= 2;
        }
    }
    if request.operation == Operation::ThreadHistory {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: String,
            limit: u8,
            #[serde(default)]
            cursor: Option<String>,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        if body.thread_id.is_empty()
            || body.thread_id.len() > MAX_THREAD_ID_LENGTH
            || body.limit == 0
            || body.limit > 100
            || body
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_CURSOR_LENGTH)
        {
            return Err(ProtocolError::invalid_request().into());
        }
        let mut limit = body.limit;
        loop {
            let value = service.thread_history(ThreadOpenRequest {
                thread_id: body.thread_id.clone(),
                limit,
                cursor: body.cursor.clone(),
            })?;
            if serde_json::to_vec(&value)
                .map_err(|_| ProtocolError::persistence_failed())?
                .len()
                <= MAX_RESPONSE_BODY_LENGTH
            {
                return Ok(response_only(value));
            }
            if limit == 1 {
                return Err(ProtocolError::persistence_failed().into());
            }
            limit /= 2;
        }
    }
    if request.operation == Operation::ThreadSelect {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            thread_id: super::Id,
        }
        let body: Body =
            serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
        service.select_thread(&body.thread_id)?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation == Operation::RetentionRecheck {
        if request.body != serde_json::json!({}) {
            return Err(ProtocolError::invalid_request().into());
        }
        service.recheck_retention()?;
        return Ok(response_only(serde_json::json!({})));
    }
    if request.operation != Operation::ThreadList {
        return Err(ProtocolError::unsupported_operation().into());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        limit: u8,
        #[serde(default)]
        cursor: Option<String>,
    }
    let body: Body =
        serde_json::from_value(request.body).map_err(|_| ProtocolError::invalid_request())?;
    if body.limit == 0
        || body.limit > 100
        || body
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
    {
        return Err(ProtocolError::invalid_request().into());
    }
    let limit = body.limit;
    let page = service.list_threads(
        workspace,
        ThreadListRequest {
            limit,
            cursor: body.cursor,
        },
    )?;
    if page.threads.len() > usize::from(limit)
        || page.threads.iter().any(|thread| {
            thread.thread_id.is_empty()
                || thread.thread_id.len() > MAX_TEXT_LENGTH
                || thread.title.len() > MAX_TEXT_LENGTH
                || thread.updated_at.is_empty()
                || thread.updated_at.len() > MAX_TEXT_LENGTH
        })
        || page
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
    {
        return Err(ProtocolError::persistence_failed().into());
    }
    Ok(serde_json::to_value(page)
        .map(response_only)
        .map_err(|_| ProtocolError::persistence_failed())?)
}
