use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvError, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::cas::LocalCas;
use crate::chat_view::{
    chat_attachments, chat_pending_permission, chat_tool_activity, projection_phase,
    ChatAppliedDiff, ChatAttachment, ChatPendingPermission, ChatToolActivity,
};
use crate::code_diff_journal::{load_applied_code_diffs_cached, load_pending_code_diff_cached};
use crate::journal::pi_translation::close_open_effects;
use crate::journal::reducer::{ChatProjection, ChatProjector, ProjectedRecall};
use crate::journal::run_append::append_run_event_in_place;
use crate::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_code_diff::CodeDiff;

/// How long a run streams text deltas before it sends its whole state again.
/// A shell that missed the start of the run, such as a reloaded window, joins
/// the stream at the next whole state.
pub const CHAT_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

/// Counts chat-event subscriptions. A run sends its whole state again after a
/// subscription starts, so every subscriber reads a whole state before a delta.
static SUBSCRIPTION_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn subscription_generation() -> u64 {
    SUBSCRIPTION_GENERATION.load(Ordering::Acquire)
}

/// A chat event is either a whole projection of the run or, with `delta`
/// set, a text delta. A text delta carries the run id, the thread id, the
/// phase and in `text` only the text appended since the run's previous event.
/// Every other field keeps the value of the previous event, except the
/// routing stage, which a text delta clears.
#[derive(Clone)]
pub struct ChatEvent {
    pub run_id: String,
    pub thread_id: Option<String>,
    pub phase: String,
    pub text: String,
    /// The shell's in-flight word: `Routing` before the accepted prompt, `Thinking` from the started turn.
    pub prompt_accepted: bool,
    pub turn_started: bool,
    pub routing_stage: Option<String>,
    pub prompt_storage_notice: Option<String>,
    pub failure_reason: Option<String>,
    pub receipt: Option<Value>,
    pub tool_activity: Vec<ChatToolActivity>,
    pub attachments: Vec<ChatAttachment>,
    pub recalls: Vec<ProjectedRecall>,
    pub applied_diffs: Vec<ChatAppliedDiff>,
    pub pending_permission: Option<ChatPendingPermission>,
    pub delta: Option<ChatTextDelta>,
}

/// Marks a chat event that carries only appended text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatTextDelta {
    /// Where the appended text starts in the run's text, in UTF-16 code units.
    pub text_start: usize,
    generation: u64,
}

impl ChatTextDelta {
    pub fn new(text_start: usize) -> Self {
        Self {
            text_start,
            generation: subscription_generation(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatEventWire<'a> {
    run_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<&'a str>,
    phase: &'a str,
    text: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    prompt_accepted: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    turn_started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    routing_stage: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_storage_notice: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<&'a Value>,
    tool_activity: &'a [ChatToolActivity],
    attachments: &'a [ChatAttachment],
    recalls: &'a [ProjectedRecall],
    applied_diffs: &'a [ChatAppliedDiff],
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_permission: Option<&'a ChatPendingPermission>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatTextDeltaWire<'a> {
    run_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<&'a str>,
    phase: &'a str,
    text: &'a str,
    text_start: usize,
}

impl Serialize for ChatEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(delta) = &self.delta {
            return ChatTextDeltaWire {
                run_id: &self.run_id,
                thread_id: self.thread_id.as_deref(),
                phase: &self.phase,
                text: &self.text,
                text_start: delta.text_start,
            }
            .serialize(serializer);
        }
        ChatEventWire {
            run_id: &self.run_id,
            thread_id: self.thread_id.as_deref(),
            phase: &self.phase,
            text: &self.text,
            prompt_accepted: self.prompt_accepted,
            turn_started: self.turn_started,
            routing_stage: self.routing_stage.as_deref(),
            prompt_storage_notice: self.prompt_storage_notice.as_deref(),
            failure_reason: self.failure_reason.as_deref(),
            receipt: self.receipt.as_ref(),
            tool_activity: &self.tool_activity,
            attachments: &self.attachments,
            recalls: &self.recalls,
            applied_diffs: &self.applied_diffs,
            pending_permission: self.pending_permission.as_ref(),
        }
        .serialize(serializer)
    }
}

/// What one run's live stream last delivered in full.
#[derive(Clone, Debug, Default)]
pub struct ChatDelivery {
    snapshot: Option<(u64, Instant)>,
}

impl ChatDelivery {
    /// Reports whether a text event may go out as a delta: a whole state went
    /// out since the newest subscription started, and less than the snapshot
    /// interval ago.
    fn allows_delta(&self, generation: u64) -> bool {
        self.snapshot.is_some_and(|(delivered, at)| {
            delivered == generation && at.elapsed() < CHAT_SNAPSHOT_INTERVAL
        })
    }

    pub(crate) fn delivered_snapshot(&mut self, generation: u64) {
        self.snapshot = Some((generation, Instant::now()));
    }
}

/// A chat-event receiver that unregisters itself when dropped. It skips a
/// text delta built before the subscription started, because this receiver
/// has no whole state for that delta to extend. The run's next event is whole.
pub struct ChatEventSubscription {
    receiver: Receiver<ChatEvent>,
    generation: u64,
    on_drop: Option<Box<dyn FnOnce() + Send>>,
}

impl ChatEventSubscription {
    pub fn new(receiver: Receiver<ChatEvent>, on_drop: impl FnOnce() + Send + 'static) -> Self {
        Self {
            receiver,
            generation: start_subscription(),
            on_drop: Some(Box::new(on_drop)),
        }
    }

    #[doc(hidden)]
    pub fn detached(receiver: Receiver<ChatEvent>) -> Self {
        Self {
            receiver,
            generation: start_subscription(),
            on_drop: None,
        }
    }

    fn current(&self, event: &ChatEvent) -> bool {
        event
            .delta
            .as_ref()
            .is_none_or(|delta| delta.generation >= self.generation)
    }

    pub fn recv(&self) -> Result<ChatEvent, RecvError> {
        loop {
            let event = self.receiver.recv()?;
            if self.current(&event) {
                return Ok(event);
            }
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<ChatEvent, RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = self.receiver.recv_timeout(remaining)?;
            if self.current(&event) {
                return Ok(event);
            }
        }
    }

    pub fn try_recv(&self) -> Result<ChatEvent, TryRecvError> {
        loop {
            let event = self.receiver.try_recv()?;
            if self.current(&event) {
                return Ok(event);
            }
        }
    }
}

fn start_subscription() -> u64 {
    SUBSCRIPTION_GENERATION.fetch_add(1, Ordering::AcqRel) + 1
}

impl Drop for ChatEventSubscription {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

pub struct ChatStorage {
    pub journal: RunJournal,
    pub cas: LocalCas,
}

pub type SharedStorage = Arc<Mutex<ChatStorage>>;

pub trait ChatEventSink {
    fn provenance(&self) -> (&str, &str);

    #[allow(clippy::result_unit_err)]
    fn deliver(&self, event: ChatEvent) -> Result<(), ()>;
}

pub fn chat_event(
    run_id: &str,
    projection: ChatProjection,
    code_diff: Option<CodeDiff>,
    applied_diffs: Vec<ChatAppliedDiff>,
) -> ChatEvent {
    ChatEvent {
        run_id: run_id.into(),
        thread_id: None,
        phase: projection_phase(&projection.status).into(),
        text: projection.text,
        prompt_accepted: projection.prompt_accepted,
        turn_started: projection.turn_started,
        routing_stage: projection.routing_stage,
        prompt_storage_notice: projection.prompt_storage_notice,
        failure_reason: crate::chat_view::failure_reason(&projection.status),
        receipt: projection.receipt,
        tool_activity: chat_tool_activity(&projection.tool_activity),
        attachments: chat_attachments(&projection.attachments),
        recalls: projection.recalls,
        applied_diffs,
        pending_permission: chat_pending_permission(projection.pending_permission, code_diff),
        delta: None,
    }
}

#[allow(clippy::result_unit_err, clippy::too_many_arguments)]
pub fn append_emit(
    sink: &impl ChatEventSink,
    storage: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    kind: &str,
    payload: Value,
    subject: Option<&str>,
) -> Result<(), ()> {
    append_emit_detailed(
        sink, storage, projector, run_id, seq, kind, payload, subject,
    )
    .map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_emit_detailed(
    sink: &impl ChatEventSink,
    storage: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    kind: &str,
    payload: Value,
    subject: Option<&str>,
) -> Result<(), String> {
    *seq += 1;
    let envelope = event_envelope(sink, run_id, *seq, kind, payload, subject);
    let event = {
        let mut storage = storage
            .lock()
            .map_err(|error| format!("Journal lock failed: {error}"))?;
        let text_start = projector.text_utf16_len();
        append_run_event_in_place(&mut storage.journal, projector, &envelope)
            .map_err(|error| format!("Journal append failed: {error:?}"))?;
        let generation = subscription_generation();
        match text_delta(projector, &envelope, text_start, generation) {
            Some(event) => event,
            None => {
                let projection = projector.projection().map_err(|error| {
                    format!(
                        "Journal append failed: {:?}",
                        crate::journal::run_append::RunAppendError::Projection(error)
                    )
                })?;
                let gate = projection.pending_permission.clone();
                let ChatStorage { journal, cas } = &mut *storage;
                let code_diff = load_pending_code_diff_cached(
                    journal,
                    cas,
                    run_id,
                    &gate,
                    &mut projector.code_diffs,
                );
                let applied_diffs = load_applied_code_diffs_cached(
                    journal,
                    cas,
                    run_id,
                    projection.applied_diffs.clone(),
                    &mut projector.code_diffs,
                );
                projector.delivery.delivered_snapshot(generation);
                chat_event(run_id, projection, code_diff, applied_diffs)
            }
        }
    };
    sink.deliver(event)
        .map_err(|()| "The shell event sink rejected the projection.".into())
}

/// Builds the text delta for an appended `model.stream.delta` event when
/// every subscriber already holds the run's whole state.
pub(crate) fn text_delta(
    projector: &ChatProjector,
    envelope: &EventEnvelope,
    text_start: usize,
    generation: u64,
) -> Option<ChatEvent> {
    if envelope.event_type != "model.stream.delta" || !projector.delivery.allows_delta(generation) {
        return None;
    }
    let EventPayload::Inline { payload_json } = &envelope.payload else {
        return None;
    };
    let text = payload_json.get("text").and_then(Value::as_str)?;
    Some(ChatEvent {
        run_id: envelope.run_id.clone(),
        thread_id: None,
        phase: projection_phase(&projector.status().cloned()).into(),
        text: text.to_owned(),
        prompt_accepted: false,
        turn_started: false,
        routing_stage: None,
        prompt_storage_notice: None,
        failure_reason: None,
        receipt: None,
        tool_activity: Vec::new(),
        attachments: Vec::new(),
        recalls: Vec::new(),
        applied_diffs: Vec::new(),
        pending_permission: None,
        delta: Some(ChatTextDelta {
            text_start,
            generation,
        }),
    })
}

#[allow(clippy::result_unit_err, clippy::too_many_arguments)]
pub fn append_terminal(
    sink: &impl ChatEventSink,
    storage: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    open_effects: &mut BTreeSet<String>,
    kind: &str,
    payload: Value,
    subject: Option<&str>,
) -> Result<(), ()> {
    if kind == "run.cancelled" {
        if let Some(gate) = projector.projection().map_err(|_| ())?.pending_permission {
            append_emit(
                sink,
                storage,
                projector,
                run_id,
                seq,
                "permission.resolved",
                json!({"gate_id": gate.gate_id, "decision": {"type": "cancelled"}}),
                subject,
            )?;
        }
    }
    close_open_effects(open_effects, |kind, payload| {
        append_emit(
            sink, storage, projector, run_id, seq, kind, payload, subject,
        )
    })?;
    append_emit(
        sink, storage, projector, run_id, seq, kind, payload, subject,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fail_with_open_effects(
    sink: &impl ChatEventSink,
    storage: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    open_effects: &mut BTreeSet<String>,
    reason: &str,
    subject: Option<&str>,
) {
    let _ = append_terminal(
        sink,
        storage,
        projector,
        run_id,
        seq,
        open_effects,
        "run.failed",
        json!({"reason": reason}),
        subject,
    );
}

pub fn fail(
    sink: &impl ChatEventSink,
    storage: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    reason: &str,
    subject: Option<&str>,
) {
    let partial = projector
        .projection()
        .is_ok_and(|projection| !projection.text.trim().is_empty());
    let reason = if partial
        && matches!(
            reason,
            "The reply could not be started." | "The reply did not start. Try again."
        ) {
        "The reply stopped before it finished."
    } else {
        reason
    };
    let _ = append_emit(
        sink,
        storage,
        projector,
        run_id,
        seq,
        "run.failed",
        json!({"reason": reason}),
        subject,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn fail_start(
    sink: &impl ChatEventSink,
    storage: &SharedStorage,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: &mut u64,
    reason: &str,
    subject: Option<&str>,
    resuming: bool,
) {
    if !resuming {
        fail(sink, storage, projector, run_id, seq, reason, subject);
    }
}

pub(crate) fn event_envelope(
    sink: &impl ChatEventSink,
    run_id: &str,
    run_seq: u64,
    kind: &str,
    payload: Value,
    subject: Option<&str>,
) -> EventEnvelope {
    let (source, source_version) = sink.provenance();
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq,
        event_type: kind.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: payload,
        },
        provenance: Provenance {
            source: source.into(),
            source_version: source_version.into(),
            actor_id: subject.map(str::to_owned),
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::journal::reducer::ChatProjection;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<ChatEvent>>,
    }

    impl ChatEventSink for RecordingSink {
        fn provenance(&self) -> (&str, &str) {
            ("test", "0.0.0")
        }

        fn deliver(&self, event: ChatEvent) -> Result<(), ()> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn storage() -> SharedStorage {
        let root = std::env::temp_dir().join(format!("muniment-run-events-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        Arc::new(Mutex::new(ChatStorage {
            journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
            cas: LocalCas::open(&root.join("cas")).unwrap(),
        }))
    }

    #[test]
    fn append_emit_appends_reduces_and_delivers_the_projection() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();

        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            Some("actor-1"),
        )
        .unwrap();

        assert_eq!(seq, 1);
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].run_id, run_id);
        assert!(events[0].thread_id.is_none());
        assert_eq!(events[0].phase, "thinking");
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert_eq!(stored[0].provenance.actor_id.as_deref(), Some("actor-1"));
    }

    #[test]
    fn detailed_append_keeps_journal_conflicts_and_sink_failures_distinct() {
        struct RejectingSink;
        impl ChatEventSink for RejectingSink {
            fn provenance(&self) -> (&str, &str) {
                ("test", "1")
            }
            fn deliver(&self, _: ChatEvent) -> Result<(), ()> {
                Err(())
            }
        }
        let storage = storage();
        let run_id = Uuid::now_v7().to_string();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let error = append_emit_detailed(
            &RejectingSink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            None,
        )
        .unwrap_err();
        assert_eq!(error, "The shell event sink rejected the projection.");
        assert_eq!(
            storage
                .lock()
                .unwrap()
                .journal
                .events(&run_id)
                .unwrap()
                .len(),
            1
        );
        let error = append_emit_detailed(
            &RecordingSink::default(),
            &storage,
            &mut ChatProjector::new(),
            &run_id,
            &mut 0,
            "run.started",
            json!({}),
            None,
        )
        .unwrap_err();
        assert!(error.contains("Append(Conflict("), "{error}");
    }

    #[test]
    fn append_terminal_closes_open_effects_before_the_terminal_event() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();
        let mut open_effects = BTreeSet::from(["tool-1".to_owned()]);

        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            None,
        )
        .unwrap();
        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "tool.effect.started",
            json!({"effect_id": "tool-1", "display_name": "Read file"}),
            None,
        )
        .unwrap();

        append_terminal(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            &mut open_effects,
            "run.failed",
            json!({"reason": "failed"}),
            None,
        )
        .unwrap();

        assert!(open_effects.is_empty());
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert_eq!(stored[2].event_type, "tool.effect.failed");
        assert_eq!(stored[3].event_type, "run.failed");
        assert_eq!(sink.events.lock().unwrap().len(), 4);
    }

    #[test]
    fn cancellation_resolves_an_unanswered_question_before_closing_its_tool() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();
        let mut effects = BTreeSet::from(["question-tool".to_owned()]);
        let question = crate::sidecar::pi_chat::ExtensionUiRequest {
            id: "question-1".into(),
            dialog: crate::sidecar::pi_chat::ExtensionUiDialog::Editor {
                title: "muniment:ask_user_question".into(),
                prefill: Some("{}".into()),
            },
            timeout: None,
        };
        for (kind, payload) in [
            ("run.started", json!({})),
            ("tool.effect.started", json!({"effect_id": "question-tool"})),
            (
                "permission.requested",
                crate::journal::pi_translation::permission_journal_payload(&question),
            ),
        ] {
            append_emit(
                &sink,
                &storage,
                &mut projector,
                &run_id,
                &mut seq,
                kind,
                payload,
                None,
            )
            .unwrap();
        }
        append_terminal(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            &mut effects,
            "run.cancelled",
            json!({}),
            None,
        )
        .unwrap();
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert_eq!(stored[3].event_type, "permission.resolved");
        assert_eq!(stored[4].event_type, "tool.effect.failed");
        assert_eq!(stored[5].event_type, "run.cancelled");
        let projection = projector.projection().unwrap();
        assert!(projection.pending_permission.is_none());
        assert_eq!(projection_phase(&projection.status), "cancelled");
    }

    #[test]
    fn fail_appends_and_delivers_the_failed_event() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();

        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            None,
        )
        .unwrap();
        fail(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "failed",
            None,
        );

        assert_eq!(seq, 2);
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        let kinds: Vec<_> = stored
            .iter()
            .map(|event| event.event_type.as_str())
            .collect();
        assert_eq!(kinds, ["run.started", "run.failed"]);
        let events = sink.events.lock().unwrap();
        let phases: Vec<_> = events.iter().map(|event| event.phase.as_str()).collect();
        assert_eq!(phases, ["thinking", "failed"]);
    }

    #[test]
    fn first_event_timeout_reaches_the_shell_and_the_failed_reply_record() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();
        let reason = "No reply arrived within 30 seconds. Try again.";
        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            None,
        )
        .unwrap();
        fail(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            reason,
            None,
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.last().unwrap().phase, "failed");
        assert_eq!(events.last().unwrap().text, "");
        assert_eq!(
            events.last().unwrap().failure_reason.as_deref(),
            Some(reason)
        );
        let payload = serde_json::to_value(events.last().unwrap()).unwrap();
        assert_eq!(payload["failureReason"], reason);
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert_eq!(stored.last().unwrap().event_type, "run.failed");
        let (projection, _) = crate::journal::reducer::project_chat_with_state(&stored).unwrap();
        assert_eq!(
            projection.status,
            Some(crate::journal::reducer::RunStatus::Failed {
                reason: Some(reason.into()),
            })
        );
        assert_eq!(
            crate::chat_view::failure_reason(&projection.status).as_deref(),
            Some(reason)
        );
        let mut partial = projection;
        partial.text = "partial reply".into();
        let event = chat_event(&run_id, partial, None, Vec::new());
        assert_eq!(event.text, "partial reply");
        assert_eq!(event.failure_reason.as_deref(), Some(reason));
        assert_eq!(crate::chat_view::failure_reason(&None), None);

        #[cfg(feature = "keyring")]
        {
            crate::chat_prompt::use_mock_keyring_for_tests();
            let root = std::env::temp_dir();
            let history = crate::thread_history::project_history_entry(
                &mut storage.lock().unwrap().journal,
                None,
                run_id,
                None,
                &root,
            )
            .unwrap();
            assert_eq!(history.text, "");
            let payload = serde_json::to_value(history).unwrap();
            assert_eq!(payload["failureReason"], reason);
        }
    }

    #[test]
    fn fail_with_open_effects_closes_effects_before_failure() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();
        let mut open_effects = BTreeSet::from(["tool-1".to_owned()]);

        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            None,
        )
        .unwrap();
        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "tool.effect.started",
            json!({"effect_id": "tool-1", "display_name": "Read file"}),
            None,
        )
        .unwrap();

        fail_with_open_effects(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            &mut open_effects,
            "failed",
            None,
        );

        assert_eq!(seq, 4);
        assert!(open_effects.is_empty());
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        let kinds: Vec<_> = stored
            .iter()
            .map(|event| event.event_type.as_str())
            .collect();
        assert_eq!(
            kinds,
            [
                "run.started",
                "tool.effect.started",
                "tool.effect.failed",
                "run.failed"
            ]
        );
        let events = sink.events.lock().unwrap();
        let phases: Vec<_> = events.iter().map(|event| event.phase.as_str()).collect();
        assert_eq!(phases, ["thinking", "thinking", "thinking", "failed"]);
        assert_eq!(events[2].tool_activity[0].status, "failed");
    }

    #[test]
    fn fail_start_fails_new_runs() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();

        append_emit(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
            None,
        )
        .unwrap();
        fail_start(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "failed",
            None,
            false,
        );

        assert_eq!(seq, 2);
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        let kinds: Vec<_> = stored
            .iter()
            .map(|event| event.event_type.as_str())
            .collect();
        assert_eq!(kinds, ["run.started", "run.failed"]);
        let events = sink.events.lock().unwrap();
        let phases: Vec<_> = events.iter().map(|event| event.phase.as_str()).collect();
        assert_eq!(phases, ["thinking", "failed"]);
    }

    #[test]
    fn fail_start_skips_resumed_runs() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 4;
        let run_id = Uuid::now_v7().to_string();

        fail_start(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "failed",
            None,
            true,
        );

        assert_eq!(seq, 4);
        assert!(sink.events.lock().unwrap().is_empty());
        assert!(storage
            .lock()
            .unwrap()
            .journal
            .events(&run_id)
            .unwrap()
            .is_empty());
    }

    fn stream(
        sink: &RecordingSink,
        storage: &SharedStorage,
        projector: &mut ChatProjector,
        run_id: &str,
        seq: &mut u64,
        kind: &str,
        payload: Value,
    ) {
        append_emit(sink, storage, projector, run_id, seq, kind, payload, None).unwrap();
    }

    /// Runs `scenario` until no other test starts a subscription during it,
    /// because a new subscription turns the next delta into a whole state.
    fn without_new_subscriptions<T>(mut scenario: impl FnMut() -> T) -> T {
        loop {
            let before = subscription_generation();
            let result = scenario();
            if subscription_generation() == before {
                return result;
            }
        }
    }

    #[test]
    fn a_text_event_after_a_whole_state_carries_only_the_appended_text() {
        let (sink, projector, run_id) = without_new_subscriptions(|| {
            let sink = RecordingSink::default();
            let storage = storage();
            let mut projector = ChatProjector::new();
            let mut seq = 0;
            let run_id = Uuid::now_v7().to_string();
            for (kind, payload) in [
                ("run.started", json!({})),
                (
                    "tool.effect.started",
                    json!({"effect_id": "tool-1", "input": "ls"}),
                ),
                ("model.stream.delta", json!({"text": "héllo"})),
                ("model.stream.delta", json!({"text": " wörld"})),
            ] {
                stream(
                    &sink,
                    &storage,
                    &mut projector,
                    &run_id,
                    &mut seq,
                    kind,
                    payload,
                );
            }
            (sink, projector, run_id)
        });

        let events = sink.events.lock().unwrap();
        assert!(events[..2].iter().all(|event| event.delta.is_none()));
        let first = &events[2];
        assert_eq!(first.text, "héllo");
        assert_eq!(first.delta.as_ref().unwrap().text_start, 0);
        let second = serde_json::to_value(&events[3]).unwrap();
        assert_eq!(
            second,
            json!({"runId": run_id, "phase": "streaming", "text": " wörld", "textStart": 5})
        );
        assert_eq!(projector.projection().unwrap().text, "héllo wörld");
    }

    #[test]
    fn a_new_subscription_gets_a_whole_state_before_any_delta() {
        let (sink, storage, mut projector, mut seq, run_id) = without_new_subscriptions(|| {
            let sink = RecordingSink::default();
            let storage = storage();
            let mut projector = ChatProjector::new();
            let mut seq = 0;
            let run_id = Uuid::now_v7().to_string();
            stream(
                &sink,
                &storage,
                &mut projector,
                &run_id,
                &mut seq,
                "run.started",
                json!({}),
            );
            stream(
                &sink,
                &storage,
                &mut projector,
                &run_id,
                &mut seq,
                "model.stream.delta",
                json!({"text": "one"}),
            );
            (sink, storage, projector, seq, run_id)
        });
        let stale = sink.events.lock().unwrap().last().cloned().unwrap();
        assert!(stale.delta.is_some());

        let (sender, receiver) = std::sync::mpsc::channel();
        let subscription = ChatEventSubscription::detached(receiver);
        stream(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "model.stream.delta",
            json!({"text": " two"}),
        );
        let whole = sink.events.lock().unwrap().last().cloned().unwrap();
        assert!(whole.delta.is_none());
        assert_eq!(whole.text, "one two");

        // A delta built before the subscription started never reaches it.
        sender.send(stale).unwrap();
        sender.send(whole).unwrap();
        assert_eq!(subscription.try_recv().unwrap().text, "one two");
        assert!(subscription.try_recv().is_err());
    }

    #[test]
    fn a_text_stream_sends_its_whole_state_again_after_the_snapshot_interval() {
        let sink = RecordingSink::default();
        let storage = storage();
        let mut projector = ChatProjector::new();
        let mut seq = 0;
        let run_id = Uuid::now_v7().to_string();
        stream(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "run.started",
            json!({}),
        );
        let generation = projector.delivery.snapshot.unwrap().0;
        projector.delivery.snapshot = Some((
            generation,
            Instant::now().checked_sub(CHAT_SNAPSHOT_INTERVAL).unwrap(),
        ));
        stream(
            &sink,
            &storage,
            &mut projector,
            &run_id,
            &mut seq,
            "model.stream.delta",
            json!({"text": "late"}),
        );
        assert!(sink.events.lock().unwrap().last().unwrap().delta.is_none());
    }

    #[test]
    fn chat_event_leaves_thread_id_absent() {
        let event = chat_event("run-1", ChatProjection::default(), None, Vec::new());
        assert!(event.thread_id.is_none());
        let value = serde_json::to_value(&event).unwrap();
        assert!(value.get("threadId").is_none());
        assert_eq!(value["runId"], "run-1");
    }

    #[test]
    fn chat_event_serializes_present_thread_id() {
        let mut event = chat_event("run-1", ChatProjection::default(), None, Vec::new());
        event.thread_id = Some("thread-1".into());
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["threadId"], "thread-1");
    }
}
