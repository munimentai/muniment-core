use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::cas::LocalCas;
use crate::chat_view::{
    chat_attachments, chat_pending_permission, chat_tool_activity, projection_phase,
    ChatAttachment, ChatPendingPermission, ChatToolActivity,
};
use crate::code_diff_journal::load_pending_code_diff;
use crate::journal::pi_translation::close_open_effects;
use crate::journal::reducer::{ChatProjection, ChatProjector, ProjectedRecall};
use crate::journal::run_append::append_run_event;
use crate::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_code_diff::CodeDiff;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatEvent {
    pub run_id: String,
    pub phase: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
    pub tool_activity: Vec<ChatToolActivity>,
    pub attachments: Vec<ChatAttachment>,
    pub recalls: Vec<ProjectedRecall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_permission: Option<ChatPendingPermission>,
}

pub struct ChatStorage {
    pub journal: RunJournal,
    pub cas: LocalCas,
}

pub type SharedStorage = Arc<Mutex<ChatStorage>>;

pub trait ChatEventSink {
    #[allow(clippy::result_unit_err)]
    fn deliver(&self, event: ChatEvent) -> Result<(), ()>;
}

pub fn chat_event(
    run_id: &str,
    projection: ChatProjection,
    code_diff: Option<CodeDiff>,
) -> ChatEvent {
    ChatEvent {
        run_id: run_id.into(),
        phase: projection_phase(&projection.status).into(),
        text: projection.text,
        receipt: projection.receipt,
        tool_activity: chat_tool_activity(&projection.tool_activity),
        attachments: chat_attachments(&projection.attachments),
        recalls: projection.recalls,
        pending_permission: chat_pending_permission(projection.pending_permission, code_diff),
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
    *seq += 1;
    let envelope = event_envelope(run_id, *seq, kind, payload, subject);
    let (projection, code_diff) = {
        let mut storage = storage.lock().map_err(|_| ())?;
        let projection =
            append_run_event(&mut storage.journal, projector, &envelope).map_err(|_| ())?;
        let gate = projection.pending_permission.clone();
        let ChatStorage { journal, cas } = &mut *storage;
        let code_diff = load_pending_code_diff(journal, cas, run_id, &gate);
        (projection, code_diff)
    };
    sink.deliver(chat_event(run_id, projection, code_diff))
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
    run_id: &str,
    run_seq: u64,
    kind: &str,
    payload: Value,
    subject: Option<&str>,
) -> EventEnvelope {
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
            source: "muniment-desktop".into(),
            source_version: env!("CARGO_PKG_VERSION").into(),
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

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<ChatEvent>>,
    }

    impl ChatEventSink for RecordingSink {
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
        assert_eq!(events[0].phase, "thinking");
        let stored = storage.lock().unwrap().journal.events(&run_id).unwrap();
        assert_eq!(stored[0].provenance.actor_id.as_deref(), Some("actor-1"));
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
        assert_eq!(phases, ["thinking", "interrupted", "thinking", "failed"]);
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
}
