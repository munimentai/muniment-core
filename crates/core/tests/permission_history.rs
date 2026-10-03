use muniment_core::journal::reducer::{ChatProjector, RunStatus};
use muniment_core::journal::run_append::append_run_event;
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::permission_gate::{
    coordinate_extension_ui_request, coordinate_permission_answer, ChatPermissionAnswer,
    PendingPermissionAnswer,
};
use muniment_core::sidecar::pi_chat::{
    ExtensionUiAnswer, ExtensionUiDialog, ExtensionUiRequest, PiChatEvent,
};
use muniment_core::thread_history::{
    chat_thread_open_page_without_prompts, HistoryEntry, HistoryRuntime,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

struct Fixture {
    journal: RunJournal,
    projector: ChatProjector,
    run: String,
    thread: String,
    seq: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut fixture = Self {
            journal: RunJournal::open(":memory:").unwrap(),
            projector: ChatProjector::new(),
            run: uuid::Uuid::now_v7().to_string(),
            thread: String::new(),
            seq: 0,
        };
        fixture.append("run.started", json!({}));
        fixture.thread = fixture
            .journal
            .run_thread_id(&fixture.run)
            .unwrap()
            .unwrap();
        fixture
    }

    fn append(&mut self, kind: &str, payload: Value) -> u64 {
        let event = EventEnvelope {
            event_id: uuid::Uuid::now_v7().to_string(),
            run_id: self.run.clone(),
            run_seq: self.seq + 1,
            event_type: kind.into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: "2026-08-08T00:00:00Z".into(),
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: payload,
            },
            provenance: Provenance {
                source: "test".into(),
                source_version: "1".into(),
                actor_id: None,
                device_id: None,
                rpc_request_id: None,
                capability_versions: None,
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        };
        if self.seq == 0 {
            self.journal.append_new_run("workspace", &event).unwrap();
            self.projector.apply(&event).unwrap();
        } else {
            append_run_event(&mut self.journal, &mut self.projector, &event).unwrap();
        }
        self.seq += 1;
        self.seq
    }

    fn history(&mut self, active: bool) -> HistoryEntry {
        chat_thread_open_page_without_prompts(
            &mut self.journal,
            None,
            None,
            HistoryRuntime {
                session_root: Path::new("."),
                active_run_id: Some(if active { &self.run } else { "another-run" }),
            },
            &self.thread,
            20,
            None,
        )
        .unwrap()
        .entries
        .remove(0)
    }
}

#[test]
fn approved_mcp_effect_stays_live_until_its_outcome_commits() {
    for outcome in ["tool.effect.completed", "tool.effect.failed"] {
        let mut fixture = Fixture::new();
        fixture.append(
            "tool.effect.started",
            json!({"effect_id": "mcp-1", "display_name": "mcp__acceptance_token"}),
        );
        assert_eq!(fixture.history(true).phase, "thinking");
        let crashed = fixture.history(false);
        assert_eq!(crashed.phase, "interrupted");
        assert_eq!(
            crashed.failure_reason.as_deref(),
            Some("unknown-effect-outcome")
        );
        assert!(!crashed.resumable);

        let mut pending = None;
        coordinate_extension_ui_request(
            PiChatEvent::ExtensionUiRequest(ExtensionUiRequest {
                id: "mcp-gate".into(),
                dialog: ExtensionUiDialog::Select {
                    title: "MCP: acceptance_token".into(),
                    options: vec!["Allow once".into(), "Deny".into()],
                },
                timeout: None,
            }),
            &mut pending,
            &mut VecDeque::new(),
            |kind, payload| {
                fixture.append(kind, payload);
                Ok(())
            },
        )
        .unwrap();
        let gate = fixture.history(true);
        assert_eq!(gate.phase, "pending-permission");
        assert_eq!(gate.pending_permission.unwrap().gate_id, "mcp-gate");

        let (sender, committed) = std::sync::mpsc::sync_channel(1);
        coordinate_permission_answer(
            &mut pending,
            PendingPermissionAnswer {
                gate_id: "mcp-gate".into(),
                answer: ChatPermissionAnswer::Select("Allow once".into()),
                resolved: Some(sender),
            },
            |_, answer| {
                assert_eq!(answer, ExtensionUiAnswer::Selection("Allow once".into()));
                Ok(())
            },
            |kind, payload| Ok(fixture.append(kind, payload)),
        )
        .unwrap();
        assert_eq!(committed.recv().unwrap(), Some(4));
        assert!(pending.is_none());
        let approved = fixture.history(true);
        assert_eq!(approved.phase, "thinking");
        assert!(approved.failure_reason.is_none());
        assert!(approved.pending_permission.is_none());
        assert!(!approved.resumable);
        assert_eq!(approved.tool_activity[0].status, "running");

        fixture.append(
            outcome,
            json!({"effect_id": "mcp-1", "output": "fixture token"}),
        );
        fixture.append("run.completed", json!({}));
        assert_eq!(fixture.projector.status(), Some(&RunStatus::Completed));
        for active in [true, false] {
            let completed = fixture.history(active);
            assert_eq!(completed.phase, "complete");
            assert!(completed.failure_reason.is_none());
            assert_eq!(
                completed.tool_activity[0].status,
                if outcome.ends_with("completed") {
                    "completed"
                } else {
                    "failed"
                }
            );
        }
        let events = fixture.journal.events(&fixture.run).unwrap();
        assert_eq!(events[3].event_type, "permission.resolved");
        assert_eq!(events[4].event_type, outcome);
    }
}

#[test]
fn runtime_ownership_never_hides_a_recorded_terminal_state() {
    for (kind, phase, reason) in [
        ("run.needs_attention", "interrupted", Some("interrupted")),
        (
            "run.needs_attention",
            "interrupted",
            Some("operator review"),
        ),
        ("run.needs_attention", "interrupted", Some("unspecified")),
        ("run.failed", "failed", Some("The provider refused access.")),
        ("run.cancelled", "cancelled", None),
    ] {
        let mut fixture = Fixture::new();
        let payload = if reason == Some("unspecified") {
            json!({})
        } else {
            json!({"reason": reason})
        };
        fixture.append(kind, payload);
        for active in [true, false] {
            let entry = fixture.history(active);
            assert_eq!(entry.phase, phase);
            assert_eq!(entry.failure_reason.as_deref(), reason);
        }
    }
}
