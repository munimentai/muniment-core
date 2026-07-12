use muniment_core::journal::reducer::{
    project_chat, reduce, AttentionReason, ReduceError, RunReducer, RunStatus, ToolActivity,
    ToolActivityStatus,
};
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const RUN: &str = "0190a100-0000-7000-8000-000000000001";
fn event(seq: u64, kind: &str, payload: Value) -> EventEnvelope {
    EventEnvelope {
        event_id: format!("0190a100-0000-7000-8000-{seq:012}"),
        run_id: RUN.into(),
        run_seq: seq,
        event_type: kind.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-07-10T12:00:00Z".into(),
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
    }
}
fn stream(spec: &[(&str, Value)]) -> Vec<EventEnvelope> {
    spec.iter()
        .enumerate()
        .map(|(i, (k, p))| event(i as u64 + 1, k, p.clone()))
        .collect()
}

#[test]
fn golden_user_visible_states() {
    let cases = [
        (
            vec![("run.started", json!({})), ("run.completed", json!({}))],
            RunStatus::Completed,
        ),
        (
            vec![
                ("run.started", json!({})),
                ("model.stream.delta", json!({"text":"hi"})),
            ],
            RunStatus::Streaming,
        ),
        (
            vec![
                ("run.started", json!({})),
                ("permission.requested", json!({"gate_id":"g1"})),
            ],
            RunStatus::PendingPermission(muniment_core::journal::reducer::PermissionGate {
                gate_id: "g1".into(),
            }),
        ),
        (
            vec![("run.started", json!({})), ("run.cancelled", json!({}))],
            RunStatus::Cancelled,
        ),
        (
            vec![
                ("run.started", json!({})),
                ("run.failed", json!({"reason":"model"})),
            ],
            RunStatus::Failed {
                reason: Some("model".into()),
            },
        ),
    ];
    for (events, expected) in cases {
        assert_eq!(reduce(&stream(&events)).unwrap().status, expected);
    }
}

#[test]
fn permission_gate_must_resolve_exactly_once() {
    let ok = stream(&[
        ("run.started", json!({})),
        ("permission.requested", json!({"gate_id":"g"})),
        ("permission.resolved", json!({"gate_id":"g"})),
    ]);
    assert_eq!(reduce(&ok).unwrap().status, RunStatus::Active);
    for bad in [
        stream(&[
            ("run.started", json!({})),
            ("permission.resolved", json!({"gate_id":"g"})),
        ]),
        stream(&[
            ("run.started", json!({})),
            ("permission.requested", json!({"gate_id":"g"})),
            ("permission.resolved", json!({"gate_id":"other"})),
        ]),
    ] {
        assert!(matches!(
            reduce(&bad),
            Err(ReduceError::InvalidTransition { .. })
        ));
    }
}

#[test]
fn every_effect_crash_boundary_is_safe() {
    let requested = stream(&[
        ("run.started", json!({})),
        ("tool.requested", json!({"effect_id":"e"})),
    ]);
    assert_eq!(reduce(&requested).unwrap().status, RunStatus::Active);
    let started = stream(&[
        ("run.started", json!({})),
        ("tool.requested", json!({"effect_id":"e"})),
        ("tool.effect.started", json!({"effect_id":"e"})),
    ]);
    assert_eq!(
        reduce(&started).unwrap().status,
        RunStatus::NeedsAttention(AttentionReason::UnknownEffectOutcome {
            effect_id: "e".into()
        })
    );
    for outcome in ["tool.effect.completed", "tool.effect.failed"] {
        let events = stream(&[
            ("run.started", json!({})),
            ("tool.effect.started", json!({"effect_id":"e"})),
            (outcome, json!({"effect_id":"e"})),
        ]);
        assert_eq!(reduce(&events).unwrap().status, RunStatus::Active);
    }
}

#[test]
fn concurrent_effects_can_finish_in_any_order() {
    let events = stream(&[
        ("run.started", json!({})),
        ("tool.effect.started", json!({"effect_id":"A"})),
        ("tool.effect.started", json!({"effect_id":"B"})),
        ("tool.effect.completed", json!({"effect_id":"B"})),
        ("tool.effect.failed", json!({"effect_id":"A"})),
        ("run.completed", json!({})),
    ]);

    assert_eq!(reduce(&events).unwrap().status, RunStatus::Completed);
}

#[test]
fn concurrent_effect_transitions_require_matching_open_effects() {
    let duplicate_start = stream(&[
        ("run.started", json!({})),
        ("tool.effect.started", json!({"effect_id":"A"})),
        ("tool.effect.started", json!({"effect_id":"A"})),
    ]);
    assert!(matches!(
        reduce(&duplicate_start),
        Err(ReduceError::InvalidTransition { .. })
    ));

    let unmatched_outcome = stream(&[
        ("run.started", json!({})),
        ("tool.effect.started", json!({"effect_id":"A"})),
        ("tool.effect.completed", json!({"effect_id":"B"})),
    ]);
    assert!(matches!(
        reduce(&unmatched_outcome),
        Err(ReduceError::InvalidTransition { .. })
    ));
}

#[test]
fn terminal_events_require_all_concurrent_effects_to_close() {
    for (terminal, expected) in [
        ("run.completed", RunStatus::Completed),
        ("run.cancelled", RunStatus::Cancelled),
        ("run.failed", RunStatus::Failed { reason: None }),
    ] {
        let open = stream(&[
            ("run.started", json!({})),
            ("tool.effect.started", json!({"effect_id":"A"})),
            ("tool.effect.started", json!({"effect_id":"B"})),
            ("tool.effect.completed", json!({"effect_id":"B"})),
            (terminal, json!({})),
        ]);
        assert!(matches!(
            reduce(&open),
            Err(ReduceError::InvalidTransition { .. })
        ));

        let closed = stream(&[
            ("run.started", json!({})),
            ("tool.effect.started", json!({"effect_id":"A"})),
            ("tool.effect.started", json!({"effect_id":"B"})),
            ("tool.effect.completed", json!({"effect_id":"B"})),
            ("tool.effect.failed", json!({"effect_id":"A"})),
            (terminal, json!({})),
        ]);
        assert_eq!(reduce(&closed).unwrap().status, expected);
    }
}

#[test]
fn dangling_concurrent_effects_report_the_earliest_start() {
    let events = stream(&[
        ("run.started", json!({})),
        ("tool.effect.started", json!({"effect_id":"first"})),
        ("tool.effect.started", json!({"effect_id":"second"})),
    ]);

    assert_eq!(
        reduce(&events).unwrap().status,
        RunStatus::NeedsAttention(AttentionReason::UnknownEffectOutcome {
            effect_id: "first".into()
        })
    );
}

#[test]
fn recorded_attention_clears_all_concurrent_effects() {
    let events = stream(&[
        ("run.started", json!({})),
        ("tool.effect.started", json!({"effect_id":"A"})),
        ("tool.effect.started", json!({"effect_id":"B"})),
        ("run.needs_attention", json!({"reason":"operator review"})),
    ]);

    assert_eq!(
        reduce(&events).unwrap().status,
        RunStatus::NeedsAttention(AttentionReason::Recorded {
            reason: "operator review".into()
        })
    );
}

#[test]
fn ordering_terminal_and_forward_compatibility_fail_closed() {
    let mut gap = stream(&[("run.started", json!({})), ("future.harmless", json!({}))]);
    gap[1].run_seq = 3;
    assert!(matches!(reduce(&gap), Err(ReduceError::Sequence { .. })));
    let duplicate = vec![
        event(1, "run.started", json!({})),
        event(1, "future.harmless", json!({})),
    ];
    assert!(matches!(
        reduce(&duplicate),
        Err(ReduceError::Sequence { .. })
    ));
    assert_eq!(
        reduce(&stream(&[
            ("run.started", json!({})),
            ("future.harmless", json!({}))
        ]))
        .unwrap()
        .status,
        RunStatus::Active
    );
    let terminal = stream(&[
        ("run.started", json!({})),
        ("run.completed", json!({})),
        ("model.requested", json!({})),
    ]);
    assert!(matches!(
        reduce(&terminal),
        Err(ReduceError::InvalidTransition { .. })
    ));
    for kind in ["permission.future", "tool.effect.future"] {
        assert!(matches!(
            reduce(&stream(&[("run.started", json!({})), (kind, json!({}))])),
            Err(ReduceError::UnsupportedSafetyEvent { .. })
        ));
    }
    let mut version = stream(&[
        ("run.started", json!({})),
        ("permission.requested", json!({"gate_id":"g"})),
    ]);
    version[1].event_version = 2;
    assert!(matches!(
        reduce(&version),
        Err(ReduceError::UnsupportedSafetyEvent { .. })
    ));
}

#[test]
fn incremental_and_full_replay_are_identical() {
    let events = stream(&[
        ("run.started", json!({})),
        ("permission.requested", json!({"gate_id":"g"})),
        ("permission.resolved", json!({"gate_id":"g"})),
        ("tool.effect.started", json!({"effect_id":"e"})),
        ("tool.effect.completed", json!({"effect_id":"e"})),
        ("run.completed", json!({})),
    ]);
    let full = reduce(&events).unwrap();
    let mut incremental = RunReducer::new();
    for event in &events {
        incremental.apply(event).unwrap();
    }
    assert_eq!(incremental.finish().unwrap(), full);
}

#[test]
fn chat_projection_replays_completed_and_failed_runs() {
    let receipt = json!({
        "route": "litellm",
        "model": "openai/gpt-5",
        "cost": "$0.01",
        "time": "1.2s",
        "capabilities": [{"name": "search", "version": "2"}]
    });
    let completed = stream(&[
        ("run.started", json!({})),
        ("model.prompt.accepted", json!({})),
        ("model.stream.delta", json!({"text": "hel"})),
        ("model.stream.delta", json!({"text": "lo"})),
        ("run.completed", json!({"receipt": receipt.clone()})),
    ]);

    let first_replay = project_chat(&completed).unwrap();
    let second_replay = project_chat(&completed).unwrap();
    assert_eq!(first_replay, second_replay);
    assert!(first_replay.prompt_accepted);
    assert_eq!(first_replay.text, "hello");
    assert_eq!(first_replay.receipt, Some(receipt));
    assert_eq!(first_replay.status, Some(RunStatus::Completed));

    let failed = stream(&[
        ("run.started", json!({})),
        ("model.prompt.accepted", json!({})),
        ("model.stream.delta", json!({"text": "partial"})),
        ("run.failed", json!({"reason": "runtime"})),
    ]);
    let projection = project_chat(&failed).unwrap();
    assert_eq!(projection.text, "partial");
    assert_eq!(projection.receipt, None);
    assert_eq!(
        projection.status,
        Some(RunStatus::Failed {
            reason: Some("runtime".into())
        })
    );
}

#[test]
fn chat_projection_tracks_tool_activity_in_start_order() {
    let cases = [
        (
            vec![
                ("run.started", json!({})),
                (
                    "tool.effect.started",
                    json!({"effect_id":"e1", "display_name":"Search"}),
                ),
            ],
            ToolActivityStatus::Running,
        ),
        (
            vec![
                ("run.started", json!({})),
                ("tool.effect.started", json!({"effect_id":"e1"})),
                ("tool.effect.completed", json!({"effect_id":"e1"})),
            ],
            ToolActivityStatus::Completed,
        ),
        (
            vec![
                ("run.started", json!({})),
                ("tool.effect.started", json!({"effect_id":"e1"})),
                ("tool.effect.failed", json!({"effect_id":"e1"})),
            ],
            ToolActivityStatus::Failed,
        ),
    ];
    for (events, status) in cases {
        assert_eq!(
            project_chat(&stream(&events)).unwrap().tool_activity[0].status,
            status
        );
    }

    let interleaved = stream(&[
        ("run.started", json!({})),
        (
            "tool.effect.started",
            json!({"effect_id":"first", "display_name":"Search"}),
        ),
        ("model.stream.delta", json!({"text":"between"})),
        ("tool.effect.completed", json!({"effect_id":"first"})),
        ("tool.effect.started", json!({"effect_id":"second"})),
        ("model.stream.delta", json!({"text":" tools"})),
        ("tool.effect.failed", json!({"effect_id":"second"})),
    ]);
    let projection = project_chat(&interleaved).unwrap();
    assert_eq!(projection.text, "between tools");
    assert_eq!(
        projection.tool_activity,
        vec![
            ToolActivity {
                effect_id: "first".into(),
                display_name: Some("Search".into()),
                status: ToolActivityStatus::Completed,
            },
            ToolActivity {
                effect_id: "second".into(),
                display_name: None,
                status: ToolActivityStatus::Failed,
            },
        ]
    );
}

#[test]
fn persisted_chat_events_exclude_request_secrets() {
    let secrets = [
        "the user's private prompt",
        "sk-virtual-user-key",
        "signed-access-token",
    ];
    let events = stream(&[
        ("run.started", json!({})),
        ("model.prompt.accepted", json!({})),
        ("model.stream.delta", json!({"text": "safe response"})),
        ("run.completed", json!({"receipt": {"route": "litellm"}})),
    ]);

    let persisted = serde_json::to_string(&events).unwrap();
    for secret in secrets {
        assert!(!persisted.contains(secret), "journal leaked {secret}");
    }
    assert_eq!(
        events[1].payload,
        EventPayload::Inline {
            payload_json: json!({})
        }
    );
}

#[test]
fn receipt_projection_preserves_absent_fields_as_unknown() {
    let authoritative = json!({
        "route": "litellm",
        "capabilities": [{"name": "filesystem", "version": "1"}]
    });
    let events = stream(&[
        ("run.started", json!({})),
        ("model.prompt.accepted", json!({})),
        ("run.completed", json!({"receipt": authoritative.clone()})),
    ]);

    let receipt = project_chat(&events).unwrap().receipt.unwrap();
    assert_eq!(receipt, authoritative);
    assert!(receipt.get("model").is_none());
    assert!(receipt.get("cost").is_none());
    assert!(receipt.get("time").is_none());
}
