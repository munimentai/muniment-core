use muniment_core::journal::reducer::{
    reduce, AttentionReason, ReduceError, RunReducer, RunStatus,
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
