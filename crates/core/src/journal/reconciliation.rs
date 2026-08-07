use super::reducer::reduce;
use super::{EventEnvelope, EventPayload, Provenance, RunEventType, RunJournal};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::SystemTime;
use uuid::Uuid;

pub fn reconcile_interrupted_runs(journal: &mut RunJournal, provenance: &Provenance) {
    let Ok(event_types) = journal.run_event_types() else {
        return;
    };
    for run in event_types.chunk_by(|left, right| left.run_id == right.run_id) {
        if event_types_are_terminal(run) {
            continue;
        }
        let run_id = &run[0].run_id;
        let Ok(events) = journal.events(run_id) else {
            continue;
        };
        let Ok(state) = reduce(&events) else {
            continue;
        };
        if state.is_terminal() {
            continue;
        }
        let envelope = EventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            run_id: run_id.clone(),
            run_seq: state.last_seq + 1,
            event_type: "run.needs_attention".into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: DateTime::<Utc>::from(SystemTime::now())
                .to_rfc3339_opts(SecondsFormat::AutoSi, true),
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: json!({"reason": "interrupted"}),
            },
            provenance: provenance.clone(),
            extra: BTreeMap::new(),
        };
        let _ = journal.append(state.last_seq, &envelope);
    }
}

fn event_types_are_terminal(events: &[RunEventType]) -> bool {
    let mut terminal = false;
    for (index, event) in events.iter().enumerate() {
        if event.run_seq != index as u64 + 1 {
            return false;
        }
        match event.event_type.as_str() {
            "run.completed" | "run.cancelled" | "run.failed" | "run.needs_attention" => {
                terminal = true;
            }
            "run.started"
            | "run.resumed"
            | "chat.attachment.ingested"
            | "runtime.pi_session.bound"
            | "model.prompt.accepted"
            | "model.stream.delta"
            | "permission.requested"
            | "permission.resolved"
            | "tool.effect.started"
            | "tool.effect.completed"
            | "tool.effect.failed" => terminal = false,
            "user.prompt.submitted"
            | "route.selected"
            | "capability.used"
            | "receipt.finalized" => {}
            _ => return false,
        }
    }
    terminal
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::time::Duration;

    fn provenance() -> Provenance {
        Provenance {
            source: "desktop-test".into(),
            source_version: "7".into(),
            actor_id: Some("actor-1".into()),
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        }
    }

    fn event(run_id: &str, run_seq: u64, event_type: &str, payload: Value) -> EventEnvelope {
        EventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            run_id: run_id.into(),
            run_seq,
            event_type: event_type.into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: "2026-08-04T00:00:00Z".into(),
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: payload,
            },
            provenance: provenance(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn interrupted_run_gets_needs_attention_with_caller_provenance() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let run_id = Uuid::now_v7().to_string();
        journal
            .append(0, &event(&run_id, 1, "run.started", json!({})))
            .unwrap();

        let caller = provenance();
        reconcile_interrupted_runs(&mut journal, &caller);

        let events = journal.events(&run_id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_type, "run.needs_attention");
        assert_eq!(events[1].provenance, caller);
    }

    #[test]
    fn terminal_run_stays_unchanged() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let run_id = Uuid::now_v7().to_string();
        journal
            .append_batch(
                0,
                &[
                    event(&run_id, 1, "run.started", json!({})),
                    event(&run_id, 2, "run.completed", json!({})),
                ],
            )
            .unwrap();

        reconcile_interrupted_runs(&mut journal, &provenance());

        assert_eq!(journal.events(&run_id).unwrap().len(), 2);
    }

    #[test]
    fn event_type_classifier_matches_reducer_for_representative_sequences() {
        let run_id = Uuid::now_v7().to_string();
        let classify = |types: &[&str]| {
            let events: Vec<_> = types
                .iter()
                .enumerate()
                .map(|(index, event_type)| {
                    event(
                        &run_id,
                        index as u64 + 1,
                        event_type,
                        match *event_type {
                            "runtime.pi_session.bound" => {
                                json!({"run_id": run_id, "locator": "session.jsonl"})
                            }
                            _ => json!({}),
                        },
                    )
                })
                .collect();
            let event_types: Vec<_> = events
                .iter()
                .map(|event| RunEventType {
                    run_id: event.run_id.clone(),
                    run_seq: event.run_seq,
                    event_type: event.event_type.clone(),
                })
                .collect();
            assert_eq!(
                event_types_are_terminal(&event_types),
                reduce(&events).unwrap().is_terminal(),
                "{types:?}"
            );
        };

        for types in [
            &["run.started"][..],
            &["run.started", "run.completed"],
            &["run.started", "run.cancelled"],
            &["run.started", "run.failed"],
            &["run.started", "run.needs_attention"],
            &[
                "run.started",
                "run.completed",
                "receipt.finalized",
                "capability.used",
            ],
            &[
                "run.started",
                "runtime.pi_session.bound",
                "run.needs_attention",
                "run.resumed",
                "model.prompt.accepted",
            ],
        ] {
            classify(types);
        }
    }

    #[test]
    fn event_type_classifier_treats_unknown_types_as_candidates() {
        let run_id = Uuid::now_v7().to_string();
        let events = [
            RunEventType {
                run_id: run_id.clone(),
                run_seq: 1,
                event_type: "run.started".into(),
            },
            RunEventType {
                run_id: run_id.clone(),
                run_seq: 2,
                event_type: "run.completed".into(),
            },
            RunEventType {
                run_id,
                run_seq: 3,
                event_type: "run.future_terminal".into(),
            },
        ];

        assert!(!event_types_are_terminal(&events));
    }

    #[test]
    fn event_type_gap_requires_full_reduction() {
        let run_id = Uuid::now_v7().to_string();
        let events = [
            RunEventType {
                run_id: run_id.clone(),
                run_seq: 1,
                event_type: "run.started".into(),
            },
            RunEventType {
                run_id,
                run_seq: 3,
                event_type: "run.completed".into(),
            },
        ];

        assert!(!event_types_are_terminal(&events));
    }

    #[test]
    fn run_that_fails_to_reduce_stays_unchanged() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let run_id = Uuid::now_v7().to_string();
        journal
            .append(0, &event(&run_id, 1, "model.stream.delta", json!({})))
            .unwrap();

        reconcile_interrupted_runs(&mut journal, &provenance());

        assert_eq!(journal.events(&run_id).unwrap().len(), 1);
    }
}
