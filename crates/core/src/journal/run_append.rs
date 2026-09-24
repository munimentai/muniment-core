use super::reducer::{ChatProjection, ChatProjector, ReduceError};
use super::{EventEnvelope, JournalError, RunJournal};

#[derive(Debug)]
pub enum RunAppendError {
    Apply(ReduceError),
    Projection(ReduceError),
    Append(JournalError),
}

pub fn append_run_event(
    journal: &mut RunJournal,
    projector: &mut ChatProjector,
    envelope: &EventEnvelope,
) -> Result<ChatProjection, RunAppendError> {
    let checkpoint = projector.checkpoint(envelope);
    if let Err(error) = projector.apply(envelope) {
        projector.restore(checkpoint);
        return Err(RunAppendError::Apply(error));
    }
    let projection = match projector.projection() {
        Ok(projection) => projection,
        Err(error) => {
            projector.restore(checkpoint);
            return Err(RunAppendError::Projection(error));
        }
    };
    if let Err(error) = journal.append(envelope.run_seq.saturating_sub(1), envelope) {
        projector.restore(checkpoint);
        return Err(RunAppendError::Append(error));
    }
    Ok(projection)
}

/// Appends one event and advances the projector without copying its
/// projection. A failed apply or append leaves the projector unchanged.
pub fn append_run_event_in_place(
    journal: &mut RunJournal,
    projector: &mut ChatProjector,
    envelope: &EventEnvelope,
) -> Result<(), RunAppendError> {
    let checkpoint = projector.checkpoint(envelope);
    if let Err(error) = projector.apply(envelope) {
        projector.restore(checkpoint);
        return Err(RunAppendError::Apply(error));
    }
    if let Err(error) = journal.append(envelope.run_seq.saturating_sub(1), envelope) {
        projector.restore(checkpoint);
        return Err(RunAppendError::Append(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{EventPayload, Provenance};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::time::Duration;
    use uuid::Uuid;

    fn envelope(run_id: &str, run_seq: u64, event_type: &str, payload: Value) -> EventEnvelope {
        EventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            run_id: run_id.into(),
            run_seq,
            event_type: event_type.into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: "2026-08-05T00:00:00Z".into(),
            occurred_at: Some("2026-08-05T00:00:01Z".into()),
            correlation_id: Some("correlation-1".into()),
            causation_id: Some("causation-1".into()),
            payload: EventPayload::Inline {
                payload_json: payload,
            },
            provenance: Provenance {
                source: "desktop-test".into(),
                source_version: "7".into(),
                actor_id: Some("actor-1".into()),
                device_id: Some("device-1".into()),
                rpc_request_id: Some("request-1".into()),
                capability_versions: None,
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn appends_envelope_and_commits_projection() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let mut projector = ChatProjector::new();
        let event = envelope(
            &Uuid::now_v7().to_string(),
            1,
            "run.started",
            json!({"caller": "payload"}),
        );

        let projection = append_run_event(&mut journal, &mut projector, &event).unwrap();

        let stored = journal.events(&event.run_id).unwrap().remove(0);
        assert_eq!(stored.event_type, event.event_type);
        assert_eq!(stored.payload, event.payload);
        assert_eq!(stored.provenance, event.provenance);
        assert_eq!(stored.run_seq, event.run_seq);
        assert_eq!(projector.projection().unwrap(), projection);
    }

    #[test]
    fn failed_apply_appends_nothing() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let mut projector = ChatProjector::new();
        let event = envelope(
            &Uuid::now_v7().to_string(),
            1,
            "model.stream.delta",
            json!({}),
        );

        assert!(matches!(
            append_run_event(&mut journal, &mut projector, &event),
            Err(RunAppendError::Apply(_))
        ));
        assert!(journal.events(&event.run_id).unwrap().is_empty());
    }

    #[test]
    fn failed_text_append_restores_the_text_and_its_length() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let mut projector = ChatProjector::new();
        for (seq, kind, payload) in [
            (1, "run.started", json!({})),
            (2, "model.routing.stage", json!({"stage": "thinking"})),
            (3, "model.stream.delta", json!({"text": "héllo "})),
        ] {
            append_run_event_in_place(
                &mut journal,
                &mut projector,
                &envelope(&run_id, seq, kind, payload),
            )
            .unwrap();
        }
        let before = projector.projection().unwrap();
        let before_len = projector.text_utf16_len();
        assert_eq!(before_len, 6);

        // A second writer takes run_seq 4, so this append conflicts.
        journal
            .append(
                3,
                &envelope(&run_id, 4, "model.stream.delta", json!({"text": "x"})),
            )
            .unwrap();
        let conflicting = envelope(&run_id, 4, "model.stream.delta", json!({"text": "wörld"}));
        assert!(matches!(
            append_run_event_in_place(&mut journal, &mut projector, &conflicting),
            Err(RunAppendError::Append(_))
        ));
        assert_eq!(projector.projection().unwrap(), before);
        assert_eq!(projector.text_utf16_len(), before_len);
    }

    #[test]
    fn failed_tool_outcome_append_restores_the_running_activity() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let mut projector = ChatProjector::new();
        for (seq, kind, payload) in [
            (1, "run.started", json!({})),
            (
                2,
                "tool.effect.started",
                json!({"effect_id": "effect-1", "input": "ls"}),
            ),
        ] {
            append_run_event_in_place(
                &mut journal,
                &mut projector,
                &envelope(&run_id, seq, kind, payload),
            )
            .unwrap();
        }
        let before = projector.projection().unwrap();
        journal
            .append(
                2,
                &envelope(
                    &run_id,
                    3,
                    "model.routing.stage",
                    json!({"stage": "thinking"}),
                ),
            )
            .unwrap();
        let finished = envelope(
            &run_id,
            3,
            "tool.effect.completed",
            json!({"effect_id": "effect-1", "output": "done"}),
        );
        assert!(matches!(
            append_run_event(&mut journal, &mut projector, &finished),
            Err(RunAppendError::Append(_))
        ));
        assert_eq!(projector.projection().unwrap(), before);
    }

    #[test]
    fn failed_append_leaves_projector_unchanged() {
        let mut journal =
            RunJournal::open_with_busy_timeout(":memory:", Duration::from_secs(60)).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let started = envelope(&run_id, 1, "run.started", json!({}));
        let mut projector = ChatProjector::new();
        projector.apply(&started).unwrap();
        let before = projector.projection().unwrap();
        let event = envelope(&run_id, 2, "model.prompt.accepted", json!({}));

        assert!(matches!(
            append_run_event(&mut journal, &mut projector, &event),
            Err(RunAppendError::Append(_))
        ));
        assert_eq!(projector.projection().unwrap(), before);
        assert!(journal.events(&run_id).unwrap().is_empty());
    }
}
