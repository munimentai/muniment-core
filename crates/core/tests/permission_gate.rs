use muniment_core::journal::reducer::{project_chat, ChatProjector, RunStatus};
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::permission_gate::{
    coordinate_extension_ui_request, coordinate_permission_answer, ChatPermissionAnswer,
    PendingPermissionAnswer,
};
use muniment_core::sidecar::pi_chat::{
    ExtensionUiAnswer, ExtensionUiDialog, ExtensionUiRequest, PiChatEvent,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

fn event_envelope(run_id: &str, run_seq: u64, kind: &str, payload: Value) -> EventEnvelope {
    EventEnvelope {
        event_id: format!("0190a100-0000-7000-8000-{run_seq:012}"),
        run_id: run_id.into(),
        run_seq,
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

fn select_gate(gate_id: &str) -> ExtensionUiRequest {
    ExtensionUiRequest {
        id: gate_id.into(),
        dialog: ExtensionUiDialog::Select {
            title: "Choose".into(),
            options: vec!["A".into(), "B".into()],
        },
        timeout: None,
    }
}

#[test]
fn extension_ui_requests_journal_the_gate_before_the_projector_accepts_it() {
    let directory =
        std::env::temp_dir().join(format!("muniment-permission-gate-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&directory).unwrap();
    let mut journal = RunJournal::open(directory.join("runs.sqlite3")).unwrap();
    let run_id = Uuid::now_v7().to_string();
    journal
        .append(0, &event_envelope(&run_id, 1, "run.started", json!({})))
        .unwrap();
    let mut projector = ChatProjector::new();
    projector
        .apply(&journal.events(&run_id).unwrap()[0])
        .unwrap();
    let mut gates = Vec::new();
    let mut pending = None;

    coordinate_extension_ui_request(
        PiChatEvent::ExtensionUiRequest(ExtensionUiRequest {
            id: "pi-request-1".into(),
            dialog: ExtensionUiDialog::Confirm {
                title: "Allow?".into(),
                message: "Proceed?".into(),
            },
            timeout: Some(5_000),
        }),
        &mut pending,
        |kind, payload| {
            let envelope = event_envelope(&run_id, 2, kind, payload);
            journal.append(1, &envelope).map_err(|_| ())?;
            assert_eq!(journal.events(&run_id).unwrap().len(), 2);
            projector.apply(&envelope).map_err(|_| ())?;
            gates.push(projector.projection().map_err(|_| ())?.pending_permission);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        journal.events(&run_id).unwrap()[1].event_type,
        "permission.requested"
    );
    assert_eq!(gates.pop().unwrap().unwrap().gate_id, "pi-request-1");
    assert_eq!(pending.as_ref().unwrap().id, "pi-request-1");

    let mut append_attempts = 0;
    assert!(coordinate_extension_ui_request(
        PiChatEvent::ExtensionUiRequest(ExtensionUiRequest {
            id: "pi-request-2".into(),
            dialog: ExtensionUiDialog::Input {
                title: "Secret".into(),
                placeholder: None,
            },
            timeout: None,
        }),
        &mut pending,
        |_kind, _payload| {
            append_attempts += 1;
            Err(())
        },
    )
    .is_err());
    assert_eq!(append_attempts, 1);

    let mut appended_after_projection_failure = false;
    assert!(coordinate_extension_ui_request(
        PiChatEvent::ExtensionUiRequest(select_gate("pi-request-3")),
        &mut pending,
        |kind, payload| {
            let envelope = event_envelope(&run_id, 3, kind, payload);
            let mut next_projector = projector.clone();
            next_projector.apply(&envelope).map_err(|_| ())?;
            next_projector.projection().map_err(|_| ())?;
            journal.append(2, &envelope).map_err(|_| ())?;
            appended_after_projection_failure = true;
            Ok(())
        },
    )
    .is_err());
    assert!(!appended_after_projection_failure);
    // A failed append leaves the first gate open. The coordinator has no
    // response transport here and therefore cannot answer the new request.
    assert_eq!(pending.as_ref().unwrap().id, "pi-request-1");
    let events = journal.events(&run_id).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_type, "run.started");
    assert_eq!(events[1].event_type, "permission.requested");
    let replayed = project_chat(&events).unwrap();
    assert_eq!(replayed.pending_permission.unwrap().gate_id, "pi-request-1");
    assert!(matches!(
        replayed.status,
        Some(RunStatus::PendingPermission(_))
    ));

    drop(journal);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn other_events_leave_the_gate_untouched() {
    let mut pending = None;
    let mut appended = Vec::new();
    coordinate_extension_ui_request(
        PiChatEvent::PromptAccepted,
        &mut pending,
        |kind, payload| {
            appended.push((kind.to_string(), payload));
            Ok(())
        },
    )
    .unwrap();
    assert!(pending.is_none());
    assert!(appended.is_empty());
}

#[test]
fn permission_answers_resolve_only_for_a_matching_gate_and_a_valid_shape() {
    let request = select_gate("gate-1");
    let mut pending = Some(request.clone());
    let mut sent = Vec::new();
    let mut appended = Vec::new();

    // The pending request no longer matches this answer. The gate drops the
    // answer and tells the caller that nothing was committed.
    let (stale_sender, stale_resolved) = std::sync::mpsc::sync_channel(1);
    coordinate_permission_answer(
        &mut pending,
        PendingPermissionAnswer {
            gate_id: "other-gate".into(),
            answer: ChatPermissionAnswer::Select("A".into()),
            resolved: Some(stale_sender),
        },
        |_, answer| {
            sent.push(answer);
            Ok(())
        },
        |kind, payload| {
            appended.push((kind.to_string(), payload));
            Ok(1)
        },
    )
    .unwrap();
    assert_eq!(stale_resolved.recv().unwrap(), None);
    assert!(sent.is_empty());
    assert!(appended.is_empty());
    assert_eq!(pending, Some(request.clone()));

    // "C" is not one of the offered options, so the gate rejects the shape.
    let (rejected_sender, rejected_resolved) = std::sync::mpsc::sync_channel(1);
    coordinate_permission_answer(
        &mut pending,
        PendingPermissionAnswer {
            gate_id: "gate-1".into(),
            answer: ChatPermissionAnswer::Select("C".into()),
            resolved: Some(rejected_sender),
        },
        |_, answer| {
            sent.push(answer);
            Ok(())
        },
        |kind, payload| {
            appended.push((kind.to_string(), payload));
            Ok(1)
        },
    )
    .unwrap();
    assert_eq!(rejected_resolved.recv().unwrap(), None);
    assert!(sent.is_empty());
    assert!(appended.is_empty());
    assert_eq!(pending, Some(request));

    let (matched_sender, matched_resolved) = std::sync::mpsc::sync_channel(1);
    coordinate_permission_answer(
        &mut pending,
        PendingPermissionAnswer {
            gate_id: "gate-1".into(),
            answer: ChatPermissionAnswer::Select("B".into()),
            resolved: Some(matched_sender),
        },
        |_, answer| {
            sent.push(answer);
            Ok(())
        },
        |kind, payload| {
            appended.push((kind.to_string(), payload));
            Ok(7)
        },
    )
    .unwrap();
    assert_eq!(sent, [ExtensionUiAnswer::Selection("B".into())]);
    assert_eq!(
        appended,
        [(
            "permission.resolved".into(),
            json!({
                "gate_id": "gate-1",
                "decision": {"type": "select", "value": "B"}
            }),
        )]
    );
    assert_eq!(matched_resolved.recv().unwrap(), Some(7));
    assert!(pending.is_none());
}

#[test]
fn a_failed_send_leaves_the_gate_open_and_journals_nothing() {
    let request = select_gate("gate-1");
    let mut pending = Some(request.clone());
    let mut appended = Vec::new();
    let (sender, resolved) = std::sync::mpsc::sync_channel(1);

    coordinate_permission_answer(
        &mut pending,
        PendingPermissionAnswer {
            gate_id: "gate-1".into(),
            answer: ChatPermissionAnswer::Select("A".into()),
            resolved: Some(sender),
        },
        |_, _| Err("the sidecar is gone".into()),
        |kind, payload| {
            appended.push((kind.to_string(), payload));
            Ok(1)
        },
    )
    .unwrap();

    assert_eq!(resolved.recv().unwrap(), None);
    assert!(appended.is_empty());
    assert_eq!(pending, Some(request));
}

#[test]
fn a_failed_append_stops_the_run_and_leaves_the_gate_open() {
    let request = select_gate("gate-1");
    let mut pending = Some(request.clone());
    let (sender, resolved) = std::sync::mpsc::sync_channel(1);

    assert!(coordinate_permission_answer(
        &mut pending,
        PendingPermissionAnswer {
            gate_id: "gate-1".into(),
            answer: ChatPermissionAnswer::Select("A".into()),
            resolved: Some(sender),
        },
        |_, _| Ok(()),
        |_, _| Err(()),
    )
    .is_err());

    // The caller waiting on the answer sees a closed channel rather than a
    // committed sequence number.
    assert!(resolved.recv().is_err());
    assert_eq!(pending, Some(request));
}
