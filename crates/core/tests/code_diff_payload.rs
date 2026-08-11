#![cfg(feature = "keyring")]

use std::collections::BTreeMap;
use std::fs;

use muniment_code_diff::CodeDiff;
use muniment_core::cas::LocalCas;
use muniment_core::code_diff_journal::{
    append_code_diff_permission_request, load_pending_code_diff, stage_code_diff_proposal,
};
use muniment_core::journal::reducer::{ChatProjector, PermissionGate, PermissionRequest};
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::run_events::chat_event;
use muniment_core::thread_history::project_history_entry;
use muniment_core::write_plan::WritePlan;
use serde_json::{json, Value};
use uuid::Uuid;

struct Fixture {
    root: std::path::PathBuf,
    cas: LocalCas,
    journal: RunJournal,
    run_id: String,
    diff: CodeDiff,
}

#[derive(Clone, Copy, Debug)]
enum MismatchedField {
    EffectId,
    CodeDiffId,
    DiffSha256,
    WritePlanSha256,
}

impl Fixture {
    fn new() -> Self {
        Self::with_mismatch(None)
    }

    fn with_mismatch(mismatch: Option<MismatchedField>) -> Self {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let root =
            std::env::temp_dir().join(format!("muniment-code-diff-payload-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        let cas = LocalCas::open(&root.join("cas")).unwrap();
        let mut journal = RunJournal::open(root.join("journal.sqlite3")).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();
        journal.append(0, &started_event(&run_id)).unwrap();
        let diff = CodeDiff {
            schema_version: 1,
            id: "proposal-1".into(),
            files: vec![],
            truncated: false,
        };
        stage_code_diff_proposal(
            &mut journal,
            &cas,
            &run_id,
            &effect_id,
            &WritePlan::new(vec![]).unwrap(),
            &diff,
        )
        .unwrap();
        if let Some(field) = mismatch {
            let events = journal.events(&run_id).unwrap();
            let EventPayload::Cas {
                payload_cas: plan_cas,
            } = &events[1].payload
            else {
                unreachable!();
            };
            let EventPayload::Cas {
                payload_cas: diff_cas,
            } = &events[2].payload
            else {
                unreachable!();
            };
            let mut gate = PermissionGate {
                gate_id: Uuid::now_v7().to_string(),
                request: PermissionRequest::CodeDiff {
                    effect_id: effect_id.clone(),
                    code_diff_id: diff.id.clone(),
                    diff_sha256: diff_cas.sha256.clone(),
                    write_plan_sha256: plan_cas.sha256.clone(),
                },
            };
            mismatch_gate(&mut gate, field);
            let mut event = started_event(&run_id);
            event.run_seq = 4;
            event.event_type = "permission.requested".into();
            event.payload = EventPayload::Inline {
                payload_json: serde_json::to_value(gate).unwrap(),
            };
            journal.append(3, &event).unwrap();
        } else {
            append_code_diff_permission_request(&mut journal, &cas, &run_id, &effect_id).unwrap();
        }
        Self {
            root,
            cas,
            journal,
            run_id,
            diff,
        }
    }

    fn tamper_diff(&mut self) {
        let events = self.journal.events(&self.run_id).unwrap();
        let EventPayload::Cas { payload_cas } = &events[2].payload else {
            panic!("code diff must use CAS");
        };
        let path = self
            .root
            .join("cas")
            .join("objects")
            .join(&payload_cas.sha256[..2])
            .join(&payload_cas.sha256[2..]);
        fs::write(path, b"tampered").unwrap();
    }
}

fn mismatch_gate(gate: &mut PermissionGate, field: MismatchedField) {
    let PermissionRequest::CodeDiff {
        effect_id,
        code_diff_id,
        diff_sha256,
        write_plan_sha256,
    } = &mut gate.request
    else {
        unreachable!();
    };
    match field {
        MismatchedField::EffectId => *effect_id = "different-effect".into(),
        MismatchedField::CodeDiffId => *code_diff_id = "different-diff".into(),
        MismatchedField::DiffSha256 => *diff_sha256 = "different-diff-hash".into(),
        MismatchedField::WritePlanSha256 => *write_plan_sha256 = "different-plan-hash".into(),
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn started_event(run_id: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-11T00:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
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

fn projection(fixture: &mut Fixture) -> muniment_core::journal::reducer::ChatProjection {
    let mut projector = ChatProjector::new();
    for event in fixture.journal.events(&fixture.run_id).unwrap() {
        projector.apply(&event).unwrap();
    }
    projector.projection().unwrap()
}

#[test]
fn live_and_history_payloads_carry_the_verified_diff() {
    let mut fixture = Fixture::new();
    let projection = projection(&mut fixture);
    let diff = load_pending_code_diff(
        &mut fixture.journal,
        &fixture.cas,
        &fixture.run_id,
        &projection.pending_permission,
    );
    let live = serde_json::to_value(chat_event(&fixture.run_id, projection, diff)).unwrap();
    let history = serde_json::to_value(
        project_history_entry(
            &mut fixture.journal,
            Some(&fixture.cas),
            fixture.run_id.clone(),
            None,
            &fixture.root,
        )
        .unwrap(),
    )
    .unwrap();

    for payload in [&live, &history] {
        assert_eq!(payload["pendingPermission"]["kind"], "code_diff");
        assert_eq!(payload["pendingPermission"]["diff"], json!(fixture.diff));
    }
}

#[test]
fn tampered_diff_keeps_the_history_gate_without_a_diff() {
    let mut fixture = Fixture::new();
    fixture.tamper_diff();

    let history = serde_json::to_value(
        project_history_entry(
            &mut fixture.journal,
            Some(&fixture.cas),
            fixture.run_id.clone(),
            None,
            &fixture.root,
        )
        .unwrap(),
    )
    .unwrap();
    let gate = &history["pendingPermission"];
    assert_eq!(gate["kind"], Value::String("code_diff".into()));
    assert!(gate.get("diff").is_none());
    assert!(matches!(
        project_history_entry(
            &mut fixture.journal,
            None,
            fixture.run_id.clone(),
            None,
            &fixture.root,
        )
        .unwrap()
        .pending_permission
        .unwrap()
        .request,
        PermissionRequest::CodeDiff { .. }
    ));
}

#[test]
fn mismatched_gate_fields_keep_both_payload_gates_without_a_diff() {
    for field in [
        MismatchedField::EffectId,
        MismatchedField::CodeDiffId,
        MismatchedField::DiffSha256,
        MismatchedField::WritePlanSha256,
    ] {
        let mut fixture = Fixture::with_mismatch(Some(field));
        let projection = projection(&mut fixture);
        let diff = load_pending_code_diff(
            &mut fixture.journal,
            &fixture.cas,
            &fixture.run_id,
            &projection.pending_permission,
        );
        let live = serde_json::to_value(chat_event(&fixture.run_id, projection, diff)).unwrap();
        let history = serde_json::to_value(
            project_history_entry(
                &mut fixture.journal,
                Some(&fixture.cas),
                fixture.run_id.clone(),
                None,
                &fixture.root,
            )
            .unwrap(),
        )
        .unwrap();

        for payload in [&live, &history] {
            let gate = &payload["pendingPermission"];
            assert_eq!(gate["kind"], "code_diff", "{field:?}");
            assert!(gate.get("diff").is_none(), "{field:?}");
        }
    }
}
