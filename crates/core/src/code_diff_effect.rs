//! Journaled application of approved code-diff proposals.

use crate::cas::LocalCas;
use crate::code_diff_apply::{apply_workspace_write_plan, ApplyWritePlanError};
use crate::code_diff_journal::{
    verify_code_diff_permission_answer, CodeDiffPermissionAnswer, VerifyCodeDiffPermissionError,
    EVENT_VERSION,
};
use crate::code_diff_observe::{verify_workspace_write_plan, VerifyWritePlanError};
use crate::journal::{
    reducer::{PermissionGate, PermissionRequest},
    EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
};
use chrono::{SecondsFormat, Utc};
use serde_json::json;
use std::{collections::BTreeMap, fmt, path::Path};
use uuid::Uuid;

pub const APPLIED_EVENT_TYPE: &str = "code.diff.applied";

#[derive(Debug)]
pub enum ApplyCodeDiffApprovalError {
    AlreadyResolved,
    RequestNotFound,
    ReadJournal(JournalError),
    Verification(VerifyCodeDiffPermissionError),
    StaleCheck(VerifyWritePlanError),
    ResolutionSequenceOverflow,
    ResolutionJournal(JournalError),
    Apply(ApplyWritePlanError),
    AppliedSequenceOverflow,
    AppliedJournal(JournalError),
}

impl fmt::Display for ApplyCodeDiffApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyResolved => formatter
                .write_str("permission resolution check failed: the gate is already resolved"),
            Self::RequestNotFound => formatter
                .write_str("permission request check failed: the gate request was not found"),
            Self::ReadJournal(error) => {
                write!(formatter, "permission resolution check failed: {error}")
            }
            Self::Verification(error) => {
                write!(formatter, "permission answer verification failed: {error}")
            }
            Self::StaleCheck(error) => write!(formatter, "write plan stale check failed: {error}"),
            Self::ResolutionSequenceOverflow => formatter.write_str(
                "permission resolution append failed: the event sequence exceeds the journal limit",
            ),
            Self::ResolutionJournal(error) => {
                write!(formatter, "permission resolution append failed: {error}")
            }
            Self::Apply(error) => write!(formatter, "write plan apply failed: {error}"),
            Self::AppliedSequenceOverflow => formatter.write_str(
                "applied event append failed: the event sequence exceeds the journal limit",
            ),
            Self::AppliedJournal(error) => {
                write!(formatter, "applied event append failed: {error}")
            }
        }
    }
}

impl std::error::Error for ApplyCodeDiffApprovalError {}

/// Verifies, resolves, and applies one approved code-diff permission gate.
pub fn apply_code_diff_approval(
    journal: &mut RunJournal,
    cas: &LocalCas,
    workspace_root: &Path,
    run_id: &str,
    pending_gate: &PermissionGate,
    answer: CodeDiffPermissionAnswer<'_>,
) -> Result<(), ApplyCodeDiffApprovalError> {
    let events = journal
        .events(run_id)
        .map_err(ApplyCodeDiffApprovalError::ReadJournal)?;
    if events
        .iter()
        .any(|event| resolution_matches(event, &pending_gate.gate_id))
    {
        return Err(ApplyCodeDiffApprovalError::AlreadyResolved);
    }
    let (plan, _) = verify_code_diff_permission_answer(journal, cas, run_id, pending_gate, answer)
        .map_err(ApplyCodeDiffApprovalError::Verification)?;
    let verified = verify_workspace_write_plan(workspace_root, &plan)
        .map_err(ApplyCodeDiffApprovalError::StaleCheck)?;
    let request_event_id = events
        .iter()
        .rev()
        .find(|event| request_matches(event, pending_gate))
        .map(|event| event.event_id.clone())
        .ok_or(ApplyCodeDiffApprovalError::RequestNotFound)?;
    let effect_id = match &pending_gate.request {
        PermissionRequest::CodeDiff { effect_id, .. } => effect_id.as_str(),
        _ => answer.effect_id,
    };

    append_effect_event(
        journal,
        run_id,
        "permission.resolved",
        effect_id,
        &request_event_id,
        json!({
            "gate_id": pending_gate.gate_id,
            "decision": "approved",
            "effect_id": answer.effect_id,
            "code_diff_id": answer.code_diff_id,
            "diff_sha256": answer.diff_sha256,
            "write_plan_sha256": answer.write_plan_sha256,
        }),
        true,
    )?;

    apply_workspace_write_plan(&plan, verified).map_err(ApplyCodeDiffApprovalError::Apply)?;

    append_effect_event(
        journal,
        run_id,
        APPLIED_EVENT_TYPE,
        effect_id,
        &request_event_id,
        json!({"effect_id": effect_id, "code_diff_id": answer.code_diff_id}),
        false,
    )
}

fn resolution_matches(event: &EventEnvelope, gate_id: &str) -> bool {
    event.event_type == "permission.resolved"
        && matches!(&event.payload, EventPayload::Inline { payload_json }
            if payload_json.get("gate_id").and_then(|value| value.as_str()) == Some(gate_id))
}

fn request_matches(event: &EventEnvelope, gate: &PermissionGate) -> bool {
    event.event_type == "permission.requested"
        && matches!(&event.payload, EventPayload::Inline { payload_json }
            if matches!(serde_json::from_value::<PermissionGate>(payload_json.clone()),
                Ok(parsed) if parsed == *gate))
}

fn append_effect_event(
    journal: &mut RunJournal,
    run_id: &str,
    event_type: &str,
    effect_id: &str,
    request_event_id: &str,
    payload_json: serde_json::Value,
    resolution: bool,
) -> Result<(), ApplyCodeDiffApprovalError> {
    let events = journal.events(run_id).map_err(|error| {
        if resolution {
            ApplyCodeDiffApprovalError::ResolutionJournal(error)
        } else {
            ApplyCodeDiffApprovalError::AppliedJournal(error)
        }
    })?;
    if resolution {
        let gate_id = payload_json
            .get("gate_id")
            .and_then(|value| value.as_str())
            .expect("permission resolution payloads carry a gate id");
        if events
            .iter()
            .any(|event| resolution_matches(event, gate_id))
        {
            return Err(ApplyCodeDiffApprovalError::AlreadyResolved);
        }
    }
    let expected_last_seq = events.last().map_or(0, |event| event.run_seq);
    let run_seq = expected_last_seq.checked_add(1).ok_or(if resolution {
        ApplyCodeDiffApprovalError::ResolutionSequenceOverflow
    } else {
        ApplyCodeDiffApprovalError::AppliedSequenceOverflow
    })?;
    let event = EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq,
        event_type: event_type.into(),
        event_version: EVENT_VERSION,
        envelope_version: 1,
        recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        occurred_at: None,
        correlation_id: Some(effect_id.into()),
        causation_id: Some(request_event_id.into()),
        payload: EventPayload::Inline { payload_json },
        provenance: Provenance {
            source: "muniment-desktop".into(),
            source_version: env!("CARGO_PKG_VERSION").into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    };
    journal.append(expected_last_seq, &event).map_err(|error| {
        if resolution {
            ApplyCodeDiffApprovalError::ResolutionJournal(error)
        } else {
            ApplyCodeDiffApprovalError::AppliedJournal(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_diff_journal::{
        append_code_diff_permission_request, compose_code_diff_proposal,
    };
    use crate::code_diff_observe::observe_workspace_write_plan;
    use crate::code_diff_staging::ProposedOperation;
    use crate::journal::reducer::{reduce, RunStatus};
    use std::fs;

    struct TestStore {
        root: std::path::PathBuf,
        workspace: std::path::PathBuf,
        journal: RunJournal,
        cas: LocalCas,
        run_id: String,
        effect_id: String,
    }

    impl TestStore {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("muniment-code-diff-effect-{}", Uuid::now_v7()));
            let workspace = root.join("workspace");
            fs::create_dir_all(&workspace).unwrap();
            let mut journal = RunJournal::open(root.join("runs.sqlite3")).unwrap();
            let cas = LocalCas::open(&root.join("cas")).unwrap();
            let run_id = Uuid::now_v7().to_string();
            let effect_id = Uuid::now_v7().to_string();
            append_effect_event(
                &mut journal,
                &run_id,
                "run.started",
                &effect_id,
                "run-request",
                json!({}),
                false,
            )
            .unwrap();
            Self {
                root,
                workspace,
                journal,
                cas,
                run_id,
                effect_id,
            }
        }

        fn proposal(&mut self) -> PermissionGate {
            let (plan, current) = observe_workspace_write_plan(
                &self.workspace,
                &[ProposedOperation::Write {
                    path: "new.txt".into(),
                    output: b"new\n".to_vec(),
                }],
            )
            .unwrap();
            compose_code_diff_proposal(
                &plan,
                &current,
                &mut self.journal,
                &self.cas,
                &self.run_id,
                &self.effect_id,
            )
            .unwrap();
            append_code_diff_permission_request(
                &mut self.journal,
                &self.cas,
                &self.run_id,
                &self.effect_id,
            )
            .unwrap()
        }

        fn apply(&mut self, gate: &PermissionGate) -> Result<(), ApplyCodeDiffApprovalError> {
            let PermissionRequest::CodeDiff {
                effect_id,
                code_diff_id,
                diff_sha256,
                write_plan_sha256,
            } = &gate.request
            else {
                unreachable!()
            };
            apply_code_diff_approval(
                &mut self.journal,
                &self.cas,
                &self.workspace,
                &self.run_id,
                gate,
                CodeDiffPermissionAnswer {
                    gate_id: &gate.gate_id,
                    effect_id,
                    code_diff_id,
                    diff_sha256,
                    write_plan_sha256,
                },
            )
        }

        fn events(&mut self) -> Vec<EventEnvelope> {
            self.journal.events(&self.run_id).unwrap()
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn applies_and_replays_the_approved_path() {
        let mut store = TestStore::new();
        let gate = store.proposal();
        let request_id = store.events().last().unwrap().event_id.clone();

        store.apply(&gate).unwrap();

        assert_eq!(fs::read(store.workspace.join("new.txt")).unwrap(), b"new\n");
        let events = store.events();
        assert_eq!(events[events.len() - 2].event_type, "permission.resolved");
        let applied = events.last().unwrap();
        assert_eq!(applied.event_type, APPLIED_EVENT_TYPE);
        assert_eq!(
            applied.correlation_id.as_deref(),
            Some(store.effect_id.as_str())
        );
        assert_eq!(applied.causation_id.as_deref(), Some(request_id.as_str()));
        let state = reduce(&events).unwrap();
        assert_eq!(state.status, RunStatus::Active);
        assert!(state.pending_permission.is_none());
    }

    #[test]
    fn refuses_reentry_before_loading_the_proposal() {
        let mut store = TestStore::new();
        let gate = store.proposal();
        store.apply(&gate).unwrap();
        let PermissionRequest::CodeDiff { diff_sha256, .. } = &gate.request else {
            unreachable!()
        };
        store.cas.remove(&diff_sha256.parse().unwrap()).unwrap();

        let error = store.apply(&gate).unwrap_err();

        assert!(matches!(error, ApplyCodeDiffApprovalError::AlreadyResolved));
        assert_eq!(
            store
                .events()
                .iter()
                .filter(|event| event.event_type == APPLIED_EVENT_TYPE)
                .count(),
            1
        );
    }

    #[test]
    fn reports_answer_verification_failure_without_resolution() {
        let mut store = TestStore::new();
        let gate = store.proposal();
        let error = apply_code_diff_approval(
            &mut store.journal,
            &store.cas,
            &store.workspace,
            &store.run_id,
            &gate,
            CodeDiffPermissionAnswer {
                gate_id: "wrong",
                effect_id: &store.effect_id,
                code_diff_id: "wrong",
                diff_sha256: "wrong",
                write_plan_sha256: "wrong",
            },
        )
        .unwrap_err();

        assert!(matches!(error, ApplyCodeDiffApprovalError::Verification(_)));
        assert_no_outcome(&mut store);
    }

    #[test]
    fn reports_stale_check_failure_without_resolution() {
        let mut store = TestStore::new();
        let gate = store.proposal();
        fs::write(store.workspace.join("new.txt"), b"stale").unwrap();

        let error = store.apply(&gate).unwrap_err();

        assert!(matches!(error, ApplyCodeDiffApprovalError::StaleCheck(_)));
        assert_no_outcome(&mut store);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reports_apply_failure_after_resolution_without_applied_event() {
        let mut store = TestStore::new();
        store.workspace = "/sys/kernel".into();
        let (plan, current) = observe_workspace_write_plan(
            &store.workspace,
            &[ProposedOperation::Delete {
                path: "notes".into(),
            }],
        )
        .unwrap();
        compose_code_diff_proposal(
            &plan,
            &current,
            &mut store.journal,
            &store.cas,
            &store.run_id,
            &store.effect_id,
        )
        .unwrap();
        let gate = append_code_diff_permission_request(
            &mut store.journal,
            &store.cas,
            &store.run_id,
            &store.effect_id,
        )
        .unwrap();

        let error = store.apply(&gate).unwrap_err();

        assert!(matches!(error, ApplyCodeDiffApprovalError::Apply(_)));
        let events = store.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "permission.resolved")
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| event.event_type == APPLIED_EVENT_TYPE));
    }

    fn assert_no_outcome(store: &mut TestStore) {
        let events = store.events();
        assert!(!events.iter().any(|event| matches!(
            event.event_type.as_str(),
            "permission.resolved" | APPLIED_EVENT_TYPE
        )));
    }
}
