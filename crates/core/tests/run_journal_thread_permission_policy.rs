use muniment_core::journal::{
    EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
    ThreadPermissionAnswerSource, ThreadPermissionDecision, ThreadPermissionPolicyDecided,
    ThreadPermissionPolicyRevoked, ThreadPermissionRequestKind, ThreadPermissionResource,
};
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

fn provenance() -> Provenance {
    Provenance {
        source: "test".into(),
        source_version: "1".into(),
        actor_id: None,
        device_id: None,
        rpc_request_id: None,
        capability_versions: None,
        extra: BTreeMap::new(),
    }
}

fn run_started() -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: Uuid::now_v7().to_string(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-02T10:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
        },
        provenance: provenance(),
        extra: BTreeMap::new(),
    }
}

fn journal_path() -> PathBuf {
    std::env::temp_dir().join(format!("muniment-thread-policy-{}.sqlite3", Uuid::new_v4()))
}

fn thread_for(path: &PathBuf, run_id: &str) -> String {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT thread_id FROM run_threads WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn path_decision(policy_id: String) -> ThreadPermissionPolicyDecided {
    ThreadPermissionPolicyDecided {
        policy_id,
        decision: ThreadPermissionDecision::Allow,
        request_kind: ThreadPermissionRequestKind::Path,
        resource: ThreadPermissionResource::Path {
            path: "/workspace/file.txt".into(),
            operation: "write".into(),
        },
        actor: "user-1".into(),
        answer_source: ThreadPermissionAnswerSource::Native,
        gate_id: Some("gate-1".into()),
    }
}

fn command_decision(policy_id: String) -> ThreadPermissionPolicyDecided {
    ThreadPermissionPolicyDecided {
        policy_id,
        decision: ThreadPermissionDecision::Allow,
        request_kind: ThreadPermissionRequestKind::Command,
        resource: ThreadPermissionResource::Command {
            arguments: vec!["git".into(), "status".into()],
            working_directory: "/workspace".into(),
        },
        actor: "user-1".into(),
        answer_source: ThreadPermissionAnswerSource::Native,
        gate_id: Some("gate-2".into()),
    }
}

fn append_decision(
    journal: &mut RunJournal,
    thread_id: &str,
    sequence: u64,
    decision: &ThreadPermissionPolicyDecided,
) {
    journal
        .append_thread_permission_policy_decided(
            sequence,
            thread_id,
            decision,
            "2026-08-02T10:01:00Z",
            &provenance(),
        )
        .unwrap();
}

#[test]
fn codecs_cover_both_resources_and_reject_invalid_payloads() {
    let policy_id = Uuid::now_v7().to_string();
    let path = path_decision(policy_id.clone());
    assert_eq!(
        serde_json::to_value(&path).unwrap(),
        json!({
            "policy_id": policy_id,
            "decision": "allow",
            "request_kind": "path",
            "resource": {"type": "path", "path": "/workspace/file.txt", "operation": "write"},
            "actor": "user-1",
            "answer_source": "native",
            "gate_id": "gate-1"
        })
    );

    let command: ThreadPermissionPolicyDecided = serde_json::from_value(json!({
        "policy_id": Uuid::now_v7().to_string(),
        "decision": "deny",
        "request_kind": "command",
        "resource": {
            "type": "command",
            "arguments": ["git", "status", "--short"],
            "working_directory": "/workspace"
        },
        "actor": "user-2",
        "answer_source": "acp"
    }))
    .unwrap();
    assert!(matches!(
        command.resource,
        ThreadPermissionResource::Command { .. }
    ));

    for invalid in [
        json!({
            "policy_id": Uuid::now_v7().to_string(), "decision": "later",
            "request_kind": "path", "resource": {"type":"path", "path":"/a", "operation":"read"},
            "actor":"user", "answer_source":"native"
        }),
        json!({
            "policy_id": Uuid::now_v7().to_string(), "decision": "allow",
            "request_kind": "network", "resource": {"type":"path", "path":"/a", "operation":"read"},
            "actor":"user", "answer_source":"native"
        }),
        json!({
            "policy_id": Uuid::now_v7().to_string(), "decision": "allow",
            "request_kind": "path", "resource": {"type":"url", "path":"/a", "operation":"read"},
            "actor":"user", "answer_source":"native"
        }),
        json!({
            "policy_id": Uuid::now_v7().to_string(), "decision": "allow",
            "request_kind": "path", "resource": {"type":"path", "path":"/a", "operation":"read"},
            "answer_source":"native"
        }),
    ] {
        assert!(serde_json::from_value::<ThreadPermissionPolicyDecided>(invalid).is_err());
    }
}

#[test]
fn append_checks_thread_tail_and_policy_history_without_partial_writes() {
    let path = journal_path();
    let mut journal = RunJournal::open(&path).unwrap();
    let started = run_started();
    let thread_id = journal.append_new_run("workspace", &started).unwrap();
    let policy_id = Uuid::now_v7().to_string();
    let decided = path_decision(policy_id.clone());
    journal
        .append_thread_permission_policy_decided(
            1,
            &thread_id,
            &decided,
            "2026-08-02T10:01:00Z",
            &provenance(),
        )
        .unwrap();

    let mut conflicting = decided.clone();
    conflicting.decision = ThreadPermissionDecision::Deny;
    assert!(matches!(
        journal.append_thread_permission_policy_decided(
            2,
            &thread_id,
            &conflicting,
            "2026-08-02T10:02:00Z",
            &provenance(),
        ),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 2);

    let unknown_revocation = ThreadPermissionPolicyRevoked {
        policy_id: Uuid::now_v7().to_string(),
        actor: "user-1".into(),
        reason: "No longer needed".into(),
    };
    assert!(matches!(
        journal.append_thread_permission_policy_revoked(
            2,
            &thread_id,
            &unknown_revocation,
            "2026-08-02T10:03:00Z",
            &provenance(),
        ),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 2);

    let revoked = ThreadPermissionPolicyRevoked {
        policy_id,
        actor: "user-1".into(),
        reason: "No longer needed".into(),
    };
    journal
        .append_thread_permission_policy_revoked(
            2,
            &thread_id,
            &revoked,
            "2026-08-02T10:04:00Z",
            &provenance(),
        )
        .unwrap();
    assert!(matches!(
        journal.append_thread_permission_policy_decided(
            2,
            &thread_id,
            &path_decision(Uuid::now_v7().to_string()),
            "2026-08-02T10:05:00Z",
            &provenance(),
        ),
        Err(JournalError::Conflict(_))
    ));
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 3);

    let unknown_thread = Uuid::now_v7().to_string();
    assert!(matches!(
        journal.append_thread_permission_policy_decided(
            0,
            &unknown_thread,
            &path_decision(Uuid::now_v7().to_string()),
            "2026-08-02T10:06:00Z",
            &provenance(),
        ),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(journal.last_thread_seq(&unknown_thread).unwrap(), 0);

    journal
        .append_thread_deleted(3, &thread_id, "2026-08-02T10:07:00Z", &provenance())
        .unwrap();
    assert!(matches!(
        journal.append_thread_permission_policy_decided(
            4,
            &thread_id,
            &path_decision(Uuid::now_v7().to_string()),
            "2026-08-02T10:08:00Z",
            &provenance(),
        ),
        Err(JournalError::InvalidEnvelope(_))
    ));
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 4);
}

#[test]
fn projection_matches_exact_resources_and_latest_active_decision() {
    let path = journal_path();
    let mut journal = RunJournal::open(&path).unwrap();
    let first_run = run_started();
    let thread_id = journal.append_new_run("workspace", &first_run).unwrap();
    let allow = path_decision(Uuid::now_v7().to_string());
    let mut deny = path_decision(Uuid::now_v7().to_string());
    deny.decision = ThreadPermissionDecision::Deny;
    let command = command_decision(Uuid::now_v7().to_string());
    append_decision(&mut journal, &thread_id, 1, &allow);
    append_decision(&mut journal, &thread_id, 2, &deny);
    append_decision(&mut journal, &thread_id, 3, &command);

    let path_resource = allow.resource.clone();
    assert_eq!(
        journal
            .lookup_thread_permission_policy(
                &thread_id,
                &ThreadPermissionRequestKind::Path,
                &path_resource,
            )
            .unwrap(),
        Some(deny.clone())
    );
    assert_eq!(
        journal
            .active_thread_permission_policies(&thread_id)
            .unwrap()
            .len(),
        3
    );

    for near_miss in [
        ThreadPermissionResource::Path {
            path: "/workspace/other.txt".into(),
            operation: "write".into(),
        },
        ThreadPermissionResource::Path {
            path: "/workspace/file.txt".into(),
            operation: "read".into(),
        },
    ] {
        assert!(journal
            .lookup_thread_permission_policy(
                &thread_id,
                &ThreadPermissionRequestKind::Path,
                &near_miss,
            )
            .unwrap()
            .is_none());
    }
    assert!(journal
        .lookup_thread_permission_policy(
            &thread_id,
            &ThreadPermissionRequestKind::Command,
            &path_resource,
        )
        .unwrap()
        .is_none());

    assert_eq!(
        journal
            .lookup_thread_permission_policy(
                &thread_id,
                &ThreadPermissionRequestKind::Command,
                &command.resource,
            )
            .unwrap(),
        Some(command.clone())
    );

    for near_miss in [
        ThreadPermissionResource::Command {
            arguments: vec!["git".into(), "status".into(), "--short".into()],
            working_directory: "/workspace".into(),
        },
        ThreadPermissionResource::Command {
            arguments: vec!["git".into(), "status".into()],
            working_directory: "/other".into(),
        },
    ] {
        assert!(journal
            .lookup_thread_permission_policy(
                &thread_id,
                &ThreadPermissionRequestKind::Command,
                &near_miss,
            )
            .unwrap()
            .is_none());
    }

    let second_run = run_started();
    let foreign_thread = journal.append_new_run("workspace", &second_run).unwrap();
    let foreign = path_decision(Uuid::now_v7().to_string());
    append_decision(&mut journal, &foreign_thread, 1, &foreign);
    assert_eq!(
        journal
            .lookup_thread_permission_policy(
                &thread_id,
                &ThreadPermissionRequestKind::Path,
                &path_resource,
            )
            .unwrap(),
        Some(deny.clone())
    );

    journal
        .append_thread_permission_policy_revoked(
            4,
            &thread_id,
            &ThreadPermissionPolicyRevoked {
                policy_id: allow.policy_id.clone(),
                actor: "user-1".into(),
                reason: "Changed choice".into(),
            },
            "2026-08-02T10:02:00Z",
            &provenance(),
        )
        .unwrap();
    journal
        .append_thread_permission_policy_revoked(
            5,
            &thread_id,
            &ThreadPermissionPolicyRevoked {
                policy_id: deny.policy_id,
                actor: "user-1".into(),
                reason: "Changed choice".into(),
            },
            "2026-08-02T10:03:00Z",
            &provenance(),
        )
        .unwrap();
    assert!(journal
        .lookup_thread_permission_policy(
            &thread_id,
            &ThreadPermissionRequestKind::Path,
            &path_resource,
        )
        .unwrap()
        .is_none());
}

#[test]
fn projection_fails_closed_for_malformed_events_and_ignores_tombstones() {
    let path = journal_path();
    let mut journal = RunJournal::open(&path).unwrap();
    let started = run_started();
    let thread_id = journal.append_new_run("workspace", &started).unwrap();
    append_decision(
        &mut journal,
        &thread_id,
        1,
        &path_decision(Uuid::now_v7().to_string()),
    );
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE thread_events SET envelope_json='{}' WHERE thread_id=?1 AND thread_seq=2",
            [&thread_id],
        )
        .unwrap();
    assert!(matches!(
        journal.active_thread_permission_policies(&thread_id),
        Err(JournalError::Corrupt(_))
    ));

    let tombstone_path = journal_path();
    let mut tombstoned = RunJournal::open(&tombstone_path).unwrap();
    let started = run_started();
    let tombstoned_thread = tombstoned.append_new_run("workspace", &started).unwrap();
    append_decision(
        &mut tombstoned,
        &tombstoned_thread,
        1,
        &path_decision(Uuid::now_v7().to_string()),
    );
    tombstoned
        .append_thread_deleted(2, &tombstoned_thread, "2026-08-02T10:04:00Z", &provenance())
        .unwrap();
    assert!(tombstoned
        .active_thread_permission_policies(&tombstoned_thread)
        .unwrap()
        .is_empty());
}

#[test]
fn append_rejects_mismatched_and_noncanonical_resources() {
    let path = journal_path();
    let mut journal = RunJournal::open(&path).unwrap();
    let started = run_started();
    let thread_id = journal.append_new_run("workspace", &started).unwrap();
    let mut decision = path_decision(Uuid::now_v7().to_string());
    decision.request_kind = ThreadPermissionRequestKind::Command;
    assert!(journal
        .append_thread_permission_policy_decided(
            1,
            &thread_id,
            &decision,
            "2026-08-02T10:01:00Z",
            &provenance(),
        )
        .is_err());
    decision.request_kind = ThreadPermissionRequestKind::Path;
    decision.resource = ThreadPermissionResource::Path {
        path: "relative/file.txt".into(),
        operation: "write".into(),
    };
    assert!(journal
        .append_thread_permission_policy_decided(
            1,
            &thread_id,
            &decision,
            "2026-08-02T10:02:00Z",
            &provenance(),
        )
        .is_err());
    assert_eq!(journal.last_thread_seq(&thread_id).unwrap(), 1);

    drop(journal);
    assert_eq!(thread_for(&path, &started.run_id), thread_id);
    RunJournal::open(&path).unwrap();
}
