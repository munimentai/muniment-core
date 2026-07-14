use muniment_core::attach::*;
use serde_json::json;
use std::{cell::Cell, path::PathBuf, rc::Rc};

fn id(n: u128) -> Id {
    Id::new(format!("{n:032x}")).unwrap()
}
fn request(operation: Operation, key: Option<Id>) -> Request {
    Request {
        protocol: Protocol,
        request_id: id(1),
        operation,
        capability: "capability".into(),
        idempotency_key: key,
        body: json!({}),
    }
}
fn path(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "muniment-attach-{name}-{}-{unique}.sqlite",
        std::process::id()
    ))
}

#[test]
fn key_policy_covers_every_operation() {
    let effectful = [
        Operation::RunStart,
        Operation::RunSteer,
        Operation::RunFollowUp,
        Operation::RunCancel,
        Operation::PermissionAnswer,
    ];
    for operation in effectful {
        let error = request(operation, None)
            .validate_idempotency_key()
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::IdempotencyKeyRequired);
        assert!(!error.retryable());
        request(operation, Some(id(2)))
            .validate_idempotency_key()
            .unwrap();
    }
    let non_effectful = [
        Operation::ThreadList,
        Operation::ThreadOpen,
        Operation::RunOpen,
        Operation::RunStream,
        Operation::RunCursorAck,
        Operation::ArtifactFetch,
        Operation::ArtifactWindow,
        Operation::RequestCancel,
    ];
    for operation in non_effectful {
        request(operation, None).validate_idempotency_key().unwrap();
        assert_eq!(
            request(operation, Some(id(2)))
                .validate_idempotency_key()
                .unwrap_err()
                .code(),
            ErrorCode::IdempotencyKeyForbidden
        );
    }
}

#[test]
fn ledger_identity_includes_each_effectful_operation() {
    let path = path("operations");
    let mut store = IdempotencyStore::open(&path).unwrap();
    for (index, operation) in [
        Operation::RunStart,
        Operation::RunSteer,
        Operation::RunFollowUp,
        Operation::RunCancel,
        Operation::PermissionAnswer,
    ]
    .into_iter()
    .enumerate()
    {
        let req = request(operation, Some(id(9)));
        let outcome = store
            .execute(
                "profile",
                &req,
                &json!({"resolved":true}),
                || Ok(()),
                |_| {
                    Ok(CommittedResult {
                        body: json!({"operation_index":index}),
                        cursor: Some(index as u64),
                    })
                },
            )
            .unwrap();
        assert!(matches!(outcome, IdempotencyOutcome::Committed(_)));
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn exact_retry_reopens_and_conflict_performs_no_work() {
    let path = path("reopen");
    let calls = Rc::new(Cell::new(0));
    let req = request(Operation::RunStart, Some(id(2)));
    {
        let mut store = IdempotencyStore::open(&path).unwrap();
        let calls = calls.clone();
        let outcome = store
            .execute(
                "profile-a",
                &req,
                &json!({"workspace":"resolved", "text":"hello"}),
                || Ok(()),
                move |_| {
                    calls.set(calls.get() + 1);
                    Ok(CommittedResult {
                        body: json!({"run_id":"redacted-id"}),
                        cursor: Some(7),
                    })
                },
            )
            .unwrap();
        assert!(matches!(outcome, IdempotencyOutcome::Committed(_)));
    }
    let mut reopened = IdempotencyStore::open(&path).unwrap();
    let mut retry = req.clone();
    retry.request_id = id(999); // transport correlation is not canonical intent
    let replay = reopened
        .execute(
            "profile-a",
            &retry,
            &json!({"text":"hello", "workspace":"resolved"}),
            || Ok(()),
            |_| panic!("replayed work"),
        )
        .unwrap();
    assert_eq!(
        replay,
        IdempotencyOutcome::Replayed(CommittedResult {
            body: json!({"run_id":"redacted-id"}),
            cursor: Some(7)
        })
    );
    assert_eq!(calls.get(), 1);
    let conflict = reopened
        .execute(
            "profile-a",
            &req,
            &json!({"workspace":"resolved", "text":"different"}),
            || Ok(()),
            |_| panic!("conflicting work"),
        )
        .unwrap_err();
    assert_eq!(conflict.code(), ErrorCode::IdempotencyConflict);
    assert!(!conflict.retryable());
    let _ = std::fs::remove_file(path);
}

#[test]
fn authorization_precedes_lookup_and_replay_precedes_mutable_preconditions() {
    let path = path("ordering");
    let req = request(Operation::RunCancel, Some(id(3)));
    let mut store = IdempotencyStore::open(&path).unwrap();
    store
        .execute(
            "profile",
            &req,
            &json!({"run":"resolved"}),
            || Ok(()),
            |_| {
                Ok(CommittedResult {
                    body: json!({"accepted":true}),
                    cursor: Some(11),
                })
            },
        )
        .unwrap();
    let auth_error = ProtocolError::malformed_frame();
    assert_eq!(
        store
            .execute(
                "profile",
                &req,
                &json!({"run":"resolved"}),
                || Err(auth_error.clone()),
                |_| panic!("unauthorized work")
            )
            .unwrap_err(),
        auth_error
    );
    assert!(matches!(
        store
            .execute(
                "profile",
                &req,
                &json!({"run":"resolved"}),
                || Ok(()),
                |_| panic!("mutable precondition must not run on replay")
            )
            .unwrap(),
        IdempotencyOutcome::Replayed(_)
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn failed_commit_rolls_back_work_and_record_and_profile_deletion_is_explicit() {
    let path = path("atomic");
    let req = request(Operation::PermissionAnswer, Some(id(4)));
    let mut store = IdempotencyStore::open(&path).unwrap();
    let error = store
        .execute(
            "profile",
            &req,
            &json!({"gate":"g", "answer":"allow"}),
            || Ok(()),
            |tx| {
                tx.execute("CREATE TABLE domain_effect (value TEXT)", [])
                    .unwrap();
                tx.execute("INSERT INTO domain_effect VALUES ('effect')", [])
                    .unwrap();
                Err(ProtocolError::persistence_failed())
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PersistenceFailed);
    let calls = Cell::new(0);
    store
        .execute(
            "profile",
            &req,
            &json!({"gate":"g", "answer":"allow"}),
            || Ok(()),
            |_| {
                calls.set(calls.get() + 1);
                Ok(CommittedResult {
                    body: json!({"accepted":true}),
                    cursor: None,
                })
            },
        )
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(store.delete_profile("profile").unwrap(), 1);
    store
        .execute(
            "profile",
            &req,
            &json!({"gate":"g", "answer":"allow"}),
            || Ok(()),
            |_| {
                calls.set(calls.get() + 1);
                Ok(CommittedResult {
                    body: json!({"accepted":true}),
                    cursor: None,
                })
            },
        )
        .unwrap();
    assert_eq!(calls.get(), 2);
    let _ = std::fs::remove_file(path);
}

#[test]
fn protocol_errors_are_closed_and_redacted() {
    for error in [
        ProtocolError::idempotency_key_required(),
        ProtocolError::idempotency_key_forbidden(),
        ProtocolError::idempotency_conflict(),
        ProtocolError::persistence_failed(),
    ] {
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains('/') && !encoded.contains("SQL") && !encoded.contains("token"));
        let decoded: ProtocolError = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, error);
    }
}
