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
        Operation::ThreadCreate,
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
        Operation::ThreadCreate,
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
                "client-a",
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
                "client-a",
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
            "client-a",
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
            "client-a",
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
fn another_client_never_replays_a_result_under_the_same_key() {
    let path = path("client-scope");
    let req = request(Operation::RunStart, Some(id(6)));
    let input = json!({"workspace":"resolved", "text":"hello"});
    let mut store = IdempotencyStore::open(&path).unwrap();
    let commit = |run: &'static str| {
        move |_: &rusqlite::Transaction<'_>| {
            Ok(CommittedResult {
                body: json!({"run_id": run}),
                cursor: None,
            })
        }
    };
    assert!(matches!(
        store
            .execute(
                "profile",
                "client-a",
                &req,
                &input,
                || Ok(()),
                commit("run-a")
            )
            .unwrap(),
        IdempotencyOutcome::Committed(_)
    ));
    assert_eq!(
        store
            .execute(
                "profile",
                "client-b",
                &req,
                &input,
                || Ok(()),
                commit("run-b")
            )
            .unwrap(),
        IdempotencyOutcome::Committed(CommittedResult {
            body: json!({"run_id":"run-b"}),
            cursor: None,
        })
    );
    assert_eq!(
        store
            .execute(
                "profile",
                "client-a",
                &req,
                &input,
                || Ok(()),
                |_| panic!("replayed work")
            )
            .unwrap(),
        IdempotencyOutcome::Replayed(CommittedResult {
            body: json!({"run_id":"run-a"}),
            cursor: None,
        })
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn a_ledger_without_a_client_column_moves_into_the_scoped_ledger() {
    let path = path("client-scope-move");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE attach_idempotency (
              profile TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
              hash_version INTEGER NOT NULL, canonical_hash BLOB NOT NULL,
              committed_result TEXT NOT NULL,
              PRIMARY KEY (profile, operation, idempotency_key));
             INSERT INTO attach_idempotency VALUES
              ('profile', 'run.start', 'key', 1, x'00', '{\"body\":{}}');",
        )
        .unwrap();
    drop(connection);
    let mut store = IdempotencyStore::open(&path).unwrap();
    let req = request(Operation::RunStart, Some(id(7)));
    store
        .execute(
            "profile",
            "client-a",
            &req,
            &json!({}),
            || Ok(()),
            |_| {
                Ok(CommittedResult {
                    body: json!({}),
                    cursor: None,
                })
            },
        )
        .unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let clients: Vec<String> = connection
        .prepare("SELECT client_identity FROM attach_idempotency ORDER BY client_identity")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(clients, ["", "client-a"]);
    drop(connection);
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
            "client-a",
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
                "client-a",
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
                "client-a",
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
            "client-a",
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
            "client-a",
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
            "client-a",
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
fn sign_in_persistence_failures_name_the_ledger_step_without_sql_or_credentials() {
    for (setup, expected) in [
        (
            "DROP TABLE attach_idempotency",
            "The runtime could not read the idempotency result.",
        ),
        (
            "CREATE TRIGGER reject_result BEFORE INSERT ON attach_idempotency
             BEGIN SELECT RAISE(ABORT, 'private-token'); END;",
            "The runtime could not save the idempotency result.",
        ),
        (
            "CREATE TABLE parent(id INTEGER PRIMARY KEY);
             CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER reject_commit AFTER INSERT ON attach_idempotency
             BEGIN INSERT INTO child VALUES (1); END;",
            "The runtime could not commit the idempotency result.",
        ),
    ] {
        let path = path("sign-in-failure");
        let mut store = IdempotencyStore::open(&path).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch(setup).unwrap();
        let error = store
            .execute(
                "profile",
                "client-a",
                &request(Operation::SessionSignIn, Some(id(5))),
                &json!({}),
                || Ok(()),
                |_| {
                    Ok(CommittedResult {
                        body: json!({"signed_in": true}),
                        cursor: None,
                    })
                },
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProtocolError::persistence_failed_with_reason(expected)
        );
        assert!(!error.to_string().contains("private-token"));
        drop(connection);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
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
