use super::{ProtocolError, Request};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

const HASH_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommittedResult {
    pub body: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IdempotencyOutcome {
    Committed(CommittedResult),
    Replayed(CommittedResult),
}

pub struct IdempotencyStore {
    connection: Connection,
}

impl IdempotencyStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProtocolError> {
        let connection = Connection::open(path).map_err(|_| ProtocolError::persistence_failed())?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS attach_idempotency (
              profile TEXT NOT NULL, operation TEXT NOT NULL, idempotency_key TEXT NOT NULL,
              hash_version INTEGER NOT NULL, canonical_hash BLOB NOT NULL,
              committed_result TEXT NOT NULL,
              PRIMARY KEY (profile, operation, idempotency_key));",
            )
            .map_err(|_| ProtocolError::persistence_failed())?;
        Ok(Self { connection })
    }

    /// Ordering is part of the contract: current authorization, key policy,
    /// ledger replay/conflict, and only then mutable preconditions and work.
    /// The callback receives the ledger transaction so its domain commit and
    /// the accepted result record commit atomically.
    pub fn execute<A, W>(
        &mut self,
        profile: &str,
        request: &Request,
        canonical_resolved_input: &Value,
        authorize: A,
        work_and_commit: W,
    ) -> Result<IdempotencyOutcome, ProtocolError>
    where
        A: FnOnce() -> Result<(), ProtocolError>,
        W: FnOnce(&Transaction<'_>) -> Result<CommittedResult, ProtocolError>,
    {
        authorize()?;
        request.validate_idempotency_key()?;
        let key = request
            .idempotency_key
            .as_ref()
            .expect("effectful request validated");
        let hash = canonical_hash(canonical_resolved_input);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let existing: Option<(i64, Vec<u8>, String)> = transaction
            .query_row(
                "SELECT hash_version, canonical_hash, committed_result FROM attach_idempotency
             WHERE profile=?1 AND operation=?2 AND idempotency_key=?3",
                params![profile, request.operation.as_str(), key.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ProtocolError::persistence_failed())?;
        if let Some((version, recorded_hash, encoded)) = existing {
            if version != HASH_VERSION || recorded_hash != hash {
                return Err(ProtocolError::idempotency_conflict());
            }
            let result =
                serde_json::from_str(&encoded).map_err(|_| ProtocolError::persistence_failed())?;
            return Ok(IdempotencyOutcome::Replayed(result));
        }
        let result = work_and_commit(&transaction)?;
        let encoded =
            serde_json::to_string(&result).map_err(|_| ProtocolError::persistence_failed())?;
        transaction
            .execute(
                "INSERT INTO attach_idempotency
            (profile,operation,idempotency_key,hash_version,canonical_hash,committed_result)
            VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    profile,
                    request.operation.as_str(),
                    key.as_str(),
                    HASH_VERSION,
                    hash,
                    encoded
                ],
            )
            .map_err(|_| ProtocolError::persistence_failed())?;
        transaction
            .commit()
            .map_err(|_| ProtocolError::persistence_failed())?;
        Ok(IdempotencyOutcome::Committed(result))
    }

    /// Profile deletion is intentionally the only ledger removal API.
    pub fn delete_profile(&mut self, profile: &str) -> Result<usize, ProtocolError> {
        self.connection
            .execute("DELETE FROM attach_idempotency WHERE profile=?1", [profile])
            .map_err(|_| ProtocolError::persistence_failed())
    }
}

fn canonical_hash(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_canonical(value, &mut bytes);
    Sha256::digest(bytes).to_vec()
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Object(object) => {
            output.push(b'{');
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            for key in keys {
                serde_json::to_writer(&mut *output, key).unwrap();
                output.push(b':');
                write_canonical(&object[key], output);
                output.push(b',');
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for value in values {
                write_canonical(value, output);
                output.push(b',');
            }
            output.push(b']');
        }
        _ => serde_json::to_writer(output, value).unwrap(),
    }
}
