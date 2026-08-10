use muniment_core::write_plan::{
    ObservedPath, ObservedState, StableFileIdentity, WriteOperation, WritePlan, WritePlanError,
    MAX_OPERATIONS, MAX_OPERATION_OUTPUT_BYTES,
};
use sha2::{Digest, Sha256};

fn identity(file: u128) -> StableFileIdentity {
    StableFileIdentity::new(7, file)
}

fn absent(path: impl Into<String>) -> ObservedPath {
    ObservedPath::new(path, ObservedState::Absent, identity(1))
}

fn file(path: &str, file: u128) -> ObservedPath {
    ObservedPath::new(
        path,
        ObservedState::File {
            byte_length: 3,
            sha256: Sha256::digest(b"old").into(),
            mode: 0o644,
            identity: identity(file),
        },
        identity(1),
    )
}

fn delete(path: impl Into<String>) -> WriteOperation {
    WriteOperation::Delete {
        target: file(&path.into(), 2),
    }
}

#[test]
fn deterministic_bytes_round_trip_with_hash_verification() {
    let plan = WritePlan::new(vec![
        WriteOperation::Write {
            target: file("src/main.rs", 2),
            output: b"fn main() {}\n".to_vec(),
            mode: 0o755,
        },
        WriteOperation::Rename {
            source: file("old.txt", 3),
            target: absent("new.txt"),
        },
        delete("unused.txt"),
    ])
    .unwrap();

    let first = plan.encode().unwrap();
    assert_eq!(first, plan.encode().unwrap());
    let hash: [u8; 32] = Sha256::digest(&first).into();
    let decoded = WritePlan::decode_verified(&first, &hash).unwrap();
    assert_eq!(decoded, plan);
    assert_eq!(decoded.encode().unwrap(), first);
}

#[test]
fn rejects_a_hash_mismatch_before_decoding() {
    assert!(matches!(
        WritePlan::decode_verified(b"not JSON", &[0; 32]),
        Err(WritePlanError::HashMismatch)
    ));
}

#[test]
fn rejects_valid_but_noncanonical_json() {
    let bytes = b"{\"operations\":[] }";
    let hash = Sha256::digest(bytes).into();
    assert!(matches!(
        WritePlan::decode_verified(bytes, &hash),
        Err(WritePlanError::NonCanonicalEncoding)
    ));
}

#[test]
fn rejects_more_than_the_operation_limit() {
    let operations = (0..=MAX_OPERATIONS)
        .map(|index| delete(format!("{index}.txt")))
        .collect();
    assert!(matches!(
        WritePlan::new(operations),
        Err(WritePlanError::TooManyOperations)
    ));
}

#[test]
fn accepts_the_operation_and_per_operation_byte_boundaries() {
    let operations = (0..MAX_OPERATIONS)
        .map(|index| delete(format!("{index}.txt")))
        .collect();
    WritePlan::new(operations).unwrap();

    WritePlan::new(vec![WriteOperation::Write {
        target: absent("large.bin"),
        output: vec![0; MAX_OPERATION_OUTPUT_BYTES],
        mode: 0o600,
    }])
    .unwrap();
}

#[test]
fn rejects_output_over_each_byte_limit() {
    assert!(matches!(
        WritePlan::new(vec![WriteOperation::Write {
            target: absent("large.bin"),
            output: vec![0; MAX_OPERATION_OUTPUT_BYTES + 1],
            mode: 0o600,
        }]),
        Err(WritePlanError::OperationOutputTooLarge)
    ));

    let operations = (0..9)
        .map(|index| WriteOperation::Write {
            target: absent(format!("{index}.bin")),
            output: vec![0; MAX_OPERATION_OUTPUT_BYTES],
            mode: 0o600,
        })
        .collect();
    assert!(matches!(
        WritePlan::new(operations),
        Err(WritePlanError::PlanOutputTooLarge)
    ));
}

#[test]
fn rejects_duplicate_and_conflicting_paths() {
    assert!(matches!(
        WritePlan::new(vec![delete("same.txt"), delete("same.txt")]),
        Err(WritePlanError::ConflictingPath(path)) if path == "same.txt"
    ));
    assert!(matches!(
        WritePlan::new(vec![WriteOperation::Rename {
            source: file("same.txt", 2),
            target: absent("same.txt"),
        }]),
        Err(WritePlanError::ConflictingPath(path)) if path == "same.txt"
    ));
}

#[test]
fn rejects_empty_paths_and_invalid_modes() {
    assert!(matches!(
        WritePlan::new(vec![delete("")]),
        Err(WritePlanError::EmptyPath)
    ));
    assert!(matches!(
        WritePlan::new(vec![WriteOperation::Write {
            target: absent("file.txt"),
            output: Vec::new(),
            mode: 0o10_000,
        }]),
        Err(WritePlanError::InvalidMode)
    ));
}

#[test]
fn rejects_operations_that_contradict_observed_state() {
    assert!(matches!(
        WritePlan::new(vec![WriteOperation::Delete {
            target: absent("missing.txt"),
        }]),
        Err(WritePlanError::InvalidObservedState)
    ));
    assert!(matches!(
        WritePlan::new(vec![WriteOperation::Rename {
            source: absent("missing.txt"),
            target: absent("new.txt"),
        }]),
        Err(WritePlanError::InvalidObservedState)
    ));
    assert!(matches!(
        WritePlan::new(vec![WriteOperation::Rename {
            source: file("old.txt", 2),
            target: file("occupied.txt", 3),
        }]),
        Err(WritePlanError::InvalidObservedState)
    ));
}
