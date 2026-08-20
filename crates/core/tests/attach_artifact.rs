use muniment_core::attach::*;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

fn id(n: u128) -> Id {
    Id::new(format!("{n:032x}")).unwrap()
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn transfer(total: u64, chunk_bytes: u64, chunk_count: u64) -> ArtifactTransfer {
    ArtifactTransfer::new(ArtifactMetadata {
        transfer_id: id(1),
        artifact_id: id(2),
        total_bytes: total,
        sha256: hash(&vec![0; total as usize]),
        chunk_bytes,
        chunk_count,
    })
    .unwrap()
}

fn empty_transfer(transfer_id: Id) -> ArtifactTransfer {
    ArtifactTransfer::new(ArtifactMetadata {
        transfer_id,
        artifact_id: id(2),
        total_bytes: 0,
        sha256: hash(&[]),
        chunk_bytes: 4,
        chunk_count: 0,
    })
    .unwrap()
}

#[test]
fn empty_and_single_chunk_complete_only_after_final_ack() {
    assert!(transfer(0, 4, 0).completion().is_some());

    let mut state = transfer(3, 4, 1);
    assert_eq!(
        state
            .admit_chunk(&id(2), 0, 0, 3, &hash(b"abc"), b"abc")
            .unwrap(),
        ArtifactChunkAdmission::Paused
    );
    state.accept_window(&id(1), -1, 1).unwrap();
    state
        .admit_chunk(&id(2), 0, 0, 3, &hash(b"abc"), b"abc")
        .unwrap();
    assert!(state.completion().is_none());
    state.accept_window(&id(1), 0, 1).unwrap();
    let complete = state.completion().unwrap();
    assert_eq!(complete.total_bytes, 3);
    assert_eq!(complete.sha256, state.metadata().sha256);
}

#[test]
fn partial_windows_pause_and_acknowledgements_are_bounded() {
    let mut state = transfer(5, 2, 3);
    state.accept_window(&id(1), -1, 2).unwrap();
    for (index, bytes) in [(0, &b"ab"[..]), (1, &b"cd"[..])] {
        state
            .admit_chunk(&id(2), index, index * 2, 2, &hash(bytes), bytes)
            .unwrap();
    }
    assert_eq!(state.outstanding_grant(), 0);
    assert_eq!(
        state
            .admit_chunk(&id(2), 2, 4, 1, &hash(b"e"), b"e")
            .unwrap(),
        ArtifactChunkAdmission::Paused
    );
    state.accept_window(&id(1), 0, 1).unwrap();
    state.accept_window(&id(1), 0, 1).unwrap();
    assert!(state.accept_window(&id(1), -1, 1).is_err());
    assert!(state.accept_window(&id(1), 2, 1).is_err());
    state
        .admit_chunk(&id(2), 2, 4, 1, &hash(b"e"), b"e")
        .unwrap();
    assert!(state.completion().is_none());
    state.accept_window(&id(1), 2, 1).unwrap();
    assert!(state.completion().is_some());
}

#[test]
fn acknowledgements_release_bytes_and_control_deadlines_across_windows() {
    let started = Instant::now();
    let mut state = transfer(5, 2, 3);
    assert_eq!(state.retained_bytes(), 0);
    assert_eq!(state.acknowledgement_deadline(), None);

    state.accept_window_at(&id(1), -1, 2, started).unwrap();
    for (index, bytes) in [(0, &b"ab"[..]), (1, &b"cd"[..])] {
        state
            .admit_chunk_at(&id(2), index, index * 2, 2, &hash(bytes), bytes, started)
            .unwrap();
    }
    let first_deadline = started + ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT;
    assert_eq!(state.retained_bytes(), 4);
    assert_eq!(state.acknowledgement_deadline(), Some(first_deadline));

    let partial_ack = started + Duration::from_secs(10);
    state.accept_window_at(&id(1), 0, 1, partial_ack).unwrap();
    assert_eq!(state.retained_bytes(), 2);
    assert_eq!(
        state.acknowledgement_deadline(),
        Some(partial_ack + ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT)
    );

    let repeated_ack = started + Duration::from_secs(20);
    state.accept_window_at(&id(1), 0, 1, repeated_ack).unwrap();
    assert_eq!(state.retained_bytes(), 2);
    assert_eq!(
        state.acknowledgement_deadline(),
        Some(partial_ack + ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT)
    );
    state.accept_window_at(&id(1), 1, 1, repeated_ack).unwrap();
    assert_eq!(state.retained_bytes(), 0);
    assert_eq!(state.acknowledgement_deadline(), None);

    state
        .admit_chunk_at(&id(2), 2, 4, 1, &hash(b"e"), b"e", repeated_ack)
        .unwrap();
    assert_eq!(state.retained_bytes(), 1);
    assert_eq!(
        state.acknowledgement_deadline(),
        Some(repeated_ack + ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT)
    );

    state.accept_window_at(&id(1), 2, 1, repeated_ack).unwrap();
    assert_eq!(state.retained_bytes(), 0);
    assert_eq!(state.acknowledgement_deadline(), None);
}

#[test]
fn exact_byte_limit_is_valid_and_one_byte_overflow_is_rejected() {
    let started = Instant::now();
    let total = MAX_UNACKNOWLEDGED_ARTIFACT_BYTES + 1;
    let chunk_count = total.div_ceil(MAX_ARTIFACT_CHUNK_BYTES);
    let mut state = transfer(total, MAX_ARTIFACT_CHUNK_BYTES, chunk_count);
    state
        .accept_window_at(&id(1), -1, chunk_count as u32, started)
        .unwrap();
    let bytes = vec![0; MAX_ARTIFACT_CHUNK_BYTES as usize];
    for index in 0..chunk_count - 1 {
        state
            .admit_chunk_at(
                &id(2),
                index,
                index * MAX_ARTIFACT_CHUNK_BYTES,
                MAX_ARTIFACT_CHUNK_BYTES,
                &hash(&bytes),
                &bytes,
                started,
            )
            .unwrap();
    }
    assert_eq!(state.retained_bytes(), MAX_UNACKNOWLEDGED_ARTIFACT_BYTES);
    let error = state
        .admit_chunk_at(
            &id(2),
            chunk_count - 1,
            MAX_UNACKNOWLEDGED_ARTIFACT_BYTES,
            1,
            &hash(b"x"),
            b"x",
            started,
        )
        .unwrap_err();
    assert!(error.is_slow_consumer());
    assert_eq!(error.error().code(), ErrorCode::SlowConsumer);
    assert!(error.error().retryable());
    assert_eq!(
        error.close(),
        StreamClose {
            code: StreamCloseCode::SlowConsumer,
            resumable: true
        }
    );
    assert_eq!(state.retained_bytes(), MAX_UNACKNOWLEDGED_ARTIFACT_BYTES);
}

#[test]
fn exact_deadline_rejects_emission_and_acknowledgement() {
    let started = Instant::now();
    let deadline = started + ARTIFACT_ACKNOWLEDGEMENT_TIMEOUT;
    let mut emission = transfer(2, 1, 2);
    emission.accept_window_at(&id(1), -1, 2, started).unwrap();
    emission
        .admit_chunk_at(&id(2), 0, 0, 1, &hash(b"a"), b"a", started)
        .unwrap();
    assert!(emission
        .admit_chunk_at(&id(2), 1, 1, 1, &hash(b"b"), b"b", deadline)
        .unwrap_err()
        .is_slow_consumer());

    let mut acknowledgement = transfer(1, 1, 1);
    acknowledgement
        .accept_window_at(&id(1), -1, 1, started)
        .unwrap();
    acknowledgement
        .admit_chunk_at(&id(2), 0, 0, 1, &hash(b"a"), b"a", started)
        .unwrap();
    assert!(acknowledgement
        .accept_window_at(&id(1), 0, 1, deadline)
        .unwrap_err()
        .is_slow_consumer());
    assert_eq!(acknowledgement.retained_bytes(), 1);
}

#[test]
fn zero_byte_transfer_never_starts_a_deadline() {
    let mut state = transfer(0, 4, 0);
    state
        .accept_window_at(&id(1), -1, 1, Instant::now())
        .unwrap();
    assert_eq!(state.retained_bytes(), 0);
    assert_eq!(state.acknowledgement_deadline(), None);
}

#[test]
fn invalid_metadata_windows_and_chunks_return_transfer_local_close() {
    for metadata in [
        (1, 0, 1),
        (1, 1, 0),
        (1, MAX_ARTIFACT_CHUNK_BYTES + 1, 1),
        (u64::MAX, 2, u64::MAX / 2 + 1),
    ] {
        assert!(ArtifactTransfer::new(ArtifactMetadata {
            transfer_id: id(1),
            artifact_id: id(2),
            total_bytes: metadata.0,
            sha256: "0".repeat(64),
            chunk_bytes: metadata.1,
            chunk_count: metadata.2,
        })
        .is_err());
    }
    let mut state = transfer(2, 2, 1);
    for grant in [0, MAX_ARTIFACT_WINDOW_CHUNKS + 1] {
        let error = state.accept_window(&id(1), -1, grant).unwrap_err();
        assert_eq!(error.error().code(), ErrorCode::InvalidArtifactCursor);
        assert_eq!(
            error.close(),
            StreamClose {
                code: StreamCloseCode::InvalidArtifactCursor,
                resumable: true
            }
        );
    }
    state
        .accept_window(&id(1), -1, MAX_ARTIFACT_WINDOW_CHUNKS)
        .unwrap();
    assert!(state.accept_window(&id(1), -1, 1).is_err());
    state = transfer(2, 2, 1);
    state.accept_window(&id(1), -1, 1).unwrap();
    for (index, offset, length, digest, bytes) in [
        (1, 0, 2, hash(b"ab"), &b"ab"[..]),
        (0, 1, 2, hash(b"ab"), &b"ab"[..]),
        (0, 0, 1, hash(b"a"), &b"a"[..]),
        (0, 0, 2, hash(b"xx"), &b"ab"[..]),
    ] {
        assert!(state
            .admit_chunk(&id(2), index, offset, length, &digest, bytes)
            .is_err());
        assert_eq!(state.highest_emitted(), -1);
    }
}

#[test]
fn registry_inserts_looks_up_and_removes_by_transfer_id() {
    let mut registry = ArtifactTransferRegistry::new();
    let transfer_id = id(1);
    let unknown = id(2);
    let missing = registry.get(&unknown).unwrap_err();
    assert_eq!(missing, ArtifactTransferRegistryError::NotFound);
    assert_eq!(registry.get_mut(&unknown).unwrap_err(), missing);
    assert_eq!(registry.remove(&unknown).unwrap_err(), missing);

    registry
        .insert(empty_transfer(transfer_id.clone()))
        .unwrap();
    assert_eq!(
        registry.get(&transfer_id).unwrap().metadata().transfer_id,
        transfer_id
    );
    assert_eq!(
        registry
            .get_mut(&transfer_id)
            .unwrap()
            .metadata()
            .transfer_id,
        transfer_id
    );
    let removed = registry.remove(&transfer_id).unwrap();
    assert_eq!(removed.metadata().transfer_id, transfer_id);
    assert_eq!(registry.get(&transfer_id).unwrap_err(), missing);
    assert_eq!(registry.remove(&transfer_id).unwrap_err(), missing);
}

#[test]
fn registry_rejects_a_sixty_fifth_insert() {
    assert_eq!(MAX_ACTIVE_ARTIFACT_TRANSFERS, 64);
    let mut registry = ArtifactTransferRegistry::new();
    for n in 1..=MAX_ACTIVE_ARTIFACT_TRANSFERS {
        registry.insert(empty_transfer(id(n as u128))).unwrap();
    }
    let overflow = id((MAX_ACTIVE_ARTIFACT_TRANSFERS as u128) + 1);
    assert_eq!(
        registry
            .insert(empty_transfer(overflow.clone()))
            .unwrap_err(),
        ArtifactTransferRegistryError::BoundReached
    );
    assert!(registry.get(&id(1)).is_ok());
    assert!(registry.get(&id(64)).is_ok());
    assert_eq!(
        registry.get(&overflow).unwrap_err(),
        ArtifactTransferRegistryError::NotFound
    );

    registry.insert(empty_transfer(id(1))).unwrap();
    registry.remove(&id(1)).unwrap();
    registry.insert(empty_transfer(overflow.clone())).unwrap();
    assert!(registry.get(&overflow).is_ok());
    assert_eq!(
        registry.get(&id(1)).unwrap_err(),
        ArtifactTransferRegistryError::NotFound
    );
}
