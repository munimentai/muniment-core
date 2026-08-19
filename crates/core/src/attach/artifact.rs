use std::collections::HashMap;

use sha2::{Digest, Sha256};

use super::{Id, ProtocolError, StreamClose, StreamCloseCode};

/// The wire protocol limits decoded chunk bodies to 256 KiB.
pub const MAX_ARTIFACT_CHUNK_BYTES: u64 = 256 * 1024;
/// A single `artifact.window` may grant at most this many chunks.
pub const MAX_ARTIFACT_WINDOW_CHUNKS: u32 = 1_024;
/// One attach session may hold this many concurrent artifact transfers.
pub const MAX_ACTIVE_ARTIFACT_TRANSFERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub transfer_id: Id,
    pub artifact_id: Id,
    pub total_bytes: u64,
    pub sha256: String,
    pub chunk_bytes: u64,
    pub chunk_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactChunkAdmission {
    Emitted,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCompletion {
    pub transfer_id: Id,
    pub artifact_id: Id,
    pub total_bytes: u64,
    pub sha256: String,
}

/// Closed failure for one pinned transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactTransferError {
    error: ProtocolError,
    close: StreamClose,
}

impl ArtifactTransferError {
    fn invalid_cursor() -> Self {
        Self {
            error: ProtocolError::invalid_artifact_cursor(),
            close: StreamClose {
                code: StreamCloseCode::InvalidArtifactCursor,
                resumable: true,
            },
        }
    }

    pub fn error(&self) -> &ProtocolError {
        &self.error
    }
    pub fn close(&self) -> StreamClose {
        self.close
    }
}

/// Allocation-free flow-control state for one pinned artifact transfer.
#[derive(Debug, Clone)]
pub struct ArtifactTransfer {
    metadata: ArtifactMetadata,
    acknowledged_through: i64,
    highest_emitted: i64,
    outstanding_grant: u64,
}

impl ArtifactTransfer {
    pub fn new(metadata: ArtifactMetadata) -> Result<Self, ArtifactTransferError> {
        let expected_count = if metadata.total_bytes == 0 {
            0
        } else if metadata.chunk_bytes == 0 {
            u64::MAX
        } else {
            metadata
                .total_bytes
                .checked_add(metadata.chunk_bytes.saturating_sub(1))
                .map(|value| value / metadata.chunk_bytes)
                .unwrap_or(u64::MAX)
        };
        let valid = metadata.chunk_bytes > 0
            && metadata.chunk_bytes <= MAX_ARTIFACT_CHUNK_BYTES
            && metadata.chunk_count == expected_count
            && metadata.chunk_count <= i64::MAX as u64
            && valid_sha256(&metadata.sha256)
            && metadata
                .chunk_count
                .checked_mul(metadata.chunk_bytes)
                .is_some();
        if !valid {
            return Err(ArtifactTransferError::invalid_cursor());
        }
        Ok(Self {
            metadata,
            acknowledged_through: -1,
            highest_emitted: -1,
            outstanding_grant: 0,
        })
    }

    pub fn metadata(&self) -> &ArtifactMetadata {
        &self.metadata
    }
    pub fn acknowledged_through(&self) -> i64 {
        self.acknowledged_through
    }
    pub fn highest_emitted(&self) -> i64 {
        self.highest_emitted
    }
    pub fn outstanding_grant(&self) -> u64 {
        self.outstanding_grant
    }

    pub fn accept_window(
        &mut self,
        transfer_id: &Id,
        ack_through_chunk: i64,
        max_chunks: u32,
    ) -> Result<u32, ArtifactTransferError> {
        if transfer_id != &self.metadata.transfer_id
            || max_chunks == 0
            || max_chunks > MAX_ARTIFACT_WINDOW_CHUNKS
            || ack_through_chunk < self.acknowledged_through
            || ack_through_chunk > self.highest_emitted
        {
            return Err(ArtifactTransferError::invalid_cursor());
        }
        let new_grant = self
            .outstanding_grant
            .checked_add(u64::from(max_chunks))
            .filter(|grant| *grant <= u64::from(MAX_ARTIFACT_WINDOW_CHUNKS))
            .ok_or_else(ArtifactTransferError::invalid_cursor)?;
        // Since emission itself is contiguous, every in-range prefix ack is contiguous.
        self.acknowledged_through = ack_through_chunk;
        self.outstanding_grant = new_grant;
        Ok(max_chunks)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_chunk(
        &mut self,
        artifact_id: &Id,
        chunk_index: u64,
        offset: u64,
        byte_length: u64,
        chunk_sha256: &str,
        data: &[u8],
    ) -> Result<ArtifactChunkAdmission, ArtifactTransferError> {
        if self.outstanding_grant == 0 {
            return Ok(ArtifactChunkAdmission::Paused);
        }
        let next = self
            .highest_emitted
            .checked_add(1)
            .map(|value| value as u64);
        let expected_offset = chunk_index.checked_mul(self.metadata.chunk_bytes);
        let expected_length = self
            .metadata
            .total_bytes
            .checked_sub(offset)
            .map(|remaining| remaining.min(self.metadata.chunk_bytes));
        let data_length = u64::try_from(data.len()).ok();
        let actual_hash = format!("{:x}", Sha256::digest(data));
        if artifact_id != &self.metadata.artifact_id
            || Some(chunk_index) != next
            || chunk_index >= self.metadata.chunk_count
            || Some(offset) != expected_offset
            || Some(byte_length) != expected_length
            || Some(byte_length) != data_length
            || byte_length > MAX_ARTIFACT_CHUNK_BYTES
            || !valid_sha256(chunk_sha256)
            || chunk_sha256 != actual_hash
        {
            return Err(ArtifactTransferError::invalid_cursor());
        }
        self.highest_emitted = chunk_index as i64;
        self.outstanding_grant -= 1;
        Ok(ArtifactChunkAdmission::Emitted)
    }

    pub fn completion(&self) -> Option<ArtifactCompletion> {
        let last = self.metadata.chunk_count as i64 - 1;
        (self.highest_emitted == last && self.acknowledged_through == last).then(|| {
            ArtifactCompletion {
                transfer_id: self.metadata.transfer_id.clone(),
                artifact_id: self.metadata.artifact_id.clone(),
                total_bytes: self.metadata.total_bytes,
                sha256: self.metadata.sha256.clone(),
            }
        })
    }
}

/// Local registry failure. This is not a wire `ErrorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactTransferRegistryError {
    NotFound,
    BoundReached,
}

/// Bounded map of live artifact transfers for one attach session.
#[derive(Debug, Default)]
pub struct ArtifactTransferRegistry {
    transfers: HashMap<Id, ArtifactTransfer>,
}

impl ArtifactTransferRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        transfer: ArtifactTransfer,
    ) -> Result<(), ArtifactTransferRegistryError> {
        let transfer_id = transfer.metadata().transfer_id.clone();
        if !self.transfers.contains_key(&transfer_id)
            && self.transfers.len() >= MAX_ACTIVE_ARTIFACT_TRANSFERS
        {
            return Err(ArtifactTransferRegistryError::BoundReached);
        }
        self.transfers.insert(transfer_id, transfer);
        Ok(())
    }

    pub fn get(
        &self,
        transfer_id: &Id,
    ) -> Result<&ArtifactTransfer, ArtifactTransferRegistryError> {
        self.transfers
            .get(transfer_id)
            .ok_or(ArtifactTransferRegistryError::NotFound)
    }

    pub fn get_mut(
        &mut self,
        transfer_id: &Id,
    ) -> Result<&mut ArtifactTransfer, ArtifactTransferRegistryError> {
        self.transfers
            .get_mut(transfer_id)
            .ok_or(ArtifactTransferRegistryError::NotFound)
    }

    pub fn remove(
        &mut self,
        transfer_id: &Id,
    ) -> Result<ArtifactTransfer, ArtifactTransferRegistryError> {
        self.transfers
            .remove(transfer_id)
            .ok_or(ArtifactTransferRegistryError::NotFound)
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
