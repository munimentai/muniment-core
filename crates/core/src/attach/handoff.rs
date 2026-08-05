//! Prepared migration handoff state.

use std::fmt;
use std::time::{Duration, Instant};

const MAX_HANDOFF_NONCE_BYTES: usize = 128;
const MAX_HANDOFF_DEADLINE_MS: u64 = 60_000;

/// A failure to prepare a migration handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedHandoffError {
    AlreadyPrepared,
    EmptyNonce,
    NonceTooLong,
    NonceNotPrintableAscii,
    DeadlineOutOfRange,
}

impl fmt::Display for PreparedHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyPrepared => "a handoff is already prepared",
            Self::EmptyNonce => "handoff nonce is empty",
            Self::NonceTooLong => "handoff nonce is too long",
            Self::NonceNotPrintableAscii => "handoff nonce contains a non-printable byte",
            Self::DeadlineOutOfRange => "handoff deadline is out of range",
        })
    }
}

impl std::error::Error for PreparedHandoffError {}

struct PreparedHandoff {
    nonce: String,
    deadline: Instant,
}

/// Holds the one live migration handoff preparation.
#[derive(Default)]
pub struct PreparedHandoffSlot {
    prepared: Option<PreparedHandoff>,
}

impl fmt::Debug for PreparedHandoffSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedHandoffSlot")
            .field("prepared", &self.prepared.is_some())
            .finish()
    }
}

impl PreparedHandoffSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepares a handoff until the deadline relative to `now`.
    pub fn prepare(
        &mut self,
        nonce: impl Into<String>,
        deadline_ms: u64,
        now: Instant,
    ) -> Result<(), PreparedHandoffError> {
        if self
            .prepared
            .as_ref()
            .is_some_and(|prepared| now < prepared.deadline)
        {
            return Err(PreparedHandoffError::AlreadyPrepared);
        }

        let nonce = nonce.into();
        if nonce.is_empty() {
            return Err(PreparedHandoffError::EmptyNonce);
        }
        if nonce.len() > MAX_HANDOFF_NONCE_BYTES {
            return Err(PreparedHandoffError::NonceTooLong);
        }
        if !nonce.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
            return Err(PreparedHandoffError::NonceNotPrintableAscii);
        }
        if !(1..=MAX_HANDOFF_DEADLINE_MS).contains(&deadline_ms) {
            return Err(PreparedHandoffError::DeadlineOutOfRange);
        }

        self.prepared = Some(PreparedHandoff {
            nonce,
            deadline: now + Duration::from_millis(deadline_ms),
        });
        Ok(())
    }

    /// Reports whether `nonce` matches the live preparation at `now`.
    pub fn matches(&self, nonce: &str, now: Instant) -> bool {
        self.prepared
            .as_ref()
            .is_some_and(|prepared| now < prepared.deadline && nonce == prepared.nonce)
    }

    /// Cancels any preparation.
    pub fn cancel(&mut self) {
        self.prepared = None;
    }
}
