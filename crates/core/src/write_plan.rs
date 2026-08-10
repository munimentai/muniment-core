//! Immutable file write plans and their verified JSON representation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

pub const MEDIA_TYPE: &str = "application/vnd.muniment.write-plan.v1+json";
pub const MAX_OPERATIONS: usize = 400;
pub const MAX_OPERATION_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PLAN_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// A filesystem identity that remains stable while an object exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StableFileIdentity {
    volume: u64,
    file: [u8; 16],
}

impl StableFileIdentity {
    pub fn new(volume: u64, file: u128) -> Self {
        Self {
            volume,
            file: file.to_be_bytes(),
        }
    }

    pub fn volume(&self) -> u64 {
        self.volume
    }

    pub fn file(&self) -> u128 {
        u128::from_be_bytes(self.file)
    }
}

/// The state observed at a path while the plan was made.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ObservedState {
    Absent,
    File {
        byte_length: u64,
        sha256: [u8; 32],
        mode: u32,
        identity: StableFileIdentity,
    },
}

/// A path and the resolved identity of its parent directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPath {
    path: String,
    state: ObservedState,
    parent_identity: StableFileIdentity,
}

impl ObservedPath {
    pub fn new(
        path: impl Into<String>,
        state: ObservedState,
        parent_identity: StableFileIdentity,
    ) -> Self {
        Self {
            path: path.into(),
            state,
            parent_identity,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn state(&self) -> &ObservedState {
        &self.state
    }

    pub fn parent_identity(&self) -> &StableFileIdentity {
        &self.parent_identity
    }
}

/// One exact filesystem change in a write plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "operation", deny_unknown_fields)]
pub enum WriteOperation {
    Write {
        target: ObservedPath,
        output: Vec<u8>,
        mode: u32,
    },
    Rename {
        source: ObservedPath,
        target: ObservedPath,
    },
    Delete {
        target: ObservedPath,
    },
}

impl WriteOperation {
    fn output_len(&self) -> usize {
        match self {
            Self::Write { output, .. } => output.len(),
            Self::Rename { .. } | Self::Delete { .. } => 0,
        }
    }

    fn paths(&self) -> [Option<&str>; 2] {
        match self {
            Self::Write { target, .. } | Self::Delete { target } => [Some(target.path()), None],
            Self::Rename { source, target } => [Some(source.path()), Some(target.path())],
        }
    }

    fn modes(&self) -> [Option<u32>; 3] {
        let observed_mode = |path: &ObservedPath| match path.state() {
            ObservedState::Absent => None,
            ObservedState::File { mode, .. } => Some(*mode),
        };
        match self {
            Self::Write { target, mode, .. } => [Some(*mode), observed_mode(target), None],
            Self::Rename { source, target } => [observed_mode(source), observed_mode(target), None],
            Self::Delete { target } => [observed_mode(target), None, None],
        }
    }

    fn has_valid_observed_states(&self) -> bool {
        match self {
            Self::Write { .. } => true,
            Self::Rename { source, target } => {
                matches!(source.state(), ObservedState::File { .. })
                    && matches!(target.state(), ObservedState::Absent)
            }
            Self::Delete { target } => matches!(target.state(), ObservedState::File { .. }),
        }
    }
}

/// A validated, immutable set of exact filesystem changes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WritePlan {
    operations: Vec<WriteOperation>,
}

impl WritePlan {
    pub fn new(operations: Vec<WriteOperation>) -> Result<Self, WritePlanError> {
        let plan = Self { operations };
        plan.validate()?;
        Ok(plan)
    }

    pub fn operations(&self) -> &[WriteOperation] {
        &self.operations
    }

    pub fn encode(&self) -> Result<Vec<u8>, WritePlanError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(WritePlanError::Json)
    }

    pub fn decode_verified(
        bytes: &[u8],
        expected_sha256: &[u8; 32],
    ) -> Result<Self, WritePlanError> {
        if Sha256::digest(bytes).as_slice() != expected_sha256 {
            return Err(WritePlanError::HashMismatch);
        }

        let plan: Self = serde_json::from_slice(bytes).map_err(WritePlanError::Json)?;
        plan.validate()?;
        if plan.encode()? != bytes {
            return Err(WritePlanError::NonCanonicalEncoding);
        }
        Ok(plan)
    }

    fn validate(&self) -> Result<(), WritePlanError> {
        if self.operations.len() > MAX_OPERATIONS {
            return Err(WritePlanError::TooManyOperations);
        }

        let mut paths = HashSet::new();
        let mut total = 0usize;
        for operation in &self.operations {
            let output_len = operation.output_len();
            if output_len > MAX_OPERATION_OUTPUT_BYTES {
                return Err(WritePlanError::OperationOutputTooLarge);
            }
            total = total
                .checked_add(output_len)
                .ok_or(WritePlanError::PlanOutputTooLarge)?;
            if total > MAX_PLAN_OUTPUT_BYTES {
                return Err(WritePlanError::PlanOutputTooLarge);
            }

            if operation
                .modes()
                .into_iter()
                .flatten()
                .any(|mode| mode & !0o7777 != 0)
            {
                return Err(WritePlanError::InvalidMode);
            }
            if !operation.has_valid_observed_states() {
                return Err(WritePlanError::InvalidObservedState);
            }

            for path in operation.paths().into_iter().flatten() {
                if path.is_empty() {
                    return Err(WritePlanError::EmptyPath);
                }
                if !paths.insert(path) {
                    return Err(WritePlanError::ConflictingPath(path.to_owned()));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum WritePlanError {
    TooManyOperations,
    OperationOutputTooLarge,
    PlanOutputTooLarge,
    EmptyPath,
    InvalidMode,
    InvalidObservedState,
    ConflictingPath(String),
    HashMismatch,
    NonCanonicalEncoding,
    Json(serde_json::Error),
}

impl fmt::Display for WritePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOperations => formatter.write_str("write plan has too many operations"),
            Self::OperationOutputTooLarge => {
                formatter.write_str("write operation output is too large")
            }
            Self::PlanOutputTooLarge => formatter.write_str("write plan output is too large"),
            Self::EmptyPath => formatter.write_str("write plan path is empty"),
            Self::InvalidMode => formatter.write_str("write plan mode is invalid"),
            Self::InvalidObservedState => {
                formatter.write_str("write operation contradicts the observed state")
            }
            Self::ConflictingPath(path) => write!(formatter, "write plan repeats path {path}"),
            Self::HashMismatch => formatter.write_str("write plan SHA-256 does not match"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("write plan JSON is not in its canonical form")
            }
            Self::Json(error) => write!(formatter, "invalid write plan JSON: {error}"),
        }
    }
}

impl std::error::Error for WritePlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}
