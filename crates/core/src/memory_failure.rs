//! Stable failures returned by the memory-search tool.

use crate::memory_index::MemoryIndexError;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryFailure {
    pub kind: &'static str,
    pub message: &'static str,
}

impl MemoryFailure {
    pub fn from_index_error(error: MemoryIndexError) -> Self {
        match error {
            MemoryIndexError::InvalidToolArguments => Self {
                kind: "invalid_tool_arguments",
                message: "The memory search arguments are invalid.",
            },
            MemoryIndexError::LimitRaised => Self {
                kind: "limit_raised",
                message: "The memory search requested a limit above the configured limit.",
            },
            MemoryIndexError::QueryTooLong => Self {
                kind: "query_too_long",
                message: "The memory search query is too long.",
            },
            MemoryIndexError::TimedOut => Self {
                kind: "timed_out",
                message: "The memory search timed out.",
            },
            MemoryIndexError::SecretRejected => Self {
                kind: "secret_rejected",
                message: "The memory search rejected content that contains a secret.",
            },
            MemoryIndexError::InvalidPath => Self {
                kind: "invalid_path",
                message: "The memory search found an invalid path.",
            },
            MemoryIndexError::Sqlite(_) => Self {
                kind: "sqlite",
                message: "The memory search database failed.",
            },
            MemoryIndexError::Io(_) => Self {
                kind: "io",
                message: "The memory search input or output operation failed.",
            },
        }
    }

    pub fn missing_prefill() -> Self {
        Self {
            kind: "missing_prefill",
            message: "The memory search arguments are missing.",
        }
    }

    pub fn runtime_unavailable() -> Self {
        Self {
            kind: "runtime_unavailable",
            message: "The memory search runtime is unavailable.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryFailureAnswer {
    pub error: MemoryFailure,
}

impl From<MemoryFailure> for MemoryFailureAnswer {
    fn from(error: MemoryFailure) -> Self {
        Self { error }
    }
}
