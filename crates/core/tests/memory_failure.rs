use muniment_core::memory_failure::MemoryFailure;
use muniment_core::memory_index::MemoryIndexError;
use rusqlite::ffi::ErrorCode;
use std::io;

#[test]
fn every_memory_index_error_has_a_distinct_named_failure() {
    let failures = [
        MemoryFailure::from_index_error(MemoryIndexError::InvalidToolArguments),
        MemoryFailure::from_index_error(MemoryIndexError::LimitRaised),
        MemoryFailure::from_index_error(MemoryIndexError::QueryTooLong),
        MemoryFailure::from_index_error(MemoryIndexError::TimedOut),
        MemoryFailure::from_index_error(MemoryIndexError::SecretRejected),
        MemoryFailure::from_index_error(MemoryIndexError::InvalidPath),
        MemoryFailure::from_index_error(MemoryIndexError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(ErrorCode::DatabaseBusy as i32),
            None,
        ))),
        MemoryFailure::from_index_error(MemoryIndexError::Io(io::Error::other("test"))),
    ];

    let expected = [
        ("invalid_tool_arguments", "arguments"),
        ("limit_raised", "limit"),
        ("query_too_long", "query"),
        ("timed_out", "timed out"),
        ("secret_rejected", "secret"),
        ("invalid_path", "path"),
        ("sqlite", "database"),
        ("io", "input or output"),
    ];

    for (failure, (kind, named_failure)) in failures.iter().zip(expected) {
        assert_eq!(failure.kind, kind);
        assert!(failure.message.contains(named_failure));
        assert!(failure.message.ends_with('.'));
    }

    for (index, failure) in failures.iter().enumerate() {
        assert!(failures[index + 1..]
            .iter()
            .all(|other| other.kind != failure.kind));
    }
}
