//! Crash-safe, non-destructive journal compaction.

use super::{open_journal_connection, JournalError, RunJournal};
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug)]
pub enum CompactionError {
    UnsupportedInMemory,
    Journal(JournalError),
    Io(io::Error),
    #[doc(hidden)]
    Injected(CompactionFault),
}

impl fmt::Display for CompactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedInMemory => {
                formatter.write_str("in-memory journals cannot be compacted")
            }
            Self::Journal(error) => write!(formatter, "journal compaction failed: {error}"),
            Self::Io(error) => write!(formatter, "journal compaction I/O failed: {error}"),
            Self::Injected(point) => write!(formatter, "injected compaction failure at {point:?}"),
        }
    }
}

impl std::error::Error for CompactionError {}

impl From<JournalError> for CompactionError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<rusqlite::Error> for CompactionError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Journal(JournalError::Sqlite(error))
    }
}

impl From<io::Error> for CompactionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactionFault {
    BeforeSnapshotCompletion,
    BeforeReplacement,
    DuringReplacement,
    AfterReplacementBeforeDirectorySync,
    AfterReplacementBeforeDirectorySyncAndReopen,
}

#[derive(Debug)]
enum ReplacementError {
    NotReplaced(io::Error),
    Replaced(io::Error),
}

impl RunJournal {
    /// Rewrites the journal into a compact snapshot and atomically installs it.
    ///
    /// Source events and CAS objects are not deleted by this operation.
    pub fn compact(&mut self) -> Result<(), CompactionError> {
        self.compact_with_fault(None)
    }

    #[doc(hidden)]
    pub fn compact_with_fault(
        &mut self,
        fault: Option<CompactionFault>,
    ) -> Result<(), CompactionError> {
        let path = self
            .path
            .clone()
            .ok_or(CompactionError::UnsupportedInMemory)?;
        let temporary = unique_temporary_path(&path)?;
        let result = self.compact_to(&path, &temporary, fault, None);
        let _ = fs::remove_file(&temporary);
        result
    }

    #[doc(hidden)]
    pub fn compact_with_close_hook(
        &mut self,
        hook: &mut dyn FnMut(),
    ) -> Result<(), CompactionError> {
        let path = self
            .path
            .clone()
            .ok_or(CompactionError::UnsupportedInMemory)?;
        let temporary = unique_temporary_path(&path)?;
        let result = self.compact_to(&path, &temporary, None, Some(hook));
        let _ = fs::remove_file(&temporary);
        result
    }

    fn compact_to(
        &mut self,
        path: &Path,
        temporary: &Path,
        fault: Option<CompactionFault>,
        mut close_hook: Option<&mut dyn FnMut()>,
    ) -> Result<(), CompactionError> {
        let coordination = self
            .coordination
            .clone()
            .expect("file journal is coordinated");
        let _operation = coordination.operation.lock().unwrap();
        // A peer may have replaced the database since this handle was opened.
        // Refresh while holding the operation lock so a stale inode can never
        // become the source of a new compacted snapshot.
        self.refresh_after_compaction()?;
        let connection = self
            .connection
            .as_ref()
            .expect("journal connection is present");
        // The journal coordination guard excludes all RunJournal mutations
        // continuously across the SQLite and filesystem phases. Avoid retained
        // SQLite exclusive locking, which would also block idle peer handles.
        let snapshot_result = (|| {
            connection
                .execute_batch("BEGIN EXCLUSIVE; COMMIT; PRAGMA wal_checkpoint(TRUNCATE);")?;

            if fault == Some(CompactionFault::BeforeSnapshotCompletion) {
                return Err(CompactionError::Injected(
                    CompactionFault::BeforeSnapshotCompletion,
                ));
            }
            connection.execute("VACUUM INTO ?1", [temporary.to_string_lossy().as_ref()])?;
            File::open(temporary)?.sync_all()?;

            if fault == Some(CompactionFault::BeforeReplacement) {
                return Err(CompactionError::Injected(
                    CompactionFault::BeforeReplacement,
                ));
            }
            Ok(())
        })();
        if let Err(error) = snapshot_result {
            // Reopen after any SQLite compaction error so the original journal
            // remains immediately usable by this instance.
            let old = self
                .connection
                .take()
                .expect("journal connection is present");
            drop(old);
            self.connection = Some(open_connection(path)?);
            return Err(error);
        }

        // Closing releases SQLite's handles and retained exclusive lock. The
        // fully synced snapshot is the only file eligible for replacement.
        let old = self
            .connection
            .take()
            .expect("journal connection is present");
        if let Err((connection, error)) = old.close() {
            drop(connection);
            self.connection = Some(open_connection(path)?);
            return Err(error.into());
        }
        if let Some(hook) = close_hook.as_mut() {
            hook();
        }
        if fault == Some(CompactionFault::DuringReplacement) {
            let missing = temporary.with_extension("missing");
            debug_assert!(!missing.exists());
            // Exercise the platform replacement call itself against the live,
            // existing destination, but with a source that cannot be moved.
            let replacement_failed = atomic_replace(&missing, path, false).is_err();
            self.connection = Some(open_connection(path)?);
            if !replacement_failed {
                return Err(io::Error::other("replacement fault unexpectedly succeeded").into());
            }
            return Err(CompactionError::Injected(
                CompactionFault::DuringReplacement,
            ));
        }
        let fail_after_replace = matches!(
            fault,
            Some(CompactionFault::AfterReplacementBeforeDirectorySync)
                | Some(CompactionFault::AfterReplacementBeforeDirectorySyncAndReopen)
        );
        if let Err(error) = atomic_replace(temporary, path, fail_after_replace) {
            let replaced = matches!(error, ReplacementError::Replaced(_));
            if replaced {
                // The pathname already names the snapshot. Publish that fact
                // even though its directory durability could not be confirmed,
                // so peers cannot remain attached to the unlinked database.
                coordination
                    .generation
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
            if fault == Some(CompactionFault::AfterReplacementBeforeDirectorySyncAndReopen) {
                return Err(CompactionError::Injected(
                    CompactionFault::AfterReplacementBeforeDirectorySyncAndReopen,
                ));
            }
            let connection = open_connection(path)?;
            self.connection = Some(connection);
            self.generation = coordination
                .generation
                .load(std::sync::atomic::Ordering::Acquire);
            if fail_after_replace && replaced {
                return Err(CompactionError::Injected(
                    CompactionFault::AfterReplacementBeforeDirectorySync,
                ));
            }
            let error = match error {
                ReplacementError::NotReplaced(error) | ReplacementError::Replaced(error) => error,
            };
            return Err(error.into());
        }
        let generation = coordination
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;
        let connection = open_connection(path)?;
        self.connection = Some(connection);
        self.generation = generation;
        Ok(())
    }
}

fn open_connection(path: &Path) -> Result<rusqlite::Connection, CompactionError> {
    open_journal_connection(path).map_err(Into::into)
}

fn unique_temporary_path(path: &Path) -> Result<PathBuf, CompactionError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "journal path has no file name")
    })?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| io::Error::other(format!("temporary name randomness failed: {error}")))?;
    Ok(parent.join(format!(
        ".{}.compact-{}.sqlite3",
        name.to_string_lossy(),
        Uuid::from_bytes(random)
    )))
}

#[cfg(unix)]
fn atomic_replace(
    temporary: &Path,
    destination: &Path,
    fail_after_replace: bool,
) -> Result<(), ReplacementError> {
    fs::rename(temporary, destination).map_err(ReplacementError::NotReplaced)?;
    if fail_after_replace {
        return Err(ReplacementError::Replaced(io::Error::other(
            "injected failure before directory sync",
        )));
    }
    File::open(destination.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(ReplacementError::Replaced)
}

#[cfg(windows)]
fn atomic_replace(
    temporary: &Path,
    destination: &Path,
    fail_after_replace: bool,
) -> Result<(), ReplacementError> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let existing: Vec<_> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let new: Vec<_> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that live
    // for the call, and MoveFileExW retains neither pointer.
    let replaced = unsafe {
        MoveFileExW(
            existing.as_ptr(),
            new.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(ReplacementError::NotReplaced(io::Error::last_os_error()))
    } else if fail_after_replace {
        Err(ReplacementError::Replaced(io::Error::other(
            "injected failure after replacement",
        )))
    } else {
        Ok(())
    }
}
