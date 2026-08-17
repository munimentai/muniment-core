use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path, time::Duration};

const RECORD_FILE: &str = "thread-retention.json";
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
pub const RETENTION_CHECK_INTERVAL: Duration = Duration::from_secs(SECONDS_PER_DAY);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionChoice {
    KeepEveryThread,
    DeleteAfter30Days,
    DeleteAfter90Days,
    DeleteAfter1Year,
}

impl RetentionChoice {
    pub const fn max_age_seconds(self) -> Option<u64> {
        match self {
            Self::KeepEveryThread => None,
            Self::DeleteAfter30Days => Some(30 * SECONDS_PER_DAY),
            Self::DeleteAfter90Days => Some(90 * SECONDS_PER_DAY),
            Self::DeleteAfter1Year => Some(365 * SECONDS_PER_DAY),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct RetentionRecord {
    choice: RetentionChoice,
}

pub fn read_retention_choice(config_dir: &Path) -> Option<RetentionChoice> {
    let bytes = fs::read(config_dir.join(RECORD_FILE)).ok()?;
    serde_json::from_slice::<RetentionRecord>(&bytes)
        .ok()
        .map(|record| record.choice)
}

/// Reads the current choice and applies its age limit when one is recorded.
pub fn apply_recorded_retention<T, E>(
    config_dir: &Path,
    apply: impl FnOnce(i64) -> Result<T, E>,
) -> Result<Option<T>, E> {
    let Some(max_age_seconds) = read_retention_choice(config_dir)
        .and_then(RetentionChoice::max_age_seconds)
        .and_then(|seconds| i64::try_from(seconds).ok())
    else {
        return Ok(None);
    };
    apply(max_age_seconds).map(Some)
}

/// Checks recorded retention at startup and after each requested wait.
pub fn run_recorded_retention_checks<E>(
    config_dir: &Path,
    mut wait_for_next: impl FnMut(Duration) -> bool,
    mut apply: impl FnMut(i64) -> Result<(), E>,
) {
    loop {
        let _ = apply_recorded_retention(config_dir, &mut apply);
        if !wait_for_next(RETENTION_CHECK_INTERVAL) {
            break;
        }
    }
}

pub fn write_retention_choice(config_dir: &Path, choice: RetentionChoice) -> io::Result<()> {
    fs::create_dir_all(config_dir)?;
    let contents =
        serde_json::to_vec_pretty(&RetentionRecord { choice }).map_err(io::Error::other)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(config_dir.join("thread-retention.lock"))?;
    lock.lock_exclusive()?;
    let destination = config_dir.join(RECORD_FILE);
    let temporary = config_dir.join(format!("{RECORD_FILE}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        io::Write::write_all(&mut file, &contents)?;
        file.sync_all()?;
        replace_file(&temporary, &destination)?;
        sync_directory(config_dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(not(target_os = "windows"))]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    if !destination.exists() {
        return fs::rename(source, destination);
    }

    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let replaced = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "muniment-retention-record-{}-{name}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn choices_round_trip() {
        let directory = test_directory("round-trip");
        for choice in [
            RetentionChoice::KeepEveryThread,
            RetentionChoice::DeleteAfter30Days,
            RetentionChoice::DeleteAfter90Days,
            RetentionChoice::DeleteAfter1Year,
        ] {
            write_retention_choice(&directory, choice).unwrap();
            assert_eq!(read_retention_choice(&directory), Some(choice));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn age_limits_use_spec_day_counts() {
        assert_eq!(RetentionChoice::KeepEveryThread.max_age_seconds(), None);
        assert_eq!(
            RetentionChoice::DeleteAfter30Days.max_age_seconds(),
            Some(30 * SECONDS_PER_DAY)
        );
        assert_eq!(
            RetentionChoice::DeleteAfter90Days.max_age_seconds(),
            Some(90 * SECONDS_PER_DAY)
        );
        assert_eq!(
            RetentionChoice::DeleteAfter1Year.max_age_seconds(),
            Some(365 * SECONDS_PER_DAY)
        );
    }

    #[test]
    fn missing_record_has_no_choice() {
        assert_eq!(read_retention_choice(&test_directory("missing")), None);
    }

    #[test]
    fn unreadable_record_has_no_choice() {
        let directory = test_directory("unreadable");
        fs::create_dir_all(directory.join(RECORD_FILE)).unwrap();
        assert_eq!(read_retention_choice(&directory), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_record_has_no_choice() {
        let directory = test_directory("malformed");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(RECORD_FILE), b"not json").unwrap();
        assert_eq!(read_retention_choice(&directory), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unrecognized_record_has_no_choice() {
        let directory = test_directory("unrecognized");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(RECORD_FILE),
            br#"{"choice":"delete_after_7_days"}"#,
        )
        .unwrap();
        assert_eq!(read_retention_choice(&directory), None);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recorded_retention_applies_only_age_limits() {
        let directory = test_directory("apply");
        let mut applied = Vec::new();
        assert_eq!(
            apply_recorded_retention(&directory, |age| {
                applied.push(age);
                Ok::<_, ()>(())
            }),
            Ok(None)
        );
        write_retention_choice(&directory, RetentionChoice::KeepEveryThread).unwrap();
        assert_eq!(
            apply_recorded_retention(&directory, |age| {
                applied.push(age);
                Ok::<_, ()>(())
            }),
            Ok(None)
        );
        write_retention_choice(&directory, RetentionChoice::DeleteAfter30Days).unwrap();
        assert_eq!(
            apply_recorded_retention(&directory, |age| {
                applied.push(age);
                Ok::<_, ()>(())
            }),
            Ok(Some(()))
        );
        assert_eq!(applied, vec![30 * SECONDS_PER_DAY as i64]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recorded_retention_checks_at_startup_and_after_each_wait() {
        let directory = test_directory("schedule");
        write_retention_choice(&directory, RetentionChoice::DeleteAfter30Days).unwrap();
        let mut waits = Vec::new();
        let mut applied = Vec::new();

        run_recorded_retention_checks(
            &directory,
            |interval| {
                waits.push(interval);
                waits.len() < 3
            },
            |age| {
                applied.push(age);
                Ok::<_, ()>(())
            },
        );

        assert_eq!(waits, vec![RETENTION_CHECK_INTERVAL; 3]);
        assert_eq!(applied, vec![30 * SECONDS_PER_DAY as i64; 3]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recorded_retention_checks_read_the_record_again_after_waiting() {
        let directory = test_directory("schedule-record-change");
        write_retention_choice(&directory, RetentionChoice::DeleteAfter30Days).unwrap();
        let mut wait_count = 0;
        let mut applied = Vec::new();

        run_recorded_retention_checks(
            &directory,
            |_| {
                wait_count += 1;
                if wait_count == 1 {
                    write_retention_choice(&directory, RetentionChoice::DeleteAfter90Days).unwrap();
                    true
                } else {
                    false
                }
            },
            |age| {
                applied.push(age);
                Ok::<_, ()>(())
            },
        );

        assert_eq!(
            applied,
            vec![30 * SECONDS_PER_DAY as i64, 90 * SECONDS_PER_DAY as i64]
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
