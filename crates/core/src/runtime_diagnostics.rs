//! Runtime diagnostics retain stderr output and reach a bounded file on macOS and Windows.

/// The runtime logs each hold at most 256 KiB.
pub const RUNTIME_LOG_MAX_BYTES: u64 = 256 * 1024;

/// The runtime prints each diagnostic with the existing stderr format.
#[macro_export]
macro_rules! runtime_eprintln {
    ($($argument:tt)*) => {
        $crate::runtime_diagnostics::emit(format_args!($($argument)*))
    };
}

#[doc(hidden)]
pub fn emit(arguments: std::fmt::Arguments<'_>) {
    #[cfg(target_os = "macos")]
    {
        let result = crate::user_diagnostics::effective_user_home().and_then(|home| {
            write_runtime_service_record(&home.join("Library/Logs/Muniment"), arguments)
        });
        if let Err(error) = result {
            eprintln!("muniment-runtime: The runtime service log failed: {error}.");
        }
    }
    #[cfg(target_os = "windows")]
    {
        let result = crate::windows_known_folders::windows_local_app_data()
            .map_err(|error| std::io::Error::other(format!("{error:?}")))
            .and_then(|root| write_windows_runtime_record(&root, arguments));
        if let Err(error) = result {
            eprintln!("muniment-runtime: The runtime log failed: {error}.");
        }
    }
    eprintln!("{arguments}");
}

/// The sink appends one diagnostic to the owner-only runtime service log.
#[cfg(unix)]
pub fn write_runtime_service_record(
    directory: &std::path::Path,
    arguments: std::fmt::Arguments<'_>,
) -> std::io::Result<()> {
    crate::user_diagnostics::append_owner_only_record(
        directory,
        c"runtime-service.log",
        RUNTIME_LOG_MAX_BYTES,
        &bounded_record(arguments),
    )
}

#[cfg(target_os = "windows")]
fn write_windows_runtime_record(
    root: &std::path::Path,
    arguments: std::fmt::Arguments<'_>,
) -> std::io::Result<()> {
    if !root.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "The local application data path must be absolute.",
        ));
    }
    crate::windows_user_diagnostics::append_owner_only_record(
        root,
        &root.join("ai.muniment.desktop/logs"),
        RUNTIME_LOG_MAX_BYTES,
        &bounded_record(arguments),
    )
}

fn bounded_record(arguments: std::fmt::Arguments<'_>) -> Vec<u8> {
    let mut record = arguments.to_string();
    // Leave room for the newline, even when a diagnostic exceeds the whole file cap.
    let mut end = record.len().min(RUNTIME_LOG_MAX_BYTES as usize - 1);
    while !record.is_char_boundary(end) {
        end -= 1;
    }
    record.truncate(end);
    record.push('\n');
    record.into_bytes()
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;
    use std::fs;

    #[test]
    fn run_and_auth_records_share_the_bounded_owner_only_log() {
        let root = std::env::temp_dir().join(format!("muniment-log-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let log = root.join("ai.muniment.desktop/logs/runtime.log");
        let write = |record: &str| {
            write_windows_runtime_record(&root, format_args!("{record}")).unwrap();
        };
        write("muniment-runtime: run_id=test run_start");
        write("muniment-runtime: native-auth failure stage=registration error=Persistence");
        let contents = fs::read_to_string(&log).unwrap();
        assert!(contents.contains("run_id=test run_start\n"));
        assert!(contents.contains("native-auth failure stage=registration error=Persistence\n"));
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    barrier.wait();
                    write("muniment-runtime: run_id=test first_event text_delta");
                });
            }
        });
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 10);
        write(&"🦀".repeat(RUNTIME_LOG_MAX_BYTES as usize));
        let contents = fs::read_to_string(&log).unwrap();
        assert!(contents.ends_with("🦀\n"));
        assert!(contents.len() as u64 <= RUNTIME_LOG_MAX_BYTES);
        write("muniment-runtime: run_id=test provider_request outcome=failed");
        let contents = fs::read_to_string(&log).unwrap();
        assert_eq!(contents.lines().count(), 1);
        fs::hard_link(&log, root.join("linked.log")).unwrap();
        assert!(write_windows_runtime_record(&root, format_args!("rejected")).is_err());
        assert_eq!(fs::read_to_string(&log).unwrap(), contents);
        assert!(write_windows_runtime_record(
            std::path::Path::new("relative"),
            format_args!("rejected")
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct Logs(PathBuf);

    impl Logs {
        fn new() -> Self {
            Self(
                std::env::temp_dir().join(format!("muniment-diagnostics-{}", uuid::Uuid::new_v4())),
            )
        }

        fn file(&self) -> PathBuf {
            self.0.join("runtime-service.log")
        }

        fn write(&self, record: &str) {
            write_runtime_service_record(&self.0, format_args!("{record}")).unwrap();
        }
    }

    impl Drop for Logs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn writes_each_record_and_caps_at_the_runtime_log_limit() {
        let logs = Logs::new();
        logs.write("muniment-runtime: started version=test");
        logs.write("muniment-runtime: run_id=test run_start");
        logs.write("");
        assert_eq!(
            fs::read_to_string(logs.file()).unwrap(),
            "muniment-runtime: started version=test\nmuniment-runtime: run_id=test run_start\n\n"
        );
        assert_eq!(
            fs::metadata(&logs.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(logs.file()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let used = fs::metadata(logs.file()).unwrap().len();
        logs.write(&"x".repeat((RUNTIME_LOG_MAX_BYTES - used - 1) as usize));
        assert_eq!(
            fs::metadata(logs.file()).unwrap().len(),
            RUNTIME_LOG_MAX_BYTES
        );
        assert!(fs::read_to_string(logs.file())
            .unwrap()
            .starts_with("muniment-runtime: started"));
        logs.write("muniment-runtime: run_id=test first_event text_delta");
        assert_eq!(
            fs::read_to_string(logs.file()).unwrap(),
            "muniment-runtime: run_id=test first_event text_delta\n"
        );
    }

    #[test]
    fn caps_an_oversized_record_without_splitting_utf8() {
        let logs = Logs::new();
        logs.write(&"🦀".repeat(RUNTIME_LOG_MAX_BYTES as usize));
        let contents = fs::read_to_string(logs.file()).unwrap();
        assert!(contents.len() as u64 <= RUNTIME_LOG_MAX_BYTES);
        assert!(contents.ends_with("🦀\n"));
        logs.write("x");
        assert!(fs::metadata(logs.file()).unwrap().len() <= RUNTIME_LOG_MAX_BYTES);
    }

    #[test]
    fn concurrent_writers_create_the_directory_and_keep_whole_records() {
        let logs = Logs::new();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let logs = &logs;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..16 {
                        logs.write(&format!("muniment-runtime: run_id={index} run_start"));
                    }
                });
            }
        });
        let contents = fs::read_to_string(logs.file()).unwrap();
        assert_eq!(contents.lines().count(), 128);
        for index in 0..8 {
            let record = format!("muniment-runtime: run_id={index} run_start");
            assert_eq!(contents.lines().filter(|line| *line == record).count(), 16);
        }
    }

    #[test]
    fn rejects_unsafe_paths_without_writing() {
        let logs = Logs::new();
        logs.write("original");
        fs::set_permissions(logs.file(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(write_runtime_service_record(&logs.0, format_args!("rejected")).is_err());
        assert_eq!(fs::read_to_string(logs.file()).unwrap(), "original\n");
        fs::set_permissions(logs.file(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&logs.0, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(write_runtime_service_record(&logs.0, format_args!("rejected")).is_err());
        fs::set_permissions(&logs.0, fs::Permissions::from_mode(0o700)).unwrap();

        let linked = Logs::new();
        symlink(&logs.0, &linked.0).unwrap();
        assert!(write_runtime_service_record(&linked.0, format_args!("rejected")).is_err());
        fs::remove_file(&linked.0).unwrap();
        fs::rename(logs.file(), logs.0.join("target")).unwrap();
        symlink(logs.0.join("target"), logs.file()).unwrap();
        assert!(write_runtime_service_record(&logs.0, format_args!("rejected")).is_err());
        assert_eq!(
            fs::read_to_string(logs.0.join("target")).unwrap(),
            "original\n"
        );
    }
}
