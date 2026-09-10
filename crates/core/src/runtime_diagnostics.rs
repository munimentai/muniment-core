//! Runtime diagnostics retain stderr output and also reach a bounded file on macOS.

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
    eprintln!("{arguments}");
}

/// The sink appends one diagnostic to the owner-only runtime service log.
#[cfg(unix)]
pub fn write_runtime_service_record(
    directory: &std::path::Path,
    arguments: std::fmt::Arguments<'_>,
) -> std::io::Result<()> {
    let mut record = arguments.to_string();
    // Leave room for the newline, even when a diagnostic exceeds the whole file cap.
    let mut end = record.len().min(RUNTIME_LOG_MAX_BYTES as usize - 1);
    while !record.is_char_boundary(end) {
        end -= 1;
    }
    record.truncate(end);
    record.push('\n');
    crate::user_diagnostics::append_owner_only_record(
        directory,
        c"runtime-service.log",
        RUNTIME_LOG_MAX_BYTES,
        record.as_bytes(),
    )
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
