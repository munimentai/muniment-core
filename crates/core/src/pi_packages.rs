//! The candidate acquires packages through the verified Pi executable's embedded Bun runtime.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde_json::Value;

pub const PI_PACKAGES: [(&str, &str); 5] = [
    ("pi-web-access", "0.28.0"),
    ("pi-subagents", "0.65.1"),
    ("pi-background-tasks", "2.5.0"),
    ("pi-mcp-adapter", "2.34.0"),
    ("pi-claude-bridge", "0.7.0"),
];

fn installed(directory: &Path) -> bool {
    PI_PACKAGES.iter().all(|(name, version)| {
        fs::read(
            directory
                .join("node_modules")
                .join(name)
                .join("package.json"),
        )
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|manifest| manifest["version"] == *version)
    })
}

#[cfg(windows)]
fn bun_install_directory(directory: &Path) -> std::path::PathBuf {
    use std::ffi::OsString;
    use std::path::{Component, Prefix};

    let mut components = directory.components();
    let mut plain = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(drive) => OsString::from(format!("{}:", char::from(drive))),
            Prefix::VerbatimUNC(server, share) => {
                let mut plain = OsString::from(r"\\");
                plain.push(server);
                plain.push("\\");
                plain.push(share);
                plain
            }
            _ => return directory.to_owned(),
        },
        _ => return directory.to_owned(),
    };
    plain.push(components.as_path());
    plain.into()
}

fn install_command(executable: &Path, directory: &Path) -> Command {
    // Bun joins package.json with a forward slash, which Windows verbatim paths reject.
    #[cfg(windows)]
    let directory = bun_install_directory(directory);
    #[cfg(windows)]
    let directory = directory.as_path();
    let mut command = Command::new(executable);
    command
        // Bun's documented BUN_BE_BUN switch exposes the embedded package manager.
        // Scope it to acquisition. The RPC process must run Pi's entrypoint.
        .env("BUN_BE_BUN", "1")
        .arg("install")
        .args(
            PI_PACKAGES
                .iter()
                .map(|(name, version)| format!("{name}@{version}")),
        )
        .args(["--omit=peer", "--ignore-scripts", "--exact", "--cwd"])
        .arg(directory)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

struct PollingStderr(std::process::ChildStderr);

impl PollingStderr {
    fn new(stderr: std::process::ChildStderr) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // The reader owns this pipe. Nonblocking reads let cancellation close it without a race.
            let fd = stderr.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags == -1
                || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(stderr))
    }
}

impl Read for PollingStderr {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
            use windows_sys::Win32::System::Pipes::PeekNamedPipe;
            let mut available = 0;
            // This thread owns the only reader, so bytes from the peek remain available for the read.
            if unsafe {
                PeekNamedPipe(
                    self.0.as_raw_handle(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    Ok(0)
                } else {
                    Err(error)
                };
            }
            if available == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let length = buffer.len().min(available as usize);
            return self.0.read(&mut buffer[..length]);
        }
        #[cfg(not(windows))]
        self.0.read(buffer)
    }
}

fn capture_stderr(mut reader: impl Read, cancelled: &AtomicBool) -> VecDeque<String> {
    let mut tail = VecDeque::new();
    let mut redactor = crate::pi_launch::DiagnosticRedactor::new();
    let mut buffer = [0; 4096];
    let mut line = Vec::new();
    let mut suppressed = false;
    loop {
        let count = if cancelled.load(Ordering::Acquire) {
            0
        } else {
            match reader.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                // Flush the pending fragment on EOF, cancellation, or a read error.
                Err(_) => 0,
            }
        };
        for byte in buffer[..count]
            .iter()
            .copied()
            .chain((count == 0).then_some(b'\n'))
        {
            if suppressed {
                continue;
            }
            if byte == b'\n' {
                let text = String::from_utf8_lossy(&line);
                let detail = redactor.line(&text);
                if !detail.is_empty() {
                    if tail.len() == 20 {
                        tail.pop_front();
                    }
                    tail.push_back(detail);
                }
                line.clear();
            } else if line.len() < 65_536 {
                line.push(byte);
            } else {
                // Discarded bytes can start a multiline credential. Suppress all later output but keep draining the pipe.
                suppressed = true;
                line.clear();
                if tail.len() == 20 {
                    tail.pop_front();
                }
                tail.push_back("[redacted]".into());
            }
        }
        if count == 0 {
            break;
        }
    }
    tail
}

#[cfg(test)]
pub(crate) fn captured_stderr_for_test(input: &[u8]) -> String {
    stderr_tail_text(capture_stderr(input, &AtomicBool::new(false)))
}

fn stderr_tail_text(tail: VecDeque<String>) -> String {
    let tail = tail.into_iter().collect::<Vec<_>>().join(" | ");
    // Bound the tail after redaction.
    tail.chars()
        .rev()
        .take(4096)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn install_failure(error: io::Error, tail: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{error} stderr_tail={tail}"))
}

fn run_install(command: &mut Command, timeout: Duration) -> io::Result<String> {
    let mut child = command.spawn()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let reader_cancelled = cancelled.clone();
    let stderr = child.stderr.take().expect("package install pipes stderr");
    let stderr = match PollingStderr::new(stderr) {
        Ok(stderr) => stderr,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let reader = match std::thread::Builder::new()
        .name("pi-package-stderr".into())
        .spawn(move || capture_stderr(stderr, &reader_cancelled))
    {
        Ok(reader) => reader,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let deadline = Instant::now() + timeout;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(status)) => {
                break Err(io::Error::other(format!(
                    "The agent runtime package install failed: {status}"
                )))
            }
            Err(error) => break Err(error),
            Ok(None) if Instant::now() >= deadline => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Pi package acquisition timed out.",
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // A descendant can keep stderr open after Bun exits. Bound the drain like the sidecar supervisor.
    let deadline = Instant::now() + Duration::from_millis(200);
    while !reader.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    cancelled.store(true, Ordering::Release);
    // The reader flushes its pending fragment and closes the pipe before the join returns.
    let tail = stderr_tail_text(
        reader
            .join()
            .map_err(|_| io::Error::other("The agent runtime package stderr reader panicked."))?,
    );
    result
        .map(|()| tail.clone())
        .map_err(|error| install_failure(error, &tail))
}

/// Acquire packages before RPC starts. The caller supplies the verified candidate executable.
pub fn prepare_pi_packages(agent_directory: &Path, executable: &Path) -> io::Result<()> {
    let directory = agent_directory.join("npm");
    fs::create_dir_all(&directory)?;
    // An OS lock releases on process death. Never hold Pi's settings lock during network access.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(".muniment-install.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => break,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
    let marker = directory.join(".muniment-packages.json");
    let identity = serde_json::to_vec(&PI_PACKAGES)?;
    // npm's lockfiles mean another package manager wrote this tree. Its files
    // are not this install, so the tree goes and the install starts over.
    let foreign_locks = [
        directory.join("package-lock.json"),
        directory.join("node_modules").join(".package-lock.json"),
    ];
    if foreign_locks.iter().any(|path| path.exists()) {
        for path in [&foreign_locks[0], &foreign_locks[1], &marker] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        match fs::remove_dir_all(directory.join("node_modules")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if fs::read(&marker).is_ok_and(|bytes| bytes == identity) && installed(&directory) {
        return Ok(());
    }
    // A failed or interrupted install must retry, even if it wrote the top-level manifests.
    match fs::remove_file(&marker) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("package.json"))
    {
        Ok(mut file) => file.write_all(b"{\"private\":true}")?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // Resolve relative overrides before --cwd changes Bun's working directory.
    let directory = fs::canonicalize(directory)?;
    let stderr_tail = run_install(
        &mut install_command(executable, &directory),
        Duration::from_secs(120),
    )?;
    if !installed(&directory) {
        return Err(install_failure(
            io::Error::other("Pi package acquisition did not install the pinned versions."),
            &stderr_tail,
        ));
    }
    let mut file = fs::File::create(marker)?;
    file.write_all(&identity)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_capture_bounds_output_and_redacts_before_retaining_the_tail() {
        let input = format!("{}\npassword=registry-secret\nhttps://user:pass@example.com/?token=hidden\n{}\nlast diagnostic", "detail\n".repeat(30), "x".repeat(70_000));
        let tail = capture_stderr(input.as_bytes(), &AtomicBool::new(false));
        assert_eq!(tail.len(), 20);
        assert_eq!(tail.back().unwrap(), "[redacted]");
        let text = tail.into_iter().collect::<Vec<_>>().join(" ");
        assert!(!text.contains("last diagnostic"));
        assert!(!text.contains("registry-secret"));
        assert!(!text.contains("hidden"));
        assert!(!text.contains(&"x".repeat(100)));
        assert!(text.contains("[redacted]"));
    }

    #[test]
    fn stderr_capture_preserves_diagnostics_at_the_line_limit() {
        for length in [65_535, 65_536] {
            let diagnostic: String = "x ".chars().cycle().take(length).collect();
            let input = format!("{diagnostic}\nlast diagnostic");
            let tail = capture_stderr(input.as_bytes(), &AtomicBool::new(false));
            assert_eq!(tail.len(), 2);
            assert_eq!(tail[0], "x ".repeat(4096));
            assert_eq!(tail[1], "last diagnostic");
        }
        let input = format!("{}\nlast diagnostic", "x".repeat(65_537));
        let tail = capture_stderr(input.as_bytes(), &AtomicBool::new(false));
        assert_eq!(tail.into_iter().collect::<Vec<_>>(), ["[redacted]"]);
    }

    #[test]
    #[cfg(unix)]
    fn failed_and_timed_out_installs_keep_stderr_and_exit_details() {
        for (script, timeout, expected) in [
            (
                "printf 'registry refused\\npassword=hidden-value\\n' >&2; exit 7",
                Duration::from_secs(2),
                "exit status: 7",
            ),
            (
                "printf 'registry stalled\\n' >&2; exec sleep 5",
                Duration::from_millis(100),
                "timed out",
            ),
        ] {
            let mut command = Command::new("sh");
            command.args(["-c", script]).stderr(Stdio::piped());
            let started = Instant::now();
            let error = run_install(&mut command, timeout).unwrap_err();
            assert!(started.elapsed() < Duration::from_secs(3));
            let detail = error.to_string();
            assert!(detail.contains(expected), "{detail}");
            assert!(detail.contains("stderr_tail=registry"), "{detail}");
            assert!(!detail.contains("hidden-value"));
        }
    }

    #[test]
    #[cfg(unix)]
    fn inherited_stderr_keeps_unterminated_fragments_without_waiting_for_descendants() {
        for (fragment, expected) in [
            ("registry refused", "registry refused"),
            (
                "registry refused password\\033[0m=short",
                "registry refused [redacted]",
            ),
            (
                "registry refused {\"password\":\\n\"opaque-credential\"}",
                "registry refused {\"[redacted]",
            ),
        ] {
            let mut command = Command::new("sh");
            command
                .args([
                    "-c",
                    "printf '%b' \"$1\" >&2; sleep 2 & exit 7",
                    "pi-stub",
                    fragment,
                ])
                .stderr(Stdio::piped());
            let started = Instant::now();
            let detail = run_install(&mut command, Duration::from_secs(3))
                .unwrap_err()
                .to_string();
            assert!(started.elapsed() < Duration::from_secs(1), "{detail}");
            assert!(detail.contains("exit status: 7"), "{detail}");
            assert!(detail.contains(expected), "{detail}");
            assert!(!detail.contains("short"), "{detail}");
            assert!(!detail.contains("opaque-credential"), "{detail}");
        }
    }

    #[test]
    fn cancellation_flushes_the_fragment_and_drops_the_reader() {
        struct PendingReader<'a> {
            cancelled: &'a AtomicBool,
            dropped: &'a AtomicBool,
        }
        impl Read for PendingReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let text = b"registry refused";
                buffer[..text.len()].copy_from_slice(text);
                self.cancelled.store(true, Ordering::Release);
                Ok(text.len())
            }
        }
        impl Drop for PendingReader<'_> {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        let cancelled = AtomicBool::new(false);
        let dropped = AtomicBool::new(false);
        let tail = capture_stderr(
            PendingReader {
                cancelled: &cancelled,
                dropped: &dropped,
            },
            &cancelled,
        );
        assert_eq!(tail.into_iter().collect::<Vec<_>>(), ["registry refused"]);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    #[cfg(unix)]
    fn missing_pinned_versions_keep_stderr_without_publishing_a_marker() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("muniment-package-version-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("pi-stub");
        fs::write(
            &executable,
            "#!/bin/sh\nprintf 'registry returned incomplete packages\\n' >&2\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let error = prepare_pi_packages(&root, &executable)
            .unwrap_err()
            .to_string();
        assert!(error.contains("did not install the pinned versions"));
        assert!(error.contains("stderr_tail=registry returned incomplete packages"));
        assert!(!root.join("npm/.muniment-packages.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn config_accepts_verbatim_session_root_and_agent_directory() {
        use crate::sidecar::pi_install::PI_CANDIDATE_ARTIFACT;
        let root = std::env::temp_dir().join(format!("muniment-verbatim-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("sessions")).unwrap();
        let root = root.canonicalize().unwrap();
        assert!(root.to_string_lossy().starts_with(r"\\?\"));
        let sessions = root.join("sessions");
        let agent = root.join("agent with spaces");
        let directory =
            crate::pi_settings::pi_agent_directory(&root, Some(agent.as_os_str())).unwrap();
        assert_eq!(directory, agent);
        crate::pi_settings::store_pi_settings(&agent.join("settings.json"), PI_CANDIDATE_ARTIFACT)
            .unwrap();
        let config = crate::sidecar::pi_sidecar_config("pi.exe", &sessions, None).unwrap();
        assert_eq!(config.args[3], sessions.to_string_lossy());
        let npm = agent.join("npm");
        for (name, version) in PI_PACKAGES {
            let package = npm.join("node_modules").join(name);
            fs::create_dir_all(&package).unwrap();
            fs::write(
                package.join("package.json"),
                format!("{{\"version\":\"{version}\"}}"),
            )
            .unwrap();
        }
        fs::write(
            npm.join(".muniment-packages.json"),
            serde_json::to_vec(&PI_PACKAGES).unwrap(),
        )
        .unwrap();
        prepare_pi_packages(&agent, Path::new("pi.exe")).unwrap();
        let command = install_command(Path::new("pi.exe"), &npm.canonicalize().unwrap());
        let resolved = command.get_current_dir().unwrap();
        assert!(resolved.is_absolute());
        assert!(!resolved.as_os_str().to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(resolved.canonicalize().unwrap(), npm);
        assert_eq!(command.get_args().last().unwrap(), resolved.as_os_str());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn install_uses_plain_windows_paths_for_argument_and_working_directory() {
        for (resolved, expected) in [
            (
                r"\\?\C:\Users\harness.DESKTOP-27SP6A1\.pi\agent\npm",
                r"C:\Users\harness.DESKTOP-27SP6A1\.pi\agent\npm",
            ),
            (
                r"\\?\D:\agent with spaces\日本語\npm",
                r"D:\agent with spaces\日本語\npm",
            ),
            (r"\\?\C:\", r"C:\"),
            (
                r"\\?\UNC\server\share\agent\npm",
                r"\\server\share\agent\npm",
            ),
            (r"C:\agent\npm", r"C:\agent\npm"),
            (r"\\server\share\agent\npm", r"\\server\share\agent\npm"),
        ] {
            let command = install_command(Path::new("pi.exe"), Path::new(resolved));
            assert_eq!(command.get_current_dir(), Some(Path::new(expected)));
            assert_eq!(command.get_args().last().unwrap(), expected);
        }
    }

    #[test]
    #[cfg(windows)]
    fn install_directory_preserves_non_unicode_windows_paths() {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let mut expected: Vec<_> = r"C:\agent\".encode_utf16().collect();
        expected.push(0xD800);
        expected.extend(r"\npm".encode_utf16());
        let verbatim: Vec<_> = r"\\?\"
            .encode_utf16()
            .chain(expected.iter().copied())
            .collect();
        let directory = OsString::from_wide(&verbatim);
        let command = install_command(Path::new("pi.exe"), Path::new(&directory));
        let resolved = command.get_current_dir().unwrap();
        assert_eq!(
            resolved.as_os_str().encode_wide().collect::<Vec<_>>(),
            expected
        );
        assert_eq!(command.get_args().last().unwrap(), resolved.as_os_str());
    }

    #[test]
    fn acquisition_uses_embedded_bun_without_system_node_or_scripts() {
        let command = install_command(Path::new("/verified/pi"), Path::new("/agent/npm"));
        assert_eq!(command.get_program(), "/verified/pi");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "install",
                "pi-web-access@0.28.0",
                "pi-subagents@0.65.1",
                "pi-background-tasks@2.5.0",
                "pi-mcp-adapter@2.34.0",
                "pi-claude-bridge@0.7.0",
                "--omit=peer",
                "--ignore-scripts",
                "--exact",
                "--cwd",
                "/agent/npm"
            ]
        );
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "BUN_BE_BUN" && value == Some("1".as_ref())));
    }

    #[test]
    fn a_tree_another_package_manager_wrote_starts_over() {
        let root = std::env::temp_dir().join(format!("muniment-packages-{}", uuid::Uuid::new_v4()));
        let npm = root.join("npm");
        for (name, version) in PI_PACKAGES {
            let directory = npm.join("node_modules").join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("package.json"),
                format!("{{\"version\":\"{version}\"}}"),
            )
            .unwrap();
        }
        let marker = npm.join(".muniment-packages.json");
        fs::write(&marker, serde_json::to_vec(&PI_PACKAGES).unwrap()).unwrap();
        let missing = root.join("missing-executable");
        prepare_pi_packages(&root, &missing).unwrap();
        fs::write(npm.join("node_modules/.package-lock.json"), "{}").unwrap();
        assert!(prepare_pi_packages(&root, &missing).is_err());
        assert!(!npm.join("node_modules").exists());
        assert!(!npm.join("node_modules/.package-lock.json").exists());
        assert!(!marker.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_acquisition_retries_and_releases_the_lock() {
        let root = std::env::temp_dir().join(format!("muniment-packages-{}", uuid::Uuid::new_v4()));
        let npm = root.join("npm");
        for (name, version) in PI_PACKAGES {
            let directory = npm.join("node_modules").join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("package.json"),
                format!("{{\"version\":\"{version}\"}}"),
            )
            .unwrap();
        }
        let missing = root.join("missing-executable");
        assert!(prepare_pi_packages(&root, &missing).is_err());
        assert!(prepare_pi_packages(&root, &missing).is_err());
        let marker = npm.join(".muniment-packages.json");
        assert!(!marker.exists());
        fs::write(&marker, serde_json::to_vec(&PI_PACKAGES).unwrap()).unwrap();
        prepare_pi_packages(&root, &missing).unwrap();
        fs::write(npm.join("node_modules/pi-web-access/package.json"), "{}").unwrap();
        assert!(prepare_pi_packages(&root, &missing).is_err());
        assert!(!marker.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
