//! Linux process readers for peer identity checks.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// A live process named by its pid and its start time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Linux `/proc/<pid>/stat` starttime, in clock ticks since boot.
    pub start_identity: u64,
}

/// Opaque failure from the injected procfs boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcReadError;

/// Injected Linux procfs boundary used by deterministic contract tests.
pub trait LinuxProcReader {
    fn start_identity(&self, pid: u32) -> Result<u64, ProcReadError>;
    fn executable(&self, pid: u32) -> Result<PathBuf, ProcReadError>;
    fn socket_owners(&self, _inode: u32) -> Result<Vec<ProcessIdentity>, ProcReadError> {
        Err(ProcReadError)
    }
}

/// Reader for the live Linux procfs.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcReader;

impl LinuxProcReader for ProcReader {
    fn start_identity(&self, pid: u32) -> Result<u64, ProcReadError> {
        let stat = fs::read(format!("/proc/{pid}/stat")).map_err(|_| ProcReadError)?;
        parse_start_identity(&stat).ok_or(ProcReadError)
    }

    fn executable(&self, pid: u32) -> Result<PathBuf, ProcReadError> {
        // Canonicalize the proc-owned link itself below. Following its target
        // pathname separately would introduce a replacement race.
        Ok(PathBuf::from(format!("/proc/{pid}/exe")))
    }

    fn socket_owners(&self, inode: u32) -> Result<Vec<ProcessIdentity>, ProcReadError> {
        socket_owners_in(Path::new("/proc"), unsafe { libc::geteuid() }, inode)
    }
}

fn socket_owners_in(
    proc_root: &Path,
    desktop_uid: u32,
    inode: u32,
) -> Result<Vec<ProcessIdentity>, ProcReadError> {
    let wanted = format!("socket:[{inode}]").into_bytes();
    let mut owners = Vec::new();
    for entry in fs::read_dir(proc_root).map_err(|_| ProcReadError)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ProcReadError),
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ProcReadError),
        };
        if metadata.uid() != desktop_uid {
            continue;
        }
        let stat = match fs::read(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ProcReadError),
        };
        let before = parse_start_identity(&stat).ok_or(ProcReadError)?;
        let fds = match fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ProcReadError),
        };
        let mut owns = false;
        for fd in fds {
            let fd = match fd {
                Ok(fd) => fd,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(ProcReadError),
            };
            let target = match fs::read_link(fd.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(ProcReadError),
            };
            if target.as_os_str().as_bytes() == wanted.as_slice() {
                owns = true;
            }
        }
        let after = match fs::read(entry.path().join("stat")) {
            Ok(stat) => parse_start_identity(&stat).ok_or(ProcReadError)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !owns => continue,
            Err(_) => return Err(ProcReadError),
        };
        if before != after {
            if owns {
                return Err(ProcReadError);
            }
            continue;
        }
        if owns {
            owners.push(ProcessIdentity {
                pid,
                start_identity: before,
            });
        }
    }
    Ok(owners)
}

fn parse_start_identity(stat: &[u8]) -> Option<u64> {
    // `comm` is parenthesized and may itself contain spaces or `)` bytes. Work
    // backwards from its final delimiter, then select field 22 (starttime).
    let comm_end = stat.iter().rposition(|byte| *byte == b')')?;
    let remaining = std::str::from_utf8(stat.get(comm_end + 1..)?).ok()?;
    remaining.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_start_identity, socket_owners_in, ProcessIdentity};
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestProc(PathBuf);

    impl TestProc {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "muniment-proc-scan-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn process(&self, pid: u32, start: Option<u64>) -> PathBuf {
            let process = self.0.join(pid.to_string());
            fs::create_dir(&process).unwrap();
            if let Some(start) = start {
                let start = start.to_string();
                let fields = std::iter::repeat_n("0", 19)
                    .chain(std::iter::once(start.as_str()))
                    .collect::<Vec<_>>()
                    .join(" ");
                fs::write(process.join("stat"), format!("{pid} (test) {fields}")).unwrap();
            }
            fs::create_dir(process.join("fd")).unwrap();
            process
        }
    }

    impl Drop for TestProc {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn add_socket(process: &Path, fd: u32, inode: u32) {
        symlink(
            format!("socket:[{inode}]"),
            process.join("fd").join(fd.to_string()),
        )
        .unwrap();
    }

    #[test]
    fn parses_starttime_after_a_difficult_comm_field() {
        let mut fields = vec!["S"; 19];
        fields.push("98765");
        assert_eq!(
            parse_start_identity(
                format!("42 (name ) with spaces) {}", fields.join(" ")).as_bytes()
            ),
            Some(98765)
        );
    }

    #[test]
    fn proc_scan_ignores_unrelated_failures_and_finds_stable_owner() {
        let procfs = TestProc::new();
        let uid = fs::metadata(&procfs.0).unwrap().uid();
        procfs.process(11, None); // The process disappeared before its stat was read.
        let owner = procfs.process(12, Some(77));
        add_socket(&owner, 4, 900);

        assert_eq!(
            socket_owners_in(&procfs.0, uid, 900),
            Ok(vec![ProcessIdentity {
                pid: 12,
                start_identity: 77,
            }])
        );
    }

    #[test]
    fn unreadable_candidate_cannot_produce_an_owner() {
        let procfs = TestProc::new();
        let uid = fs::metadata(&procfs.0).unwrap().uid();
        let candidate = procfs.process(12, Some(77));
        fs::write(candidate.join("fd/4"), b"not a readable link").unwrap();

        assert_eq!(
            socket_owners_in(&procfs.0, uid, 900),
            Err(super::ProcReadError)
        );
    }

    #[test]
    fn unreadable_candidate_concealing_a_duplicate_fails_the_scan() {
        let procfs = TestProc::new();
        let uid = fs::metadata(&procfs.0).unwrap().uid();
        let owner = procfs.process(12, Some(77));
        add_socket(&owner, 4, 900);
        let unreadable = procfs.process(13, Some(88));
        fs::write(unreadable.join("fd/5"), b"not a readable link").unwrap();

        assert_eq!(
            socket_owners_in(&procfs.0, uid, 900),
            Err(super::ProcReadError)
        );
    }
}
