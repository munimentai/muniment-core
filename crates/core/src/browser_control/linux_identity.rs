//! Linux browser executable identity verification.

use std::fmt;
use std::fs;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// The process identity observed while determining the loopback connection owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserProcessIdentity {
    pub pid: u32,
    /// Linux `/proc/<pid>/stat` starttime, in clock ticks since boot.
    pub start_identity: u64,
}

/// Proof that a live process is the desktop-selected browser executable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedBrowserProcess(());

/// A bounded failure reason. Variants deliberately carry no sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    ProcessUnavailable,
    ProcessIdentityChanged,
    ExpectedExecutableInvalid,
    ProcessExecutableInvalid,
    ExecutableMismatch,
}

/// A bounded, redacted failure while resolving a loopback socket owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    InvalidEndpoint,
    DiagnosticUnavailable,
    MalformedDiagnostic,
    SocketNotFound,
    AmbiguousSocket,
    OwnerUnavailable,
    AmbiguousOwner,
    ProcessIdentityChanged,
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEndpoint => "connection endpoints are invalid",
            Self::DiagnosticUnavailable => "socket diagnostic is unavailable",
            Self::MalformedDiagnostic => "socket diagnostic response is invalid",
            Self::SocketNotFound => "connection socket was not found",
            Self::AmbiguousSocket => "connection socket is ambiguous",
            Self::OwnerUnavailable => "socket owner is unavailable",
            Self::AmbiguousOwner => "socket owner is ambiguous",
            Self::ProcessIdentityChanged => "socket owner identity changed",
        })
    }
}

impl std::error::Error for ResolutionError {}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ProcessUnavailable => "browser process is unavailable",
            Self::ProcessIdentityChanged => "browser process identity changed",
            Self::ExpectedExecutableInvalid => "expected browser executable is invalid",
            Self::ProcessExecutableInvalid => "browser process executable is invalid",
            Self::ExecutableMismatch => "browser executable does not match",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for VerificationError {}

/// Opaque failure from the injected procfs boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcReadError;

/// Injected Linux procfs boundary used by deterministic contract tests.
pub trait LinuxProcReader {
    fn start_identity(&self, pid: u32) -> Result<u64, ProcReadError>;
    fn executable(&self, pid: u32) -> Result<PathBuf, ProcReadError>;
    fn socket_owners(&self, _inode: u32) -> Result<Vec<BrowserProcessIdentity>, ProcReadError> {
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

    fn socket_owners(&self, inode: u32) -> Result<Vec<BrowserProcessIdentity>, ProcReadError> {
        socket_owners_in(Path::new("/proc"), unsafe { libc::geteuid() }, inode)
    }
}

fn socket_owners_in(
    proc_root: &Path,
    desktop_uid: u32,
    inode: u32,
) -> Result<Vec<BrowserProcessIdentity>, ProcReadError> {
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
            owners.push(BrowserProcessIdentity {
                pid,
                start_identity: before,
            });
        }
    }
    Ok(owners)
}

/// Injected Linux socket-diagnostic boundary.
pub trait LinuxSocketDiagnostic {
    fn response(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        sequence: u32,
    ) -> Result<Vec<u8>, ProcReadError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SocketDiagnostic;

struct OwnedFd(RawFd);
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl LinuxSocketDiagnostic for SocketDiagnostic {
    fn response(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        sequence: u32,
    ) -> Result<Vec<u8>, ProcReadError> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(ProcReadError);
        }
        let fd = OwnedFd(fd);
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let bound = unsafe {
            libc::bind(
                fd.0,
                &address as *const _ as *const libc::sockaddr,
                mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if bound != 0 {
            return Err(ProcReadError);
        }

        let mut request = [0u8; 72];
        request[0..4].copy_from_slice(&(72u32).to_ne_bytes());
        request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        request[6..8]
            .copy_from_slice(&(libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16).to_ne_bytes());
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());
        request[16] = if local.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        };
        request[17] = libc::IPPROTO_TCP as u8;
        request[20..24].copy_from_slice(&(1u32 << TCP_ESTABLISHED).to_ne_bytes());
        // Query the browser-owned client half of the accepted connection.
        request[24..26].copy_from_slice(&peer.port().to_be_bytes());
        request[26..28].copy_from_slice(&local.port().to_be_bytes());
        match (local.ip(), peer.ip()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                request[28..32].copy_from_slice(&b.octets());
                request[44..48].copy_from_slice(&a.octets());
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                request[28..44].copy_from_slice(&b.octets());
                request[44..60].copy_from_slice(&a.octets());
            }
            _ => return Err(ProcReadError),
        }
        request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
        let sent = unsafe {
            libc::send(
                fd.0,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
            )
        };
        if sent != request.len() as isize {
            return Err(ProcReadError);
        }
        let mut result = Vec::new();
        loop {
            let mut buffer = [0u8; 16 * 1024];
            let read = unsafe {
                libc::recv(
                    fd.0,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if read <= 0 {
                return Err(ProcReadError);
            }
            result.extend_from_slice(&buffer[..read as usize]);
            if netlink_contains_done(&buffer[..read as usize], sequence)? {
                return Ok(result);
            }
        }
    }
}

fn netlink_contains_done(bytes: &[u8], sequence: u32) -> Result<bool, ProcReadError> {
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(ProcReadError);
        }
        let len = u32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| ProcReadError)?,
        ) as usize;
        if len < 16 || len > bytes.len() - offset {
            return Err(ProcReadError);
        }
        let kind = u16::from_ne_bytes(
            bytes[offset + 4..offset + 6]
                .try_into()
                .map_err(|_| ProcReadError)?,
        );
        let flags = u16::from_ne_bytes(
            bytes[offset + 6..offset + 8]
                .try_into()
                .map_err(|_| ProcReadError)?,
        );
        let seq = u32::from_ne_bytes(
            bytes[offset + 8..offset + 12]
                .try_into()
                .map_err(|_| ProcReadError)?,
        );
        if seq != sequence || kind == libc::NLMSG_ERROR as u16 || flags != NLM_F_MULTI {
            return Err(ProcReadError);
        }
        if kind == NLMSG_DONE {
            return Ok(true);
        }
        offset += (len + 3) & !3;
    }
    Ok(false)
}

static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

/// Resolves an accepted numeric loopback TCP connection to its live process.
pub fn resolve_browser_process(
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<BrowserProcessIdentity, ResolutionError> {
    resolve_browser_process_with_readers(local, peer, &SocketDiagnostic, &ProcReader)
}

#[doc(hidden)]
pub fn resolve_browser_process_with_readers(
    local: SocketAddr,
    peer: SocketAddr,
    diagnostic: &impl LinuxSocketDiagnostic,
    procfs: &impl LinuxProcReader,
) -> Result<BrowserProcessIdentity, ResolutionError> {
    validate_endpoints(local, peer)?;
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let bytes = diagnostic
        .response(local, peer, sequence)
        .map_err(|_| ResolutionError::DiagnosticUnavailable)?;
    let inodes = parse_diagnostic(&bytes, local, peer, sequence)?;
    let inode = match inodes.as_slice() {
        [] => return Err(ResolutionError::SocketNotFound),
        [inode] => *inode,
        _ => return Err(ResolutionError::AmbiguousSocket),
    };
    let owners = procfs
        .socket_owners(inode)
        .map_err(|_| ResolutionError::OwnerUnavailable)?;
    let owner = match owners.as_slice() {
        [] => return Err(ResolutionError::OwnerUnavailable),
        [owner] => *owner,
        _ => return Err(ResolutionError::AmbiguousOwner),
    };
    let after = procfs
        .start_identity(owner.pid)
        .map_err(|_| ResolutionError::OwnerUnavailable)?;
    if after != owner.start_identity {
        return Err(ResolutionError::ProcessIdentityChanged);
    }
    let confirmed = procfs
        .socket_owners(inode)
        .map_err(|_| ResolutionError::OwnerUnavailable)?;
    if confirmed.as_slice() != [owner] {
        return Err(if confirmed.len() > 1 {
            ResolutionError::AmbiguousOwner
        } else {
            ResolutionError::ProcessIdentityChanged
        });
    }
    Ok(owner)
}

fn validate_endpoints(local: SocketAddr, peer: SocketAddr) -> Result<(), ResolutionError> {
    if local.port() == 0
        || peer.port() == 0
        || !local.ip().is_loopback()
        || !peer.ip().is_loopback()
        || mem::discriminant(&local.ip()) != mem::discriminant(&peer.ip())
        || local == peer
    {
        return Err(ResolutionError::InvalidEndpoint);
    }
    Ok(())
}

const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const TCP_ESTABLISHED: u8 = 1;

fn parse_diagnostic(
    bytes: &[u8],
    local: SocketAddr,
    peer: SocketAddr,
    sequence: u32,
) -> Result<Vec<u32>, ResolutionError> {
    let mut offset = 0usize;
    let mut done = false;
    let mut matches = Vec::new();
    let mut response_pid = None;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(ResolutionError::MalformedDiagnostic);
        }
        let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[offset + 6..offset + 8].try_into().unwrap());
        let seq = u32::from_ne_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
        let pid = u32::from_ne_bytes(bytes[offset + 12..offset + 16].try_into().unwrap());
        if len < 16 || len > bytes.len() - offset || flags != NLM_F_MULTI || seq != sequence || done
        {
            return Err(ResolutionError::MalformedDiagnostic);
        }
        if response_pid
            .replace(pid)
            .is_some_and(|expected| expected != pid)
        {
            return Err(ResolutionError::MalformedDiagnostic);
        }
        if kind == NLMSG_DONE {
            // Some kernels include a zero `nlmsgerr` status in dump completion.
            if len != 16 && !(len == 20 && bytes[offset + 16..offset + 20] == [0; 4]) {
                return Err(ResolutionError::MalformedDiagnostic);
            }
            done = true;
        } else if kind == SOCK_DIAG_BY_FAMILY {
            if len < 88 {
                return Err(ResolutionError::MalformedDiagnostic);
            }
            let msg = &bytes[offset + 16..offset + 88];
            let family = msg[0];
            if msg[1] != TCP_ESTABLISHED {
                return Err(ResolutionError::MalformedDiagnostic);
            }
            let expected_family = if local.is_ipv4() {
                libc::AF_INET as u8
            } else {
                libc::AF_INET6 as u8
            };
            if family != expected_family {
                return Err(ResolutionError::MalformedDiagnostic);
            }
            let sport = u16::from_be_bytes([msg[4], msg[5]]);
            let dport = u16::from_be_bytes([msg[6], msg[7]]);
            let addresses_match = match (local.ip(), peer.ip()) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    msg[8..12] == b.octets() && msg[24..28] == a.octets()
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    msg[8..24] == b.octets() && msg[24..40] == a.octets()
                }
                _ => false,
            };
            if sport != peer.port() || dport != local.port() || !addresses_match {
                return Err(ResolutionError::MalformedDiagnostic);
            }
            let inode = u32::from_ne_bytes(msg[68..72].try_into().unwrap());
            if inode == 0 {
                return Err(ResolutionError::MalformedDiagnostic);
            }
            matches.push(inode);
        } else {
            return Err(ResolutionError::MalformedDiagnostic);
        }
        offset += (len + 3) & !3;
        if offset > bytes.len() {
            return Err(ResolutionError::MalformedDiagnostic);
        }
    }
    if !done {
        return Err(ResolutionError::MalformedDiagnostic);
    }
    Ok(matches)
}

/// Verifies a live process against the desktop-owned expected browser path.
pub fn verify_browser_process(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
) -> Result<AuthorizedBrowserProcess, VerificationError> {
    verify_browser_process_with_reader(observed, expected_executable, &ProcReader)
}

/// Verifies using an injected procfs boundary.
#[doc(hidden)]
pub fn verify_browser_process_with_reader(
    observed: BrowserProcessIdentity,
    expected_executable: &Path,
    reader: &impl LinuxProcReader,
) -> Result<AuthorizedBrowserProcess, VerificationError> {
    if !expected_executable.is_absolute() {
        return Err(VerificationError::ExpectedExecutableInvalid);
    }

    let before = reader
        .start_identity(observed.pid)
        .map_err(|_| VerificationError::ProcessUnavailable)?;
    if before != observed.start_identity {
        return Err(VerificationError::ProcessIdentityChanged);
    }

    let actual = reader
        .executable(observed.pid)
        .map_err(|_| VerificationError::ProcessExecutableInvalid)?;
    if !actual.is_absolute() || actual.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(VerificationError::ProcessExecutableInvalid);
    }

    let expected = canonical_executable(expected_executable)
        .map_err(|_| VerificationError::ExpectedExecutableInvalid)?;
    let actual =
        canonical_executable(&actual).map_err(|_| VerificationError::ProcessExecutableInvalid)?;

    let after = reader
        .start_identity(observed.pid)
        .map_err(|_| VerificationError::ProcessUnavailable)?;
    if after != observed.start_identity || after != before {
        return Err(VerificationError::ProcessIdentityChanged);
    }
    if actual.as_os_str().as_bytes() != expected.as_os_str().as_bytes() {
        return Err(VerificationError::ExecutableMismatch);
    }

    Ok(AuthorizedBrowserProcess(()))
}

fn canonical_executable(path: &Path) -> std::io::Result<PathBuf> {
    fs::canonicalize(path)
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
    use super::{parse_start_identity, socket_owners_in, BrowserProcessIdentity};
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
            Ok(vec![BrowserProcessIdentity {
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
