#![cfg(target_os = "linux")]

use muniment_core::browser_control::{
    resolve_browser_process_with_readers, verify_browser_process,
    verify_browser_process_with_reader, BrowserProcessIdentity, LinuxProcReader,
    LinuxSocketDiagnostic, ProcReadError, ProcReader, ResolutionError, SocketDiagnostic,
    VerificationError,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-browser-identity-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeProcReader {
    starts: RefCell<VecDeque<Result<u64, ProcReadError>>>,
    executable: Result<PathBuf, ProcReadError>,
}

impl FakeProcReader {
    fn new(
        starts: impl IntoIterator<Item = Result<u64, ProcReadError>>,
        executable: PathBuf,
    ) -> Self {
        Self {
            starts: RefCell::new(starts.into_iter().collect()),
            executable: Ok(executable),
        }
    }
}

impl LinuxProcReader for FakeProcReader {
    fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
        self.starts.borrow_mut().pop_front().unwrap()
    }

    fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
        self.executable.clone()
    }
}

fn observed(start_identity: u64) -> BrowserProcessIdentity {
    BrowserProcessIdentity {
        pid: std::process::id(),
        start_identity,
    }
}

#[test]
fn authorizes_current_process_through_temporary_symlinks() {
    let directory = TestDirectory::new();
    let current_executable = fs::read_link("/proc/self/exe").unwrap();
    let first = directory.0.join("browser");
    let second = directory.0.join("selected-browser");
    symlink(&current_executable, &first).unwrap();
    symlink(&first, &second).unwrap();
    let start_identity = ProcReader.start_identity(std::process::id()).unwrap();

    assert!(verify_browser_process(observed(start_identity), &second).is_ok());
}

#[test]
fn rejects_observed_mismatch_and_pid_reuse_during_resolution() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();

    let stale = FakeProcReader::new([Ok(8)], executable.clone());
    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &stale),
        Err(VerificationError::ProcessIdentityChanged)
    );

    let reused = FakeProcReader::new([Ok(7), Ok(8)], executable.clone());
    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &reused),
        Err(VerificationError::ProcessIdentityChanged)
    );
}

#[test]
fn rejects_process_disappearance_before_or_after_resolution() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    for starts in [vec![Err(ProcReadError)], vec![Ok(7), Err(ProcReadError)]] {
        let reader = FakeProcReader::new(starts, executable.clone());
        assert_eq!(
            verify_browser_process_with_reader(observed(7), &executable, &reader),
            Err(VerificationError::ProcessUnavailable)
        );
    }

    let during_resolution = FakeProcReader {
        starts: RefCell::new([Ok(7)].into_iter().collect()),
        executable: Err(ProcReadError),
    };
    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &during_resolution),
        Err(VerificationError::ProcessExecutableInvalid)
    );
}

#[test]
fn rejects_invalid_expected_and_proc_executable_paths() {
    let directory = TestDirectory::new();
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let missing = directory.0.join("missing");
    let loop_a = directory.0.join("loop-a");
    let loop_b = directory.0.join("loop-b");
    symlink(&loop_b, &loop_a).unwrap();
    symlink(&loop_a, &loop_b).unwrap();

    for expected in [Path::new("relative"), &missing, &loop_a] {
        let reader = FakeProcReader::new([Ok(7), Ok(7)], executable.clone());
        assert_eq!(
            verify_browser_process_with_reader(observed(7), expected, &reader),
            Err(VerificationError::ExpectedExecutableInvalid)
        );
    }

    for actual in [
        PathBuf::from("relative"),
        missing,
        loop_a,
        PathBuf::from("/secret/browser (deleted)"),
    ] {
        let reader = FakeProcReader::new([Ok(7), Ok(7)], actual);
        assert_eq!(
            verify_browser_process_with_reader(observed(7), &executable, &reader),
            Err(VerificationError::ProcessExecutableInvalid)
        );
    }
}

#[test]
fn rejects_a_different_canonical_executable() {
    let directory = TestDirectory::new();
    let other = directory.0.join("other");
    fs::write(&other, b"not the browser").unwrap();
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader::new([Ok(7), Ok(7)], other);

    assert_eq!(
        verify_browser_process_with_reader(observed(7), &executable, &reader),
        Err(VerificationError::ExecutableMismatch)
    );
}

#[test]
fn errors_are_bounded_and_redacted() {
    let secrets = [
        "424242",
        "987654321",
        "/secret/expected",
        "/secret/actual",
        "permission denied",
    ];
    for error in [
        VerificationError::ProcessUnavailable,
        VerificationError::ProcessIdentityChanged,
        VerificationError::ExpectedExecutableInvalid,
        VerificationError::ProcessExecutableInvalid,
        VerificationError::ExecutableMismatch,
    ] {
        let rendered = format!("{error:?}: {error}");
        assert!(rendered.len() < 100);
        for secret in secrets {
            assert!(!rendered.contains(secret));
        }
    }
}

struct FakeDiagnostic {
    matches: usize,
    malformed: bool,
    done_flags: u16,
}

impl LinuxSocketDiagnostic for FakeDiagnostic {
    fn response(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        sequence: u32,
    ) -> Result<Vec<u8>, ProcReadError> {
        if self.malformed {
            return Ok(vec![1, 2, 3]);
        }
        let mut response = Vec::new();
        for index in 0..self.matches {
            let mut message = vec![0u8; 88];
            message[0..4].copy_from_slice(&88u32.to_ne_bytes());
            message[4..6].copy_from_slice(&20u16.to_ne_bytes());
            message[6..8].copy_from_slice(&2u16.to_ne_bytes());
            message[8..12].copy_from_slice(&sequence.to_ne_bytes());
            message[16] = libc::AF_INET as u8;
            message[17] = 1;
            message[20..22].copy_from_slice(&peer.port().to_be_bytes());
            message[22..24].copy_from_slice(&local.port().to_be_bytes());
            let (std::net::IpAddr::V4(local_ip), std::net::IpAddr::V4(peer_ip)) =
                (local.ip(), peer.ip())
            else {
                unreachable!()
            };
            message[24..28].copy_from_slice(&peer_ip.octets());
            message[40..44].copy_from_slice(&local_ip.octets());
            message[84..88].copy_from_slice(&(900 + index as u32).to_ne_bytes());
            response.extend(message);
        }
        let mut done = vec![0u8; 16];
        done[0..4].copy_from_slice(&16u32.to_ne_bytes());
        done[4..6].copy_from_slice(&3u16.to_ne_bytes());
        done[6..8].copy_from_slice(&self.done_flags.to_ne_bytes());
        done[8..12].copy_from_slice(&sequence.to_ne_bytes());
        response.extend(done);
        Ok(response)
    }
}

struct ResolverProc {
    owners: Result<Vec<BrowserProcessIdentity>, ProcReadError>,
    starts: RefCell<VecDeque<Result<u64, ProcReadError>>>,
}

impl LinuxProcReader for ResolverProc {
    fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
        self.starts
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(ProcReadError))
    }
    fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
        Err(ProcReadError)
    }
    fn socket_owners(&self, _inode: u32) -> Result<Vec<BrowserProcessIdentity>, ProcReadError> {
        self.owners.clone()
    }
}

fn endpoints() -> (SocketAddr, SocketAddr) {
    (
        (Ipv4Addr::LOCALHOST, 41000).into(),
        (Ipv4Addr::LOCALHOST, 41001).into(),
    )
}

fn resolver_proc(
    owners: Result<Vec<BrowserProcessIdentity>, ProcReadError>,
    starts: impl IntoIterator<Item = Result<u64, ProcReadError>>,
) -> ResolverProc {
    ResolverProc {
        owners,
        starts: RefCell::new(starts.into_iter().collect()),
    }
}

#[test]
fn resolves_one_exact_socket_and_live_owner() {
    let (local, peer) = endpoints();
    let identity = BrowserProcessIdentity {
        pid: 42,
        start_identity: 77,
    };
    let procfs = resolver_proc(Ok(vec![identity]), [Ok(77)]);
    assert_eq!(
        resolve_browser_process_with_readers(
            local,
            peer,
            &FakeDiagnostic {
                matches: 1,
                malformed: false,
                done_flags: 2,
            },
            &procfs
        ),
        Ok(identity)
    );
}

#[test]
fn rejects_diagnostic_ambiguity_and_malformed_responses() {
    let (local, peer) = endpoints();
    for (diagnostic, expected) in [
        (
            FakeDiagnostic {
                matches: 2,
                malformed: false,
                done_flags: 2,
            },
            ResolutionError::AmbiguousSocket,
        ),
        (
            FakeDiagnostic {
                matches: 0,
                malformed: true,
                done_flags: 2,
            },
            ResolutionError::MalformedDiagnostic,
        ),
    ] {
        let procfs = resolver_proc(Ok(vec![]), []);
        assert_eq!(
            resolve_browser_process_with_readers(local, peer, &diagnostic, &procfs),
            Err(expected)
        );
    }
}

#[test]
fn rejects_an_interrupted_diagnostic_dump() {
    let (local, peer) = endpoints();
    let procfs = resolver_proc(Ok(vec![]), []);
    assert_eq!(
        resolve_browser_process_with_readers(
            local,
            peer,
            &FakeDiagnostic {
                matches: 1,
                malformed: false,
                done_flags: 2 | 0x10, // NLM_F_MULTI | NLM_F_DUMP_INTR
            },
            &procfs,
        ),
        Err(ResolutionError::MalformedDiagnostic)
    );
}

#[test]
fn real_diagnostic_selects_the_browser_client_half() {
    struct ExpectedInodeProc {
        inode: u32,
        identity: BrowserProcessIdentity,
    }
    impl LinuxProcReader for ExpectedInodeProc {
        fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
            Ok(self.identity.start_identity)
        }
        fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
            Err(ProcReadError)
        }
        fn socket_owners(&self, inode: u32) -> Result<Vec<BrowserProcessIdentity>, ProcReadError> {
            Ok((inode == self.inode)
                .then_some(self.identity)
                .into_iter()
                .collect())
        }
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let target = fs::read_link(format!("/proc/self/fd/{}", client.as_raw_fd())).unwrap();
    let target = target.to_str().unwrap();
    let inode = target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .unwrap()
        .parse()
        .unwrap();
    let identity = BrowserProcessIdentity {
        pid: std::process::id(),
        start_identity: ProcReader.start_identity(std::process::id()).unwrap(),
    };
    let procfs = ExpectedInodeProc { inode, identity };

    assert_eq!(
        resolve_browser_process_with_readers(
            accepted.local_addr().unwrap(),
            accepted.peer_addr().unwrap(),
            &SocketDiagnostic,
            &procfs,
        ),
        Ok(identity)
    );
}

#[test]
fn rejects_missing_duplicate_unreadable_or_reused_owners() {
    let (local, peer) = endpoints();
    let identity = BrowserProcessIdentity {
        pid: 42,
        start_identity: 77,
    };
    for (procfs, expected) in [
        (
            resolver_proc(Ok(vec![]), []),
            ResolutionError::OwnerUnavailable,
        ),
        (
            resolver_proc(Ok(vec![identity, identity]), []),
            ResolutionError::AmbiguousOwner,
        ),
        (
            resolver_proc(Err(ProcReadError), []),
            ResolutionError::OwnerUnavailable,
        ),
        (
            resolver_proc(Ok(vec![identity]), [Ok(78)]),
            ResolutionError::ProcessIdentityChanged,
        ),
    ] {
        assert_eq!(
            resolve_browser_process_with_readers(
                local,
                peer,
                &FakeDiagnostic {
                    matches: 1,
                    malformed: false,
                    done_flags: 2,
                },
                &procfs
            ),
            Err(expected)
        );
    }
}

#[test]
fn resolution_errors_are_bounded_and_redacted() {
    for error in [
        ResolutionError::InvalidEndpoint,
        ResolutionError::DiagnosticUnavailable,
        ResolutionError::MalformedDiagnostic,
        ResolutionError::SocketNotFound,
        ResolutionError::AmbiguousSocket,
        ResolutionError::OwnerUnavailable,
        ResolutionError::AmbiguousOwner,
        ResolutionError::ProcessIdentityChanged,
    ] {
        let rendered = format!("{error:?}: {error}");
        assert!(rendered.len() < 100);
        for secret in ["41000", "41001", "900", "42", "77", "permission denied"] {
            assert!(!rendered.contains(secret));
        }
    }
}

#[test]
fn rejects_wildcard_non_loopback_and_contradictory_endpoints() {
    let diagnostic = FakeDiagnostic {
        matches: 1,
        malformed: false,
        done_flags: 2,
    };
    for (local, peer) in [
        (
            "0.0.0.0:41000".parse().unwrap(),
            "127.0.0.1:41001".parse().unwrap(),
        ),
        (
            "192.0.2.1:41000".parse().unwrap(),
            "127.0.0.1:41001".parse().unwrap(),
        ),
        (
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:41001".parse().unwrap(),
        ),
        (
            "127.0.0.1:41000".parse().unwrap(),
            "[::1]:41001".parse().unwrap(),
        ),
    ] {
        let procfs = resolver_proc(Ok(vec![]), []);
        assert_eq!(
            resolve_browser_process_with_readers(local, peer, &diagnostic, &procfs),
            Err(ResolutionError::InvalidEndpoint)
        );
    }
}

#[test]
fn rejects_an_owner_change_during_confirmation() {
    struct ChangingOwner(RefCell<VecDeque<Vec<BrowserProcessIdentity>>>);
    impl LinuxProcReader for ChangingOwner {
        fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
            Ok(77)
        }
        fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
            Err(ProcReadError)
        }
        fn socket_owners(&self, _inode: u32) -> Result<Vec<BrowserProcessIdentity>, ProcReadError> {
            Ok(self.0.borrow_mut().pop_front().unwrap())
        }
    }
    let (local, peer) = endpoints();
    let identity = BrowserProcessIdentity {
        pid: 42,
        start_identity: 77,
    };
    let procfs = ChangingOwner(RefCell::new([vec![identity], vec![]].into_iter().collect()));
    assert_eq!(
        resolve_browser_process_with_readers(
            local,
            peer,
            &FakeDiagnostic {
                matches: 1,
                malformed: false,
                done_flags: 2,
            },
            &procfs
        ),
        Err(ResolutionError::ProcessIdentityChanged)
    );
}
