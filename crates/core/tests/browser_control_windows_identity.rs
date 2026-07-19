#![cfg(target_os = "windows")]

use muniment_core::browser_control::{
    authorize_browser_process_with_reader, resolve_browser_process_with_reader,
    verify_browser_process_with_reader, AuthorizationError, BrowserProcessIdentity,
    NativeProcessError, NativeReadError, ResolutionError, TcpConnection, VerificationError,
    WindowsIdentityReader,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

struct FakeReader {
    scans: RefCell<VecDeque<Result<Vec<TcpConnection>, NativeReadError>>>,
    identities: RefCell<VecDeque<Result<u64, NativeProcessError>>>,
    image: Result<(u64, PathBuf), NativeProcessError>,
    image_pids: RefCell<Vec<u32>>,
}

impl WindowsIdentityReader for FakeReader {
    fn tcp_connections(&self, _ipv6: bool) -> Result<Vec<TcpConnection>, NativeReadError> {
        self.scans.borrow_mut().pop_front().unwrap()
    }

    fn process_identity(&self, _pid: u32) -> Result<u64, NativeProcessError> {
        self.identities.borrow_mut().pop_front().unwrap()
    }

    fn process_image(&self, pid: u32) -> Result<(u64, PathBuf), NativeProcessError> {
        self.image_pids.borrow_mut().push(pid);
        self.image.clone()
    }
}

fn endpoints() -> (SocketAddr, SocketAddr) {
    (
        (Ipv4Addr::LOCALHOST, 41000).into(),
        (Ipv4Addr::LOCALHOST, 41001).into(),
    )
}

fn connection(pid: u32) -> TcpConnection {
    let (local, peer) = endpoints();
    TcpConnection {
        local: peer,
        peer: local,
        pid,
    }
}

fn reader(scans: impl IntoIterator<Item = Vec<TcpConnection>>) -> FakeReader {
    FakeReader {
        scans: RefCell::new(scans.into_iter().map(Ok).collect()),
        identities: RefCell::new([Ok(100)].into()),
        image: Ok((100, PathBuf::from(r"C:\Program Files\Browser\browser.exe"))),
        image_pids: RefCell::new(Vec::new()),
    }
}

#[test]
fn resolves_exact_stable_ipv4_and_ipv6_connections() {
    let (local, peer) = endpoints();
    assert_eq!(
        resolve_browser_process_with_reader(
            local,
            peer,
            &reader([vec![connection(42)], vec![connection(42)]])
        ),
        Ok(BrowserProcessIdentity {
            pid: 42,
            creation_time: 100
        })
    );

    let local: SocketAddr = (Ipv6Addr::LOCALHOST, 42000).into();
    let peer: SocketAddr = (Ipv6Addr::LOCALHOST, 42001).into();
    let row = TcpConnection {
        local: peer,
        peer: local,
        pid: 43,
    };
    assert_eq!(
        resolve_browser_process_with_reader(local, peer, &reader([vec![row], vec![row]])),
        Ok(BrowserProcessIdentity {
            pid: 43,
            creation_time: 100
        })
    );
}

#[test]
fn rejects_invalid_missing_mismatched_ambiguous_and_changing_connections() {
    let (local, peer) = endpoints();
    for invalid in [
        ("0.0.0.0:41000".parse().unwrap(), peer),
        (local, "192.0.2.1:41001".parse().unwrap()),
        ("127.0.0.1:0".parse().unwrap(), peer),
        (local, "[::1]:41001".parse().unwrap()),
        (local, local),
    ] {
        assert_eq!(
            resolve_browser_process_with_reader(invalid.0, invalid.1, &reader([])),
            Err(ResolutionError::InvalidEndpoint)
        );
    }

    assert_eq!(
        resolve_browser_process_with_reader(local, peer, &reader([vec![]])),
        Err(ResolutionError::SocketNotFound)
    );
    assert_eq!(
        resolve_browser_process_with_reader(
            local,
            peer,
            &reader([vec![TcpConnection {
                local,
                peer,
                pid: 42
            }]])
        ),
        Err(ResolutionError::SocketNotFound)
    );
    assert_eq!(
        resolve_browser_process_with_reader(
            local,
            peer,
            &reader([vec![connection(42), connection(43)]])
        ),
        Err(ResolutionError::AmbiguousOwner)
    );
    assert_eq!(
        resolve_browser_process_with_reader(
            local,
            peer,
            &reader([vec![connection(42)], vec![connection(43)]])
        ),
        Err(ResolutionError::OwnerChanged)
    );
}

#[test]
fn process_lookup_and_image_query_fail_closed() {
    let observed = BrowserProcessIdentity {
        pid: 42,
        creation_time: 100,
    };
    for (failure, expected) in [
        (
            NativeProcessError::OpenFailed,
            VerificationError::ProcessUnavailable,
        ),
        (
            NativeProcessError::ImageQueryFailed,
            VerificationError::ProcessExecutableInvalid,
        ),
    ] {
        let mut reader = reader([]);
        reader.image = Err(failure);
        assert_eq!(
            verify_browser_process_with_reader(
                observed,
                Path::new(r"C:\Program Files\Browser\browser.exe"),
                &reader
            ),
            Err(expected)
        );
    }
}

#[test]
fn authorizes_only_windows_equivalent_executable_and_only_after_resolution() {
    let (local, peer) = endpoints();
    let success = reader([vec![connection(42)], vec![connection(42)]]);
    assert!(authorize_browser_process_with_reader(
        local,
        peer,
        Path::new(r"c:/program files/browser/BROWSER.EXE"),
        &success
    )
    .is_ok());
    assert_eq!(success.image_pids.borrow().as_slice(), &[42]);

    let mismatch = reader([]);
    assert_eq!(
        verify_browser_process_with_reader(
            BrowserProcessIdentity {
                pid: 42,
                creation_time: 100,
            },
            Path::new(r"C:\Program Files\Other\browser.exe"),
            &mismatch
        ),
        Err(VerificationError::ExecutableMismatch)
    );

    let unresolved = reader([vec![]]);
    assert_eq!(
        authorize_browser_process_with_reader(
            local,
            peer,
            Path::new(r"C:\Program Files\Browser\browser.exe"),
            &unresolved
        ),
        Err(AuthorizationError::OwnerResolutionFailed)
    );
    assert!(unresolved.image_pids.borrow().is_empty());
}

#[test]
fn rejects_pid_reuse_between_resolution_and_verification() {
    let (local, peer) = endpoints();
    let mut reused = reader([vec![connection(42)], vec![connection(42)]]);
    reused.image = Ok((101, PathBuf::from(r"C:\Program Files\Browser\browser.exe")));

    assert_eq!(
        authorize_browser_process_with_reader(
            local,
            peer,
            Path::new(r"C:\Program Files\Browser\browser.exe"),
            &reused
        ),
        Err(AuthorizationError::ExecutableVerificationFailed)
    );
    assert_eq!(reused.image_pids.borrow().as_slice(), &[42]);
}

#[test]
fn errors_are_bounded_and_redacted() {
    let secrets = [
        "424242",
        "127.0.0.1:41000",
        r"C:\secret\browser.exe",
        "access denied",
    ];
    let rendered = [
        format!(
            "{:?}: {}",
            ResolutionError::InspectionUnavailable,
            ResolutionError::InspectionUnavailable
        ),
        format!(
            "{:?}: {}",
            VerificationError::ProcessUnavailable,
            VerificationError::ProcessUnavailable
        ),
        format!(
            "{:?}: {}",
            AuthorizationError::OwnerResolutionFailed,
            AuthorizationError::OwnerResolutionFailed
        ),
    ];
    for error in rendered {
        assert!(error.len() < 100);
        for secret in secrets {
            assert!(!error.contains(secret));
        }
    }
}
