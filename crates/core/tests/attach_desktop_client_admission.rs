#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use muniment_core::attach::linux::PeerCredentials;
use muniment_core::attach::{
    admit_desktop_client, decode_frame, encode_frame, Approval, Client,
    DesktopClientAdmissionError, DesktopClientAuthorizedGrant, ErrorCode, ErrorEnvelope, Hello, Id,
    Protocol, VersionRange, Welcome, CAPABILITY_IDLE_LIFETIME, MAX_CAPABILITY_LIFETIME,
    MAX_FRAME_LENGTH,
};
use muniment_core::browser_control::{LinuxProcReader, ProcReadError};

struct FakeProcReader {
    executable: PathBuf,
}

impl LinuxProcReader for FakeProcReader {
    fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
        Ok(7)
    }

    fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
        Ok(self.executable.clone())
    }
}

struct UnavailableProcReader;

impl LinuxProcReader for UnavailableProcReader {
    fn start_identity(&self, _pid: u32) -> Result<u64, ProcReadError> {
        Err(ProcReadError)
    }

    fn executable(&self, _pid: u32) -> Result<PathBuf, ProcReadError> {
        Err(ProcReadError)
    }
}

fn credentials() -> PeerCredentials {
    PeerCredentials {
        pid: 424242,
        uid: 1000,
        gid: 1000,
    }
}

fn approval() -> Approval {
    Approval {
        profile: "profile-1".into(),
        workspace: "/work/signed".into(),
        scopes: BTreeSet::from(["run.write".into(), "thread.read".into()]),
        lifetime: MAX_CAPABILITY_LIFETIME + Duration::from_secs(1),
    }
}

fn hello(min: u32, max: u32) -> Vec<u8> {
    encode_frame(&Hello {
        protocol: Protocol,
        client: Client {
            kind: "untrusted-claim".into(),
            version: "99.0.0".into(),
        },
        supported: VersionRange { min, max },
        client_nonce: "client-nonce".into(),
        authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000099").unwrap(),
        authorized_client_credential: Some("untrusted-credential".into()),
    })
    .unwrap()
}

fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> T {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    decode_frame(&frame).unwrap().unwrap().0
}

fn assert_hex(value: &str, length: usize) {
    assert_eq!(value.len(), length);
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn verified_peer_receives_workspace_grant_without_client_credential() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader {
        executable: executable.clone(),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();

    let (returned_stream, session) = admit_desktop_client(
        server,
        credentials(),
        &executable,
        &reader,
        "0.1.0",
        approval(),
        Duration::from_secs(30),
    )
    .unwrap();

    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(welcome.selected, 1);
    assert_eq!(welcome.desktop_version, "0.1.0");
    assert_hex(&welcome.server_nonce, 32);
    assert!(welcome.approval_challenge.is_empty());
    let grant: DesktopClientAuthorizedGrant = read_frame(&mut client);
    assert_hex(&grant.capability, 64);
    assert_eq!(grant.capability, session.capability);
    assert_eq!(grant.profile_id, "profile-1");
    assert_eq!(grant.expires_at, MAX_CAPABILITY_LIFETIME.as_secs());
    assert_eq!(
        grant.idle_timeout_seconds,
        CAPABILITY_IDLE_LIFETIME.as_secs()
    );
    assert_eq!(grant.workspace_scopes.len(), 1);
    assert_eq!(grant.workspace_scopes["/work/signed"], approval().scopes);
    assert_eq!(session.workspace, "/work/signed");
    assert_eq!(
        session.client_identity,
        "018f0000-0000-7000-8000-000000000099"
    );
    assert_eq!(session.provenance.profile, "profile-1");
    assert_eq!(session.provenance.companion_kind, "untrusted-claim");
    assert_eq!(session.provenance.companion_version, "99.0.0");
    assert_eq!(session.provenance.peer_uid, 1000);
    assert_eq!(session.provenance.peer_pid, 424242);
    returned_stream.shutdown(std::net::Shutdown::Both).unwrap();
}

#[test]
fn rejected_peer_receives_only_unauthorized() {
    let expected = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader {
        executable: fs::canonicalize("/proc/self/status").unwrap(),
    };
    let (mut client, server) = UnixStream::pair().unwrap();

    assert_eq!(
        admit_desktop_client(
            server,
            credentials(),
            &expected,
            &reader,
            "0.1.0",
            approval(),
            Duration::from_secs(1),
        )
        .unwrap_err(),
        DesktopClientAdmissionError::PeerUnauthorized
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    assert_eq!(client.read(&mut [0_u8]).unwrap(), 0);
}

#[test]
fn unresolved_peer_receives_only_unauthorized() {
    let expected = fs::canonicalize("/proc/self/exe").unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();

    assert_eq!(
        admit_desktop_client(
            server,
            credentials(),
            &expected,
            &UnavailableProcReader,
            "0.1.0",
            approval(),
            Duration::from_secs(1),
        )
        .unwrap_err(),
        DesktopClientAdmissionError::PeerUnauthorized
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    assert_eq!(client.read(&mut [0_u8]).unwrap(), 0);
}

#[test]
fn incompatible_version_receives_protocol_incompatible() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader {
        executable: executable.clone(),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(2, 2)).unwrap();

    assert_eq!(
        admit_desktop_client(
            server,
            credentials(),
            &executable,
            &reader,
            "0.1.0",
            approval(),
            Duration::from_secs(1),
        )
        .unwrap_err(),
        DesktopClientAdmissionError::ProtocolIncompatible
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::ProtocolIncompatible);
}

#[test]
fn oversized_first_frame_receives_payload_too_large() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader {
        executable: executable.clone(),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes())
        .unwrap();

    assert_eq!(
        admit_desktop_client(
            server,
            credentials(),
            &executable,
            &reader,
            "0.1.0",
            approval(),
            Duration::from_secs(1),
        )
        .unwrap_err(),
        DesktopClientAdmissionError::PayloadTooLarge
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::PayloadTooLarge);
}

#[test]
fn silent_client_reaches_the_deadline_without_a_response() {
    let executable = fs::canonicalize("/proc/self/exe").unwrap();
    let reader = FakeProcReader {
        executable: executable.clone(),
    };
    let (mut client, server) = UnixStream::pair().unwrap();

    assert_eq!(
        admit_desktop_client(
            server,
            credentials(),
            &executable,
            &reader,
            "0.1.0",
            approval(),
            Duration::from_millis(20),
        )
        .unwrap_err(),
        DesktopClientAdmissionError::Timeout
    );
    assert_eq!(client.read(&mut [0_u8]).unwrap(), 0);
}
