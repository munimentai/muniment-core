#![cfg(target_os = "linux")]

use muniment_core::attach::linux::{
    run_authenticated_session_with_authorization_and_registry, ApprovalDecision,
    AttachSessionError, AuthorizationSessionDependencies, LiveConnectionRegistry, PeerCredentials,
    ThreadListPage, ThreadListRequest, ThreadListService,
};
use muniment_core::attach::{
    decode_frame, encode_frame, Approval, AuthorizationClock, AuthorizationRandomnessError,
    AuthorizationTokenGenerator, Authorized, Client, ClientCredential, CompanionRecord,
    CompanionRegistry, ErrorCode, Event, EventName, Hello, Id, Operation, Protocol, ProtocolError,
    Request, Response, VersionRange, Welcome,
};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Barrier, Mutex},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-companion-registry-{name}-{}",
        Uuid::now_v7()
    ))
}

fn entry(
    credential: &str,
    kind: &str,
    version: &str,
    approved_at: Option<&str>,
) -> ClientCredential {
    ClientCredential {
        credential: credential.repeat(32),
        claimed_kind: kind.to_owned(),
        claimed_version: version.to_owned(),
        approved_at: approved_at.map(str::to_owned),
    }
}

fn registry(
    credentials: HashMap<String, ClientCredential>,
    path: &PathBuf,
) -> (
    CompanionRegistry,
    Arc<Mutex<HashMap<String, ClientCredential>>>,
) {
    let credentials = Arc::new(Mutex::new(credentials));
    (
        CompanionRegistry::new(credentials.clone(), path, LiveConnectionRegistry::default()),
        credentials,
    )
}

#[derive(Clone)]
struct TestClock(Instant);

impl AuthorizationClock for TestClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

struct TestTokens;

impl AuthorizationTokenGenerator for TestTokens {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), AuthorizationRandomnessError> {
        bytes.fill(1);
        Ok(())
    }
}

struct CredentialService(String);

impl ThreadListService for CredentialService {
    fn authorize_client(
        &mut self,
        _: &str,
        presented_credential: Option<&str>,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<String, ProtocolError> {
        (presented_credential == Some(self.0.as_str()))
            .then(|| self.0.clone())
            .ok_or_else(ProtocolError::unauthorized)
    }

    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        Ok(ThreadListPage {
            threads: vec![],
            next_cursor: None,
        })
    }
}

fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> T {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut bytes = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
    bytes[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut bytes[4..]).unwrap();
    decode_frame(&bytes).unwrap().unwrap().0
}

fn start_session(
    registry: LiveConnectionRegistry,
    credential: &str,
) -> (
    UnixStream,
    thread::JoinHandle<Result<(), AttachSessionError>>,
) {
    let (mut client, server) = UnixStream::pair().unwrap();
    let expected = credential.to_owned();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization_and_registry(
            server,
            PeerCredentials {
                pid: std::process::id() as libc::pid_t,
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            },
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Instant::now()),
                tokens: TestTokens,
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(Approval {
                        profile: "profile-1".into(),
                        workspace: "workspace-1".into(),
                        scopes: BTreeSet::from(["thread.read".into()]),
                        lifetime: Duration::from_secs(60),
                    }))
                },
            },
            &mut CredentialService(expected.clone()),
            &registry,
        )
    });
    client
        .write_all(
            &encode_frame(&Hello {
                protocol: Protocol,
                client: Client {
                    kind: "cli".into(),
                    version: "1.0.0".into(),
                },
                supported: VersionRange { min: 1, max: 1 },
                client_nonce: "client-nonce".into(),
                authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000001").unwrap(),
                authorized_client_credential: Some(credential.to_owned()),
            })
            .unwrap(),
        )
        .unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    (client, server_thread)
}

fn list_request() -> Vec<u8> {
    encode_frame(&Request {
        protocol: Protocol,
        request_id: Id::new("018f0000-0000-7000-8000-000000000010").unwrap(),
        operation: Operation::ThreadList,
        capability: "01".repeat(32),
        idempotency_key: None,
        body: serde_json::json!({"limit": 1}),
    })
    .unwrap()
}

#[test]
fn revoke_persists_the_removal_before_it_finishes() {
    let path = path("revoke").join("credentials.json");
    let identity = "018f0000-0000-7000-8000-000000000001";
    let credential = "ab".repeat(32);
    let credentials = Arc::new(Mutex::new(HashMap::from([(
        identity.to_owned(),
        entry("ab", "cli", "1.2.3", None),
    )])));
    let live_connections = LiveConnectionRegistry::default();
    let (mut client, server_thread) = start_session(live_connections.clone(), &credential);
    let persistence = Arc::new(Barrier::new(2));
    let persist_barrier = persistence.clone();
    let registry = CompanionRegistry::new_with_persistence(
        credentials,
        &path,
        live_connections,
        move |_, credentials| {
            assert!(!credentials.contains_key(identity));
            persist_barrier.wait();
            persist_barrier.wait();
            Ok(())
        },
    );
    let revoke_thread = thread::spawn(move || registry.revoke(identity));

    persistence.wait();
    client.write_all(&list_request()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let error = client.read(&mut [0]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    persistence.wait();
    revoke_thread.join().unwrap().unwrap();
    client.set_read_timeout(None).unwrap();
    let event: Event = read_frame(&mut client);
    assert_eq!(event.event, EventName::CapabilityRevoked);
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn failed_persist_restores_the_credential() {
    let path = path("failed-persist").join("credentials.json");
    let identity = "018f0000-0000-7000-8000-000000000001";
    let credential = "ab".repeat(32);
    let credentials = Arc::new(Mutex::new(HashMap::from([(
        identity.to_owned(),
        entry("ab", "cli", "1.2.3", None),
    )])));
    let live_connections = LiveConnectionRegistry::default();
    let (mut client, server_thread) = start_session(live_connections.clone(), &credential);
    let persistence = Arc::new(Barrier::new(2));
    let persist_barrier = persistence.clone();
    let registry = CompanionRegistry::new_with_persistence(
        credentials.clone(),
        &path,
        live_connections,
        move |_, credentials| {
            assert!(!credentials.contains_key(identity));
            persist_barrier.wait();
            persist_barrier.wait();
            Err(ProtocolError::persistence_failed())
        },
    );
    let revoke_thread = thread::spawn(move || registry.revoke(identity));

    persistence.wait();
    client.write_all(&list_request()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let error = client.read(&mut [0]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    persistence.wait();
    assert_eq!(
        revoke_thread.join().unwrap().unwrap_err().code(),
        ErrorCode::PersistenceFailed
    );
    assert!(credentials.lock().unwrap().contains_key(identity));
    client.set_read_timeout(None).unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.request_id,
        Id::new("018f0000-0000-7000-8000-000000000010").unwrap()
    );
    drop(client);
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn unknown_identity_is_unauthorized_without_changing_the_store() {
    let path = path("unknown").join("credentials.json");
    let identity = "018f0000-0000-7000-8000-000000000001";
    let (registry, credentials) = registry(
        HashMap::from([(identity.to_owned(), entry("ab", "cli", "1.2.3", None))]),
        &path,
    );

    assert_eq!(
        registry
            .revoke("018f0000-0000-7000-8000-000000000099")
            .unwrap_err()
            .code(),
        ErrorCode::Unauthorized
    );
    assert!(credentials.lock().unwrap().contains_key(identity));
    assert!(!path.exists());
}

#[test]
fn list_returns_claims_and_approval_times_sorted_by_identity() {
    let path = path("list").join("credentials.json");
    let first = "018f0000-0000-7000-8000-000000000001";
    let second = "018f0000-0000-7000-8000-000000000002";
    let (registry, _) = registry(
        HashMap::from([
            (second.to_owned(), entry("cd", "mobile", "2.0.0", None)),
            (
                first.to_owned(),
                entry("ab", "cli", "1.2.3", Some("2026-08-04T12:00:00Z")),
            ),
        ]),
        &path,
    );

    assert_eq!(
        registry.list().unwrap(),
        vec![
            CompanionRecord {
                identity: first.to_owned(),
                claimed_kind: "cli".to_owned(),
                claimed_version: "1.2.3".to_owned(),
                approved_at: Some("2026-08-04T12:00:00Z".to_owned()),
            },
            CompanionRecord {
                identity: second.to_owned(),
                claimed_kind: "mobile".to_owned(),
                claimed_version: "2.0.0".to_owned(),
                approved_at: None,
            },
        ]
    );
}
