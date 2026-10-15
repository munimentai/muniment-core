//! The remote attach route over loopback TLS: pinning, pairing, device
//! credentials, scopes, revocation, the connection cap and backoff.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use muniment_core::attach::thread_service::{ThreadListPage, ThreadListRequest, ThreadListService};
use muniment_core::attach::{
    connect_pinned, connect_remote_runtime, decode_frame, encode_frame, pair_with_link,
    CertificateFingerprint, ClientError, ErrorCode, FailureBackoffPolicy, Id, InstallKind,
    Operation, PairingLink, PairingLinkRequest, ProtocolError, RemoteAccess, RemoteAccessOptions,
    RemoteClientOptions, RemoteConnectError, RemoteListener, RemoteListenerConfig,
    RemoteRuntimeRecord, SignedWorkspaceApproval, SCOPE_RUNTIME_ADMIN, SCOPE_RUNTIME_UPDATE,
    SCOPE_RUN_WRITE, SCOPE_THREAD_READ,
};
use serde_json::{json, Value};

struct TestService;

impl ThreadListService for TestService {
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

struct Runtime {
    access: RemoteAccess,
    address: SocketAddr,
    directory: PathBuf,
    clock: Arc<AtomicI64>,
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Runtime {
    fn start(configure: impl FnOnce(&mut RemoteListenerConfig)) -> Self {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-attach-{}", uuid::Uuid::now_v7()));
        let clock = Arc::new(AtomicI64::new(0));
        let access = open_access(&directory, &clock);
        let mut config = RemoteListenerConfig::new("127.0.0.1:0".parse().unwrap());
        configure(&mut config);
        let listener = RemoteListener::bind(config).unwrap();
        let address = listener.local_addr().unwrap();
        access
            .set_advertised_endpoints(vec![address.to_string()])
            .unwrap();
        let (stop, stopped) = mpsc::channel();
        let served = access.clone();
        let thread = std::thread::spawn(move || {
            listener
                .serve(
                    served,
                    SignedWorkspaceApproval::default(),
                    || Ok::<_, ()>(TestService),
                    stopped,
                )
                .unwrap();
        });
        Self {
            access,
            address,
            directory,
            clock,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn link(&self, scopes: Option<&[&str]>) -> PairingLink {
        self.access
            .create_pairing_link(PairingLinkRequest {
                scopes: scopes.map(|scopes| scopes.iter().map(|s| (*s).to_owned()).collect()),
                endpoints: None,
            })
            .unwrap()
            .link
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn open_access(directory: &std::path::Path, clock: &Arc<AtomicI64>) -> RemoteAccess {
    let clock = Arc::clone(clock);
    RemoteAccess::open_with_clock(
        directory.join("remote"),
        RemoteAccessOptions {
            runtime_name: Some("Test runtime".into()),
            runtime_version: "9.8.7".into(),
            install_kind: InstallKind::Container,
        },
        Box::new(move || {
            chrono::Utc::now() + chrono::Duration::seconds(clock.load(Ordering::SeqCst))
        }),
    )
    .unwrap()
}

fn options(scopes: Option<&[&str]>) -> RemoteClientOptions {
    RemoteClientOptions {
        kind: "desktop-client".into(),
        version: "1.0.0".into(),
        device_name: Some("Test laptop".into()),
        scopes: scopes.map(|scopes| scopes.iter().map(|s| (*s).to_owned()).collect()),
        io_timeout: Duration::from_secs(5),
    }
}

fn scopes(scopes: &[&str]) -> BTreeSet<String> {
    scopes.iter().map(|scope| (*scope).to_owned()).collect()
}

fn error_code(client: &muniment_core::attach::DesktopClient) -> Option<ErrorCode> {
    client.last_request_error().map(ProtocolError::code)
}

fn wait_for(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn the_handshake_trusts_the_pinned_certificate_and_refuses_any_other() {
    let runtime = Runtime::start(|_| {});
    let endpoints = vec![runtime.address.to_string()];
    assert!(connect_pinned(
        &endpoints,
        runtime.access.certificate_fingerprint(),
        Duration::from_secs(5)
    )
    .is_ok());

    let other_directory =
        std::env::temp_dir().join(format!("muniment-remote-other-{}", uuid::Uuid::now_v7()));
    let other = open_access(&other_directory, &Arc::new(AtomicI64::new(0)));
    assert_ne!(
        other.certificate_fingerprint(),
        runtime.access.certificate_fingerprint()
    );
    for fingerprint in [
        other.certificate_fingerprint(),
        CertificateFingerprint::from_bytes([0; 32]),
    ] {
        assert_eq!(
            connect_pinned(&endpoints, fingerprint, Duration::from_secs(5)).err(),
            Some(RemoteConnectError::CertificateMismatch)
        );
    }

    // A pairing link whose pin names another runtime never sends its secret.
    let mut link = runtime.link(None);
    link.fingerprint = other.certificate_fingerprint();
    assert_eq!(
        pair_with_link(&link, &options(None)).err(),
        Some(RemoteConnectError::CertificateMismatch)
    );
    link.fingerprint = runtime.access.certificate_fingerprint();
    assert!(pair_with_link(&link, &options(None)).is_ok());
    std::fs::remove_dir_all(other_directory).unwrap();
}

#[test]
fn pairing_issues_a_credential_and_the_welcome_names_the_runtime() {
    let runtime = Runtime::start(|_| {});
    let link = PairingLink::parse(&runtime.link(None).to_uri()).unwrap();
    let (client, record) = pair_with_link(&link, &options(None)).unwrap();

    let info = client.runtime_info().unwrap();
    assert_eq!(info, &runtime.access.runtime_info());
    assert_eq!(info.runtime_name, "Test runtime");
    assert_eq!(info.runtime_version, "9.8.7");
    assert_eq!(info.install_kind, Some(InstallKind::Container));
    assert_eq!(client.runtime_version(), "9.8.7");
    assert_eq!(record.runtime_id.as_str(), info.runtime_id);
    assert_eq!(
        record.scopes,
        scopes(&[SCOPE_THREAD_READ, SCOPE_RUN_WRITE, SCOPE_RUNTIME_UPDATE])
    );
    assert_eq!(client.remote_scopes(), Some(&record.scopes));

    let devices = runtime.access.list_devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, record.credential.device_id.as_str());
    assert_eq!(devices[0].name, "Test laptop");
    assert_eq!(devices[0].kind, "desktop-client");
    let stored = std::fs::read_to_string(runtime.directory.join("remote/access.json")).unwrap();
    assert!(!stored.contains(&record.credential.secret));
    assert!(!stored.contains(&link.secret));
}

#[test]
fn an_expired_reused_malformed_or_wrong_secret_is_refused() {
    let runtime = Runtime::start(|config| {
        config.backoff.free_attempts = 100;
    });

    let expired = runtime.link(None);
    runtime.clock.store(10 * 60 + 1, Ordering::SeqCst);
    assert_eq!(
        pair_with_link(&expired, &options(None)).err(),
        Some(RemoteConnectError::Unauthorized)
    );
    runtime.clock.store(0, Ordering::SeqCst);

    let link = runtime.link(None);
    assert!(pair_with_link(&link, &options(None)).is_ok());
    assert_eq!(
        pair_with_link(&link, &options(None)).err(),
        Some(RemoteConnectError::Unauthorized)
    );

    let unspent = runtime.link(None);
    for secret in ["", "zz", &"AB".repeat(16), &"ab".repeat(17)] {
        let mut malformed = unspent.clone();
        malformed.secret = secret.to_owned();
        assert_eq!(
            pair_with_link(&malformed, &options(None)).err(),
            Some(RemoteConnectError::Unauthorized),
            "{secret:?}"
        );
    }
    let mut wrong = unspent.clone();
    wrong.secret = "0".repeat(32);
    assert_eq!(
        pair_with_link(&wrong, &options(None)).err(),
        Some(RemoteConnectError::Unauthorized)
    );
    assert_eq!(runtime.access.list_devices().unwrap().len(), 1);
    assert!(pair_with_link(&unspent, &options(None)).is_ok());
}

#[test]
fn a_first_frame_that_is_not_a_hello_is_refused() {
    let runtime = Runtime::start(|_| {});
    let mut stream = connect_pinned(
        &[runtime.address.to_string()],
        runtime.access.certificate_fingerprint(),
        Duration::from_secs(5),
    )
    .unwrap();
    stream
        .write_all(&encode_frame(&json!({"operation": "thread.list"})).unwrap())
        .unwrap();
    stream
        .socket()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let (error, _): (Value, usize) = decode_frame(&bytes).unwrap().unwrap();
    assert_eq!(error["error"]["code"], "malformed_frame");

    // A hello that carries both a pairing secret and a credential is refused.
    let mut stream = connect_pinned(
        &[runtime.address.to_string()],
        runtime.access.certificate_fingerprint(),
        Duration::from_secs(5),
    )
    .unwrap();
    let link = runtime.link(None);
    stream
        .write_all(
            &encode_frame(&json!({
                "protocol": "muniment.attach/1",
                "client": {"kind": "cli", "version": "1.0.0"},
                "supported": {"min": 1, "max": 1},
                "client_nonce": "nonce",
                "authorized_client_id": "018f0000-0000-7000-8000-000000000099",
                "authorized_client_credential": "ab".repeat(32),
                "pairing": {"secret": link.secret},
            }))
            .unwrap(),
        )
        .unwrap();
    stream
        .socket()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let (error, _): (Value, usize) = decode_frame(&bytes).unwrap().unwrap();
    assert_eq!(error["error"]["code"], "unauthorized");
    assert!(runtime.access.list_devices().unwrap().is_empty());

    // Before authentication a frame larger than any hello is refused unread.
    let mut stream = connect_pinned(
        &[runtime.address.to_string()],
        runtime.access.certificate_fingerprint(),
        Duration::from_secs(5),
    )
    .unwrap();
    stream.write_all(&(64_u32 * 1024).to_be_bytes()).unwrap();
    stream
        .socket()
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let (error, _): (Value, usize) = decode_frame(&bytes).unwrap().unwrap();
    assert_eq!(error["error"]["code"], "payload_too_large");
}

#[test]
fn wrong_unknown_and_revoked_credentials_are_refused() {
    let runtime = Runtime::start(|config| {
        config.backoff.free_attempts = 100;
    });
    let (_, record) = pair_with_link(&runtime.link(None), &options(None)).unwrap();
    assert!(connect_remote_runtime(&record, &options(None)).is_ok());

    let mut wrong = record.clone();
    wrong.credential.secret = "0".repeat(64);
    let mut unknown = record.clone();
    unknown.credential.device_id = Id::new("018f0000-0000-7000-8000-0000000000ff").unwrap();
    let mut malformed = record.clone();
    malformed.credential.secret = "short".into();
    for record in [&wrong, &unknown, &malformed] {
        assert_eq!(
            connect_remote_runtime(record, &options(None)).err(),
            Some(RemoteConnectError::Unauthorized)
        );
    }

    assert!(runtime
        .access
        .revoke_device(record.credential.device_id.as_str())
        .unwrap());
    assert!(!runtime
        .access
        .revoke_device(record.credential.device_id.as_str())
        .unwrap());
    assert_eq!(
        connect_remote_runtime(&record, &options(None)).err(),
        Some(RemoteConnectError::Unauthorized)
    );
}

#[test]
fn revocation_closes_a_live_session_in_this_process_and_from_another() {
    let runtime = Runtime::start(|_| {});
    for other_process in [false, true] {
        let (_, record) = pair_with_link(&runtime.link(None), &options(None)).unwrap();
        let mut client = connect_remote_runtime(&record, &options(None)).unwrap();
        assert!(client
            .request(Operation::ThreadList, None, json!({"limit": 10}))
            .is_ok());
        if other_process {
            // A second open of the same directory stands in for another process.
            let other = open_access(&runtime.directory, &runtime.clock);
            assert!(other
                .revoke_device(record.credential.device_id.as_str())
                .unwrap());
        } else {
            assert!(runtime
                .access
                .revoke_device(record.credential.device_id.as_str())
                .unwrap());
        }
        let started = Instant::now();
        assert!(wait_for(|| client
            .request(Operation::ThreadList, None, json!({"limit": 10}))
            .is_err()));
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            connect_remote_runtime(&record, &options(None)).err(),
            Some(RemoteConnectError::Unauthorized)
        );
    }
}

#[test]
fn scopes_narrow_at_pairing_and_gate_each_operation() {
    let runtime = Runtime::start(|config| {
        config.backoff.free_attempts = 100;
    });

    // A request that keeps no scope of the link fails without spending it.
    let admin_link = runtime.link(Some(&[SCOPE_THREAD_READ, SCOPE_RUNTIME_ADMIN]));
    assert_eq!(
        pair_with_link(&admin_link, &options(Some(&[SCOPE_RUN_WRITE]))).err(),
        Some(RemoteConnectError::Unauthorized)
    );
    let (mut admin, admin_record) = pair_with_link(
        &admin_link,
        &options(Some(&[
            SCOPE_RUNTIME_ADMIN,
            SCOPE_RUN_WRITE,
            SCOPE_THREAD_READ,
        ])),
    )
    .unwrap();
    assert_eq!(
        admin_record.scopes,
        scopes(&[SCOPE_THREAD_READ, SCOPE_RUNTIME_ADMIN])
    );

    // An admin delegates only scopes it holds.
    assert!(admin
        .create_pairing_link(Some(&scopes(&[SCOPE_RUN_WRITE])), None)
        .is_err());
    assert_eq!(error_code(&admin), Some(ErrorCode::Unauthorized));
    let reader_link = admin
        .create_pairing_link(Some(&scopes(&[SCOPE_THREAD_READ])), None)
        .unwrap();
    assert_eq!(
        reader_link.fingerprint,
        runtime.access.certificate_fingerprint()
    );
    let (mut reader, _) = pair_with_link(&reader_link, &options(None)).unwrap();
    assert_eq!(reader.remote_scopes(), Some(&scopes(&[SCOPE_THREAD_READ])));

    // Read is admitted, write and admin are not, same-machine operations never are.
    assert!(reader
        .request(Operation::ThreadList, None, json!({"limit": 10}))
        .is_ok());
    assert!(reader.read_runtime_info().is_ok());
    let refused = [
        (Operation::ThreadCreate, json!({}), ErrorCode::Unauthorized),
        (
            Operation::RunStart,
            json!({"text": "hi"}),
            ErrorCode::Unauthorized,
        ),
        (
            Operation::RemoteDeviceList,
            json!({}),
            ErrorCode::Unauthorized,
        ),
        (
            Operation::RuntimeUpdate,
            json!({"version": "1.0.0"}),
            ErrorCode::Unauthorized,
        ),
        (
            Operation::ModelsRequest,
            json!({"action": "router_set_enabled", "data": {"enabled": true}}),
            ErrorCode::Unauthorized,
        ),
        (
            Operation::WorkspaceOnboard,
            json!({"opened_directory": "/tmp", "memory_location": "/tmp"}),
            ErrorCode::UnsupportedOperation,
        ),
        (
            Operation::SessionStatus,
            json!({}),
            ErrorCode::UnsupportedOperation,
        ),
        (
            Operation::CompanionList,
            json!({}),
            ErrorCode::UnsupportedOperation,
        ),
        (
            Operation::MigrationControl,
            json!({}),
            ErrorCode::Unauthorized,
        ),
    ];
    for (operation, body, code) in refused {
        let key = operation
            .requires_idempotency_key()
            .then(|| Id::new(uuid::Uuid::now_v7().to_string()).unwrap());
        assert!(
            reader.request(operation, key, body).is_err(),
            "{operation:?}"
        );
        assert_eq!(error_code(&reader), Some(code), "{operation:?}");
    }

    // The admin device lists and revokes devices but holds no write scope.
    let devices = admin.list_remote_devices().unwrap();
    assert_eq!(devices["devices"].as_array().unwrap().len(), 2);
    assert!(admin
        .request(
            Operation::ThreadCreate,
            Some(Id::new(uuid::Uuid::now_v7().to_string()).unwrap()),
            json!({})
        )
        .is_err());
    assert_eq!(error_code(&admin), Some(ErrorCode::Unauthorized));
}

#[test]
fn an_admin_update_request_is_recorded_for_the_host() {
    let runtime = Runtime::start(|_| {});
    let requests = runtime.access.update_requests();
    let link = runtime.link(Some(&[SCOPE_THREAD_READ, SCOPE_RUNTIME_ADMIN]));
    let (mut admin, record) = pair_with_link(&link, &options(None)).unwrap();
    assert!(admin.request_runtime_update("1.2.x;rm").is_err());
    assert_eq!(error_code(&admin), Some(ErrorCode::InvalidRequest));
    // The runtime runs 9.8.7, so an older version is refused.
    assert!(admin.request_runtime_update("1.3.0").is_err());
    assert_eq!(error_code(&admin), Some(ErrorCode::InvalidRequest));
    let answer = admin.request_runtime_update("9.9.0").unwrap();
    assert_eq!(answer["version"], "9.9.0");
    let request = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(request.version, "9.9.0");
    assert_eq!(request.requested_by, record.credential.device_id.as_str());
    assert_eq!(runtime.access.requested_update(), Some(request));
    let info = admin.read_runtime_info().unwrap();
    assert_eq!(info["update_request"]["version"], "9.9.0");
    assert_eq!(
        info["certificate_sha256"],
        runtime.access.certificate_fingerprint().to_hex()
    );
    runtime.access.clear_update_request().unwrap();
    assert_eq!(runtime.access.requested_update(), None);
}

#[test]
fn the_connection_cap_refuses_extra_connections_until_one_ends() {
    let runtime = Runtime::start(|config| {
        config.max_connections = 1;
        config.handshake_timeout = Duration::from_secs(30);
    });
    let holder = TcpStream::connect(runtime.address).unwrap();
    // The held connection waits in its handshake, so the next one is refused.
    std::thread::sleep(Duration::from_millis(200));
    let link = runtime.link(None);
    assert_eq!(
        pair_with_link(&link, &options(None)).err(),
        Some(RemoteConnectError::Unreachable)
    );
    drop(holder);
    assert!(wait_for(|| pair_with_link(&link, &options(None)).is_ok()));
}

#[test]
fn repeated_refusals_hold_the_peer_back() {
    let runtime = Runtime::start(|config| {
        config.backoff = FailureBackoffPolicy {
            free_attempts: 2,
            base_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(60),
            memory: Duration::from_secs(60),
        };
    });
    let link = runtime.link(None);
    let mut wrong = link.clone();
    wrong.secret = "0".repeat(32);
    for _ in 0..2 {
        assert_eq!(
            pair_with_link(&wrong, &options(None)).err(),
            Some(RemoteConnectError::Unauthorized)
        );
    }
    // The held peer is dropped before TLS, so even the right secret is not spent.
    assert_eq!(
        pair_with_link(&link, &options(None)).err(),
        Some(RemoteConnectError::Unreachable)
    );
    assert!(runtime.access.list_devices().unwrap().is_empty());
}

#[test]
fn a_client_pairs_reconnects_reads_and_is_revoked_over_loopback() {
    let runtime = Runtime::start(|_| {});
    let link = runtime.link(None).to_uri();
    let record_path = runtime.directory.join("client/runtime.json");

    let link = PairingLink::parse(&link).unwrap();
    let (paired, record) = pair_with_link(&link, &options(None)).unwrap();
    drop(paired);
    record.save(&record_path).unwrap();

    let record = RemoteRuntimeRecord::load(&record_path).unwrap();
    let mut client = connect_remote_runtime(&record, &options(None)).unwrap();
    assert_eq!(
        client.runtime_info().map(|info| info.runtime_id.as_str()),
        Some(record.runtime_id.as_str())
    );
    let page = client
        .request(Operation::ThreadList, None, json!({"limit": 10}))
        .unwrap();
    assert_eq!(page.body["threads"], json!([]));
    let info = client.read_runtime_info().unwrap();
    assert_eq!(info["runtime_id"], record.runtime_id.as_str());

    assert!(runtime
        .access
        .revoke_device(record.credential.device_id.as_str())
        .unwrap());
    assert!(wait_for(|| client
        .request(Operation::ThreadList, None, json!({"limit": 10}))
        .is_err()));
    assert!(matches!(
        connect_remote_runtime(&record, &options(None)),
        Err(RemoteConnectError::Unauthorized)
    ));
    assert!(matches!(
        client.request(Operation::ThreadList, None, json!({"limit": 10})),
        Err(ClientError::ConnectionClosed
            | ClientError::DesktopUnavailable
            | ClientError::UnexpectedMessage)
    ));
}
