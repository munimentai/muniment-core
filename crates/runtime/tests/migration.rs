#![cfg(target_os = "linux")]

use muniment_attach::{decode_frame, Request};
use muniment_core::attach::linux::{
    AttachFilesystem, AttachTransport, LiveConnectionRegistry, ThreadListPage, ThreadListRequest,
    ThreadListService,
};
use muniment_core::attach::{
    probe_handoff, ApprovalCoordinator, CompanionRegistry, ProtocolError, SignedWorkspaceApproval,
};
use muniment_runtime_core::{run_migration_takeover, AttachListenerInputs, MigrationTakeoverError};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct TestService;

impl ThreadListService for TestService {
    fn list_threads(
        &mut self,
        _workspace: &str,
        _request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!("the handshake does not list threads")
    }
}

struct RuntimeDirectory(PathBuf);

impl RuntimeDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-runtime-migration-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn listener_state(
    runtime: &RuntimeDirectory,
) -> (
    CompanionRegistry,
    SignedWorkspaceApproval,
    ApprovalCoordinator,
) {
    let approval = SignedWorkspaceApproval::default();
    approval.record("workspace-a".into());
    let approvals = ApprovalCoordinator::default();
    let decisions = approvals.clone();
    approvals.register_presenter(move |request| {
        let decisions = decisions.clone();
        let challenge = request.challenge.clone();
        thread::spawn(move || decisions.decide(&challenge, true));
        true
    });
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        runtime.0.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    (registry, approval, approvals)
}

fn inputs<'a>(
    registry: &'a CompanionRegistry,
    approval: &SignedWorkspaceApproval,
    approvals: &ApprovalCoordinator,
) -> AttachListenerInputs<'a> {
    AttachListenerInputs {
        runtime_version: env!("CARGO_PKG_VERSION"),
        companion_registry: registry,
        approval: approval.clone(),
        approvals: approvals.clone(),
        expected_desktop_executable: std::env::current_exe().ok(),
    }
}

#[test]
fn stop_ends_takeover_after_acceptance_while_the_holder_retains_the_lock() {
    let runtime = RuntimeDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let _desktop_lock = filesystem.acquire_instance_lock().unwrap();
    let desktop = AttachTransport::bind(&filesystem).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (registry, approval, approvals) = listener_state(&runtime);

    let started = Instant::now();
    thread::scope(|scope| {
        let takeover = scope.spawn(|| {
            run_migration_takeover(
                &runtime.0,
                inputs(&registry, &approval, &approvals),
                || Ok::<_, ()>(TestService),
                started + Duration::from_secs(2),
                stop_rx,
            )
        });
        let (mut stream, _) = desktop.accept().unwrap();
        let request = complete_handshake(&mut stream);
        let nonce = request.body["handoff_nonce"].as_str().unwrap();
        write_success(&mut stream, &request, nonce);

        stop_tx.send(()).unwrap();
        assert_eq!(takeover.join().unwrap(), Ok(()));
    });
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn stop_interrupts_a_stalled_takeover_handshake() {
    let runtime = RuntimeDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let _desktop_lock = filesystem.acquire_instance_lock().unwrap();
    let desktop = AttachTransport::bind(&filesystem).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (registry, approval, approvals) = listener_state(&runtime);

    let started = Instant::now();
    thread::scope(|scope| {
        let takeover = scope.spawn(|| {
            run_migration_takeover(
                &runtime.0,
                inputs(&registry, &approval, &approvals),
                || Ok::<_, ()>(TestService),
                started + Duration::from_secs(2),
                stop_rx,
            )
        });
        let (_stream, _) = desktop.accept().unwrap();

        stop_tx.send(()).unwrap();
        assert_eq!(takeover.join().unwrap(), Ok(()));
    });
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn stop_interrupts_a_stalled_takeover_control_request() {
    let runtime = RuntimeDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let _desktop_lock = filesystem.acquire_instance_lock().unwrap();
    let desktop = AttachTransport::bind(&filesystem).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (registry, approval, approvals) = listener_state(&runtime);

    let started = Instant::now();
    thread::scope(|scope| {
        let takeover = scope.spawn(|| {
            run_migration_takeover(
                &runtime.0,
                inputs(&registry, &approval, &approvals),
                || Ok::<_, ()>(TestService),
                started + Duration::from_secs(2),
                stop_rx,
            )
        });
        let (mut stream, _) = desktop.accept().unwrap();
        let _request = complete_handshake(&mut stream);

        stop_tx.send(()).unwrap();
        assert_eq!(takeover.join().unwrap(), Ok(()));
    });
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn retries_migration_not_ready_before_acceptance() {
    let runtime = RuntimeDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    let desktop_lock = filesystem.acquire_instance_lock().unwrap();
    let desktop = AttachTransport::bind(&filesystem).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    let (registry, approval, approvals) = listener_state(&runtime);
    let test_timeout = Duration::from_secs(2);

    thread::scope(|scope| {
        let takeover = scope.spawn(|| {
            run_migration_takeover(
                &runtime.0,
                inputs(&registry, &approval, &approvals),
                || Ok::<_, ()>(TestService),
                Instant::now() + test_timeout,
                stop_rx,
            )
            .unwrap()
        });
        let (mut first, _) = desktop.accept().unwrap();
        let first_request = complete_handshake(&mut first);
        write_error(&mut first, &first_request, "migration_not_ready", true);
        drop(first);

        let (mut second, _) = desktop.accept().unwrap();
        let second_request = complete_handshake(&mut second);
        let nonce = second_request.body["handoff_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        write_success(&mut second, &second_request, &nonce);
        drop(second);
        drop(desktop);
        drop(desktop_lock);

        assert!(probe_handoff(&endpoint, &nonce, Instant::now() + test_timeout).is_ok());
        stop_tx.send(()).unwrap();
        takeover.join().unwrap();
    });
}

#[test]
fn retries_compatibility_answers_until_the_deadline() {
    let cases = ["migration_not_ready", "unsupported_operation"];
    let test_timeout = Duration::from_secs(2);

    for code in cases {
        let runtime = RuntimeDirectory::new();
        let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
        let _desktop_lock = filesystem.acquire_instance_lock().unwrap();
        let desktop = AttachTransport::bind(&filesystem).unwrap();
        let (_stop_tx, stop_rx) = mpsc::channel();
        let (registry, approval, approvals) = listener_state(&runtime);

        let started = Instant::now();
        thread::scope(|scope| {
            let takeover = scope.spawn(|| {
                run_migration_takeover(
                    &runtime.0,
                    inputs(&registry, &approval, &approvals),
                    || Ok::<_, ()>(TestService),
                    Instant::now() + Duration::from_millis(100),
                    stop_rx,
                )
            });
            let (mut stream, _) = desktop.accept().unwrap();
            let request = complete_handshake(&mut stream);
            write_error(&mut stream, &request, code, false);
            drop(stream);
            assert_eq!(
                takeover.join().unwrap().unwrap_err(),
                MigrationTakeoverError::DeadlineElapsed
            );
        });
        assert!(started.elapsed() < test_timeout);
    }
}

#[test]
fn maps_unauthorized_control_answer_to_a_typed_error() {
    let runtime = RuntimeDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let _desktop_lock = filesystem.acquire_instance_lock().unwrap();
    let desktop = AttachTransport::bind(&filesystem).unwrap();
    let (_stop_tx, stop_rx) = mpsc::channel();
    let (registry, approval, approvals) = listener_state(&runtime);

    thread::scope(|scope| {
        let takeover = scope.spawn(|| {
            run_migration_takeover(
                &runtime.0,
                inputs(&registry, &approval, &approvals),
                || Ok::<_, ()>(TestService),
                Instant::now() + Duration::from_secs(2),
                stop_rx,
            )
        });
        let (mut stream, _) = desktop.accept().unwrap();
        let request = complete_handshake(&mut stream);
        write_error(&mut stream, &request, "unauthorized", false);
        assert_eq!(
            takeover.join().unwrap().unwrap_err(),
            MigrationTakeoverError::Unauthorized
        );
    });
}

#[test]
fn stalled_desktop_cannot_extend_the_caller_deadline() {
    let runtime = RuntimeDirectory::new();
    let filesystem = AttachFilesystem::from_runtime_directory(&runtime.0).unwrap();
    let _desktop_lock = filesystem.acquire_instance_lock().unwrap();
    let desktop = AttachTransport::bind(&filesystem).unwrap();
    let (_stop_tx, stop_rx) = mpsc::channel();
    let (registry, approval, approvals) = listener_state(&runtime);
    let caller_deadline = Duration::from_millis(100);
    let test_timeout = Duration::from_secs(1);
    let started = Instant::now();

    thread::scope(|scope| {
        let takeover = scope.spawn(|| {
            run_migration_takeover(
                &runtime.0,
                inputs(&registry, &approval, &approvals),
                || Ok::<_, ()>(TestService),
                started + caller_deadline,
                stop_rx,
            )
        });
        let (mut stream, _) = desktop.accept().unwrap();
        let _request = complete_handshake(&mut stream);
        assert_eq!(
            takeover.join().unwrap().unwrap_err(),
            MigrationTakeoverError::DeadlineElapsed
        );
    });
    assert!(started.elapsed() < test_timeout);
}

fn complete_handshake(stream: &mut impl ReadWrite) -> Request {
    let _hello: muniment_attach::Hello = read_hello(stream);
    write_json_frame(
        stream,
        r#"{"selected":1,"desktop_version":"0.0.1","server_nonce":"11111111111111111111111111111111","authorization":"authorized","approval_challenge":""}"#,
    );
    write_json_frame(
        stream,
        r#"{"profile_id":"","capability":"3333333333333333333333333333333333333333333333333333333333333333","expires_at":60,"idle_timeout_seconds":60,"workspace_scopes":{}}"#,
    );
    read_request(stream)
}

fn write_success(stream: &mut impl Write, request: &Request, nonce: &str) {
    let response = format!(
        r#"{{"protocol":"muniment.attach/1","request_id":"{}","ok":true,"body":{{"handoff_nonce":"{nonce}"}}}}"#,
        request.request_id.as_str()
    );
    write_json_frame(stream, &response);
}

fn write_error(stream: &mut impl Write, request: &Request, code: &str, retryable: bool) {
    let message = match code {
        "migration_not_ready" => "The desktop cannot hand off ownership yet.",
        "unauthorized" => "The capability is not authorized.",
        "unsupported_operation" => "The operation is not supported.",
        _ => unreachable!(),
    };
    let response = format!(
        r#"{{"protocol":"muniment.attach/1","request_id":"{}","ok":false,"error":{{"code":"{code}","message":"{message}","retryable":{retryable}}}}}"#,
        request.request_id.as_str()
    );
    write_json_frame(stream, &response);
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn read_bytes(stream: &mut impl Read) -> Vec<u8> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; 4 + u32::from_be_bytes(prefix) as usize];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    frame
}

fn read_hello(stream: &mut impl Read) -> muniment_attach::Hello {
    decode_frame(&read_bytes(stream)).unwrap().unwrap().0
}

fn read_request(stream: &mut impl Read) -> Request {
    decode_frame(&read_bytes(stream)).unwrap().unwrap().0
}

fn write_json_frame(stream: &mut impl Write, json: &str) {
    stream
        .write_all(&(json.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(json.as_bytes()).unwrap();
}
