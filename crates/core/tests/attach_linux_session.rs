#![cfg(target_os = "linux")]

use muniment_core::attach::linux::{
    approval_waiter_with_claims, run_authenticated_session_with,
    run_authenticated_session_with_authorization,
    run_authenticated_session_with_authorization_and_registry,
    run_authenticated_session_with_authorization_registry_and_migration,
    run_authenticated_session_with_service_and_approvals, ApprovalDecision, AttachSessionError,
    AuthorizationSessionDependencies, CompanionProvenance, LiveConnectionRegistry,
    MigrationControlRequest, MigrationControlSessionDependencies, PeerCredentials,
    PermissionAnswerAccepted, PermissionAnswerRequest, RedactedThreadSummary, RunCancelAccepted,
    RunCancelRequest, RunStartAccepted, RunStartRequest, RunStreamPage, ThreadListPage,
    ThreadListRequest, ThreadListService, ThreadOpenRequest, MAX_PERMISSION_GATE_ID_LENGTH,
    MAX_RUN_START_CONTEXT_LENGTH, MAX_RUN_START_TEXT_LENGTH,
};
use muniment_core::attach::{
    decode_frame, encode_frame, Approval, AuthorizationClock, AuthorizationTokenGenerator,
    Authorized, DrainState, Envelope, ErrorAction, ErrorCode, ErrorEnvelope, Event, EventName,
    Hello, Id, Operation, Protocol, Request, Response, VersionRange, Welcome,
    WorkspaceOnboardRequest, WorkspaceOnboarded, CHALLENGE_LIFETIME, MAX_FRAME_LENGTH,
    MAX_JSON_DEPTH, MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS,
    MAX_RUN_STREAM_WINDOW_TEXT_BYTES,
};
use muniment_core::browser_control::{LinuxProcReader, ProcReadError};
use muniment_core::journal::{
    EventEnvelope, EventPayload, Provenance, RunEventProjection, RunJournal,
};
use serde_json::json;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

fn credentials() -> PeerCredentials {
    PeerCredentials {
        pid: std::process::id() as libc::pid_t,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}

struct DrainingService {
    drain: DrainState,
}

impl ThreadListService for DrainingService {
    fn drain_state(&self) -> Option<&DrainState> {
        Some(&self.drain)
    }

    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        unreachable!()
    }
}

#[test]
fn companion_drain_gate_refuses_new_activity_and_serves_completion_operations() {
    let (mut client, server_thread) = draining_companion_session();

    for (index, operation) in [
        Operation::RunStart,
        Operation::RunSubmit,
        Operation::RunResume,
        Operation::SessionSignIn,
    ]
    .into_iter()
    .enumerate()
    {
        client
            .write_all(&request_with_idempotency(
                10 + index as u128,
                operation,
                json!({}),
            ))
            .unwrap();
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::RuntimeDraining);
    }
    client.shutdown(Shutdown::Both).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));

    for operation in [
        Operation::RunPermissionAnswer,
        Operation::RunCancel,
        Operation::ThreadOpen,
        Operation::RunStream,
    ] {
        let (mut client, server_thread) = draining_companion_session();
        client
            .write_all(&request_with_idempotency(20, operation, json!({})))
            .unwrap();
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_ne!(error.error.code(), ErrorCode::RuntimeDraining);
        drop(client);
        let _ = server_thread.join().unwrap();
    }
}

fn draining_companion_session() -> (
    UnixStream,
    thread::JoinHandle<Result<(), AttachSessionError>>,
) {
    let drain = DrainState::new();
    drain.set();
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: SessionTestClock(Instant::now()),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut DrainingService { drain },
        )
    });

    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    (client, server_thread)
}

fn sole_thread_id(journal: &mut RunJournal, workspace: &str) -> String {
    let page = journal
        .workspace_thread_summaries(workspace, 2, None)
        .unwrap();
    assert_eq!(page.summaries.len(), 1);
    page.summaries[0].thread_id.clone()
}

fn hello(min: u32, max: u32) -> Vec<u8> {
    hello_for_client(min, max, "018f0000-0000-7000-8000-000000000099")
}

fn hello_for_client(min: u32, max: u32, client_id: &str) -> Vec<u8> {
    hello_for_client_with_credential(min, max, client_id, None)
}

fn hello_for_client_with_credential(
    min: u32,
    max: u32,
    client_id: &str,
    credential: Option<&str>,
) -> Vec<u8> {
    hello_with_claims(min, max, client_id, credential, "cli", "1.0.0")
}

fn hello_with_claims(
    min: u32,
    max: u32,
    client_id: &str,
    credential: Option<&str>,
    kind: &str,
    version: &str,
) -> Vec<u8> {
    encode_frame(&Hello {
        protocol: Protocol,
        client: muniment_core::attach::Client {
            kind: kind.into(),
            version: version.into(),
        },
        supported: VersionRange { min, max },
        client_nonce: "client-nonce".into(),
        authorized_client_id: Id::new(client_id).unwrap(),
        authorized_client_credential: credential.map(str::to_owned),
    })
    .unwrap()
}

struct CredentialService {
    expected: String,
    bound: bool,
    claims: Option<(String, String)>,
}

impl ThreadListService for CredentialService {
    fn reconnect_approval(&self) -> Option<Approval> {
        Some(approval())
    }

    fn authorize_client(
        &mut self,
        _: &str,
        presented_credential: Option<&str>,
        issued_credential: &str,
        claimed_kind: &str,
        claimed_version: &str,
    ) -> Result<String, muniment_core::attach::ProtocolError> {
        self.claims = Some((claimed_kind.into(), claimed_version.into()));
        if presented_credential == Some(self.expected.as_str()) {
            self.bound = true;
            Ok(self.expected.clone())
        } else if presented_credential.is_none() {
            self.bound = true;
            Ok(issued_credential.to_owned())
        } else {
            Err(muniment_core::attach::ProtocolError::unauthorized())
        }
    }

    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("request must not dispatch")
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

#[derive(Clone)]
struct TestClock(Rc<Cell<Duration>>);
impl AuthorizationClock for TestClock {
    fn now(&self) -> Duration {
        self.0.get()
    }
}
struct TestTokens(u8);
impl AuthorizationTokenGenerator for TestTokens {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), muniment_core::attach::AuthorizationRandomnessError> {
        bytes.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}

struct FailingTokens {
    calls_before_failure: usize,
}
impl AuthorizationTokenGenerator for FailingTokens {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), muniment_core::attach::AuthorizationRandomnessError> {
        if self.calls_before_failure == 0 {
            return Err(muniment_core::attach::AuthorizationRandomnessError);
        }
        self.calls_before_failure -= 1;
        bytes.fill(1);
        Ok(())
    }
}
fn approval() -> Approval {
    Approval {
        profile: "profile-1".into(),
        workspace: "workspace-1".into(),
        scopes: BTreeSet::from(["thread.read".into()]),
        lifetime: Duration::from_secs(3600),
    }
}

fn unavailable_service(
    _: &str,
    _: ThreadListRequest,
) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
    panic!("request must not dispatch")
}

#[derive(Default)]
struct StartService {
    calls: Vec<(String, String, RunStartRequest, Id, Id, CompanionProvenance)>,
    output: Option<RunStartAccepted>,
}

#[derive(Default)]
struct MigrationControlService {
    calls: Vec<(MigrationControlRequest, CompanionProvenance)>,
}

#[derive(Clone)]
struct MigrationProcessReader {
    executable: Result<PathBuf, ProcReadError>,
}

impl LinuxProcReader for MigrationProcessReader {
    fn start_identity(&self, _: u32) -> Result<u64, ProcReadError> {
        self.executable.as_ref().map(|_| 42).map_err(|error| *error)
    }

    fn executable(&self, _: u32) -> Result<PathBuf, ProcReadError> {
        self.executable.clone()
    }
}

impl ThreadListService for MigrationControlService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn control_migration(
        &mut self,
        request: MigrationControlRequest,
        provenance: CompanionProvenance,
    ) -> Result<(), muniment_core::attach::ProtocolError> {
        self.calls.push((request, provenance));
        Ok(())
    }
}

#[derive(Clone, Default)]
struct OnboardingStartService {
    instructions: Arc<std::sync::Mutex<HashMap<String, HashMap<String, String>>>>,
    runs: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    client_identity: Option<String>,
}

impl ThreadListService for OnboardingStartService {
    fn bind_authorized_client(&mut self, client_identity: &str) {
        self.client_identity = Some(client_identity.to_owned());
    }

    fn onboard_workspace(
        &mut self,
        _session_workspace: &str,
        request: WorkspaceOnboardRequest,
    ) -> Result<WorkspaceOnboarded, muniment_core::attach::ProtocolError> {
        let instructions = format!("instructions for {}", request.opened_directory);
        let mut all_instructions = self.instructions.lock().unwrap();
        let instructions_by_workspace = all_instructions
            .entry(self.client_identity.clone().unwrap())
            .or_default();
        instructions_by_workspace.insert(request.opened_directory.clone(), instructions.clone());
        instructions_by_workspace.insert(request.memory_location.clone(), instructions.clone());
        Ok(WorkspaceOnboarded {
            opened_directory: request.opened_directory,
            memory_location: request.memory_location,
            instructions: Some(instructions),
        })
    }

    fn authorized_workspace(&self, _session_workspace: &str, workspace: &str) -> Option<String> {
        self.client_identity.as_ref().and_then(|identity| {
            self.instructions
                .lock()
                .unwrap()
                .get(identity)
                .and_then(|workspaces| {
                    workspaces
                        .contains_key(workspace)
                        .then(|| workspace.to_owned())
                })
        })
    }

    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn start_run(
        &mut self,
        workspace: &str,
        execution_root: &str,
        _: RunStartRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunStartAccepted, muniment_core::attach::ProtocolError> {
        self.runs.lock().unwrap().push((
            workspace.to_owned(),
            execution_root.to_owned(),
            self.instructions.lock().unwrap()[self.client_identity.as_ref().unwrap()]
                [execution_root]
                .clone(),
        ));
        Ok(RunStartAccepted {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            thread_id: "0190a100-0000-7000-8000-000000000002".into(),
            committed_seq: 2,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        })
    }
}

#[derive(Default)]
struct PermissionService {
    calls: Vec<(String, PermissionAnswerRequest, Id, Id, CompanionProvenance)>,
    fail: bool,
}

#[derive(Default)]
struct CancelService {
    calls: Vec<(String, RunCancelRequest, Id)>,
}

impl ThreadListService for CancelService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn cancel_run(
        &mut self,
        workspace: &str,
        request: RunCancelRequest,
        _: &Id,
        idempotency_key: &Id,
        _: CompanionProvenance,
    ) -> Result<RunCancelAccepted, muniment_core::attach::ProtocolError> {
        self.calls
            .push((workspace.into(), request.clone(), idempotency_key.clone()));
        Ok(RunCancelAccepted {
            run_id: request.run_id,
            accepted_at: "2026-07-18T00:00:00Z".into(),
        })
    }
}

impl ThreadListService for PermissionService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn answer_permission(
        &mut self,
        workspace: &str,
        request: PermissionAnswerRequest,
        request_id: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<PermissionAnswerAccepted, muniment_core::attach::ProtocolError> {
        self.calls.push((
            workspace.into(),
            request.clone(),
            request_id.clone(),
            idempotency_key.clone(),
            provenance,
        ));
        if self.fail {
            return Err(muniment_core::attach::ProtocolError::persistence_failed());
        }
        Ok(PermissionAnswerAccepted {
            run_id: request.run_id,
            gate_id: request.gate_id,
            decision: request.decision,
            committed_seq: 9,
            accepted_at: "2026-07-18T00:00:00Z".into(),
        })
    }
}

struct StreamService {
    page: RunStreamPage,
}

struct SubscribeRaceService {
    journal: RunJournal,
    racing_event: Option<EventEnvelope>,
}

struct CountingJournalService {
    journal: RunJournal,
    stream_calls: Arc<AtomicUsize>,
}

impl ThreadListService for CountingJournalService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn subscribe_run_commits(
        &mut self,
        run_id: &str,
    ) -> Result<
        Option<muniment_core::journal::CommitSubscription>,
        muniment_core::attach::ProtocolError,
    > {
        self.journal
            .subscribe_commits(run_id)
            .map(Some)
            .map_err(|_| muniment_core::attach::ProtocolError::persistence_failed())
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<RunStreamPage, muniment_core::attach::ProtocolError> {
        self.stream_calls.fetch_add(1, Ordering::SeqCst);
        let page = self
            .journal
            .workspace_catch_up(
                workspace,
                run_id,
                after_run_seq,
                MAX_RUN_STREAM_WINDOW_EVENTS,
                MAX_RUN_STREAM_WINDOW_BYTES,
            )
            .map_err(|_| muniment_core::attach::ProtocolError::persistence_failed())?;
        Ok(RunStreamPage {
            run_id: run_id.to_owned(),
            first_available_run_seq: page.first_available_run_seq,
            current_run_seq: page.current_run_seq,
            events: page.events,
            exhausted: page.exhausted,
        })
    }
}

impl ThreadListService for SubscribeRaceService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn subscribe_run_commits(
        &mut self,
        run_id: &str,
    ) -> Result<
        Option<muniment_core::journal::CommitSubscription>,
        muniment_core::attach::ProtocolError,
    > {
        let subscription = self
            .journal
            .subscribe_commits(run_id)
            .map_err(|_| muniment_core::attach::ProtocolError::persistence_failed())?;
        if let Some(event) = self.racing_event.take() {
            self.journal
                .append(event.run_seq - 1, &event)
                .map_err(|_| muniment_core::attach::ProtocolError::persistence_failed())?;
        }
        Ok(Some(subscription))
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<RunStreamPage, muniment_core::attach::ProtocolError> {
        let page = self
            .journal
            .workspace_catch_up(
                workspace,
                run_id,
                after_run_seq,
                MAX_RUN_STREAM_WINDOW_EVENTS,
                MAX_RUN_STREAM_WINDOW_BYTES,
            )
            .map_err(|_| muniment_core::attach::ProtocolError::persistence_failed())?;
        Ok(RunStreamPage {
            run_id: run_id.to_owned(),
            first_available_run_seq: page.first_available_run_seq,
            current_run_seq: page.current_run_seq,
            events: page.events,
            exhausted: page.exhausted,
        })
    }
}

impl ThreadListService for StreamService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        _: u64,
    ) -> Result<RunStreamPage, muniment_core::attach::ProtocolError> {
        assert_eq!(workspace, "workspace-1");
        assert_eq!(run_id, self.page.run_id);
        Ok(self.page.clone())
    }
}

fn stream_projection(run_id: &str, run_seq: u64, event_type: String) -> RunEventProjection {
    RunEventProjection {
        run_id: run_id.into(),
        run_seq,
        event_type,
        event_version: 1,
        recorded_at: "2026-07-16T03:00:00Z".into(),
        text: None,
        effect_id: None,
        display_name: None,
        tool_effect_valid: false,
        pending_permission: None,
        receipt: None,
    }
}

fn projected_run_event_frame_len(run_id: &str, run_seq: u64, event_type: &str) -> usize {
    encode_frame(&Event {
        protocol: Protocol,
        subscription_id: Id::new("0".repeat(32)).unwrap(),
        event: EventName::RunEvent,
        run_id: Some(Id::new(run_id.to_owned()).unwrap()),
        run_seq: Some(run_seq),
        body: json!({
            "event_type": event_type,
            "event_version": 1,
            "recorded_at": "2026-07-16T03:00:00Z",
            "payload": {"withheld": true},
        }),
    })
    .unwrap()
    .len()
}

impl ThreadListService for StartService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, muniment_core::attach::ProtocolError> {
        panic!("thread reads must not dispatch")
    }

    fn start_run(
        &mut self,
        workspace: &str,
        execution_root: &str,
        request: RunStartRequest,
        request_id: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<RunStartAccepted, muniment_core::attach::ProtocolError> {
        self.calls.push((
            workspace.into(),
            execution_root.into(),
            request,
            request_id.clone(),
            idempotency_key.clone(),
            provenance,
        ));
        Ok(self.output.clone().unwrap_or_else(|| RunStartAccepted {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            thread_id: "0190a100-0000-7000-8000-000000000002".into(),
            committed_seq: 2,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        }))
    }
}

#[test]
fn authorization_randomness_failures_close_without_authorized() {
    for calls_before_failure in [0, 1] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        let result = run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: FailingTokens {
                    calls_before_failure,
                },
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut unavailable_service,
        );
        assert_eq!(result, Err(AttachSessionError::Randomness));
        if calls_before_failure == 1 {
            let _: Welcome = read_frame(&mut client);
        }
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn approval_continues_into_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(1, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let clock = TestClock(Rc::new(Cell::new(Duration::ZERO)));
    let mut service = |_: &str, _: ThreadListRequest| {
        Ok(ThreadListPage {
            threads: vec![],
            next_cursor: None,
        })
    };
    assert_eq!(
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |b: &mut [u8]| {
                    b.fill(9);
                    Ok(())
                },
                clock,
                tokens: TestTokens(1),
                approvals: approval_waiter_with_claims(
                    |_: &muniment_core::attach::PairingChallenge,
                     kind: &str,
                     version: &str,
                     _: Duration| {
                        assert_eq!(kind, "cli");
                        assert_eq!(version, "1.0.0");
                        Some(ApprovalDecision::Approve(approval()))
                    },
                ),
            },
            &mut service,
        ),
        Ok(())
    );
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(welcome.approval_challenge, "01".repeat(16));
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.capability, "02".repeat(32));
    assert_eq!(authorized.expires_at, 3600);
    assert_eq!(authorized.idle_timeout_seconds, 900);
    let response: Response = read_frame(&mut client);
    assert_eq!(response.request_id, Id::new(format!("{:032x}", 1)).unwrap());
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn live_registry_blocks_resumes_and_revokes_a_session() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let registry = LiveConnectionRegistry::default();
    let session_registry = registry.clone();
    let server_thread = thread::spawn(move || {
        let mut service = |_: &str, _: ThreadListRequest| {
            Ok(ThreadListPage {
                threads: vec![],
                next_cursor: None,
            })
        };
        run_authenticated_session_with_authorization_and_registry(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: SessionTestClock(Instant::now()),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
            &session_registry,
        )
    });

    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let authorized: Authorized = read_frame(&mut client);
    let credential = authorized.authorized_client_credential;
    let mut blocked = 0;
    for _ in 0..20 {
        blocked = registry.block(&credential);
        if blocked == 1 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(blocked, 1);

    client
        .write_all(&request(1, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let error = client.read(&mut [0]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    assert_eq!(registry.resume(&credential), 1);
    client.set_read_timeout(None).unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(response.request_id, Id::new(format!("{:032x}", 1)).unwrap());

    assert_eq!(registry.revoke(&credential), 1);
    assert_eq!(registry.resume(&credential), 1);
    let event: Event = read_frame(&mut client);
    assert_eq!(event.event, EventName::CapabilityRevoked);
    assert!(uuid::Uuid::parse_str(event.subscription_id.as_str()).is_ok());
    assert_eq!(event.run_id, None);
    assert_eq!(event.run_seq, None);
    assert_eq!(
        event.body,
        json!({
            "capability": authorized.capability,
            "reason": "companion_revoked",
        })
    );
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    assert_eq!(server_thread.join().unwrap(), Ok(()));
    assert_eq!(registry.revoke(&credential), 0);
}

#[test]
fn registration_inherits_a_blocked_credential_state() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let registry = LiveConnectionRegistry::default();
    let credential = "09".repeat(32);
    assert_eq!(registry.block(&credential), 0);
    let session_registry = registry.clone();
    let server_thread = thread::spawn(move || {
        let mut service = |_: &str, _: ThreadListRequest| {
            Ok(ThreadListPage {
                threads: vec![],
                next_cursor: None,
            })
        };
        run_authenticated_session_with_authorization_and_registry(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: SessionTestClock(Instant::now()),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
            &session_registry,
        )
    });

    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.authorized_client_credential, credential);
    client
        .write_all(&request(1, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let error = client.read(&mut [0]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    assert_eq!(registry.resume(&credential), 1);
    client.set_read_timeout(None).unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(response.request_id, Id::new(format!("{:032x}", 1)).unwrap());
    client.shutdown(Shutdown::Both).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn registration_inherits_a_revoked_credential_state() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let registry = LiveConnectionRegistry::default();
    let credential = "09".repeat(32);
    assert_eq!(registry.revoke(&credential), 0);
    let session_registry = registry.clone();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization_and_registry(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: SessionTestClock(Instant::now()),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut unavailable_service,
            &session_registry,
        )
    });

    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.authorized_client_credential, credential);
    let event: Event = read_frame(&mut client);
    assert_eq!(event.event, EventName::CapabilityRevoked);
    assert_eq!(event.body["capability"], authorized.capability);
    assert_eq!(event.body["reason"], "companion_revoked");
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[derive(Clone)]
struct SessionTestClock(Instant);

impl AuthorizationClock for SessionTestClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

#[test]
fn hostile_companion_claim_reaches_approval_waiter_without_authority() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let hostile_kind = format!("acp\u{0000}{}", "x".repeat(100));
    client
        .write_all(&hello_with_claims(
            1,
            1,
            "018f0000-0000-7000-8000-000000000099",
            None,
            &hostile_kind,
            "\u{001b}[31m",
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: approval_waiter_with_claims(
                |_: &muniment_core::attach::PairingChallenge,
                 kind: &str,
                 version: &str,
                 _: Duration| {
                    assert_eq!(kind, hostile_kind);
                    assert_eq!(version, "\u{001b}[31m");
                    Some(ApprovalDecision::Deny)
                },
            ),
        },
        &mut unavailable_service,
    );
    assert_eq!(result, Ok(()));
    let _: Welcome = read_frame(&mut client);
}

#[test]
fn authorized_client_reconnects_without_waiting_for_pairing() {
    let credential = "ab".repeat(32);
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&hello_for_client_with_credential(
            1,
            1,
            "018f0000-0000-7000-8000-000000000099",
            Some(&credential),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = CredentialService {
        expected: credential.clone(),
        bound: false,
        claims: None,
    };
    assert_eq!(
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    panic!("known clients must not invoke the pairing waiter")
                },
            },
            &mut service,
        ),
        Ok(())
    );
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(
        welcome.authorization,
        muniment_attach::Authorization::Authorized
    );
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.authorized_client_credential, credential);
    assert!(service.bound);
    assert_eq!(service.claims, Some(("cli".into(), "1.0.0".into())));
}

#[test]
fn invalid_reconnect_credential_still_requires_pairing_and_is_not_replaced() {
    let expected = "ab".repeat(32);
    let presented = "cd".repeat(32);
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&hello_for_client_with_credential(
            1,
            1,
            "018f0000-0000-7000-8000-000000000099",
            Some(&presented),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let waits = Rc::new(Cell::new(0));
    let waiter_calls = waits.clone();
    let mut service = CredentialService {
        expected: expected.clone(),
        bound: false,
        claims: None,
    };
    assert_eq!(
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    waiter_calls.set(waiter_calls.get() + 1);
                    (waiter_calls.get() == 1).then(|| ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        ),
        Err(AttachSessionError::Authorization)
    );
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(
        welcome.authorization,
        muniment_attach::Authorization::PairingRequired
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    assert_eq!(waits.get(), 2);
    assert_eq!(service.expected, expected);
    assert!(!service.bound);
}

#[test]
fn production_service_composition_uses_approved_pairing_and_dispatches() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let mut service = |_: &str, _: ThreadListRequest| {
            Ok(ThreadListPage {
                threads: vec![],
                next_cursor: None,
            })
        };
        run_authenticated_session_with_service_and_approvals(
            server,
            credentials(),
            "0.1.0",
            &mut service,
            |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approval()))
            },
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let authorized: Authorized = read_frame(&mut client);
    let request = Request {
        protocol: Protocol,
        request_id: Id::new(format!("{:032x}", 91)).unwrap(),
        operation: Operation::ThreadList,
        capability: authorized.capability,
        idempotency_key: None,
        body: json!({"limit": 1}),
    };
    client
        .write_all(&encode_frame(&Envelope::Request(request)).unwrap())
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.request_id,
        Id::new(format!("{:032x}", 91)).unwrap()
    );
    client.shutdown(Shutdown::Both).unwrap();
    assert_eq!(worker.join().unwrap(), Ok(()));
}

#[test]
fn approval_after_hello_timeout_but_before_challenge_expiry_is_sent() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let now = Rc::new(Cell::new(Duration::ZERO));
    client.shutdown(Shutdown::Write).unwrap();
    let decision_clock = now.clone();
    let decided = Rc::new(Cell::new(false));
    let decision_made = decided.clone();
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |b: &mut [u8]| {
                b.fill(9);
                Ok(())
            },
            clock: TestClock(now),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, remaining: Duration| {
                if decision_made.replace(true) {
                    return None;
                }
                assert_eq!(remaining, CHALLENGE_LIFETIME);
                decision_clock.set(Duration::from_secs(6));
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut unavailable_service,
    );
    assert_eq!(result, Ok(()));
    let _: Welcome = read_frame(&mut client);
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.profile_id, "profile-1");
    assert_eq!(authorized.capability, "02".repeat(32));
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn second_approval_after_consumption_cannot_write_another_grant() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let calls = Rc::new(Cell::new(0));
    let approval_calls = calls.clone();
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |b: &mut [u8]| {
                b.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                approval_calls.set(approval_calls.get() + 1);
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut unavailable_service,
    );
    assert_eq!(result, Ok(()));
    assert_eq!(calls.get(), 2);
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn denial_and_expired_challenge_close_without_authorized() {
    for expired in [false, true] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        let now = Rc::new(Cell::new(Duration::ZERO));
        let decision_clock = now.clone();
        let result = run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |b: &mut [u8]| {
                    b.fill(9);
                    Ok(())
                },
                clock: TestClock(now),
                tokens: TestTokens(1),
                approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    if expired {
                        decision_clock.set(CHALLENGE_LIFETIME + Duration::from_nanos(1));
                        Some(ApprovalDecision::Approve(approval()))
                    } else {
                        Some(ApprovalDecision::Deny)
                    }
                },
            },
            &mut unavailable_service,
        );
        assert_eq!(
            result,
            if expired {
                Err(AttachSessionError::Timeout)
            } else {
                Ok(())
            }
        );
        let welcome: serde_json::Value = read_frame(&mut client);
        assert!(welcome.get("profile_id").is_none());
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn fragmented_hello_receives_deterministic_welcome_then_closes() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let task = thread::spawn(move || {
        run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |bytes| {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = index as u8;
                }
                Ok(())
            },
        )
    });
    let frame = hello(1, 1);
    for part in frame.chunks(3) {
        client.write_all(part).unwrap();
    }
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(welcome.selected, 1);
    assert_eq!(welcome.desktop_version, "0.1.0");
    assert_eq!(welcome.server_nonce, "000102030405060708090a0b0c0d0e0f");
    assert_eq!(welcome.approval_challenge.len(), 32);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    assert_eq!(task.join().unwrap(), Ok(()));
}

#[test]
fn hello_deadline_is_short_and_closes_without_a_response() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let start = Instant::now();
    let result = run_authenticated_session_with(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(20),
        |_| Ok(()),
    );
    assert_eq!(result, Err(AttachSessionError::Timeout));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn incompatibility_actions_are_framed_and_terminal() {
    for (range, action) in [
        ((0, 0), ErrorAction::UpgradeCompanion),
        ((2, 2), ErrorAction::UpgradeDesktop),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(range.0, range.1)).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            run_authenticated_session_with(
                server,
                credentials(),
                "0.1.0",
                Duration::from_secs(1),
                |_| Ok(())
            ),
            Err(AttachSessionError::ProtocolIncompatible)
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.action(), Some(action));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

fn raw_frame(payload: &[u8]) -> Vec<u8> {
    [&(payload.len() as u32).to_be_bytes()[..], payload].concat()
}

#[test]
fn malformed_first_messages_are_redacted_terminal_and_never_negotiate() {
    let non_hello = encode_frame(&json!({
        "protocol": "muniment.attach/1",
        "request_id": "00000000000000000000000000000001",
        "operation": "thread.list",
        "capability": "/home/user/secret",
        "body": {"raw": "do not disclose"}
    }))
    .unwrap();
    let nested = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    let cases = [
        (non_hello, AttachSessionError::MalformedFrame, true),
        (
            raw_frame(&[0xff]),
            AttachSessionError::MalformedFrame,
            false,
        ),
        (
            raw_frame(br#"{"raw":"do not disclose""#),
            AttachSessionError::MalformedFrame,
            false,
        ),
        (
            raw_frame(nested.as_bytes()),
            AttachSessionError::MalformedFrame,
            false,
        ),
    ];

    for (mut first, expected, queue_second) in cases {
        if queue_second {
            // A queued valid hello proves a terminal first-message failure does not proceed.
            first.extend_from_slice(&hello(1, 1));
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&first).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let random_calls = Cell::new(0);
        let result = run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |_| {
                random_calls.set(random_calls.get() + 1);
                Ok(())
            },
        );

        assert_eq!(result, Err(expected));
        assert_eq!(random_calls.get(), 0);
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.protocol, Protocol);
        assert_eq!(error.request_id, None);
        assert_eq!(error.error.code(), ErrorCode::MalformedFrame);
        let visible = serde_json::to_string(&error).unwrap();
        for forbidden in ["/home", "secret", "do not disclose", "thread.list", "pid"] {
            assert!(!visible.contains(forbidden));
        }
        let terminal_read = client.read(&mut [0]);
        if queue_second {
            // Linux reports reset when the peer closes with deliberately unread input.
            assert!(matches!(terminal_read, Ok(0) | Err(_)));
        } else {
            assert_eq!(terminal_read.unwrap(), 0);
        }
    }
}

#[test]
fn oversized_declared_length_is_redacted_terminal_and_never_negotiate() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&((MAX_FRAME_LENGTH as u32) + 1).to_be_bytes())
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let random_calls = Cell::new(0);

    assert_eq!(
        run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |_| {
                random_calls.set(random_calls.get() + 1);
                Ok(())
            },
        ),
        Err(AttachSessionError::PayloadTooLarge)
    );
    assert_eq!(random_calls.get(), 0);
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.protocol, Protocol);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::PayloadTooLarge);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

#[test]
fn eof_is_terminal_without_a_response_or_negotiation() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&[0, 0]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let random_calls = Cell::new(0);

    assert_eq!(
        run_authenticated_session_with(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            |_| {
                random_calls.set(random_calls.get() + 1);
                Ok(())
            },
        ),
        Err(AttachSessionError::Closed)
    );
    assert_eq!(random_calls.get(), 0);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}

fn request(id: u128, operation: Operation, body: serde_json::Value) -> Vec<u8> {
    encode_frame(&Request {
        protocol: Protocol,
        request_id: Id::new(format!("{id:032x}")).unwrap(),
        operation,
        capability: "02".repeat(32),
        idempotency_key: None,
        body,
    })
    .unwrap()
}

fn request_with_idempotency(id: u128, operation: Operation, body: serde_json::Value) -> Vec<u8> {
    encode_frame(&Request {
        protocol: Protocol,
        request_id: Id::new(format!("{id:032x}")).unwrap(),
        operation,
        capability: "02".repeat(32),
        idempotency_key: Some(Id::new(format!("{:032x}", id + 1000)).unwrap()),
        body,
    })
    .unwrap()
}

fn prompt(run_id: &str, title: &str, recorded_at: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: run_id.replacen("a100", "a200", 1),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "user.prompt.submitted".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: recorded_at.into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({"prompt": title, "secret": "/home/user/private"}),
        },
        provenance: Provenance {
            source: "test".into(),
            source_version: "1".into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

fn dispatch_session<S>(
    client: &mut UnixStream,
    server: UnixStream,
    clock: TestClock,
    service: &mut S,
) -> Result<(), AttachSessionError>
where
    S: muniment_core::attach::linux::ThreadListService,
{
    dispatch_session_with_approval(client, server, clock, approval(), service)
}

fn dispatch_session_with_approval<S>(
    client: &mut UnixStream,
    server: UnixStream,
    clock: TestClock,
    approved: Approval,
    service: &mut S,
) -> Result<(), AttachSessionError>
where
    S: muniment_core::attach::linux::ThreadListService,
{
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock,
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approved.clone()))
            },
        },
        service,
    );
    let _: Welcome = read_frame(client);
    let _: Authorized = read_frame(client);
    result
}

#[test]
fn authorized_thread_list_is_bounded_paginated_and_correlated() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            10,
            Operation::ThreadList,
            json!({"limit": 100, "cursor": "opaque-page-2"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let calls = Cell::new(0);
    let mut service = |workspace: &str, request: ThreadListRequest| {
        calls.set(calls.get() + 1);
        assert_eq!(workspace, "workspace-1");
        assert_eq!(request.limit, 100);
        assert_eq!(request.cursor.as_deref(), Some("opaque-page-2"));
        Ok(ThreadListPage {
            threads: vec![RedactedThreadSummary {
                thread_id: "thread-1".into(),
                title: "Safe title".into(),
                updated_at: "2026-07-16T00:00:00Z".into(),
            }],
            next_cursor: Some("opaque-page-3".into()),
        })
    };
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.request_id,
        Id::new(format!("{:032x}", 10)).unwrap()
    );
    assert_eq!(response.body["next_cursor"], "opaque-page-3");
    assert_eq!(calls.get(), 1);
}

#[test]
fn authorized_run_stream_catches_up_in_order_with_redacted_projection() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000011";
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN, "private prompt", "2026-07-16T03:00:00Z"))
        .unwrap();
    let mut delta = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    delta.event_id = "0190a200-0000-7000-8000-000000000013".into();
    delta.run_seq = 2;
    delta.event_type = "model.stream.delta".into();
    delta.payload = EventPayload::Inline {
        payload_json: json!({"text":"released reply", "content_disclosure":"released"}),
    };
    journal.append(1, &delta).unwrap();
    let mut withheld = delta.clone();
    withheld.event_id = "0190a200-0000-7000-8000-000000000014".into();
    withheld.run_seq = 3;
    withheld.payload = EventPayload::Inline {
        payload_json: json!({"text":"legacy reply"}),
    };
    journal.append(2, &withheld).unwrap();
    for (seq, event_type, payload) in [
        (
            4,
            "tool.effect.started",
            json!({"effect_id":"tool-1","display_name":"Search"}),
        ),
        (5, "tool.effect.completed", json!({"effect_id":"tool-1"})),
        (6, "tool.effect.started", json!({"effect_id":"tool-2"})),
        (7, "tool.effect.failed", json!({"effect_id":"tool-2"})),
    ] {
        let mut tool = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
        tool.event_id = format!("0190a200-0000-7000-8001-{seq:012}");
        tool.run_seq = seq;
        tool.event_type = event_type.into();
        tool.payload = EventPayload::Inline {
            payload_json: payload,
        };
        journal.append(seq - 1, &tool).unwrap();
    }
    let mut completed = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    completed.event_id = "0190a200-0000-7000-8000-000000000012".into();
    completed.run_seq = 8;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({
            "receipt": {"route": "cloud", "capabilities": [{"name": "search", "version": "1"}]},
            "private": "must remain withheld"
        }),
    };
    journal.append(7, &completed).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            41,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(response.body["run_id"], RUN);
    assert_eq!(response.body["first_available_run_seq"], 1);
    assert_eq!(response.body["current_run_seq"], 8);
    let subscription = response.body["subscription_id"].as_str().unwrap();
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected run event")
    };
    assert_eq!(event.event, EventName::RunEvent);
    assert_eq!(event.subscription_id.as_str(), subscription);
    assert_eq!(event.run_seq, Some(1));
    assert_eq!(event.body["payload"]["withheld"], true);
    assert!(!event.body.to_string().contains("private"));
    let Envelope::Event(delta) = read_frame::<Envelope>(&mut client) else {
        panic!("expected assistant delta")
    };
    assert_eq!(delta.run_seq, Some(2));
    assert_eq!(delta.body["payload"], json!({"text":"released reply"}));
    let Envelope::Event(withheld) = read_frame::<Envelope>(&mut client) else {
        panic!("expected withheld assistant delta")
    };
    assert_eq!(withheld.run_seq, Some(3));
    assert_eq!(withheld.body["payload"], json!({"withheld":true}));
    assert!(!withheld.body.to_string().contains("legacy reply"));
    let Envelope::Event(tool_started) = read_frame::<Envelope>(&mut client) else {
        panic!("expected started tool effect")
    };
    assert_eq!(tool_started.run_seq, Some(4));
    assert_eq!(
        tool_started.body["payload"],
        json!({"effect_id":"tool-1","display_name":"Search"})
    );
    let Envelope::Event(tool_completed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected completed tool effect")
    };
    assert_eq!(tool_completed.run_seq, Some(5));
    assert_eq!(
        tool_completed.body["payload"],
        json!({"effect_id":"tool-1"})
    );
    let Envelope::Event(tool_started) = read_frame::<Envelope>(&mut client) else {
        panic!("expected second started tool effect")
    };
    assert_eq!(tool_started.run_seq, Some(6));
    assert_eq!(tool_started.body["payload"], json!({"effect_id":"tool-2"}));
    let Envelope::Event(tool_failed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected failed tool effect")
    };
    assert_eq!(tool_failed.run_seq, Some(7));
    assert_eq!(tool_failed.body["payload"], json!({"effect_id":"tool-2"}));
    let Envelope::Event(completed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected completed event")
    };
    assert_eq!(completed.run_seq, Some(8));
    assert_eq!(completed.body["payload"]["withheld"], true);
    assert_eq!(completed.body["payload"]["receipt"]["route"], "cloud");
    assert!(completed.body["payload"]["receipt"].get("model").is_none());
    assert!(!completed.body.to_string().contains("must remain withheld"));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.subscription_id.as_str(), subscription);
}

#[test]
fn authorized_run_stream_delivers_exact_bounded_pending_permission() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000041";
    let mut started = prompt(RUN, "private prompt", "2026-07-16T03:00:00Z");
    let mut permission = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    permission.event_id = "0190a200-0000-7000-8001-000000000041".into();
    permission.run_seq = 2;
    permission.event_type = "permission.requested".into();
    permission.payload = EventPayload::Inline {
        payload_json: json!({
            "gate_id": "gate-41", "kind": "confirm", "title": "Allow search?",
            "message": "Search the public web", "secret": "never emit me",
            "command": "rm private", "path": "/private/path"
        }),
    };
    let mut permission_without_message = permission.clone();
    permission_without_message.event_id = "0190a200-0000-7000-8001-000000000042".into();
    permission_without_message.run_seq = 3;
    permission_without_message.payload = EventPayload::Inline {
        payload_json: json!({
            "gate_id": "gate-42", "kind": "confirm", "title": "Allow without context?"
        }),
    };
    started.event_id = "0190a200-0000-7000-8001-000000000040".into();
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append_batch(0, &[started, permission, permission_without_message])
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            43,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"].as_str().unwrap();
    let Envelope::Event(first) = read_frame::<Envelope>(&mut client) else {
        panic!("expected withheld run event")
    };
    assert_eq!(first.event, EventName::RunEvent);
    let Envelope::Event(pending) = read_frame::<Envelope>(&mut client) else {
        panic!("expected pending permission")
    };
    assert_eq!(pending.event, EventName::PermissionPending);
    assert_eq!(pending.subscription_id.as_str(), subscription);
    assert_eq!(pending.run_id.as_ref().unwrap().as_str(), RUN);
    assert_eq!(pending.run_seq, Some(2));
    assert_eq!(
        pending.body,
        json!({
            "gate_id": "gate-41", "kind": "confirm", "title": "Allow search?",
            "message": "Search the public web"
        })
    );
    let Envelope::Event(without_message) = read_frame::<Envelope>(&mut client) else {
        panic!("expected pending permission without message")
    };
    assert_eq!(without_message.event, EventName::PermissionPending);
    assert_eq!(without_message.subscription_id.as_str(), subscription);
    assert_eq!(without_message.run_id.as_ref().unwrap().as_str(), RUN);
    assert_eq!(without_message.run_seq, Some(3));
    assert_eq!(
        without_message.body,
        json!({
            "gate_id": "gate-42", "kind": "confirm", "title": "Allow without context?"
        })
    );
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up marker")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
}

#[test]
fn run_stream_catch_up_fails_closed_for_hostile_pending_permissions() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000043";
    let cases = [
        EventPayload::Inline {
            payload_json: json!({
                "gate_id": "malformed-secret", "kind": "confirm", "title": "Malformed",
                "message": {"private": "malformed-private"}
            }),
        },
        EventPayload::Inline {
            payload_json: json!({
                "gate_id": "unsupported-secret", "kind": "select", "title": "Unsupported",
                "options": ["unsupported-private"]
            }),
        },
        EventPayload::Inline {
            payload_json: json!({
                "gate_id": "oversized-secret", "kind": "confirm", "title": "x".repeat(1_025),
                "message": "oversized-private"
            }),
        },
        EventPayload::Cas {
            payload_cas: muniment_core::journal::CasReference {
                sha256: "ab".repeat(32),
                media_type: "application/private+json".into(),
                byte_length: 999_999,
            },
        },
    ];
    let mut expected_error = None;
    for (index, payload) in cases.into_iter().enumerate() {
        let mut permission = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        permission.event_id = format!("0190a200-0000-7000-8001-{:012}", 100 + index);
        permission.event_type = "permission.requested".into();
        permission.payload = payload;
        let mut later = prompt(RUN, "later-private", "2026-07-16T03:00:01Z");
        later.event_id = format!("0190a200-0000-7000-8001-{:012}", 200 + index);
        later.run_seq = 2;
        let mut journal = RunJournal::open(":memory:").unwrap();
        journal.append_batch(0, &[permission, later]).unwrap();
        journal.bind_run_workspace(RUN, "workspace-1").unwrap();

        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(
                44,
                Operation::RunStream,
                json!({"run_id": RUN, "after_run_seq": 0}),
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            dispatch_session(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                &mut journal,
            ),
            Ok(())
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);
        let encoded = serde_json::to_string(&error).unwrap();
        for private in [
            "malformed-secret",
            "malformed-private",
            "unsupported-secret",
            "unsupported-private",
            "oversized-secret",
            "oversized-private",
            "application/private+json",
            "later-private",
        ] {
            assert!(!encoded.contains(private));
        }
        let error_value = serde_json::to_value(error).unwrap();
        if let Some(expected) = &expected_error {
            assert_eq!(&error_value, expected);
        } else {
            expected_error = Some(error_value);
        }
        let mut remaining = Vec::new();
        client.read_to_end(&mut remaining).unwrap();
        assert!(remaining.is_empty());
    }
}

#[test]
fn run_stream_does_not_read_or_emit_an_oversized_inline_payload() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000012";
    let secret = "payload-secret-".repeat(MAX_FRAME_LENGTH);
    let mut event = prompt(RUN, "placeholder", "2026-07-16T03:00:00Z");
    event.payload = EventPayload::Inline {
        payload_json: json!({"secret": secret}),
    };
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append(0, &event).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            42,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    let event: Envelope = read_frame(&mut client);
    let caught_up: Envelope = read_frame(&mut client);
    let encoded = format!("{response:?}{event:?}{caught_up:?}");
    assert!(!encoded.contains("payload-secret"));
    assert!(encoded.len() < 10_000);
}

#[test]
fn run_stream_rejects_missing_scope_other_workspace_and_strictly_malformed_bodies() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000013";
    let cases = [
        (
            false,
            json!({"run_id": RUN, "after_run_seq": 0}),
            ErrorCode::Unauthorized,
        ),
        (
            true,
            json!({"run_id": RUN, "after_run_seq": 0}),
            ErrorCode::InvalidRequest,
        ),
        (true, json!({"run_id": RUN}), ErrorCode::InvalidRequest),
        (
            true,
            json!({"run_id": RUN, "after_run_seq": -1}),
            ErrorCode::InvalidRequest,
        ),
        (
            true,
            json!({"run_id": RUN, "after_run_seq": 0, "extra": true}),
            ErrorCode::InvalidRequest,
        ),
    ];
    for (has_scope, body, expected) in cases {
        let mut journal = RunJournal::open(":memory:").unwrap();
        let mut permission = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        permission.event_type = "permission.requested".into();
        permission.payload = EventPayload::Inline {
            payload_json: json!({
                "gate_id": "other-workspace-private-gate", "kind": "confirm",
                "title": "Other workspace private title",
                "message": "other-workspace-private-context"
            }),
        };
        journal.append(0, &permission).unwrap();
        journal.bind_run_workspace(RUN, "workspace-2").unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(43, Operation::RunStream, body))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        if !has_scope {
            approved.scopes.clear();
        }
        let _ = dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut journal,
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), expected);
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("other-workspace-private-gate"));
        assert!(!encoded.contains("Other workspace private title"));
        assert!(!encoded.contains("other-workspace-private-context"));
        let mut remaining = Vec::new();
        client.read_to_end(&mut remaining).unwrap();
        assert!(remaining.is_empty());
    }
}

#[test]
fn run_stream_rejects_missing_removed_ahead_and_expired_cursors() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000014";
    for (present, after, expected) in [
        (false, 0, ErrorCode::InvalidRequest),
        (true, 2, ErrorCode::InvalidCursor),
    ] {
        let mut journal = RunJournal::open(":memory:").unwrap();
        if present {
            journal
                .append(0, &prompt(RUN, "private", "2026-07-16T03:00:00Z"))
                .unwrap();
            journal.bind_run_workspace(RUN, "workspace-1").unwrap();
        }
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(
                44,
                Operation::RunStream,
                json!({"run_id": RUN, "after_run_seq": after}),
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal,
        )
        .unwrap();
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), expected);
    }

    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN, "private", "2026-07-16T03:00:00Z"))
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    journal.delete_run(RUN).unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            45,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    dispatch_session(
        &mut client,
        server,
        TestClock(Rc::new(Cell::new(Duration::ZERO))),
        &mut journal,
    )
    .unwrap();
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
}

#[test]
fn run_stream_resumes_in_order_without_duplicates_and_marks_only_exhausted_catch_up() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000015";
    let mut events = Vec::new();
    for seq in 1..=3 {
        let mut event = prompt(RUN, "private", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a200-0000-7000-8000-{seq:012x}");
        event.run_seq = seq;
        event.event_type = format!("safe.event.{seq}");
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            46,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 1}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    dispatch_session(
        &mut client,
        server,
        TestClock(Rc::new(Cell::new(Duration::ZERO))),
        &mut journal,
    )
    .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"].as_str().unwrap();
    for expected_seq in [2, 3] {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected event")
        };
        assert_eq!(event.event, EventName::RunEvent);
        assert_eq!(event.subscription_id.as_str(), subscription);
        assert_eq!(event.run_id.as_ref().unwrap().as_str(), RUN);
        assert_eq!(event.run_seq, Some(expected_seq));
        assert!(!event.body.to_string().contains("private"));
    }
    let Envelope::Event(caught) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught up")
    };
    assert_eq!(caught.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught.run_seq, Some(3));
}

#[test]
fn run_stream_event_window_ack_resumes_and_catches_up_once() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000016";
    let events = (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
        .map(|seq| stream_projection(RUN, seq, "safe.event".into()))
        .collect();
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(30),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            47,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut sequences = Vec::new();
    for _ in 0..MAX_RUN_STREAM_WINDOW_EVENTS {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected event")
        };
        assert_eq!(event.event, EventName::RunEvent);
        sequences.push(event.run_seq.unwrap());
    }
    assert_eq!(sequences.len(), MAX_RUN_STREAM_WINDOW_EVENTS);
    assert_eq!(sequences.first(), Some(&1));
    assert_eq!(
        sequences.last(),
        Some(&(MAX_RUN_STREAM_WINDOW_EVENTS as u64))
    );

    client
        .write_all(&request(
            48,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let ack: Response = read_frame(&mut client);
    assert_eq!(ack.body["through_run_seq"], MAX_RUN_STREAM_WINDOW_EVENTS);
    let Envelope::Event(last) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed event")
    };
    assert_eq!(last.run_seq, Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);

    client
        .write_all(&request(
            49,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let duplicate: Response = read_frame(&mut client);
    assert_eq!(
        duplicate.body["through_run_seq"],
        MAX_RUN_STREAM_WINDOW_EVENTS
    );
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

fn assert_redacted_request_error(error: &ErrorEnvelope, request: u128, code: ErrorCode) {
    assert_eq!(
        error.request_id.as_ref().map(Id::as_str),
        Some(format!("{request:032x}").as_str())
    );
    assert_eq!(error.error.code(), code);
    assert_eq!(
        serde_json::to_value(&error.error).unwrap().get("details"),
        None
    );
}

#[test]
fn run_cursor_ack_rejections_are_correlated_redacted_and_stream_local() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000019";
    let events = (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
        .map(|seq| stream_projection(RUN, seq, "safe.event".into()))
        .collect();
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(30),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);

    client
        .write_all(&request(
            60,
            Operation::RunCursorAck,
            json!({"subscription_id": "0".repeat(32), "through_run_seq": 0}),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut client), 60, ErrorCode::InvalidCursor);
    for (request_id, body) in [
        (
            61,
            json!({"subscription_id": "not-an-id", "through_run_seq": 0}),
        ),
        (62, json!({"subscription_id": "0".repeat(32)})),
        (
            63,
            json!({"subscription_id": "0".repeat(32), "through_run_seq": "1"}),
        ),
        (
            64,
            json!({
                "subscription_id": "0".repeat(32),
                "through_run_seq": 0,
                "workspace": "workspace-2",
                "run_id": "0190a100-0000-7000-8000-000000000020"
            }),
        ),
    ] {
        client
            .write_all(&request(request_id, Operation::RunCursorAck, body))
            .unwrap();
        assert_redacted_request_error(
            &read_frame(&mut client),
            request_id,
            ErrorCode::InvalidRequest,
        );
    }

    let mut subscriptions = Vec::new();
    for request_id in [65, 66, 69] {
        client
            .write_all(&request(
                request_id,
                Operation::RunStream,
                json!({"run_id": RUN, "after_run_seq": 0}),
            ))
            .unwrap();
        let response: Response = read_frame(&mut client);
        subscriptions.push(
            response.body["subscription_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        for expected in 1..=MAX_RUN_STREAM_WINDOW_EVENTS as u64 {
            let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
                panic!("expected run event")
            };
            assert_eq!(
                event.subscription_id.as_str(),
                subscriptions.last().unwrap()
            );
            assert_eq!(event.run_seq, Some(expected));
            assert_eq!(event.body["payload"]["withheld"], true);
        }
    }

    client
        .write_all(&request(
            67,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[0],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS + 1,
            }),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut client), 67, ErrorCode::InvalidCursor);
    let Envelope::Event(closed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected stream close")
    };
    assert_eq!(closed.event, EventName::StreamClosed);
    assert_eq!(closed.subscription_id.as_str(), subscriptions[0]);
    assert_eq!(closed.run_id.as_ref().unwrap().as_str(), RUN);
    assert_eq!(closed.run_seq, Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64));
    assert_eq!(
        closed.body,
        json!({"code": "invalid_cursor", "resumable": true})
    );

    client
        .write_all(&request(
            68,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[1],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(response.request_id.as_str(), format!("{:032x}", 68));
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed event")
    };
    assert_eq!(resumed.subscription_id.as_str(), subscriptions[1]);
    assert_eq!(
        resumed.run_seq,
        Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1)
    );
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.subscription_id.as_str(), subscriptions[1]);

    client
        .write_all(&request(
            70,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[2],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS - 1,
            }),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed event")
    };
    assert_eq!(resumed.subscription_id.as_str(), subscriptions[2]);
    assert_eq!(
        resumed.run_seq,
        Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1)
    );
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.subscription_id.as_str(), subscriptions[2]);

    client
        .write_all(&request(
            71,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscriptions[2],
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS - 2,
            }),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut client), 71, ErrorCode::InvalidCursor);
    let Envelope::Event(closed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected stream close")
    };
    assert_eq!(closed.event, EventName::StreamClosed);
    assert_eq!(closed.subscription_id.as_str(), subscriptions[2]);
    assert_eq!(closed.body["code"], "invalid_cursor");

    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn run_cursor_ack_subscription_ids_are_isolated_between_connections() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000021";
    let page = RunStreamPage {
        run_id: RUN.into(),
        first_available_run_seq: 1,
        current_run_seq: MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1,
        events: (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
            .map(|seq| stream_projection(RUN, seq, "safe.event".into()))
            .collect(),
        exhausted: true,
    };
    let mut clients = Vec::new();
    let mut threads = Vec::new();
    for _ in 0..2 {
        let mut service = StreamService { page: page.clone() };
        let (mut client, server) = UnixStream::pair().unwrap();
        threads.push(thread::spawn(move || {
            run_authenticated_session_with_authorization(
                server,
                credentials(),
                "0.1.0",
                Duration::from_secs(30),
                AuthorizationSessionDependencies {
                    fill_random: |bytes: &mut [u8]| {
                        bytes.fill(9);
                        Ok(())
                    },
                    clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                    tokens: TestTokens(1),
                    approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                        Some(ApprovalDecision::Approve(approval()))
                    },
                },
                &mut service,
            )
        }));
        client.write_all(&hello(1, 1)).unwrap();
        let _: Welcome = read_frame(&mut client);
        let _: Authorized = read_frame(&mut client);
        clients.push(client);
    }

    clients[0]
        .write_all(&request(
            72,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut clients[0]);
    let foreign_subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for _ in 0..MAX_RUN_STREAM_WINDOW_EVENTS {
        let _: Envelope = read_frame(&mut clients[0]);
    }

    clients[1]
        .write_all(&request(
            73,
            Operation::RunCursorAck,
            json!({
                "subscription_id": foreign_subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    assert_redacted_request_error(&read_frame(&mut clients[1]), 73, ErrorCode::InvalidCursor);

    clients[0]
        .write_all(&request(
            74,
            Operation::RunCursorAck,
            json!({
                "subscription_id": foreign_subscription,
                "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS,
            }),
        ))
        .unwrap();
    let _: Response = read_frame(&mut clients[0]);
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut clients[0]) else {
        panic!("expected owner connection to resume")
    };
    assert_eq!(
        resumed.run_seq,
        Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1)
    );
    assert_eq!(resumed.subscription_id.as_str(), foreign_subscription);
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut clients[0]) else {
        panic!("expected owner connection caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.subscription_id.as_str(), foreign_subscription);

    for client in &mut clients {
        client.shutdown(Shutdown::Write).unwrap();
    }
    for server_thread in threads {
        assert_eq!(server_thread.join().unwrap(), Ok(()));
    }
}

#[test]
fn real_journal_run_stream_fetches_next_page_after_window_ack() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000018";
    let events = (1..=(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1))
        .map(|seq| {
            let mut event = prompt(RUN, "private", "2026-07-16T03:00:00Z");
            event.event_id = format!("0190a200-0000-7000-8001-{seq:012x}");
            event.run_seq = seq;
            event
        })
        .collect::<Vec<_>>();
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(30),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut journal,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            50,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for expected in 1..=MAX_RUN_STREAM_WINDOW_EVENTS as u64 {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected first-page event")
        };
        assert_eq!(event.run_seq, Some(expected));
    }
    client
        .write_all(&request(
            51,
            Operation::RunCursorAck,
            json!({"subscription_id": subscription, "through_run_seq": MAX_RUN_STREAM_WINDOW_EVENTS}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected second-page event")
    };
    assert_eq!(event.run_seq, Some(MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn file_journal_run_stream_stays_live_and_ignores_other_run_commits() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000028";
    const OTHER_RUN: &str = "0190a100-0000-7000-8000-000000000029";
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-live-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut writer = RunJournal::open(&path).unwrap();
    let mut initial = prompt(RUN, "private-initial", "2026-07-16T02:59:00Z");
    initial.event_id = "0190a200-0000-7000-8001-000000000027".into();
    let mut other_initial = prompt(OTHER_RUN, "private-other", "2026-07-16T02:59:00Z");
    other_initial.event_id = "0190a200-0000-7000-8001-000000000026".into();
    writer.append_batch(0, &[initial]).unwrap();
    writer.append_batch(0, &[other_initial]).unwrap();
    writer.bind_run_workspace(RUN, "workspace-1").unwrap();
    writer.bind_run_workspace(OTHER_RUN, "workspace-2").unwrap();
    let mut service = RunJournal::open(&path).unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            75,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 1}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up marker")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);

    let mut unrelated = prompt(OTHER_RUN, "private-other", "2026-07-16T03:00:00Z");
    unrelated.event_id = "0190a200-0000-7000-8001-000000000029".into();
    unrelated.run_seq = 2;
    writer.append_batch(1, &[unrelated]).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut byte = [0];
    assert!(matches!(
        client.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    let mut committed = prompt(RUN, "private-live", "2026-07-16T03:00:01Z");
    committed.event_id = "0190a200-0000-7000-8001-000000000028".into();
    committed.run_seq = 2;
    committed.event_type = "permission.requested".into();
    committed.payload = EventPayload::Inline {
        payload_json: json!({
            "gate_id": "live-gate", "kind": "confirm", "title": "Allow live action?",
            "message": "Continue the running task", "private": "private-live"
        }),
    };
    writer.append_batch(1, &[committed]).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected live run event")
    };
    assert_eq!(event.event, EventName::PermissionPending);
    assert_eq!(event.run_seq, Some(2));
    assert_eq!(
        event.body,
        json!({
            "gate_id": "live-gate", "kind": "confirm", "title": "Allow live action?",
            "message": "Continue the running task"
        })
    );
    assert!(!format!("{event:?}").contains("private-live"));

    let mut hostile = prompt(RUN, "unused", "2026-07-16T03:00:02Z");
    hostile.event_id = "0190a200-0000-7000-8001-000000000030".into();
    hostile.run_seq = 3;
    hostile.event_type = "permission.requested".into();
    hostile.payload = EventPayload::Cas {
        payload_cas: muniment_core::journal::CasReference {
            sha256: "cd".repeat(32),
            media_type: "application/live-private+json".into(),
            byte_length: 999_999,
        },
    };
    let mut later = prompt(RUN, "later-live-private", "2026-07-16T03:00:03Z");
    later.event_id = "0190a200-0000-7000-8001-000000000031".into();
    later.run_seq = 4;
    writer.append_batch(2, &[hostile, later]).unwrap();
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);
    let error_value = serde_json::to_value(&error).unwrap();
    assert_eq!(error_value["error"]["code"], "persistence_failed");
    assert_eq!(error_value["error"].get("details"), None);
    let encoded = serde_json::to_string(&error).unwrap();
    assert!(!encoded.contains("live-private"));
    assert!(!encoded.contains("later-live-private"));
    client.shutdown(Shutdown::Write).unwrap();
    let mut remaining = Vec::new();
    client.read_to_end(&mut remaining).unwrap();
    assert!(remaining.is_empty());

    assert!(matches!(
        server_thread.join().unwrap(),
        Ok(()) | Err(AttachSessionError::Closed)
    ));
}

#[test]
fn run_stream_waits_for_an_initial_held_suffix_without_advancing_or_repeating() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000032";
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-held-initial-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut writer = RunJournal::open(&path).unwrap();
    let first = prompt(RUN, "question", "2026-07-16T03:00:00Z");
    let mut held = first.clone();
    held.event_id = "0190a200-0000-7000-8003-000000000002".into();
    held.run_seq = 2;
    held.event_type = "model.stream.delta".into();
    held.payload = EventPayload::Inline {
        payload_json: json!({"text":"safe AKIAAAAA", "content_disclosure":"released"}),
    };
    writer.append_batch(0, &[first, held]).unwrap();
    writer.bind_run_workspace(RUN, "workspace-1").unwrap();
    let mut service = RunJournal::open(&path).unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            79,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(first_event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected the first event")
    };
    assert_eq!(first_event.run_seq, Some(1));
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut byte = [0];
    assert!(matches!(
        client.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    let mut remainder = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    remainder.event_id = "0190a200-0000-7000-8003-000000000003".into();
    remainder.run_seq = 3;
    remainder.event_type = "model.stream.delta".into();
    remainder.payload = EventPayload::Inline {
        payload_json: json!({"text":"AAAAAAAAAAAA end", "content_disclosure":"released"}),
    };
    let mut completed = remainder.clone();
    completed.event_id = "0190a200-0000-7000-8003-000000000004".into();
    completed.run_seq = 4;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    writer.append_batch(2, &[remainder, completed]).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut sequences = Vec::new();
    for _ in 0..3 {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected a released event")
        };
        sequences.push(event.run_seq.unwrap());
    }
    assert_eq!(sequences, [2, 3, 4]);
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected a caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.run_seq, Some(4));

    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn live_run_stream_waits_for_a_held_delta_without_advancing_or_repeating() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000033";
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-held-live-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut writer = RunJournal::open(&path).unwrap();
    writer
        .append(0, &prompt(RUN, "question", "2026-07-16T03:00:00Z"))
        .unwrap();
    writer.bind_run_workspace(RUN, "workspace-1").unwrap();
    let mut service = RunJournal::open(&path).unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            80,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 1}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected the initial caught-up event")
    };
    assert_eq!(caught_up.run_seq, Some(1));

    let mut held = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    held.event_id = "0190a200-0000-7000-8004-000000000002".into();
    held.run_seq = 2;
    held.event_type = "model.stream.delta".into();
    held.payload = EventPayload::Inline {
        payload_json: json!({"text":"safe AKIAAAAA", "content_disclosure":"released"}),
    };
    writer.append(1, &held).unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut byte = [0];
    assert!(matches!(
        client.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    let mut completed = held.clone();
    completed.event_id = "0190a200-0000-7000-8004-000000000003".into();
    completed.run_seq = 3;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    writer.append(2, &completed).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let Envelope::Event(delta) = read_frame::<Envelope>(&mut client) else {
        panic!("expected the held delta")
    };
    let Envelope::Event(terminal) = read_frame::<Envelope>(&mut client) else {
        panic!("expected the terminal event")
    };
    assert_eq!(delta.run_seq, Some(2));
    assert_eq!(terminal.run_seq, Some(3));

    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn file_journal_run_stream_captures_commit_racing_subscription_snapshot() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000030";
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-race-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut journal = RunJournal::open(&path).unwrap();
    journal
        .append(0, &prompt(RUN, "private-initial", "2026-07-16T03:00:00Z"))
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let mut racing_event = prompt(RUN, "private-racing", "2026-07-16T03:00:01Z");
    racing_event.event_id = "0190a200-0000-7000-8001-000000000030".into();
    racing_event.run_seq = 2;
    let mut service = SubscribeRaceService {
        journal,
        racing_event: Some(racing_event),
    };

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(2),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            76,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 1}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected racing event before caught-up")
    };
    assert_eq!(event.event, EventName::RunEvent);
    assert_eq!(event.run_seq, Some(2));
    assert_eq!(event.body["payload"], json!({"withheld": true}));
    assert!(!format!("{event:?}").contains("private-racing"));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up after racing event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(caught_up.run_seq, Some(2));

    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn live_run_stream_stays_bounded_and_recovers_after_hint_overflow_and_ack() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000031";
    let path = std::env::temp_dir().join(format!(
        "muniment-attach-overflow-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut writer = RunJournal::open(&path).unwrap();
    writer
        .append(0, &prompt(RUN, "private-initial", "2026-07-16T03:00:00Z"))
        .unwrap();
    writer.bind_run_workspace(RUN, "workspace-1").unwrap();
    let stream_calls = Arc::new(AtomicUsize::new(0));
    let mut service = CountingJournalService {
        journal: RunJournal::open(&path).unwrap(),
        stream_calls: Arc::clone(&stream_calls),
    };

    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(30),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            77,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 1}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    let subscription = response.body["subscription_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected initial caught-up marker")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);

    let window_end = MAX_RUN_STREAM_WINDOW_EVENTS as u64 + 1;
    let window_events = (2..=window_end)
        .map(|seq| {
            let mut event = prompt(RUN, "private-live", "2026-07-16T03:00:01Z");
            event.event_id = format!("0190a200-0000-7000-8002-{seq:012x}");
            event.run_seq = seq;
            event
        })
        .collect::<Vec<_>>();
    writer.append_batch(1, &window_events).unwrap();
    for expected in 2..=window_end {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected live window event")
        };
        assert_eq!(event.run_seq, Some(expected));
        assert_eq!(event.body["payload"], json!({"withheld": true}));
    }
    assert_eq!(stream_calls.load(Ordering::SeqCst), 2);

    let final_seq = window_end + 66;
    for seq in (window_end + 1)..=final_seq {
        let mut event = prompt(RUN, "private-live", "2026-07-16T03:00:01Z");
        event.event_id = format!("0190a200-0000-7000-8002-{seq:012x}");
        event.run_seq = seq;
        writer.append(seq - 1, &event).unwrap();
    }
    client
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let mut byte = [0];
    assert!(matches!(
        client.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    assert_eq!(stream_calls.load(Ordering::SeqCst), 2);

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .write_all(&request(
            78,
            Operation::RunCursorAck,
            json!({
                "subscription_id": subscription,
                "through_run_seq": window_end,
            }),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    for expected in (window_end + 1)..=final_seq {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected overflow recovery event")
        };
        assert_eq!(event.run_seq, Some(expected));
        assert_eq!(event.body["payload"], json!({"withheld": true}));
    }
    assert_eq!(stream_calls.load(Ordering::SeqCst), 3);

    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn run_stream_byte_window_counts_exact_framed_bytes_and_pauses_one_byte_over() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000017";
    let event_count = MAX_RUN_STREAM_WINDOW_BYTES.div_ceil(60_000);
    let base_target = MAX_RUN_STREAM_WINDOW_BYTES / event_count;
    let remainder = MAX_RUN_STREAM_WINDOW_BYTES % event_count;
    let targets = (0..event_count)
        .map(|index| base_target + usize::from(index < remainder))
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    for (index, target) in targets.iter().copied().enumerate() {
        let seq = index as u64 + 1;
        let base = projected_run_event_frame_len(RUN, seq, "x") - 1;
        let event_type = "x".repeat(target - base);
        assert_eq!(projected_run_event_frame_len(RUN, seq, &event_type), target);
        assert!(target <= MAX_FRAME_LENGTH + 4);
        events.push(stream_projection(RUN, seq, event_type));
    }
    let over_seq = events.len() as u64 + 1;
    events.push(stream_projection(RUN, over_seq, "one-byte-over".into()));
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: over_seq,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(30),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            48,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body["window"]["max_bytes"],
        MAX_RUN_STREAM_WINDOW_BYTES
    );
    let mut event_bytes = 0;
    let mut sequences = Vec::new();
    for _ in 0..targets.len() {
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).unwrap();
        let mut frame = vec![0; 4 + u32::from_be_bytes(prefix) as usize];
        frame[..4].copy_from_slice(&prefix);
        client.read_exact(&mut frame[4..]).unwrap();
        event_bytes += frame.len();
        let (Envelope::Event(event), _) = decode_frame(&frame).unwrap().unwrap() else {
            panic!("expected event")
        };
        assert_eq!(event.event, EventName::RunEvent);
        sequences.push(event.run_seq.unwrap());
    }
    assert_eq!(sequences.len(), targets.len());
    assert_eq!(sequences.last(), Some(&(targets.len() as u64)));
    assert_eq!(event_bytes, MAX_RUN_STREAM_WINDOW_BYTES);
    client
        .write_all(&request(
            49,
            Operation::RunCursorAck,
            json!({"subscription_id": response.body["subscription_id"], "through_run_seq": targets.len()}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(resumed) = read_frame::<Envelope>(&mut client) else {
        panic!("expected byte-window resumed event")
    };
    assert_eq!(resumed.run_seq, Some(over_seq));
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn run_stream_text_window_pauses_before_excess_and_ack_resumes_without_repeating() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000018";
    const CHUNK_BYTES: usize = 65_536;
    let events = (1..=5)
        .map(|run_seq| RunEventProjection {
            text: Some(
                char::from(b'a' + run_seq as u8)
                    .to_string()
                    .repeat(CHUNK_BYTES),
            ),
            ..stream_projection(RUN, run_seq, "model.stream.delta".into())
        })
        .collect();
    let mut service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: 5,
            events,
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(30),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
        )
    });
    client.write_all(&hello(1, 1)).unwrap();
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    client
        .write_all(&request(
            50,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body["window"]["max_text_bytes"],
        MAX_RUN_STREAM_WINDOW_TEXT_BYTES
    );
    let subscription = response.body["subscription_id"].clone();
    let mut sequences = Vec::new();
    for expected in 1..=4 {
        let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
            panic!("expected text event")
        };
        sequences.push(event.run_seq.unwrap());
        assert_eq!(
            event.body["payload"]["text"].as_str().unwrap().len(),
            CHUNK_BYTES
        );
        assert_eq!(
            event.body["payload"]["text"].as_str().unwrap().as_bytes()[0],
            b'a' + expected as u8
        );
    }
    client
        .write_all(&request(
            51,
            Operation::RunCursorAck,
            json!({"subscription_id": subscription, "through_run_seq": 4}),
        ))
        .unwrap();
    let _: Response = read_frame(&mut client);
    let Envelope::Event(last) = read_frame::<Envelope>(&mut client) else {
        panic!("expected resumed text event")
    };
    sequences.push(last.run_seq.unwrap());
    assert_eq!(
        last.body["payload"]["text"].as_str().unwrap().len(),
        CHUNK_BYTES
    );
    let Envelope::Event(caught_up) = read_frame::<Envelope>(&mut client) else {
        panic!("expected caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);
    assert_eq!(sequences, vec![1, 2, 3, 4, 5]);
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server_thread.join().unwrap(), Ok(()));
}

#[test]
fn authorized_thread_list_pages_real_journal_summaries_without_payloads() {
    const RUN_A: &str = "0190a100-0000-7000-8000-000000000001";
    const RUN_B: &str = "0190a100-0000-7000-8000-000000000002";
    const RUN_C: &str = "0190a100-0000-7000-8000-000000000003";
    const HIDDEN_RUN: &str = "0190a100-0000-7000-8000-000000000004";
    let mut journal = RunJournal::open(":memory:").unwrap();
    for (run_id, title, recorded_at) in [
        (RUN_A, "first", "2026-07-16T03:00:00Z"),
        (RUN_B, "second", "2026-07-16T02:00:00Z"),
        (RUN_C, "third", "2026-07-16T01:00:00Z"),
    ] {
        journal
            .append(0, &prompt(run_id, title, recorded_at))
            .unwrap();
        journal.bind_run_workspace(run_id, "workspace-1").unwrap();
    }
    journal
        .append(0, &prompt(HIDDEN_RUN, "hidden", "2026-07-16T04:00:00Z"))
        .unwrap();
    journal
        .bind_run_workspace(HIDDEN_RUN, "workspace-2")
        .unwrap();
    let listed = journal
        .workspace_thread_summaries("workspace-1", 10, None)
        .unwrap();
    let listed_ids = listed
        .summaries
        .iter()
        .map(|summary| summary.thread_id.clone())
        .collect::<Vec<_>>();

    let (mut client, server) = UnixStream::pair().unwrap();
    let client_thread = thread::spawn(move || {
        client.write_all(&hello(1, 1)).unwrap();
        let _: Welcome = read_frame(&mut client);
        let _: Authorized = read_frame(&mut client);
        client
            .write_all(&request(11, Operation::ThreadList, json!({"limit": 2})))
            .unwrap();
        let first: Response = read_frame(&mut client);
        client
            .write_all(&request(
                12,
                Operation::ThreadList,
                json!({"limit": 2, "cursor": first.body["next_cursor"]}),
            ))
            .unwrap();
        let second: Response = read_frame(&mut client);
        client.shutdown(Shutdown::Write).unwrap();
        (first, second)
    });
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_secs(1),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut journal,
    );
    assert_eq!(result, Ok(()));
    let (first, second) = client_thread.join().unwrap();
    assert_eq!(
        first.body,
        json!({
            "threads": [
                {"thread_id": listed_ids[0], "title": "first", "updated_at": "2026-07-16T03:00:00Z"},
                {"thread_id": listed_ids[1], "title": "second", "updated_at": "2026-07-16T02:00:00Z"}
            ],
            "next_cursor": first.body["next_cursor"]
        })
    );
    assert_eq!(
        second.body,
        json!({
            "threads": [
                {"thread_id": listed_ids[2], "title": "third", "updated_at": "2026-07-16T01:00:00Z"}
            ]
        })
    );
    let encoded = format!("{}{}", first.body, second.body);
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("/home/user/private"));
}

#[test]
fn authorized_thread_open_pages_a_redacted_journal_projection() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    let mut journal = RunJournal::open(":memory:").unwrap();
    let first = prompt(RUN, "hello", "2026-07-16T03:00:00Z");
    let mut second = first.clone();
    second.event_id = "0190a200-0000-7000-8000-000000000002".into();
    second.run_seq = 2;
    second.event_type = "model.stream.delta".into();
    second.payload = EventPayload::Inline {
        payload_json: json!({"text": "answer", "secret": "/home/user/private", "content_disclosure": "released"}),
    };
    let mut completed = second.clone();
    completed.event_id = "0190a200-0000-7000-8000-000000000003".into();
    completed.run_seq = 3;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    journal
        .append_batch(0, &[first, second, completed])
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");

    let (mut client, server) = UnixStream::pair().unwrap();
    let client_thread = thread::spawn(move || {
        client.write_all(&hello(1, 1)).unwrap();
        let _: Welcome = read_frame(&mut client);
        let _: Authorized = read_frame(&mut client);
        client
            .write_all(&request(
                40,
                Operation::ThreadOpen,
                json!({"thread_id": thread_id.clone(), "limit": 1}),
            ))
            .unwrap();
        let first: Response = read_frame(&mut client);
        client
            .write_all(&request(
                41,
                Operation::ThreadOpen,
                json!({"thread_id": thread_id, "limit": 1, "cursor": first.body["next_cursor"]}),
            ))
            .unwrap();
        let second: Response = read_frame(&mut client);
        client.shutdown(Shutdown::Write).unwrap();
        (first, second)
    });
    assert_eq!(
        run_authenticated_session_with_authorization(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| Some(
                    ApprovalDecision::Approve(approval())
                ),
            },
            &mut journal
        ),
        Ok(())
    );
    let (first, second) = client_thread.join().unwrap();
    assert_eq!(
        first.body["entries"],
        json!([{"run_seq": 1, "kind": "user_message", "text": "hello"}])
    );
    assert_eq!(
        second.body["entries"],
        json!([{"run_seq": 2, "kind": "assistant_message", "text": "answer"}])
    );
    assert!(!format!("{first:?}{second:?}").contains("/home"));
}

#[test]
fn thread_open_uses_released_deltas_and_workspace_path_policy() {
    const RUN: &str = "0190a105-0000-7000-8000-000000000001";
    let root = std::env::temp_dir().join(format!("muniment-thread-open-{}", uuid::Uuid::now_v7()));
    let workspace = root.join("workspace");
    let outside = root.join("private.txt");
    let inside = workspace.join("notes.txt");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(&inside, "inside").unwrap();
    std::fs::write(&outside, "outside").unwrap();

    let mut events = vec![prompt(RUN, "question", "2026-07-16T03:00:00Z")];
    for (seq, payload) in [
        (
            2,
            json!({"text":"safe AKIAAAAA", "content_disclosure":"released"}),
        ),
        (
            3,
            json!({"text":"AAAAAAAAAAAA end ", "content_disclosure":"released"}),
        ),
        (
            4,
            json!({
                "text": format!("inside {} outside {} done", inside.display(), outside.display()),
                "content_disclosure":"released"
            }),
        ),
        (5, json!({"text":" legacy must stay hidden"})),
    ] {
        let mut event = events[0].clone();
        event.event_id = format!("0190a205-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = "model.stream.delta".into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut completed = events[0].clone();
    completed.event_id = "0190a205-0000-7000-8000-000000000006".into();
    completed.run_seq = 6;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    events.push(completed);
    let workspace = workspace.to_string_lossy().into_owned();
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, &workspace).unwrap();
    let thread_id = sole_thread_id(&mut journal, &workspace);
    let page = journal
        .open_thread(
            &workspace,
            ThreadOpenRequest {
                thread_id,
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    let assistant = page
        .entries
        .iter()
        .filter(|entry| entry.kind == "assistant_message")
        .filter_map(|entry| entry.text.as_deref())
        .collect::<String>();
    assert_eq!(
        assistant,
        format!("safe  end inside {} outside  done", inside.display())
    );
    assert!(!assistant.contains("AKIA"));
    assert!(!assistant.contains(outside.to_string_lossy().as_ref()));
    assert!(!assistant.contains("legacy"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn run_stream_text_matches_thread_open_and_replay_skips_the_cursor() {
    const RUN: &str = "0190a105-0000-7000-8000-000000000002";
    let mut events = vec![prompt(RUN, "question", "2026-07-16T03:00:00Z")];
    for (seq, text) in [(2, "safe AKIAAAAA"), (3, "AAAAAAAAAAAA end")] {
        let mut delta = events[0].clone();
        delta.event_id = format!("0190a205-0000-7000-8001-{seq:012}");
        delta.run_seq = seq;
        delta.event_type = "model.stream.delta".into();
        delta.payload = EventPayload::Inline {
            payload_json: json!({"text":text, "content_disclosure":"released"}),
        };
        events.push(delta);
    }
    let mut completed = events[0].clone();
    completed.event_id = "0190a205-0000-7000-8001-000000000004".into();
    completed.run_seq = 4;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    events.push(completed);

    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let stream = journal.stream_run("workspace-1", RUN, 0).unwrap();
    assert_eq!(
        stream
            .events
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    let stream_text = stream
        .events
        .iter()
        .filter_map(|event| event.text.as_deref())
        .collect::<String>();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");
    let thread = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id,
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    let thread_text = thread
        .entries
        .iter()
        .filter(|entry| entry.kind == "assistant_message")
        .filter_map(|entry| entry.text.as_deref())
        .collect::<String>();
    assert_eq!(stream_text, thread_text);
    assert_eq!(stream_text, "safe  end");
    assert!(!stream_text.contains("AKIA"));

    let resumed = journal.stream_run("workspace-1", RUN, 2).unwrap();
    assert_eq!(
        resumed
            .events
            .iter()
            .map(|event| event.run_seq)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert_eq!(
        resumed
            .events
            .iter()
            .filter_map(|event| event.text.as_deref())
            .collect::<String>(),
        " end"
    );
}

#[test]
fn run_stream_page_projects_tool_effect_fields() {
    const RUN: &str = "0190a105-0000-7000-8000-000000000003";
    let mut events = Vec::new();
    for (seq, event_type, payload) in [
        (
            1,
            "tool.effect.started",
            json!({"effect_id":"tool-1","display_name":"Search"}),
        ),
        (2, "tool.effect.completed", json!({"effect_id":"tool-1"})),
        (3, "tool.effect.failed", json!({"effect_id":"tool-2"})),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a205-0000-7000-8001-{seq:012}");
        event.run_seq = seq;
        event.event_type = event_type.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();

    let stream = journal.stream_run("workspace-1", RUN, 0).unwrap();
    assert_eq!(stream.events[0].effect_id.as_deref(), Some("tool-1"));
    assert_eq!(stream.events[0].display_name.as_deref(), Some("Search"));
    assert!(stream.events[0].tool_effect_valid);
    assert_eq!(stream.events[1].effect_id.as_deref(), Some("tool-1"));
    assert_eq!(stream.events[1].display_name, None);
    assert!(stream.events[1].tool_effect_valid);
    assert_eq!(stream.events[2].effect_id.as_deref(), Some("tool-2"));
    assert_eq!(stream.events[2].display_name, None);
    assert!(stream.events[2].tool_effect_valid);
}

#[test]
fn run_stream_tool_effect_projection_enforces_identity_bounds() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000044";
    let boundary = "x".repeat(65_536);
    let valid = RunEventProjection {
        effect_id: Some(boundary.clone()),
        display_name: Some(boundary.clone()),
        tool_effect_valid: true,
        ..stream_projection(RUN, 1, "tool.effect.started".into())
    };
    let invalid = [
        RunEventProjection {
            effect_id: Some(String::new()),
            tool_effect_valid: true,
            ..stream_projection(RUN, 1, "tool.effect.started".into())
        },
        RunEventProjection {
            effect_id: Some("x".repeat(65_537)),
            tool_effect_valid: true,
            ..stream_projection(RUN, 1, "tool.effect.started".into())
        },
        RunEventProjection {
            effect_id: Some("private-effect".into()),
            display_name: Some("x".repeat(65_537)),
            tool_effect_valid: true,
            ..stream_projection(RUN, 1, "tool.effect.started".into())
        },
        RunEventProjection {
            effect_id: Some("private-effect".into()),
            display_name: Some("private-name".into()),
            tool_effect_valid: true,
            ..stream_projection(RUN, 1, "tool.effect.completed".into())
        },
        RunEventProjection {
            effect_id: Some("private-effect".into()),
            display_name: Some("private-name".into()),
            tool_effect_valid: true,
            ..stream_projection(RUN, 1, "tool.effect.failed".into())
        },
    ];

    let mut valid_service = StreamService {
        page: RunStreamPage {
            run_id: RUN.into(),
            first_available_run_seq: 1,
            current_run_seq: 1,
            events: vec![valid],
            exhausted: true,
        },
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            45,
            Operation::RunStream,
            json!({"run_id": RUN, "after_run_seq": 0}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut valid_service,
        ),
        Ok(())
    );
    let _: Response = read_frame(&mut client);
    let Envelope::Event(event) = read_frame::<Envelope>(&mut client) else {
        panic!("expected boundary tool effect")
    };
    assert_eq!(event.body["payload"]["effect_id"], boundary);
    assert_eq!(event.body["payload"]["display_name"], boundary);

    for projection in invalid {
        let mut service = StreamService {
            page: RunStreamPage {
                run_id: RUN.into(),
                first_available_run_seq: 1,
                current_run_seq: 2,
                events: vec![
                    projection,
                    RunEventProjection {
                        effect_id: Some("later-private-effect".into()),
                        tool_effect_valid: true,
                        ..stream_projection(RUN, 2, "tool.effect.completed".into())
                    },
                ],
                exhausted: true,
            },
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(
                46,
                Operation::RunStream,
                json!({"run_id": RUN, "after_run_seq": 0}),
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            dispatch_session(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                &mut service,
            ),
            Ok(())
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("private-effect"));
        assert!(!encoded.contains("private-name"));
        assert!(!encoded.contains("later-private-effect"));
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
    }
}

#[test]
fn thread_open_keeps_an_active_suffix_withheld_until_terminal_projection() {
    const RUN: &str = "0190a106-0000-7000-8000-000000000001";
    let mut journal = RunJournal::open(":memory:").unwrap();
    let first = prompt(RUN, "question", "2026-07-16T03:00:00Z");
    let mut candidate = first.clone();
    candidate.event_id = "0190a206-0000-7000-8000-000000000002".into();
    candidate.run_seq = 2;
    candidate.event_type = "model.stream.delta".into();
    candidate.payload = EventPayload::Inline {
        payload_json: json!({"text":"safe AKIAAAAA", "content_disclosure":"released"}),
    };
    journal.append_batch(0, &[first, candidate]).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");

    let active = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: thread_id.clone(),
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    let active_text = active
        .entries
        .iter()
        .filter_map(|entry| entry.text.as_deref())
        .collect::<String>();
    assert_eq!(active_text, "question");

    let mut remainder = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    remainder.event_id = "0190a206-0000-7000-8000-000000000003".into();
    remainder.run_seq = 3;
    remainder.event_type = "model.stream.delta".into();
    remainder.payload = EventPayload::Inline {
        payload_json: json!({"text":"AAAAAAAAAAAA end", "content_disclosure":"released"}),
    };
    let mut completed = remainder.clone();
    completed.event_id = "0190a206-0000-7000-8000-000000000004".into();
    completed.run_seq = 4;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    journal.append_batch(2, &[remainder, completed]).unwrap();

    let terminal = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id,
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    let terminal_text = terminal
        .entries
        .iter()
        .filter_map(|entry| entry.text.as_deref())
        .collect::<String>();
    assert_eq!(terminal_text, "questionsafe  end");
    assert!(!terminal_text.contains("AKIA"));
}

#[test]
fn journal_attach_uses_renamed_ledger_threads_and_hides_tombstones() {
    const LIVE_RUN: &str = "0190a110-0000-7000-8000-000000000001";
    const DELETED_RUN: &str = "0190a110-0000-7000-8000-000000000002";
    let mut journal = RunJournal::open(":memory:").unwrap();
    let live_first = prompt(LIVE_RUN, "old title", "2026-07-16T03:00:00Z");
    let provenance = live_first.provenance.clone();
    let mut live_second = live_first.clone();
    live_second.event_id = "0190a210-0000-7000-8000-000000000002".into();
    live_second.run_seq = 2;
    live_second.event_type = "model.stream.delta".into();
    live_second.payload = EventPayload::Inline {
        payload_json: json!({"text":"answer", "content_disclosure":"released"}),
    };
    journal.append_batch(0, &[live_first, live_second]).unwrap();
    journal.bind_run_workspace(LIVE_RUN, "workspace-1").unwrap();
    let live_thread = sole_thread_id(&mut journal, "workspace-1");
    journal
        .append_thread_title_renamed(
            1,
            &live_thread,
            "Renamed thread",
            "2026-07-16T03:01:00Z",
            &provenance,
        )
        .unwrap();

    journal
        .append(0, &prompt(DELETED_RUN, "deleted", "2026-07-16T02:00:00Z"))
        .unwrap();
    journal
        .bind_run_workspace(DELETED_RUN, "workspace-1")
        .unwrap();
    let deleted_thread = journal
        .workspace_thread_summaries("workspace-1", 10, None)
        .unwrap()
        .summaries
        .into_iter()
        .find(|summary| summary.title == "deleted")
        .unwrap()
        .thread_id;
    journal
        .append_thread_deleted(1, &deleted_thread, "2026-07-16T03:02:00Z", &provenance)
        .unwrap();

    let listed = journal
        .list_threads(
            "workspace-1",
            ThreadListRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(listed.threads.len(), 1);
    assert_eq!(listed.threads[0].thread_id, live_thread);
    assert_eq!(listed.threads[0].title, "Renamed thread");

    let first = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: live_thread.clone(),
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert!(first.next_cursor.is_some());
    let second = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: live_thread,
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert!(second.next_cursor.is_none());

    for rejected in [DELETED_RUN, deleted_thread.as_str()] {
        let error = journal
            .open_thread(
                "workspace-1",
                ThreadOpenRequest {
                    thread_id: rejected.to_owned(),
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidRequest);
    }
}

#[test]
fn thread_open_cursor_is_bound_to_its_thread_and_workspace() {
    const RUN_A: &str = "0190a120-0000-7000-8000-000000000001";
    const RUN_B: &str = "0190a120-0000-7000-8000-000000000002";
    let mut journal = RunJournal::open(":memory:").unwrap();
    for (run_id, workspace, title) in [
        (RUN_A, "workspace-1", "first"),
        (RUN_B, "workspace-2", "second"),
    ] {
        let first = prompt(run_id, title, "2026-07-16T03:00:00Z");
        let mut second = first.clone();
        second.event_id = format!("0190a220-0000-7000-8000-{}", &run_id[24..]);
        second.run_seq = 2;
        second.event_type = "model.stream.delta".into();
        second.payload = EventPayload::Inline {
            payload_json: json!({"text":"answer", "content_disclosure":"released"}),
        };
        journal.append_batch(0, &[first, second]).unwrap();
        journal.bind_run_workspace(run_id, workspace).unwrap();
    }
    let thread_a = sole_thread_id(&mut journal, "workspace-1");
    let thread_b = sole_thread_id(&mut journal, "workspace-2");
    let cursor = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: thread_a,
                limit: 1,
                cursor: None,
            },
        )
        .unwrap()
        .next_cursor;

    let error = journal
        .open_thread(
            "workspace-2",
            ThreadOpenRequest {
                thread_id: thread_b,
                limit: 1,
                cursor,
            },
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidCursor);
}

#[test]
fn projected_pages_preserve_cross_boundary_state_and_ignore_unknown_events() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    let mut events = Vec::new();
    for (seq, kind, payload) in [
        (1, "run.started", json!({})),
        (
            2,
            "model.stream.delta",
            json!({"text":"hello ", "content_disclosure":"released"}),
        ),
        (3, "future.event", json!({"private":"ignored"})),
        (
            4,
            "model.stream.delta",
            json!({"text":"world", "content_disclosure":"released"}),
        ),
        (
            5,
            "tool.effect.started",
            json!({"effect_id":"tool-1","display_name":"Search"}),
        ),
        (
            6,
            "permission.requested",
            json!({"gate_id":"gate-1","kind":"confirm","title":"Allow?","message":"Proceed?"}),
        ),
        (7, "permission.resolved", json!({"gate_id":"gate-1"})),
        (8, "tool.effect.completed", json!({"effect_id":"tool-1"})),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a200-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = kind.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut attachment = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
    attachment.event_id = "0190a200-0000-7000-8000-000000000009".into();
    attachment.run_seq = 9;
    attachment.event_type = "chat.attachment.ingested".into();
    attachment.payload = EventPayload::Attachment {
        attachment: serde_json::from_value(json!({
            "sha256": "00".repeat(32), "display_name": "notes.txt", "byte_length": 12,
            "media_type": "text/plain"
        }))
        .unwrap(),
    };
    events.push(attachment);
    let mut completed = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
    completed.event_id = "0190a200-0000-7000-8000-000000000010".into();
    completed.run_seq = 10;
    completed.event_type = "run.completed".into();
    completed.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    events.push(completed);
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");
    let first = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: thread_id.clone(),
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    let second = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: thread_id.clone(),
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(first.entries[0].text.as_deref(), Some("hello world"));
    assert_eq!(second.entries[0].kind, "tool_completed");
    assert_eq!(second.entries[0].text.as_deref(), Some("Search"));
    let third = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id,
                limit: 1,
                cursor: second.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(third.entries[0].kind, "attachment");
    assert_eq!(third.entries[0].text.as_deref(), Some("notes.txt"));
    assert!(third.next_cursor.is_none());
}

#[test]
fn large_escaped_projection_continues_losslessly_with_bounded_pages() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    let fragment = "\\\"\n".repeat(400);
    let expected = fragment.repeat(1000);
    let mut events = Vec::with_capacity(1002);
    for seq in 1..=1002 {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a200-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = match seq {
            1 => "run.started",
            1002 => "run.completed",
            _ => "model.stream.delta",
        }
        .into();
        event.payload = EventPayload::Inline {
            payload_json: if seq == 1 || seq == 1002 {
                json!({})
            } else {
                json!({"text": fragment, "content_disclosure":"released"})
            },
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");
    // The journal projection seam itself stays bounded.
    assert_eq!(
        journal
            .projected_thread_entries("workspace-1", RUN, 1002, -1, 3)
            .unwrap()
            .len(),
        3
    );
    let started = std::time::Instant::now();
    let mut cursor = None;
    let mut found = String::new();
    loop {
        let page = journal
            .open_thread(
                "workspace-1",
                ThreadOpenRequest {
                    thread_id: thread_id.clone(),
                    limit: 100,
                    cursor,
                },
            )
            .unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() < MAX_FRAME_LENGTH);
        for entry in page.entries {
            found.push_str(entry.text.as_deref().unwrap_or(""));
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(found, expected);
}

#[test]
fn thread_open_cursor_skips_removed_projection_ordinals_without_duplicates() {
    const RUN: &str = "0190a250-0000-7000-8000-000000000001";
    let mut events = Vec::new();
    for (seq, kind, payload) in [
        (1, "user.prompt.submitted", json!({"prompt":"first"})),
        (
            2,
            "permission.requested",
            json!({"gate_id":"gate-1","kind":"confirm","title":"Allow?","message":"Proceed?"}),
        ),
        (3, "user.prompt.submitted", json!({"prompt":"second"})),
        (4, "permission.resolved", json!({"gate_id":"gate-1"})),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a250-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = kind.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");

    let mut cursor = None;
    let mut found = Vec::new();
    loop {
        let page = journal
            .open_thread(
                "workspace-1",
                ThreadOpenRequest {
                    thread_id: thread_id.clone(),
                    limit: 1,
                    cursor,
                },
            )
            .unwrap();
        found.extend(page.entries.into_iter().map(|entry| entry.text));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(found, [Some("first".into()), Some("second".into())]);
}

#[test]
fn thread_projection_cursor_keeps_its_snapshot_after_later_deltas() {
    const RUN: &str = "0190a300-0000-7000-8000-000000000001";
    let mut events = Vec::new();
    for (seq, kind, payload) in [
        (1, "run.started", json!({})),
        (2, "user.prompt.submitted", json!({"prompt":"question"})),
        (
            3,
            "model.stream.delta",
            json!({"text":"hello", "content_disclosure":"released"}),
        ),
    ] {
        let mut event = prompt(RUN, "unused", "2026-07-16T03:00:00Z");
        event.event_id = format!("0190a300-0000-7000-8000-{seq:012}");
        event.run_seq = seq;
        event.event_type = kind.into();
        event.payload = EventPayload::Inline {
            payload_json: payload,
        };
        events.push(event);
    }
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal.append_batch(0, &events).unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");
    let first = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id: thread_id.clone(),
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();

    let mut later = prompt(RUN, "unused", "2026-07-16T03:00:01Z");
    later.event_id = "0190a300-0000-7000-8000-000000000004".into();
    later.run_seq = 4;
    later.event_type = "model.stream.delta".into();
    later.payload = EventPayload::Inline {
        payload_json: json!({"text":" world", "content_disclosure":"released"}),
    };
    journal.append(3, &later).unwrap();

    let second = journal
        .open_thread(
            "workspace-1",
            ThreadOpenRequest {
                thread_id,
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(second.entries[0].text, None);
}

#[test]
fn thread_open_rejects_bad_cursor_missing_thread_and_oversized_body_values() {
    const RUN: &str = "0190a100-0000-7000-8000-000000000001";
    const OTHER_RUN: &str = "0190a100-0000-7000-8000-000000000002";
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN, "hello", "2026-07-16T03:00:00Z"))
        .unwrap();
    journal.bind_run_workspace(RUN, "workspace-1").unwrap();
    journal
        .append(0, &prompt(OTHER_RUN, "hidden", "2026-07-16T03:01:00Z"))
        .unwrap();
    journal
        .bind_run_workspace(OTHER_RUN, "workspace-2")
        .unwrap();
    let thread_id = sole_thread_id(&mut journal, "workspace-1");
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            50,
            Operation::ThreadOpen,
            json!({"thread_id": thread_id, "limit": 1, "cursor": "forged"}),
        ))
        .unwrap();
    client
        .write_all(&request(
            51,
            Operation::ThreadOpen,
            json!({"thread_id": "0190a100-0000-7000-8000-000000000099", "limit": 1}),
        ))
        .unwrap();
    client
        .write_all(&request(
            52,
            Operation::ThreadOpen,
            json!({"thread_id": thread_id, "limit": 101}),
        ))
        .unwrap();
    for (id, body) in [
        (53, json!({"thread_id": "", "limit": 1})),
        (54, json!({"thread_id": "x".repeat(37), "limit": 1})),
        (
            55,
            json!({"thread_id": thread_id, "limit": 1, "cursor": ""}),
        ),
        (
            56,
            json!({"thread_id": thread_id, "limit": 1, "cursor": "x".repeat(1025)}),
        ),
        (
            57,
            json!({"thread_id": thread_id, "limit": 1, "workspace": "other"}),
        ),
    ] {
        client
            .write_all(&request(id, Operation::ThreadOpen, body))
            .unwrap();
    }
    client
        .write_all(&request_with_idempotency(
            58,
            Operation::ThreadOpen,
            json!({"thread_id": thread_id, "limit": 1}),
        ))
        .unwrap();
    client
        .write_all(&request(
            59,
            Operation::ThreadOpen,
            json!({"thread_id": OTHER_RUN, "limit": 1}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut journal
        ),
        Ok(())
    );
    let cursor: ErrorEnvelope = read_frame(&mut client);
    let missing: ErrorEnvelope = read_frame(&mut client);
    let oversized: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(cursor.error.code(), ErrorCode::InvalidCursor);
    assert_eq!(missing.error.code(), ErrorCode::InvalidRequest);
    assert_eq!(oversized.error.code(), ErrorCode::InvalidRequest);
    for id in 53..=58 {
        let hostile: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(
            hostile.request_id,
            Some(Id::new(format!("{id:032x}")).unwrap())
        );
        assert!(matches!(
            hostile.error.code(),
            ErrorCode::InvalidRequest | ErrorCode::IdempotencyKeyForbidden
        ));
        assert_eq!(
            serde_json::to_value(hostile.error).unwrap().get("details"),
            None
        );
    }
    let other_workspace: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(other_workspace.error.code(), missing.error.code());
    assert_eq!(
        serde_json::to_value(other_workspace.error)
            .unwrap()
            .get("details"),
        None
    );
    assert_eq!(
        serde_json::to_value(cursor.error).unwrap().get("details"),
        None
    );
    assert_eq!(
        serde_json::to_value(missing.error).unwrap().get("details"),
        None
    );
}

#[test]
fn journal_thread_list_maps_cursor_and_storage_failures_without_details() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    let cursor_error = journal
        .list_threads(
            "workspace-1",
            ThreadListRequest {
                limit: 1,
                cursor: Some("forged".into()),
            },
        )
        .unwrap_err();
    assert_eq!(cursor_error.code(), ErrorCode::InvalidCursor);

    let path = std::env::temp_dir().join(format!(
        "muniment-thread-list-storage-failure-{}.sqlite3",
        std::process::id()
    ));
    let mut journal = RunJournal::open(&path).unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE events")
        .unwrap();
    let storage_error = journal
        .list_threads(
            "workspace-1",
            ThreadListRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap_err();
    assert_eq!(storage_error.code(), ErrorCode::PersistenceFailed);
    assert!(!serde_json::to_string(&storage_error)
        .unwrap()
        .contains("events"));
    drop(journal);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn malformed_post_authorization_request_is_redacted_and_terminal() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&raw_frame(br#"{"secret":"/home/user""#))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = |_: &str, _: ThreadListRequest| -> Result<ThreadListPage, _> {
        panic!("malformed input must not dispatch")
    };
    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service
        ),
        Err(AttachSessionError::MalformedFrame)
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::MalformedFrame);
    assert!(!serde_json::to_string(&error).unwrap().contains("/home"));
}

#[test]
fn authorization_is_rechecked_before_every_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(20, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client
        .write_all(&request(21, Operation::ThreadList, json!({"limit": 1})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let now = Rc::new(Cell::new(Duration::ZERO));
    let advance = now.clone();
    let calls = Cell::new(0);
    let mut service = move |_: &str, _: ThreadListRequest| {
        calls.set(calls.get() + 1);
        advance.set(Duration::from_secs(3601));
        Ok(ThreadListPage {
            threads: vec![],
            next_cursor: None,
        })
    };
    assert_eq!(
        dispatch_session(&mut client, server, TestClock(now), &mut service),
        Err(AttachSessionError::Authorization)
    );
    let _: Response = read_frame(&mut client);
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(
        error.request_id,
        Some(Id::new(format!("{:032x}", 21)).unwrap())
    );
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
}

#[test]
fn thread_open_without_read_scope_fails_closed_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(30, Operation::ThreadOpen, json!({})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = |_: &str, _: ThreadListRequest| -> Result<ThreadListPage, _> {
        panic!("unsupported operations must not dispatch")
    };
    let mut approved = approval();
    approved.scopes.clear();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service
        ),
        Err(AttachSessionError::Authorization)
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(
        error.request_id,
        Some(Id::new(format!("{:032x}", 30)).unwrap())
    );
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
}

#[test]
fn authorized_run_start_dispatches_once_with_bounded_input_and_provenance() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request_with_idempotency(
            70,
            Operation::RunStart,
            json!({
                "text": "Do the work",
                "context": {"selection": "safe"},
                "thread_id": "0190a100-0000-7000-8000-000000000099"
            }),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = StartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body,
        json!({
            "run_id": "0190a100-0000-7000-8000-000000000001",
            "thread_id": "0190a100-0000-7000-8000-000000000002",
            "committed_seq": 2,
            "accepted_at": "2026-07-17T00:00:00Z"
        })
    );
    assert_eq!(service.calls.len(), 1);
    let (workspace, execution_root, body, request_id, key, provenance) = &service.calls[0];
    assert_eq!(workspace, "workspace-1");
    assert_eq!(execution_root, "workspace-1");
    assert_eq!(body.text, "Do the work");
    assert_eq!(body.context, Some(json!({"selection": "safe"})));
    assert_eq!(
        body.thread_id.as_deref(),
        Some("0190a100-0000-7000-8000-000000000099")
    );
    assert_eq!(request_id, &Id::new(format!("{:032x}", 70)).unwrap());
    assert_eq!(key, &Id::new(format!("{:032x}", 1070)).unwrap());
    assert_eq!(provenance.profile, "profile-1");
    assert_eq!(provenance.companion_kind, "cli");
    assert_eq!(provenance.companion_version, "1.0.0");
    assert_eq!(provenance.peer_uid, unsafe { libc::geteuid() });
}

#[test]
fn onboarding_authorizes_only_opened_and_memory_workspaces_for_run_start() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let workspaces = [
        ("/cli/default", "/cli/default"),
        ("/cli/override-repo", "/cli/external-memory"),
        ("/extension/root-one", "/extension/root-one"),
        ("/extension/root-two", "/extension/external-memory"),
    ];
    for (index, (opened, memory)) in workspaces.iter().enumerate() {
        client
            .write_all(&request(
                200 + index as u128,
                Operation::WorkspaceOnboard,
                json!({"opened_directory": opened, "memory_location": memory}),
            ))
            .unwrap();
        client
            .write_all(&request_with_idempotency(
                210 + index as u128,
                Operation::RunStart,
                json!({"text": "use instructions", "workspace": memory}),
            ))
            .unwrap();
    }
    client
        .write_all(&request_with_idempotency(
            220,
            Operation::RunStart,
            json!({"text": "escape grant", "workspace": "/arbitrary/not-onboarded"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = OnboardingStartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Ok(())
    );
    for _ in workspaces {
        let _: Response = read_frame(&mut client);
        let _: Response = read_frame(&mut client);
    }
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    let runs = service.runs.lock().unwrap();
    assert_eq!(runs.len(), workspaces.len());
    for ((workspace, execution_root, instructions), (opened, memory)) in
        runs.iter().zip(workspaces.iter())
    {
        assert_eq!(workspace, "workspace-1");
        assert_eq!(execution_root, memory);
        assert_eq!(instructions, &format!("instructions for {opened}"));
    }
}

#[test]
fn workspace_registrations_are_bounded_to_the_approved_client_across_connections() {
    let shared = OnboardingStartService::default();
    let instructions = shared.instructions.clone();
    let runs = shared.runs.clone();
    let workspace = "workspace-1";
    let override_memory = "/sensitive/external-memory";

    let run_session = |client_id: &str, frames: Vec<Vec<u8>>| {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(&hello_for_client(1, 1, client_id))
            .unwrap();
        for frame in frames {
            client.write_all(&frame).unwrap();
        }
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        approved.profile = "desktop-owner".into();
        approved.scopes.insert("run.write".into());
        let mut service = OnboardingStartService {
            instructions: instructions.clone(),
            runs: runs.clone(),
            client_identity: None,
        };
        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approved,
                &mut service,
            ),
            Ok(())
        );
        client
    };

    let mut onboarding = run_session(
        "018f0000-0000-7000-8000-00000000000a",
        vec![request(
            230,
            Operation::WorkspaceOnboard,
            json!({"opened_directory": workspace, "memory_location": override_memory}),
        )],
    );
    let _: Response = read_frame(&mut onboarding);

    for (request_id, selected) in [(231, workspace), (234, override_memory)] {
        let mut client_b = run_session(
            "018f0000-0000-7000-8000-00000000000b",
            vec![request_with_idempotency(
                request_id,
                Operation::RunStart,
                json!({"text": "steal context", "workspace": selected}),
            )],
        );
        let rejected: ErrorEnvelope = read_frame(&mut client_b);
        assert_eq!(rejected.error.code(), ErrorCode::Unauthorized);
    }
    assert!(runs.lock().unwrap().is_empty());

    let mut client_a_follow_up = run_session(
        "018f0000-0000-7000-8000-00000000000a",
        vec![
            request_with_idempotency(
                232,
                Operation::RunStart,
                json!({"text": "default registration", "workspace": workspace}),
            ),
            request_with_idempotency(
                233,
                Operation::RunStart,
                json!({"text": "override registration", "workspace": override_memory}),
            ),
        ],
    );
    let _: Response = read_frame(&mut client_a_follow_up);
    let _: Response = read_frame(&mut client_a_follow_up);
    assert_eq!(runs.lock().unwrap().len(), 2);
}

#[test]
fn authorized_permission_answers_dispatch_allow_and_deny_once() {
    for (offset, decision) in [(0, "allow"), (1, "deny")] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client.write_all(&request_with_idempotency(
            170 + offset,
            Operation::PermissionAnswer,
            json!({"run_id":"0190a100-0000-7000-8000-000000000001", "gate_id":"gate-private", "decision":decision}),
        )).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        approved.scopes.insert("run.write".into());
        let mut service = PermissionService::default();
        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approved,
                &mut service
            ),
            Ok(())
        );
        let response: Response = read_frame(&mut client);
        assert_eq!(response.body["decision"], decision);
        assert_eq!(response.body["committed_seq"], 9);
        assert_eq!(service.calls.len(), 1);
        assert_eq!(service.calls[0].1.gate_id, "gate-private");
        assert_eq!(service.calls[0].4.profile, "profile-1");
    }
}

#[test]
fn authorized_run_cancel_dispatches_once() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request_with_idempotency(
            168,
            Operation::RunCancel,
            json!({"run_id":"0190a100-0000-7000-8000-000000000001"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = CancelService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Ok(())
    );
    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body["run_id"],
        "0190a100-0000-7000-8000-000000000001"
    );
    assert_eq!(service.calls.len(), 1);
}

#[test]
fn run_cancel_rejects_invalid_requests_without_dispatch() {
    for (has_scope, frame) in [
        (
            false,
            request_with_idempotency(
                160,
                Operation::RunCancel,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001"}),
            ),
        ),
        (
            true,
            request(
                161,
                Operation::RunCancel,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001"}),
            ),
        ),
        (
            true,
            request_with_idempotency(162, Operation::RunCancel, json!({"run_id":"bad"})),
        ),
        (
            true,
            request_with_idempotency(
                163,
                Operation::RunCancel,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001", "extra":true}),
            ),
        ),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client.write_all(&frame).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        if has_scope {
            approved.scopes.insert("run.write".into());
        }
        let mut service = CancelService::default();
        let _ = dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        );
        let _: ErrorEnvelope = read_frame(&mut client);
        assert!(service.calls.is_empty());
    }
}

#[test]
fn permission_answer_rejects_unauthorized_and_invalid_requests_without_dispatch() {
    let cases = [
        (
            false,
            request_with_idempotency(
                180,
                Operation::PermissionAnswer,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"secret-gate","decision":"allow"}),
            ),
        ),
        (
            true,
            request(
                181,
                Operation::PermissionAnswer,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"secret-gate","decision":"allow"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                182,
                Operation::PermissionAnswer,
                json!({"run_id":"bad","gate_id":"secret-gate","decision":"allow"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                183,
                Operation::PermissionAnswer,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"","decision":"allow"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                184,
                Operation::PermissionAnswer,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"x".repeat(MAX_PERMISSION_GATE_ID_LENGTH + 1),"decision":"allow"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                185,
                Operation::PermissionAnswer,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"secret-gate","decision":"later"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                186,
                Operation::PermissionAnswer,
                json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"secret-gate","decision":"deny","actor_id":"forged"}),
            ),
        ),
    ];
    for (has_scope, frame) in cases {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client.write_all(&frame).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        if has_scope {
            approved.scopes.insert("run.write".into());
        }
        let mut service = PermissionService::default();
        let _ = dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("secret-gate"));
        assert!(!encoded.contains("forged"));
        assert!(service.calls.is_empty());
    }
}

#[test]
fn permission_answer_service_failure_is_redacted() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client.write_all(&request_with_idempotency(190, Operation::PermissionAnswer, json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"secret-gate","decision":"deny"}))).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = PermissionService {
        fail: true,
        ..Default::default()
    };
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service
        ),
        Ok(())
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);
    assert!(!serde_json::to_string(&error)
        .unwrap()
        .contains("secret-gate"));
    assert_eq!(service.calls.len(), 1);
}

#[test]
fn unserved_operations_remain_unsupported_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(79, Operation::RunOpen, json!({})))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = StartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Ok(())
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(
        error.request_id,
        Some(Id::new(format!("{:032x}", 79)).unwrap())
    );
    assert_eq!(error.error.code(), ErrorCode::UnsupportedOperation);
    assert!(service.calls.is_empty());
}

#[test]
fn companion_refuses_desktop_only_run_controls() {
    for (id, operation, body) in [
        (
            201,
            Operation::RunSubmit,
            json!({"text":"submit","files":[],"thread_id":null}),
        ),
        (
            202,
            Operation::RunResume,
            json!({"run_id":"0190a100-0000-7000-8000-000000000001"}),
        ),
        (
            203,
            Operation::RunSteer,
            json!({"run_id":"0190a100-0000-7000-8000-000000000001","text":"steer"}),
        ),
        (
            204,
            Operation::RunFollowUp,
            json!({"run_id":"0190a100-0000-7000-8000-000000000001","text":"follow up"}),
        ),
        (
            205,
            Operation::RunPermissionAnswer,
            json!({"run_id":"0190a100-0000-7000-8000-000000000001","gate_id":"gate-1","answer":{"type":"confirm","value":true}}),
        ),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request_with_idempotency(id, operation, body))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut service = StartService::default();

        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approval(),
                &mut service,
            ),
            Err(AttachSessionError::Authorization)
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
        assert!(service.calls.is_empty());
    }
}

#[test]
fn companion_refuses_desktop_only_thread_mutations() {
    for (id, operation, body) in [
        (
            191,
            Operation::ThreadRename,
            json!({"thread_id":"0190a100-0000-7000-8000-000000000001","title":"Renamed thread"}),
        ),
        (
            192,
            Operation::ThreadDelete,
            json!({"thread_id":"0190a100-0000-7000-8000-000000000001"}),
        ),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request_with_idempotency(id, operation, body))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        approved.scopes.insert("run.write".into());
        let mut service = StartService::default();

        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approved,
                &mut service,
            ),
            Err(AttachSessionError::Authorization)
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
        assert!(service.calls.is_empty());
    }
}

#[test]
fn companion_refuses_desktop_only_session_operations() {
    for (id, operation, body) in [
        (193, Operation::SessionStatus, json!({})),
        (194, Operation::EntitlementSnapshot, json!({})),
        (195, Operation::DeviceList, json!({})),
        (196, Operation::SessionSignIn, json!({})),
        (197, Operation::SessionSignOut, json!({})),
        (198, Operation::CompanionList, json!({})),
        (
            199,
            Operation::CompanionRevoke,
            json!({"client_identity": "companion-1"}),
        ),
        (200, Operation::ThreadSummaries, json!({"limit": 10})),
        (
            203,
            Operation::ThreadSelect,
            json!({"thread_id": "thread-1"}),
        ),
        (
            201,
            Operation::ThreadHistory,
            json!({"thread_id": "thread-1", "limit": 10}),
        ),
        (202, Operation::RunChatEvents, json!({})),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        let frame = if matches!(
            operation,
            Operation::SessionSignIn | Operation::SessionSignOut | Operation::CompanionRevoke
        ) {
            request_with_idempotency(id, operation, body)
        } else {
            request(id, operation, body)
        };
        client.write_all(&frame).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut service = StartService::default();

        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approval(),
                &mut service,
            ),
            Err(AttachSessionError::Authorization)
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
        assert!(service.calls.is_empty());
    }
}

#[test]
fn migration_control_uses_the_service_and_echoes_the_nonce() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            81,
            Operation::MigrationControl,
            json!({"deadline_ms": 30_000, "handoff_nonce": "fixture-handoff-nonce"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = MigrationControlService::default();

    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service,
        ),
        Ok(())
    );

    let response: Response = read_frame(&mut client);
    assert_eq!(
        response.body,
        json!({"handoff_nonce": "fixture-handoff-nonce"})
    );
    assert_eq!(service.calls.len(), 1);
    let (request, provenance) = &service.calls[0];
    assert_eq!(
        request,
        &MigrationControlRequest {
            handoff_nonce: "fixture-handoff-nonce".into(),
            deadline_ms: 30_000,
        }
    );
    assert_eq!(provenance.peer_pid, std::process::id());
    assert_eq!(provenance.peer_uid, unsafe { libc::geteuid() });
}

#[test]
fn verified_runtime_enters_a_migration_only_session_without_approval_or_credential() {
    let executable =
        std::env::temp_dir().join(format!("muniment-runtime-session-{}", uuid::Uuid::new_v4()));
    std::fs::write(&executable, b"runtime").unwrap();
    let reader = MigrationProcessReader {
        executable: Ok(executable.clone()),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .write_all(&hello_with_claims(
            1,
            1,
            "018f0000-0000-7000-8000-000000000099",
            Some(&"ab".repeat(32)),
            "hostile-claim",
            "9.9.9",
        ))
        .unwrap();
    let approvals = Arc::new(AtomicUsize::new(0));
    let approval_calls = Arc::clone(&approvals);
    let worker = thread::spawn(move || {
        let mut service = MigrationControlService::default();
        let result = run_authenticated_session_with_authorization_registry_and_migration(
            server,
            credentials(),
            "0.1.0",
            Duration::from_secs(1),
            AuthorizationSessionDependencies {
                fill_random: |bytes: &mut [u8]| {
                    bytes.fill(9);
                    Ok(())
                },
                clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
                tokens: TestTokens(1),
                approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                    approval_calls.fetch_add(1, Ordering::SeqCst);
                    Some(ApprovalDecision::Approve(approval()))
                },
            },
            &mut service,
            muniment_core::attach::linux::SessionRegistryDependencies {
                registry: &LiveConnectionRegistry::default(),
                migration: Some(MigrationControlSessionDependencies {
                    expected_executable: &executable,
                    process_reader: &reader,
                }),
                handoff_nonce: None,
            },
        );
        std::fs::remove_file(executable).unwrap();
        (result, service)
    });

    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(
        welcome.authorization,
        muniment_core::attach::Authorization::Authorized
    );
    let authorized: serde_json::Value = read_frame(&mut client);
    assert_eq!(authorized["workspace_scopes"], json!({}));
    assert!(authorized.get("authorized_client_credential").is_none());
    let capability = authorized["capability"].as_str().unwrap();
    let forbidden_operations = [
        Operation::WorkspaceOnboard,
        Operation::HomeEnsure,
        Operation::ThreadList,
        Operation::ThreadOpen,
        Operation::ThreadCreate,
        Operation::RunOpen,
        Operation::RunStart,
        Operation::RunStream,
        Operation::RunCursorAck,
        Operation::RunSteer,
        Operation::RunFollowUp,
        Operation::RunCancel,
        Operation::PermissionAnswer,
        Operation::ArtifactFetch,
        Operation::ArtifactWindow,
        Operation::RequestCancel,
    ];
    for (index, operation) in forbidden_operations.into_iter().enumerate() {
        client
            .write_all(
                &encode_frame(&json!({
                    "protocol": "muniment.attach/1",
                    "request_id": format!("{:032x}", 811 + index),
                    "operation": operation.as_str(),
                    "capability": capability,
                    "body": {}
                }))
                .unwrap(),
            )
            .unwrap();
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    }
    client
        .write_all(
            &encode_frame(&json!({
                "protocol": "muniment.attach/1",
                "request_id": format!("{:032x}", 900),
                "operation": "migration.control",
                "capability": capability,
                "body": {"deadline_ms": 30_000, "handoff_nonce": "session-nonce"}
            }))
            .unwrap(),
        )
        .unwrap();
    let response: Response = read_frame(&mut client);
    assert_eq!(response.body, json!({"handoff_nonce": "session-nonce"}));
    client.shutdown(Shutdown::Both).unwrap();
    let (result, service) = worker.join().unwrap();
    assert_eq!(result, Err(AttachSessionError::Closed));
    assert_eq!(approvals.load(Ordering::SeqCst), 0);
    assert_eq!(service.calls.len(), 1);
}

#[test]
fn unresolved_runtime_peer_uses_the_ordinary_approval_path() {
    let expected =
        std::env::temp_dir().join(format!("muniment-runtime-missing-{}", uuid::Uuid::new_v4()));
    let reader = MigrationProcessReader {
        executable: Err(ProcReadError),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let approvals = Rc::new(Cell::new(0));
    let approval_calls = Rc::clone(&approvals);
    let mut service = MigrationControlService::default();
    let result = run_authenticated_session_with_authorization_registry_and_migration(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(100),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                approval_calls.set(approval_calls.get() + 1);
                if approval_calls.get() == 1 {
                    Some(ApprovalDecision::Approve(approval()))
                } else {
                    None
                }
            },
        },
        &mut service,
        muniment_core::attach::linux::SessionRegistryDependencies {
            registry: &LiveConnectionRegistry::default(),
            migration: Some(MigrationControlSessionDependencies {
                expected_executable: &expected,
                process_reader: &reader,
            }),
            handoff_nonce: None,
        },
    );
    assert_eq!(result, Ok(()));
    let welcome: Welcome = read_frame(&mut client);
    assert_eq!(
        welcome.authorization,
        muniment_core::attach::Authorization::PairingRequired
    );
    let authorized: Authorized = read_frame(&mut client);
    assert_eq!(authorized.workspace_scopes.len(), 1);
    assert_eq!(authorized.authorized_client_credential, "09".repeat(32));
    assert_eq!(approvals.get(), 2);
    assert!(service.calls.is_empty());
}

#[test]
fn migration_control_defaults_to_unsupported_operation() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request(
            82,
            Operation::MigrationControl,
            json!({"deadline_ms": 30_000, "handoff_nonce": "handoff-nonce"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = unavailable_service;

    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service,
        ),
        Ok(())
    );

    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::UnsupportedOperation);
}

#[test]
fn migration_control_rejects_invalid_bodies_without_dispatch() {
    let cases = [
        json!({"deadline_ms": 30_000, "handoff_nonce": ""}),
        json!({"deadline_ms": 30_000, "handoff_nonce": "x".repeat(129)}),
        json!({"deadline_ms": 30_000, "handoff_nonce": "line\nbreak"}),
        json!({"deadline_ms": 30_000, "handoff_nonce": "non-ascii-é"}),
        json!({"deadline_ms": 0, "handoff_nonce": "handoff-nonce"}),
        json!({"deadline_ms": 60_001, "handoff_nonce": "handoff-nonce"}),
        json!({"deadline_ms": 30_000, "handoff_nonce": "handoff-nonce", "extra": true}),
    ];

    for (index, body) in cases.into_iter().enumerate() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request(
                90 + index as u128,
                Operation::MigrationControl,
                body,
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut service = MigrationControlService::default();

        assert_eq!(
            dispatch_session(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                &mut service,
            ),
            Ok(())
        );

        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
        assert!(service.calls.is_empty());
    }
}

#[test]
fn migration_control_forbids_an_idempotency_key_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request_with_idempotency(
            100,
            Operation::MigrationControl,
            json!({"deadline_ms": 30_000, "handoff_nonce": "handoff-nonce"}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = MigrationControlService::default();

    assert_eq!(
        dispatch_session(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            &mut service,
        ),
        Ok(())
    );

    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::IdempotencyKeyForbidden);
    assert!(service.calls.is_empty());
}

#[test]
fn run_start_rejects_missing_scope_key_and_hostile_bodies_without_dispatch() {
    let cases = [
        (
            false,
            request_with_idempotency(71, Operation::RunStart, json!({"text": "secret prompt"})),
        ),
        (
            true,
            request(72, Operation::RunStart, json!({"text": "secret prompt"})),
        ),
        (
            true,
            request_with_idempotency(73, Operation::RunStart, json!({"text": ""})),
        ),
        (
            true,
            request_with_idempotency(
                74,
                Operation::RunStart,
                json!({"text": "x", "actor_id": "forged"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                75,
                Operation::RunStart,
                json!({"text": "x".repeat(MAX_RUN_START_TEXT_LENGTH + 1)}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                76,
                Operation::RunStart,
                json!({"text": "x", "context": vec!["x".repeat(40_000); MAX_RUN_START_CONTEXT_LENGTH / 40_000 + 1]}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                77,
                Operation::RunStart,
                json!({"text": "x", "thread_id": "not-a-uuid"}),
            ),
        ),
        (
            true,
            request_with_idempotency(
                78,
                Operation::RunStart,
                json!({"text": "x", "thread_id": "0190a100-0000-7000-8000-000000000099x"}),
            ),
        ),
    ];
    for (has_scope, frame) in cases {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client.write_all(&frame).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        if has_scope {
            approved.scopes.insert("run.write".into());
        }
        let mut service = StartService::default();
        let _ = dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert!(matches!(
            error.error.code(),
            ErrorCode::Unauthorized | ErrorCode::IdempotencyKeyRequired | ErrorCode::InvalidRequest
        ));
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("secret prompt"));
        assert!(!encoded.contains("forged"));
        assert!(service.calls.is_empty());
    }
}

#[test]
fn thread_create_without_run_write_scope_fails_closed() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(&request_with_idempotency(
            81,
            Operation::ThreadCreate,
            json!({}),
        ))
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut service = StartService::default();

    let _ = dispatch_session(
        &mut client,
        server,
        TestClock(Rc::new(Cell::new(Duration::ZERO))),
        &mut service,
    );

    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    assert!(service.calls.is_empty());
}

#[test]
fn malformed_run_start_service_output_is_a_redacted_closed_error() {
    let valid_run_id = "0190a100-0000-7000-8000-000000000001";
    let valid_thread_id = "0190a100-0000-7000-8000-000000000002";
    let cases = [
        RunStartAccepted {
            run_id: "not-a-run-id".into(),
            thread_id: valid_thread_id.into(),
            committed_seq: 2,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            thread_id: valid_thread_id.into(),
            committed_seq: 0,
            accepted_at: "2026-07-17T00:00:00Z".into(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            thread_id: valid_thread_id.into(),
            committed_seq: 2,
            accepted_at: String::new(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            thread_id: valid_thread_id.into(),
            committed_seq: 2,
            accepted_at: "private malformed timestamp".into(),
        },
        RunStartAccepted {
            run_id: valid_run_id.into(),
            thread_id: valid_thread_id.into(),
            committed_seq: 2,
            accepted_at: "private oversized timestamp".repeat(MAX_FRAME_LENGTH),
        },
    ];
    let mut expected_error = None;
    for (offset, output) in cases.into_iter().enumerate() {
        let id = 81 + offset as u128;
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&hello(1, 1)).unwrap();
        client
            .write_all(&request_with_idempotency(
                id,
                Operation::RunStart,
                json!({"text": "private prompt"}),
            ))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut approved = approval();
        approved.scopes.insert("run.write".into());
        let mut service = StartService {
            output: Some(output),
            ..Default::default()
        };
        assert_eq!(
            dispatch_session_with_approval(
                &mut client,
                server,
                TestClock(Rc::new(Cell::new(Duration::ZERO))),
                approved,
                &mut service,
            ),
            Ok(())
        );
        let error: ErrorEnvelope = read_frame(&mut client);
        assert_eq!(
            error.request_id,
            Some(Id::new(format!("{id:032x}")).unwrap())
        );
        assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);
        let encoded = serde_json::to_string(&error).unwrap();
        assert!(!encoded.contains("private prompt"));
        assert!(!encoded.contains("private malformed timestamp"));
        assert!(!encoded.contains("private oversized timestamp"));
        assert!(!encoded.contains("profile-1"));
        assert!(!encoded.contains("1.0.0"));
        let error_value = serde_json::to_value(error.error).unwrap();
        assert_eq!(error_value.get("details"), None);
        if let Some(expected) = &expected_error {
            assert_eq!(&error_value, expected);
        } else {
            expected_error = Some(error_value);
        }
        assert_eq!(service.calls.len(), 1);
    }
}

#[test]
fn invalid_run_start_idempotency_key_is_terminal_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    client
        .write_all(
            &encode_frame(&json!({
                "protocol": "muniment.attach/1",
                "request_id": format!("{:032x}", 78),
                "operation": "run.start",
                "capability": "02".repeat(32),
                "idempotency_key": "invalid secret key",
                "body": {"text": "private prompt"}
            }))
            .unwrap(),
        )
        .unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut approved = approval();
    approved.scopes.insert("run.write".into());
    let mut service = StartService::default();
    assert_eq!(
        dispatch_session_with_approval(
            &mut client,
            server,
            TestClock(Rc::new(Cell::new(Duration::ZERO))),
            approved,
            &mut service,
        ),
        Err(AttachSessionError::MalformedFrame)
    );
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::MalformedFrame);
    let encoded = serde_json::to_string(&error).unwrap();
    assert!(!encoded.contains("private prompt"));
    assert!(!encoded.contains("invalid secret key"));
    assert!(service.calls.is_empty());
}

#[test]
fn idle_expiry_is_typed_as_unauthorized_not_malformed() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let now = Rc::new(Cell::new(Duration::ZERO));
    let advance = now.clone();
    let calls = Rc::new(Cell::new(0));
    let approval_calls = calls.clone();
    let mut service = unavailable_service;
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(20),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(now),
            tokens: TestTokens(1),
            approvals: move |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                if approval_calls.replace(approval_calls.get() + 1) == 0 {
                    Some(ApprovalDecision::Approve(approval()))
                } else {
                    advance.set(Duration::from_secs(901));
                    None
                }
            },
        },
        &mut service,
    );
    assert_eq!(result, Err(AttachSessionError::Authorization));
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    let error: ErrorEnvelope = read_frame(&mut client);
    assert_eq!(error.request_id, None);
    assert_eq!(error.error.code(), ErrorCode::Unauthorized);
}

#[test]
fn fragmented_request_frame_deadline_is_not_reported_as_malformed() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello(1, 1)).unwrap();
    let frame = request(40, Operation::ThreadList, json!({"limit": 1}));
    client.write_all(&frame[..5]).unwrap();
    let mut service = unavailable_service;
    let result = run_authenticated_session_with_authorization(
        server,
        credentials(),
        "0.1.0",
        Duration::from_millis(20),
        AuthorizationSessionDependencies {
            fill_random: |bytes: &mut [u8]| {
                bytes.fill(9);
                Ok(())
            },
            clock: TestClock(Rc::new(Cell::new(Duration::ZERO))),
            tokens: TestTokens(1),
            approvals: |_: &muniment_core::attach::PairingChallenge, _: Duration| {
                Some(ApprovalDecision::Approve(approval()))
            },
        },
        &mut service,
    );
    assert_eq!(result, Err(AttachSessionError::Timeout));
    let _: Welcome = read_frame(&mut client);
    let _: Authorized = read_frame(&mut client);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}
