#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use muniment_core::attach::linux::{
    serve_desktop_client_session, CompanionProvenance, RunStartAccepted, RunStartRequest,
    RunStreamPage, ThreadListPage, ThreadListRequest, ThreadListService,
};
use muniment_core::attach::{
    decode_frame, encode_frame, DesktopClientSession, Envelope, ErrorCode, EventName, Id,
    Operation, Protocol, ProtocolError, Request, WorkspaceOnboardRequest, WorkspaceOnboarded,
};
use muniment_core::journal::{CommitSubscription, JournalCommitHint, RunEventProjection};

struct TestService;

fn session() -> DesktopClientSession {
    DesktopClientSession {
        capability: "admitted".into(),
        workspace: "/work/signed".into(),
        client_identity: "018f0000-0000-7000-8000-000000000200".into(),
        provenance: CompanionProvenance {
            profile: "profile-1".into(),
            companion_kind: "desktop-client".into(),
            companion_version: "1.2.3".into(),
            peer_uid: 1000,
            peer_pid: 4242,
        },
    }
}

impl ThreadListService for TestService {
    fn list_threads(
        &mut self,
        workspace: &str,
        _request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        assert_eq!(workspace, "/work/signed");
        Ok(ThreadListPage {
            threads: Vec::new(),
            next_cursor: None,
        })
    }
}

fn request(id: &str, operation: Operation, capability: &str, body: serde_json::Value) -> Request {
    Request {
        protocol: Protocol,
        request_id: Id::new(id).unwrap(),
        operation,
        capability: capability.into(),
        idempotency_key: None,
        body,
    }
}

fn exchange(stream: &mut UnixStream, request: Request) -> Envelope {
    stream.write_all(&encode_frame(&request).unwrap()).unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    decode_frame(&frame).unwrap().unwrap().0
}

fn idempotent_request(id: &str, operation: Operation, body: serde_json::Value) -> Request {
    let mut request = request(id, operation, "admitted", body);
    request.idempotency_key = Some(Id::new("018f0000-0000-7000-8000-000000000299").unwrap());
    request
}

#[test]
fn unauthorized_requests_do_not_end_the_session() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut TestService)
    });

    for (id, operation, capability) in [
        (
            "018f0000-0000-7000-8000-000000000201",
            Operation::MigrationControl,
            "admitted",
        ),
        (
            "018f0000-0000-7000-8000-000000000202",
            Operation::ApprovalPresent,
            "admitted",
        ),
        (
            "018f0000-0000-7000-8000-000000000203",
            Operation::ThreadList,
            "other",
        ),
    ] {
        let Envelope::Error(error) = exchange(
            &mut client,
            request(id, operation, capability, serde_json::json!({})),
        ) else {
            panic!("unauthorized request did not return an error");
        };
        assert_eq!(error.error.code(), ErrorCode::Unauthorized);
    }

    let response = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000204",
            Operation::ThreadList,
            "admitted",
            serde_json::json!({"limit": 20}),
        ),
    );
    assert!(matches!(response, Envelope::Response(_)));
    drop(client);
    assert_eq!(session.join().unwrap(), Ok(()));
}

#[derive(Clone, Default)]
struct MutationService {
    client_identity: Option<String>,
    calls: Arc<Mutex<Vec<MutationCall>>>,
}

type MutationCall = (String, String, Id, CompanionProvenance);

impl ThreadListService for MutationService {
    fn bind_authorized_client(&mut self, client_identity: &str) {
        self.client_identity = Some(client_identity.to_owned());
    }

    fn onboard_workspace(
        &mut self,
        _: &str,
        request: WorkspaceOnboardRequest,
    ) -> Result<WorkspaceOnboarded, ProtocolError> {
        assert_eq!(
            self.client_identity.as_deref(),
            Some("018f0000-0000-7000-8000-000000000200")
        );
        Ok(WorkspaceOnboarded {
            opened_directory: request.opened_directory,
            memory_location: request.memory_location,
            instructions: None,
        })
    }

    fn authorized_workspace(&self, _: &str, workspace: &str) -> Option<String> {
        self.client_identity.as_ref().map(|_| workspace.to_owned())
    }

    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn start_run(
        &mut self,
        workspace: &str,
        execution_root: &str,
        _: RunStartRequest,
        _: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<RunStartAccepted, ProtocolError> {
        self.calls.lock().unwrap().push((
            workspace.to_owned(),
            execution_root.to_owned(),
            idempotency_key.clone(),
            provenance,
        ));
        Ok(RunStartAccepted {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            thread_id: "0190a100-0000-7000-8000-000000000002".into(),
            committed_seq: 1,
            accepted_at: "2026-08-14T00:00:00Z".into(),
        })
    }
}

#[test]
fn session_binds_identity_and_passes_admission_provenance() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let service = MutationService::default();
    let calls = service.calls.clone();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut service.clone())
    });

    assert!(matches!(
        exchange(
            &mut client,
            request(
                "018f0000-0000-7000-8000-000000000210",
                Operation::WorkspaceOnboard,
                "admitted",
                serde_json::json!({"opened_directory":"/work/root","memory_location":"/work/memory"}),
            ),
        ),
        Envelope::Response(_)
    ));
    assert!(matches!(
        exchange(
            &mut client,
            idempotent_request(
                "018f0000-0000-7000-8000-000000000211",
                Operation::RunStart,
                serde_json::json!({"text":"test","workspace":"/work/root"}),
            ),
        ),
        Envelope::Response(_)
    ));

    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "/work/signed");
    assert_eq!(calls[0].1, "/work/root");
    assert_eq!(calls[0].2.as_str(), "018f0000-0000-7000-8000-000000000299");
    assert_eq!(calls[0].3, session().provenance);
    drop(calls);
    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

struct LiveService {
    sender: Arc<Mutex<Option<mpsc::SyncSender<JournalCommitHint>>>>,
    live: Arc<Mutex<bool>>,
}

impl ThreadListService for LiveService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn subscribe_run_commits(
        &mut self,
        _: &str,
    ) -> Result<Option<CommitSubscription>, ProtocolError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        *self.sender.lock().unwrap() = Some(sender);
        Ok(Some(CommitSubscription::detached(0, receiver)))
    }

    fn stream_run(
        &mut self,
        _: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<RunStreamPage, ProtocolError> {
        let live = *self.live.lock().unwrap();
        Ok(RunStreamPage {
            run_id: run_id.into(),
            first_available_run_seq: 1,
            current_run_seq: u64::from(live),
            events: if live && after_run_seq == 0 {
                vec![RunEventProjection {
                    run_id: run_id.into(),
                    run_seq: 1,
                    event_type: "model.stream.delta".into(),
                    event_version: 1,
                    recorded_at: "2026-08-14T00:00:00Z".into(),
                    text: Some("later".into()),
                    effect_id: None,
                    display_name: None,
                    tool_effect_valid: false,
                    pending_permission: None,
                    receipt: None,
                }]
            } else {
                Vec::new()
            },
            exhausted: true,
        })
    }
}

#[test]
fn subscription_delivers_a_later_commit_without_another_request() {
    let run_id = "0190a100-0000-7000-8000-000000000010";
    let sender = Arc::new(Mutex::new(None));
    let live = Arc::new(Mutex::new(false));
    let service = LiveService {
        sender: sender.clone(),
        live: live.clone(),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut { service })
    });
    let response = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000220",
            Operation::RunStream,
            "admitted",
            serde_json::json!({"run_id":run_id,"after_run_seq":0}),
        ),
    );
    assert!(matches!(response, Envelope::Response(_)));
    let Envelope::Event(caught_up) = read_envelope(&mut client) else {
        panic!("expected a caught-up event")
    };
    assert_eq!(caught_up.event, EventName::SubscriptionCaughtUp);

    *live.lock().unwrap() = true;
    sender
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .send(JournalCommitHint {
            run_id: run_id.into(),
            run_seq: 1,
        })
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let Envelope::Event(event) = read_envelope(&mut client) else {
        panic!("expected a live event")
    };
    assert_eq!(event.event, EventName::RunEvent);
    assert_eq!(event.run_seq, Some(1));
    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

fn read_envelope(stream: &mut UnixStream) -> Envelope {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    decode_frame(&frame).unwrap().unwrap().0
}
