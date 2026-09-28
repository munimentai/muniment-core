use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread::JoinHandle;

use muniment_attach::{
    handshake_desktop_client, reconnect_welcome, ClientError, DesktopClient, Id,
};
use serde_json::{json, Value};

use super::super::desktop_service_message::{
    CompanionProvenance, RunCancelAccepted, RunCancelRequest,
};
use super::super::thread_service::{
    ThreadListPage, ThreadListRequest, ThreadListService, ThreadOpenRequest,
};
use super::*;
use crate::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};

const RUN: &str = "018f0000-0000-7000-8000-000000000201";

struct Profile {
    root: PathBuf,
    journal: RunJournal,
    thread: String,
    seq: u64,
}

impl Profile {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("muniment-snapshot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let mut journal = RunJournal::open(&root.join("runs.sqlite3")).unwrap();
        let thread = journal
            .append_new_run("local", &event(1, "run.started", json!({})))
            .unwrap();
        let mut profile = Self {
            root,
            journal,
            thread,
            seq: 1,
        };
        profile.append("model.prompt.accepted", json!({}));
        for index in 0..300 {
            profile.append(
                "tool.effect.started",
                json!({"effect_id": format!("tool-{index}"),
                "display_name": "read", "input": "synthetic input"}),
            );
            profile.append(
                "tool.effect.completed",
                json!({"effect_id": format!("tool-{index}"),
                "output": "synthetic output"}),
            );
        }
        profile
    }

    fn append(&mut self, kind: &str, payload: Value) {
        self.journal
            .append_batch(self.seq, &[event(self.seq + 1, kind, payload)])
            .unwrap();
        self.seq += 1;
    }

    fn history(&mut self) -> Value {
        serde_json::to_value(
            crate::thread_history::chat_thread_open_page_without_prompts(
                &mut self.journal,
                None,
                None,
                &self.root,
                &self.thread,
                100,
                None,
            )
            .unwrap(),
        )
        .unwrap()
    }
}

fn event(seq: u64, kind: &str, payload: Value) -> EventEnvelope {
    EventEnvelope {
        event_id: uuid::Uuid::now_v7().to_string(),
        run_id: RUN.into(),
        run_seq: seq,
        event_type: kind.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-01-01T00:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: payload,
        },
        provenance: Provenance {
            source: "synthetic-test".into(),
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

struct Service {
    history: Value,
    chat: Option<std::sync::mpsc::Receiver<crate::run_events::ChatEvent>>,
    stops: usize,
}
impl ThreadListService for Service {
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
    fn thread_history(&mut self, _: ThreadOpenRequest) -> Result<Value, ProtocolError> {
        Ok(self.history.clone())
    }
    fn subscribe_chat_events(
        &mut self,
    ) -> Result<crate::run_events::ChatEventSubscription, ProtocolError> {
        self.chat
            .take()
            .map(crate::run_events::ChatEventSubscription::detached)
            .ok_or_else(ProtocolError::invalid_request)
    }
    fn cancel_run(
        &mut self,
        _: &str,
        request: RunCancelRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunCancelAccepted, ProtocolError> {
        assert_eq!(request.run_id, RUN);
        self.stops += 1;
        Ok(RunCancelAccepted {
            run_id: RUN.into(),
            accepted_at: "2026-01-01T00:00:00Z".into(),
        })
    }
}

type SessionWorker = JoinHandle<(Result<(), AttachSessionError>, Vec<String>, usize)>;

fn connect(history: Value) -> (DesktopClient, SessionWorker) {
    connect_with_events(history, None)
}

fn connect_with_events(
    history: Value,
    chat: Option<std::sync::mpsc::Receiver<crate::run_events::ChatEvent>>,
) -> (DesktopClient, SessionWorker) {
    let (client, mut server) = UnixStream::pair().unwrap();
    let worker = std::thread::spawn(move || {
        let mut prefix = [0; 4];
        server.read_exact(&mut prefix).unwrap();
        let mut hello = vec![0; u32::from_be_bytes(prefix) as usize];
        server.read_exact(&mut hello).unwrap();
        server
            .write_all(&encode_frame(&reconnect_welcome(1, "0.0.1", "11".repeat(16), "")).unwrap())
            .unwrap();
        server
            .write_all(
                &encode_frame(
                    &json!({"profile_id": "synthetic", "capability": "33".repeat(32),
            "expires_at": 60, "idle_timeout_seconds": 30, "workspace_scopes": {}}),
                )
                .unwrap(),
            )
            .unwrap();
        let mut lines = Vec::new();
        let mut service = Service {
            history,
            chat,
            stops: 0,
        };
        let result = serve_desktop_client_requests_with_diagnostics(
            &mut server,
            &"33".repeat(32),
            "local",
            CompanionProvenance {
                profile: "synthetic".into(),
                companion_kind: "desktop-client".into(),
                companion_version: "0.0.1".into(),
                peer_uid: 1,
                peer_pid: 1,
            },
            &mut service,
            |line| lines.push(line),
        );
        (result, lines, service.stops)
    });
    let client = handshake_desktop_client(Box::new(client), "0.0.1", REQUEST_TIMEOUT).unwrap();
    (client, worker)
}

#[test]
fn isolated_tool_history_keeps_stop_usable_and_restores_completion_after_reconnect() {
    let mut profile = Profile::new();
    let history = profile.history();
    let bytes = serde_json::to_vec(&history).unwrap().len();
    assert!(bytes < MAX_FRAME_LENGTH);
    assert!(matches!(
        encode_frame(&history),
        Err(FrameError::StructureLimit)
    ));
    eprintln!("Synthetic history reproduction: tools=300 bytes={bytes} error=StructureLimit");
    let (mut client, worker) = connect(history.clone());
    assert_eq!(
        client.thread_history(&profile.thread, 100, None).unwrap(),
        history
    );
    assert_eq!(client.run_cancel(RUN).unwrap().run_id, RUN);
    assert!(client
        .request(Operation::ThreadList, None, json!({"limit": 1}))
        .is_ok());
    drop(client);
    let (result, lines, stops) = worker.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(stops, 1);
    assert!(lines.iter().any(
        |line| line.contains("direction=outbound kind=thread.history")
            && line.contains("error=StructureLimit")
    ));
    assert!(lines.iter().all(|line| line.len() < 300
        && !line.contains("synthetic input")
        && !line.contains("synthetic output")));

    // The runtime commits completion while no desktop session exists.
    profile.append("run.completed", json!({}));
    let complete = profile.history();
    assert_eq!(complete["entries"][0]["phase"], "complete");
    let (mut client, worker) = connect(complete.clone());
    assert_eq!(
        client.thread_history(&profile.thread, 100, None).unwrap(),
        complete
    );
    assert_eq!(
        complete["entries"][0]["toolActivity"]
            .as_array()
            .unwrap()
            .len(),
        300
    );
    assert!(client
        .request(Operation::ThreadList, None, json!({"limit": 1}))
        .is_ok());
    drop(client);
    assert_eq!(worker.join().unwrap().0, Ok(()));
    let root = profile.root.clone();
    drop(profile);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_unencodable_response_rejects_only_the_request() {
    let (mut client, worker) = connect(json!({"entries": [{"text": "x".repeat(70_000)}]}));
    // A client without chunk support still receives a correlated error.
    assert_eq!(
        client
            .request(
                Operation::ThreadHistory,
                None,
                json!({"thread_id": RUN, "limit": 1})
            )
            .unwrap_err(),
        ClientError::RequestRejected
    );
    assert_eq!(
        client.last_request_error().unwrap().code(),
        muniment_attach::ErrorCode::PayloadTooLarge
    );
    assert_eq!(client.run_cancel(RUN).unwrap().run_id, RUN);
    assert!(client
        .request(Operation::ThreadList, None, json!({"limit": 1}))
        .is_ok());
    drop(client);
    let (result, lines, stops) = worker.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(stops, 1);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("error=StructureLimit"));
}

#[test]
fn snapshot_opt_in_rejects_non_boolean_values_without_consuming_the_subscription() {
    let (sender, receiver) = std::sync::mpsc::channel();
    let (mut client, worker) = connect_with_events(json!({}), Some(receiver));
    for flag in [json!(null), json!(0), json!("true"), json!([])] {
        for operation in [Operation::ThreadHistory, Operation::RunChatEvents] {
            let body = if operation == Operation::ThreadHistory {
                json!({"thread_id": RUN, "limit": 1, "snapshot_chunks": flag})
            } else {
                json!({"snapshot_chunks": flag})
            };
            assert!(client.request(operation, None, body).is_err());
            assert_eq!(
                client.last_request_error().unwrap().code(),
                muniment_attach::ErrorCode::InvalidRequest
            );
        }
    }
    client.subscribe_chat_events().unwrap();
    drop(sender);
    assert_eq!(worker.join().unwrap().0, Ok(()));
}

#[test]
fn chat_snapshot_frames_keep_every_tool_and_the_terminal_phase() {
    let mut profile = Profile::new();
    profile.append("run.completed", json!({}));
    let projection =
        crate::journal::reducer::project_chat(&profile.journal.events(RUN).unwrap()).unwrap();
    let event = crate::run_events::ChatEvent {
        run_id: RUN.into(),
        thread_id: Some(profile.thread.clone()),
        phase: "complete".into(),
        text: "Synthetic reply".into(),
        prompt_accepted: true,
        turn_started: true,
        routing_stage: None,
        prompt_storage_notice: None,
        failure_reason: None,
        receipt: None,
        tool_activity: crate::chat_view::chat_tool_activity(&projection.tool_activity),
        attachments: vec![],
        recalls: vec![],
        applied_diffs: vec![],
        pending_permission: None,
        delta: None,
    };
    let expected = serde_json::to_value(&event).unwrap();
    assert!(matches!(
        encode_frame(&expected),
        Err(FrameError::StructureLimit)
    ));
    let (sender, receiver) = std::sync::mpsc::channel();
    let (mut client, worker) = connect_with_events(json!({}), Some(receiver));
    client.subscribe_chat_events().unwrap();
    sender.send(event).unwrap();
    assert_eq!(client.read_chat_event().unwrap(), expected);
    drop(sender);
    let (result, lines, _) = worker.join().unwrap();
    assert_eq!(result, Ok(()));
    assert!(lines[0].contains("direction=outbound kind=chat.event"));
    assert!(lines[0].contains(&format!("run_id={RUN}")));
    let root = profile.root.clone();
    drop(profile);
    std::fs::remove_dir_all(root).unwrap();
}
