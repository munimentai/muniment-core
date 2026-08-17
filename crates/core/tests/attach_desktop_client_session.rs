#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use muniment_core::attach::linux::{
    serve_desktop_client_session, AttachSessionError, CompanionProvenance,
    EntitlementSnapshotResult, RunMessageAccepted, RunMessageRequest, RunPermissionAnswerAccepted,
    RunPermissionAnswerRequest, RunResumeAccepted, RunResumeRequest, RunStartAccepted,
    RunStartRequest, RunStreamPage, RunSubmitAccepted, RunSubmitRequest, ThreadListPage,
    ThreadListRequest, ThreadListService,
};
use muniment_core::attach::{
    decode_frame, encode_frame, CompanionRecord, DesktopClientSession, Envelope, ErrorCode,
    EventName, Id, Operation, Protocol, ProtocolError, Request, WorkspaceOnboardRequest,
    WorkspaceOnboarded,
};
use muniment_core::auth::{
    AuthStatus, EntitlementSnapshotView, NativeDeviceList, NativeEntitlementGroup,
    NativeSessionRole,
};
use muniment_core::journal::MAX_THREAD_TITLE_CHARS;
use muniment_core::journal::{CommitSubscription, JournalCommitHint, RunEventProjection};
use muniment_core::run_events::ChatEvent;

struct TestService;

struct InvalidRunSubmitService {
    accepted: Option<RunSubmitAccepted>,
}

impl ThreadListService for InvalidRunSubmitService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn submit_run(
        &mut self,
        _: &str,
        _: RunSubmitRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunSubmitAccepted, ProtocolError> {
        Ok(self.accepted.take().unwrap())
    }
}

#[derive(Default)]
struct RunControlService {
    calls: Vec<Operation>,
}

impl ThreadListService for RunControlService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn steer_run(
        &mut self,
        _: &str,
        request: RunMessageRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        self.calls.push(Operation::RunSteer);
        Ok(RunMessageAccepted {
            run_id: request.run_id,
            accepted_at: "2026-08-16T00:00:00Z".into(),
        })
    }

    fn submit_run(
        &mut self,
        _: &str,
        _: RunSubmitRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunSubmitAccepted, ProtocolError> {
        self.calls.push(Operation::RunSubmit);
        Ok(RunSubmitAccepted {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            thread_id: "0190a100-0000-7000-8000-000000000002".into(),
            attachments: vec![muniment_core::chat_view::ChatAttachment {
                display_name: "main.rs".into(),
                byte_length: 128,
                media_type: Some("text/rust".into()),
            }],
            committed_seq: 1,
            accepted_at: "2026-08-16T00:00:00Z".into(),
        })
    }

    fn resume_run(
        &mut self,
        _: &str,
        request: RunResumeRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunResumeAccepted, ProtocolError> {
        self.calls.push(Operation::RunResume);
        Ok(RunResumeAccepted {
            run_id: request.run_id,
            thread_id: "0190a100-0000-7000-8000-000000000002".into(),
            committed_seq: 2,
            accepted_at: "2026-08-16T00:00:00Z".into(),
        })
    }

    fn follow_up_run(
        &mut self,
        _: &str,
        request: RunMessageRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        self.calls.push(Operation::RunFollowUp);
        Ok(RunMessageAccepted {
            run_id: request.run_id,
            accepted_at: "2026-08-16T00:00:00Z".into(),
        })
    }

    fn answer_run_permission(
        &mut self,
        _: &str,
        request: RunPermissionAnswerRequest,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<RunPermissionAnswerAccepted, ProtocolError> {
        self.calls.push(Operation::RunPermissionAnswer);
        Ok(RunPermissionAnswerAccepted {
            run_id: request.run_id,
            gate_id: request.gate_id,
            answer: request.answer,
            committed_seq: 7,
            accepted_at: "2026-08-16T00:00:00Z".into(),
        })
    }
}

#[test]
fn desktop_client_dispatches_each_run_control() {
    let run_id = "0190a100-0000-7000-8000-000000000001";
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = RunControlService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service.calls)
    });

    for (operation, body) in [
        (
            Operation::RunSteer,
            serde_json::json!({"run_id":run_id,"text":"steer"}),
        ),
        (
            Operation::RunFollowUp,
            serde_json::json!({"run_id":run_id,"text":"follow up"}),
        ),
        (
            Operation::RunPermissionAnswer,
            serde_json::json!({"run_id":run_id,"gate_id":"gate-1","answer":{"type":"confirm","value":true}}),
        ),
    ] {
        let Envelope::Response(response) = exchange(
            &mut client,
            idempotent_request("018f0000-0000-7000-8000-000000000210", operation, body),
        ) else {
            panic!("run control did not return an answer")
        };
        assert_eq!(response.body["run_id"], run_id);
    }
    drop(client);
    let (result, calls) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(
        calls,
        [
            Operation::RunSteer,
            Operation::RunFollowUp,
            Operation::RunPermissionAnswer
        ]
    );
}

#[test]
fn desktop_client_dispatches_submit_and_resume() {
    let run_id = "0190a100-0000-7000-8000-000000000001";
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = RunControlService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service.calls)
    });

    let Envelope::Response(submit) = exchange(
        &mut client,
        idempotent_request(
            "018f0000-0000-7000-8000-000000000211",
            Operation::RunSubmit,
            serde_json::json!({"text":"summarize","files":["/work/signed/main.rs"],"thread_id":null}),
        ),
    ) else {
        panic!("run submit did not return an answer")
    };
    assert_eq!(submit.body["run_id"], run_id);
    assert_eq!(
        submit.body["thread_id"],
        "0190a100-0000-7000-8000-000000000002"
    );
    assert_eq!(submit.body["attachments"][0]["displayName"], "main.rs");
    assert_eq!(submit.body["committed_seq"], 1);
    assert_eq!(submit.body["accepted_at"], "2026-08-16T00:00:00Z");

    let Envelope::Response(resume) = exchange(
        &mut client,
        idempotent_request(
            "018f0000-0000-7000-8000-000000000212",
            Operation::RunResume,
            serde_json::json!({"run_id":run_id}),
        ),
    ) else {
        panic!("run resume did not return an answer")
    };
    assert_eq!(resume.body["run_id"], run_id);
    assert_eq!(
        resume.body["thread_id"],
        "0190a100-0000-7000-8000-000000000002"
    );
    assert_eq!(resume.body["committed_seq"], 2);
    assert_eq!(resume.body["accepted_at"], "2026-08-16T00:00:00Z");

    drop(client);
    let (result, calls) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(calls, [Operation::RunSubmit, Operation::RunResume]);
}

#[test]
fn desktop_run_submit_rejects_invalid_accepted_attachments() {
    let cases = [
        ("attachment count", vec![]),
        (
            "display name",
            vec![muniment_core::chat_view::ChatAttachment {
                display_name: " \t".into(),
                byte_length: 128,
                media_type: Some("text/rust".into()),
            }],
        ),
        (
            "media type",
            vec![muniment_core::chat_view::ChatAttachment {
                display_name: "main.rs".into(),
                byte_length: 128,
                media_type: Some(" \t".into()),
            }],
        ),
    ];

    for (name, attachments) in cases {
        let (mut client, server) = UnixStream::pair().unwrap();
        let session_thread = std::thread::spawn(move || {
            let mut service = InvalidRunSubmitService {
                accepted: Some(RunSubmitAccepted {
                    run_id: "0190a100-0000-7000-8000-000000000001".into(),
                    thread_id: "0190a100-0000-7000-8000-000000000002".into(),
                    attachments,
                    committed_seq: 1,
                    accepted_at: "2026-08-16T00:00:00Z".into(),
                }),
            };
            serve_desktop_client_session(server, &session(), &mut service)
        });

        let Envelope::Error(error) = exchange(
            &mut client,
            idempotent_request(
                "018f0000-0000-7000-8000-000000000210",
                Operation::RunSubmit,
                serde_json::json!({"text":"hello","files":["main.rs"],"thread_id":null}),
            ),
        ) else {
            panic!("invalid accepted {name} did not return an error")
        };
        assert_eq!(error.error.code(), ErrorCode::PersistenceFailed, "{name}");
        drop(client);
        assert_eq!(session_thread.join().unwrap(), Ok(()));
    }
}

#[test]
fn desktop_run_controls_reject_invalid_fields_without_dispatch() {
    let run_id = "0190a100-0000-7000-8000-000000000001";
    let oversized = "x".repeat(32 * 1024 + 1);
    let cases = vec![
        (
            Operation::RunSubmit,
            serde_json::json!({"text":"","files":[],"thread_id":null}),
        ),
        (
            Operation::RunSubmit,
            serde_json::json!({"text":"hello","files":[""],"thread_id":null}),
        ),
        (
            Operation::RunSubmit,
            serde_json::json!({"text":"hello","files":[],"thread_id":"bad"}),
        ),
        (
            Operation::RunSubmit,
            serde_json::json!({"text":"hello","files":[],"thread_id":null,"extra":true}),
        ),
        (Operation::RunResume, serde_json::json!({"run_id":"bad"})),
        (
            Operation::RunResume,
            serde_json::json!({"run_id":run_id,"extra":true}),
        ),
        (
            Operation::RunSteer,
            serde_json::json!({"run_id":run_id,"text":""}),
        ),
        (
            Operation::RunSteer,
            serde_json::json!({"run_id":run_id,"text":oversized}),
        ),
        (
            Operation::RunSteer,
            serde_json::json!({"run_id":"bad","text":"hello"}),
        ),
        (
            Operation::RunSteer,
            serde_json::json!({"run_id":run_id,"text":"hello","extra":true}),
        ),
        (
            Operation::RunFollowUp,
            serde_json::json!({"run_id":run_id,"text":""}),
        ),
        (
            Operation::RunFollowUp,
            serde_json::json!({"run_id":run_id,"text":oversized}),
        ),
        (
            Operation::RunFollowUp,
            serde_json::json!({"run_id":"bad","text":"hello"}),
        ),
        (
            Operation::RunFollowUp,
            serde_json::json!({"run_id":run_id,"text":"hello","extra":true}),
        ),
        (
            Operation::RunPermissionAnswer,
            serde_json::json!({"run_id":run_id,"gate_id":"","answer":{"type":"confirm","value":true}}),
        ),
        (
            Operation::RunPermissionAnswer,
            serde_json::json!({"run_id":run_id,"gate_id":oversized,"answer":{"type":"confirm","value":true}}),
        ),
        (
            Operation::RunPermissionAnswer,
            serde_json::json!({"run_id":"bad","gate_id":"gate-1","answer":{"type":"confirm","value":true}}),
        ),
        (
            Operation::RunPermissionAnswer,
            serde_json::json!({"run_id":run_id,"gate_id":"gate-1","answer":{"type":"confirm","value":true},"extra":true}),
        ),
    ];
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = RunControlService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service.calls)
    });

    for (index, (operation, body)) in cases.into_iter().enumerate() {
        let request_id = format!("018f0000-0000-7000-8000-{:012x}", 300 + index);
        let Envelope::Error(error) = exchange(
            &mut client,
            idempotent_request(&request_id, operation, body),
        ) else {
            panic!("invalid run control did not return an error")
        };
        assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
    }
    drop(client);
    let (result, calls) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert!(calls.is_empty());
}

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

#[derive(Default)]
struct DesktopThreadReadService {
    calls: Vec<(Operation, u8, Option<String>, Option<String>)>,
}

impl ThreadListService for DesktopThreadReadService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn thread_summaries(
        &mut self,
        request: ThreadListRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        self.calls.push((
            Operation::ThreadSummaries,
            request.limit,
            request.cursor,
            None,
        ));
        Ok(serde_json::json!({
            "summaries": [{
                "thread_id": "thread-1",
                "title": "Desktop title",
                "updated_at": "2026-08-15T00:00:00Z"
            }],
            "next_cursor": "summary-next"
        }))
    }

    fn thread_history(
        &mut self,
        request: muniment_core::attach::linux::ThreadOpenRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        self.calls.push((
            Operation::ThreadHistory,
            request.limit,
            request.cursor,
            Some(request.thread_id),
        ));
        Ok(serde_json::json!({
            "entries": [],
            "nextCursor": "history-next"
        }))
    }
}

#[test]
fn desktop_client_dispatches_thread_summaries_and_history() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = DesktopThreadReadService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    let Envelope::Response(response) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000201",
            Operation::ThreadSummaries,
            "admitted",
            serde_json::json!({"limit": 10, "cursor": "summary-cursor"}),
        ),
    ) else {
        panic!("thread summaries did not return a response");
    };
    assert_eq!(
        response.body,
        serde_json::json!({
            "summaries": [{
                "thread_id": "thread-1",
                "title": "Desktop title",
                "updated_at": "2026-08-15T00:00:00Z"
            }],
            "next_cursor": "summary-next"
        })
    );

    let Envelope::Response(response) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000202",
            Operation::ThreadHistory,
            "admitted",
            serde_json::json!({
                "thread_id": "thread-1",
                "limit": 8,
                "cursor": "history-cursor"
            }),
        ),
    ) else {
        panic!("thread history did not return a response");
    };
    assert_eq!(
        response.body,
        serde_json::json!({
            "entries": [],
            "nextCursor": "history-next"
        })
    );

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(
        service.calls,
        [
            (
                Operation::ThreadSummaries,
                10,
                Some("summary-cursor".into()),
                None,
            ),
            (
                Operation::ThreadHistory,
                8,
                Some("history-cursor".into()),
                Some("thread-1".into()),
            ),
        ]
    );
}

struct ThreadSelectService;

impl ThreadListService for ThreadSelectService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn select_thread(&mut self, thread_id: &Id) -> Result<(), ProtocolError> {
        if thread_id.as_str() == "0190a100-0000-7000-8000-000000000001" {
            Ok(())
        } else {
            Err(ProtocolError::thread_not_found())
        }
    }
}

#[test]
fn desktop_client_selects_only_an_owned_live_thread() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut ThreadSelectService)
    });

    let Envelope::Response(response) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000203",
            Operation::ThreadSelect,
            "admitted",
            serde_json::json!({"thread_id":"0190a100-0000-7000-8000-000000000001"}),
        ),
    ) else {
        panic!("owned thread selection did not return a response");
    };
    assert_eq!(response.body, serde_json::json!({}));

    for (request_id, thread_id) in [
        (
            "018f0000-0000-7000-8000-000000000204",
            "0190a100-0000-7000-8000-000000000002",
        ),
        (
            "018f0000-0000-7000-8000-000000000205",
            "0190a100-0000-7000-8000-000000000003",
        ),
    ] {
        let Envelope::Error(error) = exchange(
            &mut client,
            request(
                request_id,
                Operation::ThreadSelect,
                "admitted",
                serde_json::json!({"thread_id":thread_id}),
            ),
        ) else {
            panic!("unavailable thread selection did not return an error");
        };
        assert_eq!(error.error.code(), ErrorCode::ThreadNotFound);
    }

    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

#[test]
fn thread_select_validates_the_thread_id_and_idempotency_key() {
    for (mut invalid, expected) in [
        (
            request(
                "018f0000-0000-7000-8000-000000000206",
                Operation::ThreadSelect,
                "admitted",
                serde_json::json!({"thread_id":"not-an-id"}),
            ),
            ErrorCode::InvalidRequest,
        ),
        (
            idempotent_request(
                "018f0000-0000-7000-8000-000000000207",
                Operation::ThreadSelect,
                serde_json::json!({"thread_id":"0190a100-0000-7000-8000-000000000001"}),
            ),
            ErrorCode::IdempotencyKeyForbidden,
        ),
    ] {
        let (mut client, server) = UnixStream::pair().unwrap();
        let session_thread = std::thread::spawn(move || {
            serve_desktop_client_session(server, &session(), &mut ThreadSelectService)
        });
        invalid.capability = "admitted".into();
        let Envelope::Error(error) = exchange(&mut client, invalid) else {
            panic!("invalid thread selection did not return an error");
        };
        assert_eq!(error.error.code(), expected);
        drop(client);
        assert_eq!(session_thread.join().unwrap(), Ok(()));
    }
}

#[derive(Default)]
struct ShrinkingThreadReadService {
    calls: Vec<(Operation, u8)>,
}

impl ThreadListService for ShrinkingThreadReadService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn thread_summaries(
        &mut self,
        request: ThreadListRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        self.calls.push((Operation::ThreadSummaries, request.limit));
        Ok(serde_json::json!({
            "entries": if request.limit == 1 { "fits".into() } else { "x".repeat(2 * 1024 * 1024) }
        }))
    }

    fn thread_history(
        &mut self,
        request: muniment_core::attach::linux::ThreadOpenRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        self.calls.push((Operation::ThreadHistory, request.limit));
        Ok(serde_json::json!({
            "entries": if request.limit == 1 { "fits".into() } else { "x".repeat(2 * 1024 * 1024) }
        }))
    }
}

#[test]
fn desktop_thread_reads_shrink_oversized_pages_to_one_entry() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = ShrinkingThreadReadService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    for (id, operation, body) in [
        (
            "018f0000-0000-7000-8000-000000000203",
            Operation::ThreadSummaries,
            serde_json::json!({"limit": 5}),
        ),
        (
            "018f0000-0000-7000-8000-000000000204",
            Operation::ThreadHistory,
            serde_json::json!({"thread_id": "thread-1", "limit": 4}),
        ),
    ] {
        let Envelope::Response(response) =
            exchange(&mut client, request(id, operation, "admitted", body))
        else {
            panic!("shrunk thread page did not return a response");
        };
        assert_eq!(response.body, serde_json::json!({"entries": "fits"}));
    }

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(
        service.calls,
        [
            (Operation::ThreadSummaries, 5),
            (Operation::ThreadSummaries, 2),
            (Operation::ThreadSummaries, 1),
            (Operation::ThreadHistory, 4),
            (Operation::ThreadHistory, 2),
            (Operation::ThreadHistory, 1),
        ]
    );
}

struct OversizedThreadReadService;

impl ThreadListService for OversizedThreadReadService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn thread_summaries(
        &mut self,
        _: ThreadListRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        Ok(serde_json::json!({"entries": "x".repeat(2 * 1024 * 1024)}))
    }
}

#[test]
fn desktop_thread_read_rejects_an_oversized_one_entry_page() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut OversizedThreadReadService)
    });

    let Envelope::Error(error) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000205",
            Operation::ThreadSummaries,
            "admitted",
            serde_json::json!({"limit": 1}),
        ),
    ) else {
        panic!("oversized one-entry page did not return an error");
    };
    assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);

    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

#[test]
fn desktop_thread_reads_reject_invalid_bodies_without_dispatch() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = ShrinkingThreadReadService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });
    let oversized_thread_id = "x".repeat(1025);

    for (index, (operation, body)) in [
        (Operation::ThreadSummaries, serde_json::json!({"limit": 0})),
        (
            Operation::ThreadSummaries,
            serde_json::json!({"limit": 101}),
        ),
        (
            Operation::ThreadSummaries,
            serde_json::json!({"limit": 1, "extra": true}),
        ),
        (
            Operation::ThreadHistory,
            serde_json::json!({"thread_id": oversized_thread_id, "limit": 1}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let Envelope::Error(error) = exchange(
            &mut client,
            request(
                &format!("018f0000-0000-7000-8000-{index:012}"),
                operation,
                "admitted",
                body,
            ),
        ) else {
            panic!("invalid thread request did not return an error");
        };
        assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
    }

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert!(service.calls.is_empty());
}

struct ChatEventService {
    receiver: Option<mpsc::Receiver<ChatEvent>>,
}

impl ThreadListService for ChatEventService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn subscribe_chat_events(
        &mut self,
    ) -> Result<muniment_core::run_events::ChatEventSubscription, ProtocolError> {
        self.receiver
            .take()
            .map(muniment_core::run_events::ChatEventSubscription::detached)
            .ok_or_else(ProtocolError::invalid_request)
    }
}

#[test]
fn desktop_chat_subscription_delivers_events_and_owns_the_session() {
    let (sender, receiver) = mpsc::channel();
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(
            server,
            &session(),
            &mut ChatEventService {
                receiver: Some(receiver),
            },
        )
    });

    let Envelope::Response(response) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000210",
            Operation::RunChatEvents,
            "admitted",
            serde_json::json!({}),
        ),
    ) else {
        panic!("chat subscription did not return a response");
    };
    let subscription_id = response.body["subscription_id"].as_str().unwrap();

    for (phase, text) in [("running", "first"), ("completed", "second")] {
        sender
            .send(ChatEvent {
                run_id: "018f0000-0000-7000-8000-000000000211".into(),
                phase: phase.into(),
                text: text.into(),
                receipt: None,
                tool_activity: Vec::new(),
                attachments: Vec::new(),
                recalls: Vec::new(),
                applied_diffs: Vec::new(),
                pending_permission: None,
            })
            .unwrap();
        let Envelope::Event(event) = read_envelope(&mut client) else {
            panic!("chat event did not arrive");
        };
        assert_eq!(event.subscription_id.as_str(), subscription_id);
        assert_eq!(event.event, EventName::ChatEvent);
        assert_eq!(event.body["phase"], phase);
        assert_eq!(event.body["text"], text);
    }

    for (id, operation, expected) in [
        (
            "018f0000-0000-7000-8000-000000000212",
            Operation::RunChatEvents,
            ErrorCode::InvalidRequest,
        ),
        (
            "018f0000-0000-7000-8000-000000000213",
            Operation::ThreadList,
            ErrorCode::UnsupportedOperation,
        ),
    ] {
        let Envelope::Error(error) = exchange(
            &mut client,
            request(id, operation, "admitted", serde_json::json!({})),
        ) else {
            panic!("request after the chat subscription did not return an error");
        };
        assert_eq!(error.error.code(), expected);
    }

    drop(sender);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

#[test]
fn desktop_chat_subscription_stays_responsive_under_sustained_events() {
    let (sender, receiver) = mpsc::channel();
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(
            server,
            &session(),
            &mut ChatEventService {
                receiver: Some(receiver),
            },
        )
    });

    assert!(matches!(
        exchange(
            &mut client,
            request(
                "018f0000-0000-7000-8000-000000000215",
                Operation::RunChatEvents,
                "admitted",
                serde_json::json!({}),
            ),
        ),
        Envelope::Response(_)
    ));
    let producing = Arc::new(AtomicBool::new(true));
    let producer_flag = Arc::clone(&producing);
    let producer = std::thread::spawn(move || {
        while producer_flag.load(Ordering::Relaxed) {
            if sender
                .send(ChatEvent {
                    run_id: "018f0000-0000-7000-8000-000000000214".into(),
                    phase: "running".into(),
                    text: "event".into(),
                    receipt: None,
                    tool_activity: Vec::new(),
                    attachments: Vec::new(),
                    recalls: Vec::new(),
                    applied_diffs: Vec::new(),
                    pending_permission: None,
                })
                .is_err()
            {
                break;
            }
        }
    });
    assert!(matches!(read_envelope(&mut client), Envelope::Event(_)));

    client
        .write_all(
            &encode_frame(&request(
                "018f0000-0000-7000-8000-000000000216",
                Operation::ThreadList,
                "admitted",
                serde_json::json!({}),
            ))
            .unwrap(),
        )
        .unwrap();
    loop {
        match read_envelope(&mut client) {
            Envelope::Event(_) => {}
            Envelope::Error(error) => {
                assert_eq!(error.error.code(), ErrorCode::UnsupportedOperation);
                break;
            }
            envelope => panic!("unexpected envelope: {envelope:?}"),
        }
    }

    drop(client);
    let session_result = session_thread.join().unwrap();
    producing.store(false, Ordering::Relaxed);
    producer.join().unwrap();
    assert_eq!(session_result, Err(AttachSessionError::Closed));
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

#[derive(Default)]
struct SessionService {
    calls: Vec<Operation>,
}

impl ThreadListService for SessionService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn session_status(&mut self) -> Result<AuthStatus, ProtocolError> {
        self.calls.push(Operation::SessionStatus);
        Ok(auth_status())
    }

    fn entitlement_snapshot(&mut self) -> Result<EntitlementSnapshotResult, ProtocolError> {
        self.calls.push(Operation::EntitlementSnapshot);
        Ok(EntitlementSnapshotResult {
            snapshot: EntitlementSnapshotView {
                snapshot_version: 7,
                org_id: uuid::Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap(),
                user_id: uuid::Uuid::parse_str("30000000-0000-4000-8000-000000000003").unwrap(),
                role: NativeSessionRole::Owner,
                user_display_name: Some("User".into()),
                organization_display_name: Some("Muniment".into()),
                groups: Vec::<NativeEntitlementGroup>::new(),
            },
            changed_snapshot_version: Some(7),
        })
    }

    fn list_devices(&mut self) -> Result<NativeDeviceList, ProtocolError> {
        self.calls.push(Operation::DeviceList);
        Ok(serde_json::from_value(serde_json::json!({"devices": [{
            "device_id": "10000000-0000-4000-8000-000000000001",
            "client_id": "desktop-1",
            "client_role": "desktop",
            "platform": "desktop",
            "created_at": "2026-01-01T00:00:00Z",
            "revoked_at": null,
            "last_active_at": "2026-01-02T00:00:00Z",
            "current": true
        }]}))
        .unwrap())
    }

    fn sign_out(
        &mut self,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<AuthStatus, ProtocolError> {
        self.calls.push(Operation::SessionSignOut);
        Ok(AuthStatus {
            signed_in: false,
            subject: None,
            expires_at: None,
        })
    }

    fn sign_in(
        &mut self,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<AuthStatus, ProtocolError> {
        self.calls.push(Operation::SessionSignIn);
        Ok(auth_status())
    }
}

fn auth_status() -> AuthStatus {
    AuthStatus {
        signed_in: true,
        subject: Some("user-1".into()),
        expires_at: Some(1_800_000_000),
    }
}

#[test]
fn desktop_client_dispatches_session_operations() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = SessionService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    let cases = [
        (
            request(
                "018f0000-0000-7000-8000-000000000210",
                Operation::SessionStatus,
                "admitted",
                serde_json::json!({}),
            ),
            serde_json::json!({"signed_in":true,"subject":"user-1","expires_at":1800000000_u64}),
        ),
        (
            request(
                "018f0000-0000-7000-8000-000000000211",
                Operation::EntitlementSnapshot,
                "admitted",
                serde_json::json!({}),
            ),
            serde_json::json!({
                "snapshot": {
                    "snapshot_version": 7,
                    "org_id": "20000000-0000-4000-8000-000000000002",
                    "user_id": "30000000-0000-4000-8000-000000000003",
                    "role": "owner",
                    "user_display_name": "User",
                    "organization_display_name": "Muniment",
                    "groups": []
                },
                "changed_snapshot_version": 7
            }),
        ),
        (
            request(
                "018f0000-0000-7000-8000-000000000212",
                Operation::DeviceList,
                "admitted",
                serde_json::json!({}),
            ),
            serde_json::json!({"devices":[{
                "device_id":"10000000-0000-4000-8000-000000000001",
                "client_id":"desktop-1","client_role":"desktop","platform":"desktop",
                "created_at":"2026-01-01T00:00:00Z","revoked_at":null,
                "last_active_at":"2026-01-02T00:00:00Z","current":true
            }]}),
        ),
        (
            idempotent_request(
                "018f0000-0000-7000-8000-000000000213",
                Operation::SessionSignIn,
                serde_json::json!({}),
            ),
            serde_json::json!({"status":{"signed_in":true,"subject":"user-1","expires_at":1800000000_u64}}),
        ),
        (
            idempotent_request(
                "018f0000-0000-7000-8000-000000000214",
                Operation::SessionSignOut,
                serde_json::json!({}),
            ),
            serde_json::json!({"status":{"signed_in":false,"subject":null,"expires_at":null}}),
        ),
    ];

    for (request, expected) in cases {
        let Envelope::Response(response) = exchange(&mut client, request) else {
            panic!("session operation did not return a response");
        };
        assert_eq!(response.body, expected);
    }

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(
        service.calls,
        [
            Operation::SessionStatus,
            Operation::EntitlementSnapshot,
            Operation::DeviceList,
            Operation::SessionSignIn,
            Operation::SessionSignOut,
        ]
    );
}

#[test]
fn desktop_session_operations_validate_empty_bodies_and_idempotency() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = SessionService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    for (id, operation) in [
        (
            "018f0000-0000-7000-8000-000000000214",
            Operation::SessionStatus,
        ),
        (
            "018f0000-0000-7000-8000-000000000215",
            Operation::EntitlementSnapshot,
        ),
        (
            "018f0000-0000-7000-8000-000000000216",
            Operation::DeviceList,
        ),
    ] {
        let Envelope::Error(error) = exchange(
            &mut client,
            request(
                id,
                operation,
                "admitted",
                serde_json::json!({"extra": true}),
            ),
        ) else {
            panic!("nonempty body did not return an error");
        };
        assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
    }

    for (missing_key_id, nonempty_id, operation) in [
        (
            "018f0000-0000-7000-8000-000000000217",
            "018f0000-0000-7000-8000-000000000218",
            Operation::SessionSignIn,
        ),
        (
            "018f0000-0000-7000-8000-000000000219",
            "018f0000-0000-7000-8000-000000000220",
            Operation::SessionSignOut,
        ),
    ] {
        let Envelope::Error(error) = exchange(
            &mut client,
            request(missing_key_id, operation, "admitted", serde_json::json!({})),
        ) else {
            panic!("missing idempotency key did not return an error");
        };
        assert_eq!(error.error.code(), ErrorCode::IdempotencyKeyRequired);

        let Envelope::Error(error) = exchange(
            &mut client,
            idempotent_request(nonempty_id, operation, serde_json::json!({"extra": true})),
        ) else {
            panic!("nonempty body did not return an error");
        };
        assert_eq!(error.error.code(), ErrorCode::InvalidRequest);
    }

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert!(service.calls.is_empty());
}

struct OversizedSessionService;

impl ThreadListService for OversizedSessionService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn session_status(&mut self) -> Result<AuthStatus, ProtocolError> {
        Ok(AuthStatus {
            signed_in: true,
            subject: Some("x".repeat(2 * 1024 * 1024)),
            expires_at: None,
        })
    }
}

#[test]
fn desktop_session_operation_rejects_an_oversized_response() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut OversizedSessionService)
    });

    let Envelope::Error(error) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000218",
            Operation::SessionStatus,
            "admitted",
            serde_json::json!({}),
        ),
    ) else {
        panic!("oversized response did not return an error");
    };
    assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);

    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

#[derive(Default)]
struct CompanionService {
    revoked: Vec<String>,
}

impl ThreadListService for CompanionService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn list_companions(&mut self) -> Result<Vec<CompanionRecord>, ProtocolError> {
        Ok(vec![CompanionRecord {
            identity: "companion-1".into(),
            claimed_kind: "cli".into(),
            claimed_version: "1.2.3".into(),
            approved_at: Some("2026-08-14T12:00:00Z".into()),
        }])
    }

    fn revoke_companion(
        &mut self,
        client_identity: &str,
        _: &Id,
        _: &Id,
        _: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        self.revoked.push(client_identity.into());
        Ok(())
    }
}

#[test]
fn desktop_client_dispatches_companion_operations() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = CompanionService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    let Envelope::Response(response) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000220",
            Operation::CompanionList,
            "admitted",
            serde_json::json!({}),
        ),
    ) else {
        panic!("companion list did not return a response");
    };
    assert_eq!(
        response.body,
        serde_json::json!({"companions": [{
            "identity": "companion-1",
            "claimed_kind": "cli",
            "claimed_version": "1.2.3",
            "approved_at": "2026-08-14T12:00:00Z"
        }]})
    );

    let Envelope::Response(response) = exchange(
        &mut client,
        idempotent_request(
            "018f0000-0000-7000-8000-000000000221",
            Operation::CompanionRevoke,
            serde_json::json!({"client_identity": "companion-1"}),
        ),
    ) else {
        panic!("companion revoke did not return a response");
    };
    assert_eq!(response.body, serde_json::json!({}));

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(service.revoked, ["companion-1"]);
}

#[test]
fn companion_operations_validate_requests() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut CompanionService::default())
    });

    for (request, expected) in [
        (
            request(
                "018f0000-0000-7000-8000-000000000222",
                Operation::CompanionList,
                "admitted",
                serde_json::json!({"extra": true}),
            ),
            ErrorCode::InvalidRequest,
        ),
        (
            request(
                "018f0000-0000-7000-8000-000000000223",
                Operation::CompanionRevoke,
                "admitted",
                serde_json::json!({"client_identity": "companion-1"}),
            ),
            ErrorCode::IdempotencyKeyRequired,
        ),
        (
            idempotent_request(
                "018f0000-0000-7000-8000-000000000224",
                Operation::CompanionRevoke,
                serde_json::json!({"client_identity": ""}),
            ),
            ErrorCode::InvalidRequest,
        ),
    ] {
        let Envelope::Error(error) = exchange(&mut client, request) else {
            panic!("invalid companion request did not return an error");
        };
        assert_eq!(error.error.code(), expected);
    }

    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

struct OversizedCompanionService;

impl ThreadListService for OversizedCompanionService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn list_companions(&mut self) -> Result<Vec<CompanionRecord>, ProtocolError> {
        Ok(vec![CompanionRecord {
            identity: "x".repeat(2 * 1024 * 1024),
            claimed_kind: "cli".into(),
            claimed_version: "1.2.3".into(),
            approved_at: None,
        }])
    }
}

#[test]
fn companion_list_rejects_an_oversized_response() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        serve_desktop_client_session(server, &session(), &mut OversizedCompanionService)
    });

    let Envelope::Error(error) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000225",
            Operation::CompanionList,
            "admitted",
            serde_json::json!({}),
        ),
    ) else {
        panic!("oversized companion list did not return an error");
    };
    assert_eq!(error.error.code(), ErrorCode::PersistenceFailed);

    drop(client);
    assert_eq!(session_thread.join().unwrap(), Ok(()));
}

#[derive(Default)]
struct ThreadMutationService {
    renames: Vec<(String, Id, String, Id, Id, CompanionProvenance)>,
    deletes: Vec<(String, Id, Id, Id, CompanionProvenance)>,
}

impl ThreadListService for ThreadMutationService {
    fn list_threads(
        &mut self,
        _: &str,
        _: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        unreachable!()
    }

    fn rename_thread(
        &mut self,
        workspace: &str,
        thread_id: &Id,
        title: &str,
        request_id: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        self.renames.push((
            workspace.into(),
            thread_id.clone(),
            title.into(),
            request_id.clone(),
            idempotency_key.clone(),
            provenance,
        ));
        Ok(())
    }

    fn delete_thread(
        &mut self,
        workspace: &str,
        thread_id: &Id,
        request_id: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        self.deletes.push((
            workspace.into(),
            thread_id.clone(),
            request_id.clone(),
            idempotency_key.clone(),
            provenance,
        ));
        Ok(())
    }
}

#[test]
fn desktop_client_dispatches_thread_mutations() {
    let thread_id = "0190a100-0000-7000-8000-000000000001";
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = ThreadMutationService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    for request in [
        idempotent_request(
            "018f0000-0000-7000-8000-000000000230",
            Operation::ThreadRename,
            serde_json::json!({"thread_id":thread_id,"title":"Renamed thread"}),
        ),
        idempotent_request(
            "018f0000-0000-7000-8000-000000000231",
            Operation::ThreadDelete,
            serde_json::json!({"thread_id":thread_id}),
        ),
    ] {
        let Envelope::Response(response) = exchange(&mut client, request) else {
            panic!("thread mutation did not return a response");
        };
        assert_eq!(response.body, serde_json::json!({}));
    }

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(service.renames.len(), 1);
    assert_eq!(service.deletes.len(), 1);
    assert_eq!(service.renames[0].0, "/work/signed");
    assert_eq!(service.renames[0].1.as_str(), thread_id);
    assert_eq!(service.renames[0].2, "Renamed thread");
    assert_eq!(
        service.renames[0].3.as_str(),
        "018f0000-0000-7000-8000-000000000230"
    );
    assert_eq!(
        service.renames[0].4.as_str(),
        "018f0000-0000-7000-8000-000000000299"
    );
    assert_eq!(
        service.deletes[0].2.as_str(),
        "018f0000-0000-7000-8000-000000000231"
    );
    assert_eq!(
        service.deletes[0].3.as_str(),
        "018f0000-0000-7000-8000-000000000299"
    );
}

#[test]
fn desktop_thread_mutations_validate_idempotency_and_title() {
    let thread_id = "0190a100-0000-7000-8000-000000000001";
    let (mut client, server) = UnixStream::pair().unwrap();
    let session_thread = std::thread::spawn(move || {
        let mut service = ThreadMutationService::default();
        let result = serve_desktop_client_session(server, &session(), &mut service);
        (result, service)
    });

    let Envelope::Error(error) = exchange(
        &mut client,
        request(
            "018f0000-0000-7000-8000-000000000232",
            Operation::ThreadDelete,
            "admitted",
            serde_json::json!({"thread_id":thread_id}),
        ),
    ) else {
        panic!("missing idempotency key did not return an error");
    };
    assert_eq!(error.error.code(), ErrorCode::IdempotencyKeyRequired);

    let long_title = "x".repeat(MAX_THREAD_TITLE_CHARS + 1);
    let Envelope::Error(error) = exchange(
        &mut client,
        idempotent_request(
            "018f0000-0000-7000-8000-000000000233",
            Operation::ThreadRename,
            serde_json::json!({"thread_id":thread_id,"title":long_title}),
        ),
    ) else {
        panic!("long title did not return an error");
    };
    assert_eq!(error.error.code(), ErrorCode::InvalidRequest);

    drop(client);
    let (result, service) = session_thread.join().unwrap();
    assert_eq!(result, Ok(()));
    assert!(service.renames.is_empty());
    assert!(service.deletes.is_empty());
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
