use muniment_core::sidecar::pi_chat::{
    parse_frame, ExtensionUiAnswer, ExtensionUiDialog, ExtensionUiRequest, ExtensionUiResponse,
    FollowUpCommand, PiChatEvent, PiImageContent, PiRunAdapter, PromptCommand, SteerCommand,
};

fn extension_request(frame: serde_json::Value) -> ExtensionUiRequest {
    let PiChatEvent::ExtensionUiRequest(request) = parse_frame(&frame).unwrap() else {
        panic!("expected extension UI request")
    };
    request
}

#[test]
fn blocking_extension_ui_dialogs_are_typed() {
    assert_eq!(
        extension_request(json!({
            "type":"extension_ui_request", "id":"select-1", "method":"select",
            "title":"Allow command?", "options":["Allow", "Block"], "timeout":10000
        })),
        ExtensionUiRequest {
            id: "select-1".into(),
            dialog: ExtensionUiDialog::Select {
                title: "Allow command?".into(),
                options: vec!["Allow".into(), "Block".into()]
            },
            timeout: Some(10000)
        }
    );
    assert_eq!(
        extension_request(json!({
            "type":"extension_ui_request", "id":"confirm-1", "method":"confirm",
            "title":"Clear session?", "message":"All messages will be lost."
        }))
        .dialog,
        ExtensionUiDialog::Confirm {
            title: "Clear session?".into(),
            message: "All messages will be lost.".into()
        }
    );
    assert_eq!(
        extension_request(json!({
            "type":"extension_ui_request", "id":"input-1", "method":"input",
            "title":"Enter a value", "placeholder":"type something..."
        }))
        .dialog,
        ExtensionUiDialog::Input {
            title: "Enter a value".into(),
            placeholder: Some("type something...".into())
        }
    );
    assert_eq!(
        extension_request(json!({
            "type":"extension_ui_request", "id":"editor-1", "method":"editor",
            "title":"Edit text", "prefill":"Line 1\nLine 2"
        }))
        .dialog,
        ExtensionUiDialog::Editor {
            title: "Edit text".into(),
            prefill: Some("Line 1\nLine 2".into())
        }
    );
}

#[test]
fn malformed_dialogs_never_create_answerable_events() {
    for frame in [
        json!({"type":"extension_ui_request", "method":"select", "title":"Choose", "options":["A"]}),
        json!({"type":"extension_ui_request", "id":"", "method":"confirm", "title":"Sure?", "message":"Really?"}),
        json!({"type":"extension_ui_request", "id":"1", "method":"select", "title":"Choose", "options":[]}),
        json!({"type":"extension_ui_request", "id":"1", "method":"select", "title":"Choose", "options":[1]}),
        json!({"type":"extension_ui_request", "id":"1", "method":"confirm", "title":"Sure?"}),
        json!({"type":"extension_ui_request", "id":"1", "method":"input", "title":"Value", "placeholder":false}),
        json!({"type":"extension_ui_request", "id":"1", "method":"editor", "title":"Edit", "timeout":-1}),
    ] {
        assert!(!matches!(
            parse_frame(&frame),
            Ok(PiChatEvent::ExtensionUiRequest(_))
        ));
    }

    for method in [
        "notify",
        "setStatus",
        "setWidget",
        "setTitle",
        "set_editor_text",
    ] {
        assert_eq!(
            parse_frame(&json!({"type":"extension_ui_request", "id":"ff-1", "method":method}))
                .unwrap(),
            PiChatEvent::Interleaved
        );
    }
}

#[test]
fn extension_ui_responses_are_correlated_and_typed() {
    let cases = [
        (
            extension_request(
                json!({"type":"extension_ui_request", "id":"s", "method":"select", "title":"Pick", "options":["A"]}),
            ),
            ExtensionUiAnswer::Selection("A".into()),
            json!({"type":"extension_ui_response", "id":"s", "value":"A"}),
        ),
        (
            extension_request(
                json!({"type":"extension_ui_request", "id":"c", "method":"confirm", "title":"Sure?", "message":"Really?"}),
            ),
            ExtensionUiAnswer::Confirmation(false),
            json!({"type":"extension_ui_response", "id":"c", "confirmed":false}),
        ),
        (
            extension_request(
                json!({"type":"extension_ui_request", "id":"i", "method":"input", "title":"Value"}),
            ),
            ExtensionUiAnswer::Input("answer".into()),
            json!({"type":"extension_ui_response", "id":"i", "value":"answer"}),
        ),
        (
            extension_request(
                json!({"type":"extension_ui_request", "id":"e", "method":"editor", "title":"Edit"}),
            ),
            ExtensionUiAnswer::Editor("lines".into()),
            json!({"type":"extension_ui_response", "id":"e", "value":"lines"}),
        ),
    ];
    for (request, answer, expected) in cases {
        assert_eq!(
            ExtensionUiResponse::new(&request, answer)
                .unwrap()
                .into_value(),
            expected
        );
        assert_eq!(
            ExtensionUiResponse::new(&request, ExtensionUiAnswer::Cancelled)
                .unwrap()
                .into_value(),
            json!({"type":"extension_ui_response", "id":request.id, "cancelled":true})
        );
    }
}

#[test]
fn extension_ui_responses_reject_mismatched_answers() {
    let request = extension_request(json!({
        "type":"extension_ui_request", "id":"confirm-1", "method":"confirm",
        "title":"Sure?", "message":"Really?"
    }));
    assert!(ExtensionUiResponse::new(&request, ExtensionUiAnswer::Input("yes".into())).is_err());

    let select = extension_request(json!({
        "type":"extension_ui_request", "id":"select-1", "method":"select",
        "title":"Pick", "options":["A"]
    }));
    assert!(ExtensionUiResponse::new(&select, ExtensionUiAnswer::Selection("B".into())).is_err());
}
use muniment_core::journal::reducer::reduce;
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::sidecar::{PiRpcWiring, SidecarConfig, SidecarStatus, SidecarSupervisor};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "muniment-pi-chat-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn prompt_contract_and_interleaved_deltas_are_typed() {
    assert_eq!(
        PromptCommand::new("private prompt").into_value(),
        json!({
            "type":"prompt", "message":"private prompt", "streamingBehavior":"steer"
        })
    );
    assert_eq!(
        parse_frame(&json!({
            "type":"response", "command":"prompt", "success":true
        }))
        .unwrap(),
        PiChatEvent::PromptAccepted
    );
    assert!(matches!(
        parse_frame(&json!({"type":"tool_execution_start"})),
        Ok(PiChatEvent::Interleaved)
    ));
    assert_eq!(
        parse_frame(&json!({"type":"message_update","assistantMessageEvent":{
            "type":"text_delta", "delta":"hello"
        }}))
        .unwrap(),
        PiChatEvent::TextDelta("hello".into())
    );
    assert_eq!(
        parse_frame(&json!({"type":"cancelled"})).unwrap(),
        PiChatEvent::Cancelled
    );
    assert_eq!(
        parse_frame(&json!({"type":"error","message":"secret upstream detail"})).unwrap(),
        PiChatEvent::Failed
    );
}

fn captured_prompt(images: Option<Vec<PiImageContent>>) -> (serde_json::Value, PiChatEvent) {
    let temp = TempDir::new();
    let capture = temp.path().join("prompt.json");
    let mut config = SidecarConfig::new(env!("CARGO_BIN_EXE_sidecar-test-stub"));
    config.args = vec![
        "pi-chat-capture".into(),
        capture.to_string_lossy().into_owned(),
    ];
    config.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_millis(100)))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.status() != SidecarStatus::Healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    let transport = wiring.transport().unwrap();
    let (_, accepted) = match images {
        Some(images) => PiRunAdapter::start_with_images(
            "run-1",
            &transport,
            "inspect these",
            images,
            Duration::from_secs(1),
        ),
        None => PiRunAdapter::start("run-1", &transport, "inspect these", Duration::from_secs(1)),
    }
    .unwrap();
    let outbound = serde_json::from_str(&fs::read_to_string(capture).unwrap()).unwrap();
    supervisor.shutdown().unwrap();
    (outbound, accepted)
}

#[test]
fn text_only_adapter_prompt_omits_images_and_is_acknowledged() {
    let (outbound, accepted) = captured_prompt(None);
    assert_eq!(
        outbound,
        json!({
            "id":"muniment-pi-2", "type":"prompt", "message":"inspect these",
            "streamingBehavior":"steer"
        })
    );
    assert_eq!(accepted, PiChatEvent::PromptAccepted);
}

#[test]
fn multi_image_adapter_prompt_matches_pi_contract_and_is_acknowledged() {
    let (outbound, accepted) = captured_prompt(Some(vec![
        PiImageContent::new("aGVsbG8=", "image/png"),
        PiImageContent::new("d29ybGQ=", "image/jpeg"),
    ]));
    assert_eq!(
        outbound,
        json!({
            "id":"muniment-pi-2", "type":"prompt", "message":"inspect these",
            "streamingBehavior":"steer",
            "images":[
                {"type":"image", "data":"aGVsbG8=", "mimeType":"image/png"},
                {"type":"image", "data":"d29ybGQ=", "mimeType":"image/jpeg"}
            ]
        })
    );
    assert_eq!(accepted, PiChatEvent::PromptAccepted);
}

#[test]
fn tool_execution_frames_include_bounded_details_and_filter_credentials() {
    let started = parse_frame(&json!({
        "type":"tool_execution_start",
        "toolCallId":"call-1",
        "toolName":"bash",
        "args":{"command":"API_KEY=sk-test1234567890secret"}
    }))
    .unwrap();
    assert_eq!(
        started,
        PiChatEvent::ToolStarted {
            tool_call_id: "call-1".into(),
            tool_name: "bash".into(),
            input: Some("Details withheld because they may contain a secret.".into()),
        }
    );

    let finished = parse_frame(&json!({
        "type":"tool_execution_end",
        "toolCallId":"call-1",
        "toolName":"bash",
        "result":{"content":[{"type":"text","text":"API_KEY=sk-test1234567890secret"}]},
        "isError":true,
        "error":"secret upstream error"
    }))
    .unwrap();
    assert_eq!(
        finished,
        PiChatEvent::ToolFinished {
            tool_call_id: "call-1".into(),
            failed: true,
            output: Some("Details withheld because they may contain a secret.".into()),
        }
    );

    let projected = format!("{started:?} {finished:?}");
    for secret in [
        "API_KEY=sk-test1234567890secret",
        "API_KEY=sk-test1234567890secret",
        "secret upstream error",
    ] {
        assert!(!projected.contains(secret));
    }
}

#[test]
fn pi_completion_does_not_claim_authoritative_provenance() {
    assert_eq!(
        parse_frame(&json!({"type":"agent_end","receipt":{
            "route":"untrusted", "model":"untrusted"
        }}))
        .unwrap(),
        PiChatEvent::Completed
    );
}

#[test]
fn queued_message_commands_match_the_pinned_contract() {
    assert_eq!(
        SteerCommand::new("redirect here").unwrap().into_value(),
        json!({"type":"steer", "message":"redirect here"})
    );
    assert_eq!(
        FollowUpCommand::new("then do this").unwrap().into_value(),
        json!({"type":"follow_up", "message":"then do this"})
    );
}

#[test]
fn queued_message_commands_reject_blank_messages() {
    for error in [
        SteerCommand::new("").unwrap_err(),
        SteerCommand::new(" \n\t").unwrap_err(),
        FollowUpCommand::new("  ").unwrap_err(),
    ] {
        assert_eq!(error, "Pi queued message must not be empty");
    }
}

#[test]
fn adapter_queues_messages_without_consuming_interleaved_stream_events() {
    let mut config = SidecarConfig::new(env!("CARGO_BIN_EXE_sidecar-test-stub"));
    config.args = vec!["pi-chat-queue".into()];
    config.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_millis(100)))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.status() != SidecarStatus::Healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    let transport = wiring.transport().unwrap();
    let (adapter, accepted) =
        PiRunAdapter::start("run-1", &transport, "initial", Duration::from_millis(100)).unwrap();
    assert_eq!(accepted, PiChatEvent::PromptAccepted);

    adapter
        .steer(&transport, "redirect", Duration::from_millis(100))
        .unwrap();
    assert_eq!(
        adapter.next(Duration::from_secs(1)).unwrap(),
        PiChatEvent::Interleaved
    );
    assert_eq!(
        adapter.next(Duration::from_secs(1)).unwrap(),
        PiChatEvent::TextDelta("still streaming".into())
    );
    adapter
        .follow_up(&transport, "next", Duration::from_millis(100))
        .unwrap();

    for (message, expected) in [
        ("mismatch", "Pi queue command failed"),
        ("failed", "Pi queue command failed"),
        ("  ", "Pi queued message must not be empty"),
    ] {
        assert_eq!(
            adapter
                .steer(&transport, message, Duration::from_millis(100))
                .unwrap_err(),
            expected
        );
    }
    supervisor.shutdown().unwrap();
}

#[test]
fn late_correlated_responses_do_not_become_stream_events() {
    let temp = TempDir::new();
    let release_marker = temp.path().join("release-response");
    let mut config = SidecarConfig::new(env!("CARGO_BIN_EXE_sidecar-test-stub"));
    config.args = vec![
        "pi-chat-late-response".into(),
        release_marker.to_string_lossy().into_owned(),
    ];
    config.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_millis(100)))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.status() != SidecarStatus::Healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    let transport = wiring.transport().unwrap();
    let (adapter, _) =
        PiRunAdapter::start("run-1", &transport, "prompt", Duration::from_secs(1)).unwrap();

    // Give the stdin writer time to run. The release marker keeps the response
    // late regardless of the request timeout.
    let error = transport
        .session_locator(std::path::Path::new("."), Duration::from_secs(1))
        .unwrap_err();
    assert!(
        error.contains("timed out waiting for Pi RPC response"),
        "expected a response timeout, got: {error}"
    );
    fs::write(release_marker, "").unwrap();
    assert_eq!(
        adapter.next(Duration::from_secs(1)).unwrap(),
        PiChatEvent::TextDelta("after late response".into())
    );
    supervisor.shutdown().unwrap();
}

fn deferred_session_supervisor(
    session_file: &std::path::Path,
    cancel_marker: Option<&std::path::Path>,
) -> (SidecarSupervisor, PiRpcWiring) {
    let mut config = SidecarConfig::new(env!("CARGO_BIN_EXE_sidecar-test-stub"));
    config.args = vec![
        "pi-session-deferred".into(),
        session_file.to_string_lossy().into_owned(),
    ];
    if let Some(marker) = cancel_marker {
        config.args.push(marker.to_string_lossy().into_owned());
    }
    config.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_millis(100)))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.status() != SidecarStatus::Healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    (supervisor, wiring)
}

#[test]
fn accepted_prompt_waits_for_session_file_and_preserves_stream_frames() {
    let temp = TempDir::new();
    let session_file = temp.path().join("session.jsonl");
    let (mut supervisor, wiring) = deferred_session_supervisor(&session_file, None);
    let transport = wiring.transport().unwrap();
    let (adapter, _) =
        PiRunAdapter::start("run-1", &transport, "prompt", Duration::from_secs(1)).unwrap();

    let (locator, buffered) = adapter
        .await_session_binding(&transport, temp.path(), Duration::from_secs(3))
        .unwrap();

    assert_eq!(locator.as_str(), "session.jsonl");
    assert_eq!(buffered, vec![PiChatEvent::TextDelta("buffered".into())]);
    assert!(session_file.is_file());

    let journal_path = temp.path().join("journal.sqlite3");
    let run_id = "0190a100-0000-7000-8000-000000000001";
    let binding = EventEnvelope {
        event_id: "0190a100-0000-7000-8000-000000000002".into(),
        run_id: run_id.into(),
        run_seq: 2,
        event_type: "runtime.pi_session.bound".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-07-14T00:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({"run_id":run_id, "locator":locator.as_str()}),
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
    };
    let mut started = binding.clone();
    started.event_id = "0190a100-0000-7000-8000-000000000003".into();
    started.run_seq = 1;
    started.event_type = "run.started".into();
    started.payload = EventPayload::Inline {
        payload_json: json!({}),
    };
    RunJournal::open(&journal_path)
        .unwrap()
        .append_batch(0, &[started, binding])
        .unwrap();
    let replayed = RunJournal::open(&journal_path)
        .unwrap()
        .events(run_id)
        .unwrap();
    assert_eq!(
        reduce(&replayed).unwrap().pi_session.unwrap().locator,
        "session.jsonl"
    );
    supervisor.shutdown().unwrap();
}

#[test]
fn invalid_session_state_cancels_accepted_agent_work() {
    let owned_root = TempDir::new();
    let outside_root = TempDir::new();
    let marker = owned_root.path().join("cancelled");
    let outside = outside_root.path().join("outside-session.jsonl");
    fs::write(&outside, "{}\n").unwrap();
    let (mut supervisor, wiring) = deferred_session_supervisor(&outside, Some(&marker));
    let transport = wiring.transport().unwrap();
    let (adapter, _) =
        PiRunAdapter::start("run-1", &transport, "prompt", Duration::from_secs(1)).unwrap();

    assert_eq!(
        adapter
            .await_session_binding(&transport, owned_root.path(), Duration::from_millis(100))
            .unwrap_err(),
        "Pi session binding failed"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(fs::read_to_string(marker).unwrap(), "cancelled");
    supervisor.shutdown().unwrap();
}

#[test]
fn expired_state_request_preserves_stdin_for_cancellation() {
    let temp = TempDir::new();
    let marker = temp.path().join("cancelled");
    let session_file = temp.path().join("session.jsonl");
    let (mut supervisor, wiring) = deferred_session_supervisor(&session_file, Some(&marker));
    let transport = wiring.transport().unwrap();
    let (adapter, _) =
        PiRunAdapter::start("run-1", &transport, "prompt", Duration::from_secs(1)).unwrap();

    assert!(transport
        .session_locator(temp.path(), Duration::ZERO)
        .unwrap_err()
        .contains("timed out writing Pi RPC stdin"));
    adapter
        .cancel_and_drain(&transport, Duration::from_secs(2))
        .unwrap();
    assert_eq!(fs::read_to_string(marker).unwrap(), "cancelled");
    supervisor.shutdown().unwrap();
}

fn extension_ui_supervisor(capture: &std::path::Path) -> (SidecarSupervisor, PiRpcWiring) {
    let mut config = SidecarConfig::new(env!("CARGO_BIN_EXE_sidecar-test-stub"));
    config.args = vec![
        "pi-chat-extension-ui".into(),
        capture.to_string_lossy().into_owned(),
    ];
    config.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let supervisor =
        SidecarSupervisor::spawn(config, wiring.readiness_probe(Duration::from_millis(100)))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while supervisor.status() != SidecarStatus::Healthy && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    (supervisor, wiring)
}

fn read_complete_capture(path: &std::path::Path) -> Option<String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("could not read capture: {error}"),
    };
    // The stub creates the file before it writes each newline-delimited frame.
    bytes
        .ends_with(b"\n")
        .then(|| String::from_utf8(bytes).unwrap())
}

#[test]
fn capture_reader_waits_for_complete_frames() {
    let temp = TempDir::new();
    let capture = temp.path().join("answers.jsonl");
    assert_eq!(read_complete_capture(&capture), None);
    let first = "{\"value\":\"café\"}\n";
    let frames = format!("{first}{{\"cancelled\":true}}\n");
    for end in 0..=frames.len() {
        fs::write(&capture, &frames.as_bytes()[..end]).unwrap();
        let expected = if end == first.len() {
            Some(first.to_owned())
        } else if end == frames.len() {
            Some(frames.clone())
        } else {
            None
        };
        assert_eq!(read_complete_capture(&capture), expected, "prefix {end}");
    }
    // A complete malformed frame must reach the parser, not trigger a retry.
    fs::write(&capture, "invalid JSON\n").unwrap();
    let captured = read_complete_capture(&capture).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&captured).is_err());
}

#[test]
fn adapter_sends_exact_extension_ui_answer_frames() {
    let temp = TempDir::new();
    let capture = temp.path().join("answers.jsonl");
    let (mut supervisor, wiring) = extension_ui_supervisor(&capture);
    let transport = wiring.transport().unwrap();
    let (adapter, _) =
        PiRunAdapter::start("run-1", &transport, "start", Duration::from_secs(1)).unwrap();
    let cases = [
        (
            extension_request(json!({
                "type":"extension_ui_request", "id":"select-1", "method":"select",
                "title":"Pick", "options":["A"]
            })),
            ExtensionUiAnswer::Selection("A".into()),
            json!({"type":"extension_ui_response", "id":"select-1", "value":"A"}),
        ),
        (
            extension_request(json!({
                "type":"extension_ui_request", "id":"confirm-1", "method":"confirm",
                "title":"Sure?", "message":"Really?"
            })),
            ExtensionUiAnswer::Confirmation(false),
            json!({"type":"extension_ui_response", "id":"confirm-1", "confirmed":false}),
        ),
        (
            extension_request(json!({
                "type":"extension_ui_request", "id":"input-1", "method":"input", "title":"Value"
            })),
            ExtensionUiAnswer::Input("answer".into()),
            json!({"type":"extension_ui_response", "id":"input-1", "value":"answer"}),
        ),
        (
            extension_request(json!({
                "type":"extension_ui_request", "id":"editor-1", "method":"editor", "title":"Edit"
            })),
            ExtensionUiAnswer::Editor("lines".into()),
            json!({"type":"extension_ui_response", "id":"editor-1", "value":"lines"}),
        ),
        (
            extension_request(json!({
                "type":"extension_ui_request", "id":"cancel-1", "method":"confirm",
                "title":"Sure?", "message":"Really?"
            })),
            ExtensionUiAnswer::Cancelled,
            json!({"type":"extension_ui_response", "id":"cancel-1", "cancelled":true}),
        ),
    ];
    let expected: Vec<_> = cases.iter().map(|(_, _, frame)| frame.clone()).collect();
    for (request, answer, _) in cases {
        adapter
            .answer_extension_ui(&transport, &request, answer)
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let captured = loop {
        let frames = read_complete_capture(&capture).unwrap_or_default();
        let captured: Vec<serde_json::Value> = frames
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        if captured.len() == expected.len() || Instant::now() >= deadline {
            break captured;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(captured, expected);
    supervisor.shutdown().unwrap();
}

#[test]
fn adapter_rejects_mismatched_answer_without_writing() {
    let temp = TempDir::new();
    let capture = temp.path().join("answers.jsonl");
    let (mut supervisor, wiring) = extension_ui_supervisor(&capture);
    let transport = wiring.transport().unwrap();
    let (adapter, _) =
        PiRunAdapter::start("run-1", &transport, "start", Duration::from_secs(1)).unwrap();
    let request = extension_request(json!({
        "type":"extension_ui_request", "id":"confirm-1", "method":"confirm",
        "title":"Sure?", "message":"Really?"
    }));

    assert_eq!(
        adapter.answer_extension_ui(&transport, &request, ExtensionUiAnswer::Input("yes".into())),
        Err("answer kind does not match extension UI request".into())
    );
    std::thread::sleep(Duration::from_millis(25));
    assert!(!capture.exists());
    supervisor.shutdown().unwrap();
}

#[test]
fn transport_send_completes_while_call_waits() {
    let temp = TempDir::new();
    let capture = temp.path().join("answers.jsonl");
    let waiting = PathBuf::from(format!("{}.waiting", capture.to_string_lossy()));
    let (mut supervisor, wiring) = extension_ui_supervisor(&capture);
    let transport = wiring.transport().unwrap();
    let calling = std::sync::Arc::clone(&transport);
    let call = std::thread::spawn(move || {
        calling.call(
            json!({"type":"prompt", "message":"wait"}),
            Duration::from_secs(1),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !waiting.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(waiting.exists());

    let started = Instant::now();
    assert_eq!(
        transport
            .call(json!({"type":"get_state"}), Duration::from_millis(20))
            .unwrap_err(),
        "timed out waiting for Pi RPC call lock"
    );
    assert!(started.elapsed() < Duration::from_millis(500));

    let started = Instant::now();
    transport
        .send(json!({
            "type":"extension_ui_response", "id":"gate-1", "confirmed":true
        }))
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(100));
    let deadline = Instant::now() + Duration::from_secs(1);
    let frames = loop {
        if let Some(frames) = read_complete_capture(&capture) {
            break frames;
        }
        assert!(Instant::now() < deadline, "timed out waiting for capture");
        std::thread::sleep(Duration::from_millis(5));
    };
    let captured: serde_json::Value = serde_json::from_str(&frames).unwrap();
    assert_eq!(
        captured,
        json!({"type":"extension_ui_response", "id":"gate-1", "confirmed":true})
    );
    assert!(call.join().unwrap().is_err());
    supervisor.shutdown().unwrap();
}

#[test]
fn action_output_keeps_text_bounds_unicode_and_omits_images() {
    let output = "é".repeat(9000);
    let event = parse_frame(&json!({"type":"tool_execution_end", "toolCallId":"read-1", "isError":false,
        "result":{"content":[{"type":"text","text":output},{"type":"image","data":"not-for-history"}]}})).unwrap();
    let PiChatEvent::ToolFinished {
        output: Some(text), ..
    } = event
    else {
        panic!("missing action detail")
    };
    assert!(text.starts_with(&"é".repeat(8000)));
    assert!(text.ends_with("[Output shortened]"));
    assert!(!text.contains("not-for-history"));
}

#[test]
fn startup_answers_name_requests_before_acknowledgement_and_keeps_other_frames() {
    let temp = TempDir::new();
    let capture = temp.path().join("name-answer.jsonl");
    let (mut supervisor, wiring) = extension_ui_supervisor(&capture);
    let transport = wiring.transport().unwrap();
    let mut answered = 0;
    let (adapter, accepted) = PiRunAdapter::start_with_images_and_handler(
        "run-name",
        &transport,
        "name-first",
        vec![],
        Duration::from_secs(2),
        |adapter, event| {
            let PiChatEvent::ExtensionUiRequest(request) = event else {
                return false;
            };
            answered += 1;
            adapter
                .answer_extension_ui(
                    &transport,
                    request,
                    ExtensionUiAnswer::Editor("{\"prompt\":\"Compare leases\"}".into()),
                )
                .unwrap();
            true
        },
    )
    .unwrap();
    assert_eq!(accepted, PiChatEvent::PromptAccepted);
    assert_eq!(answered, 1);
    assert_eq!(
        adapter.next(Duration::from_secs(1)).unwrap(),
        PiChatEvent::TurnStarted
    );
    assert_eq!(
        adapter.next(Duration::from_secs(1)).unwrap(),
        PiChatEvent::Completed
    );
    supervisor.shutdown().unwrap();
}
