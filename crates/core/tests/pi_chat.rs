use muniment_core::sidecar::pi_chat::{
    parse_frame, FollowUpCommand, PiChatEvent, PiRunAdapter, PromptCommand, SteerCommand,
};
use muniment_core::sidecar::{PiRpcWiring, SidecarConfig, SidecarStatus, SidecarSupervisor};
use serde_json::json;
use std::time::{Duration, Instant};

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
    assert_eq!(
        parse_frame(&json!({"type":"tool_execution_start"})).unwrap(),
        PiChatEvent::Interleaved
    );
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
