use muniment_core::sidecar::pi_chat::{parse_frame, PiChatEvent, PromptCommand};
use serde_json::json;

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
