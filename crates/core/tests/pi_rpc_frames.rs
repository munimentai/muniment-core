//! Parses the RPC frames that `scripts/pins/compat/pi-rpc.test.mjs` captured
//! from the real pinned Pi. `muniment-pins compat` sets `MUNIMENT_PI_RPC_FRAMES`
//! to the capture. Without it the test does nothing.

use muniment_core::sidecar::pi_chat::{parse_frame, PiChatEvent};
use serde_json::Value;

#[test]
fn captured_pi_frames_parse_into_a_completed_tool_turn() {
    let Ok(path) = std::env::var("MUNIMENT_PI_RPC_FRAMES") else {
        eprintln!("The frame test requires MUNIMENT_PI_RPC_FRAMES.");
        return;
    };
    let text = std::fs::read_to_string(path).unwrap();
    let events: Vec<PiChatEvent> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let frame: Value = serde_json::from_str(line).unwrap();
            parse_frame(&frame).unwrap_or_else(|error| panic!("{error}: {line}"))
        })
        .collect();
    let position = |what: &str, matches: &dyn Fn(&PiChatEvent) -> bool| {
        events
            .iter()
            .position(matches)
            .unwrap_or_else(|| panic!("no {what} event in {events:?}"))
    };
    let accepted = position("prompt acceptance", &|event| {
        *event == PiChatEvent::PromptAccepted
    });
    let started = position("turn start", &|event| *event == PiChatEvent::TurnStarted);
    let tool = position(
        "write tool start",
        &|event| matches!(event, PiChatEvent::ToolStarted { tool_name, .. } if tool_name == "write"),
    );
    let finished = position("tool finish", &|event| {
        matches!(event, PiChatEvent::ToolFinished { failed: false, .. })
    });
    let reported = events
        .iter()
        .rposition(|event| matches!(event, PiChatEvent::ModelReported { .. }))
        .expect("an assistant message end reports its model");
    let completed = position("completion", &|event| *event == PiChatEvent::Completed);
    assert!(accepted < finished && started < tool && tool < finished);
    assert!(finished < reported && reported < completed);
    let text: String = events
        .iter()
        .filter_map(|event| match event {
            PiChatEvent::TextDelta(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text, "12");
    match &events[reported] {
        PiChatEvent::ModelReported {
            provider,
            model,
            usage,
            ..
        } => {
            assert_eq!(provider, "muniment-router");
            assert_eq!(model, "openai/gpt-6-luna");
            assert_eq!(usage.as_ref().map(|usage| usage.cache_read), Some(50));
        }
        _ => unreachable!(),
    }
    assert!(!events
        .iter()
        .any(|event| matches!(event, PiChatEvent::Failed | PiChatEvent::Cancelled)));
}
