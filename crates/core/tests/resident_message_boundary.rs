use std::collections::HashMap;
use std::fs;

#[test]
fn raw_chat_message_calls_stay_at_reviewed_sites() {
    let source_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/llama.rs");
    let source = fs::read_to_string(source_path).expect("llama.rs must be readable");
    let allowlist = HashMap::from([
        (
            "ChatMessage::system(DICTATION_POLISH_SYSTEM_PROMPT),",
            "dictation polish system prompt",
        ),
        (
            "ChatMessage::system(DICTATION_TRANSFORM_SYSTEM_PROMPT),",
            "dictation transform system prompt",
        ),
        (
            "ChatMessage::user(self.transform.instruction()),",
            "dictation transform selector instruction",
        ),
        (
            "ChatMessage::system(ROUTING_CLASSIFIER_SYSTEM_PROMPT),",
            "routing classifier system prompt",
        ),
        (
            "ChatMessage::system(ONBOARDING_TRIAGE_SYSTEM_PROMPT),",
            "onboarding triage system prompt",
        ),
    ]);
    let mut permitted_calls = HashMap::new();

    for (line_number, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.contains("ChatMessage::system(") || line.contains("ChatMessage::user(") {
            let site = allowlist.get(line).unwrap_or_else(|| {
                panic!(
                    "llama.rs:{} constructs a raw chat message outside a reviewed site. \
                     Route external content through ChatMessage::untrusted_json.",
                    line_number + 1
                )
            });
            assert!(
                permitted_calls.insert(*site, line_number + 1).is_none(),
                "reviewed site appears more than once: {site}"
            );
        }
    }

    for site in allowlist.values() {
        assert!(
            permitted_calls.contains_key(site),
            "reviewed raw chat message site is missing: {site}"
        );
    }
}
