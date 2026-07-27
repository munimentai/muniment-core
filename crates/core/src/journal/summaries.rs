//! Shared title derivation and page bounds for journal summaries.

use super::{EventEnvelope, EventPayload};

/// Maximum number of summaries returned by one call.
pub const MAX_PAGE_SIZE: usize = 100;
/// Maximum title length in Unicode scalar values, including a trailing ellipsis.
pub const MAX_TITLE_CHARS: usize = 80;
/// Title used when a thread has no prompt.
pub const UNTITLED_RUN_TITLE: &str = "Untitled run";

pub(super) fn title_from(events: &[EventEnvelope]) -> String {
    let prompt = events.iter().find_map(|event| {
        if event.event_type != "user.prompt.submitted" {
            return None;
        }
        let EventPayload::Inline { payload_json } = &event.payload else {
            return None;
        };
        payload_json.get("prompt")?.as_str()
    });
    let normalized = prompt
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return UNTITLED_RUN_TITLE.to_owned();
    }
    if normalized.chars().count() <= MAX_TITLE_CHARS {
        return normalized;
    }
    normalized
        .chars()
        .take(MAX_TITLE_CHARS - 1)
        .chain(std::iter::once('…'))
        .collect()
}
