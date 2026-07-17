use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use muniment_core::journal::{
    summaries::{RunSummaryListError, MAX_PAGE_SIZE, MAX_TITLE_CHARS, UNTITLED_RUN_TITLE},
    EventEnvelope, EventPayload, Provenance, RunJournal,
};
use serde_json::json;
use std::collections::BTreeMap;

const RUN_A: &str = "0190a100-0000-7000-8000-000000000001";
const RUN_B: &str = "0190a100-0000-7000-8000-000000000002";
const RUN_C: &str = "0190a100-0000-7000-8000-000000000003";
const RUN_D: &str = "0190a100-0000-7000-8000-000000000004";

fn event(run_id: &str, seq: u64, event_type: &str, recorded_at: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: format!(
            "0190a200-0000-7000-8000-{:012}",
            run_id.as_bytes().last().unwrap() - b'0' + (seq as u8 * 10)
        ),
        run_id: run_id.into(),
        run_seq: seq,
        event_type: event_type.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: recorded_at.into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
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

fn prompt(run_id: &str, text: &str, recorded_at: &str) -> EventEnvelope {
    let mut event = event(run_id, 1, "user.prompt.submitted", recorded_at);
    event.payload = EventPayload::Inline {
        payload_json: json!({"prompt": text}),
    };
    event
}

#[test]
fn summaries_derive_titles_latest_times_and_stable_order() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(
            0,
            &prompt(RUN_A, "  First\n prompt  ", "2026-07-10T10:00:00Z"),
        )
        .unwrap();
    journal
        .append(1, &event(RUN_A, 2, "run.completed", "2026-07-10T12:00:00Z"))
        .unwrap();
    journal
        .append(0, &prompt(RUN_C, "third", "2026-07-10T12:00:00Z"))
        .unwrap();
    journal
        .append(0, &prompt(RUN_B, "second", "2026-07-10T12:00:00Z"))
        .unwrap();
    journal
        .append(0, &event(RUN_D, 1, "run.started", "2026-07-10T09:00:00Z"))
        .unwrap();

    let page = journal.run_summaries(10, None).unwrap();
    assert_eq!(page.next_cursor, None);
    assert_eq!(
        page.summaries
            .iter()
            .map(|item| item.run_id.as_str())
            .collect::<Vec<_>>(),
        [RUN_A, RUN_B, RUN_C, RUN_D]
    );
    assert_eq!(page.summaries[0].title, "First prompt");
    assert_eq!(page.summaries[0].updated_at, "2026-07-10T12:00:00Z");
    assert_eq!(page.summaries[3].title, UNTITLED_RUN_TITLE);
}

#[test]
fn pagination_is_gap_free_at_boundaries_and_empty_is_empty() {
    let mut empty = RunJournal::open(":memory:").unwrap();
    assert!(empty.run_summaries(1, None).unwrap().summaries.is_empty());

    let mut journal = RunJournal::open(":memory:").unwrap();
    for (run, title, time) in [
        (RUN_A, "one", "2026-07-10T13:00:00Z"),
        (RUN_B, "two", "2026-07-10T12:00:00Z"),
        (RUN_C, "three", "2026-07-10T12:00:00Z"),
        (RUN_D, "four", "2026-07-10T11:00:00Z"),
    ] {
        journal.append(0, &prompt(run, title, time)).unwrap();
    }
    let first = journal.run_summaries(2, None).unwrap();
    let second = journal
        .run_summaries(2, first.next_cursor.as_deref())
        .unwrap();
    assert_eq!(
        first
            .summaries
            .iter()
            .chain(&second.summaries)
            .map(|item| item.run_id.as_str())
            .collect::<Vec<_>>(),
        [RUN_A, RUN_B, RUN_C, RUN_D]
    );
    assert!(second.next_cursor.is_none());
}

#[test]
fn limits_and_forged_cursors_are_typed_errors() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    journal
        .append(0, &prompt(RUN_A, "one", "2026-07-10T13:00:00Z"))
        .unwrap();
    journal
        .append(0, &prompt(RUN_B, "two", "2026-07-10T12:00:00Z"))
        .unwrap();
    assert!(matches!(
        journal.run_summaries(0, None),
        Err(RunSummaryListError::InvalidLimit { .. })
    ));
    assert!(matches!(
        journal.run_summaries(MAX_PAGE_SIZE + 1, None),
        Err(RunSummaryListError::InvalidLimit { .. })
    ));
    assert!(matches!(
        journal.run_summaries(1, Some("not-a-cursor")),
        Err(RunSummaryListError::InvalidCursor)
    ));

    let cursor = journal.run_summaries(1, None).unwrap().next_cursor.unwrap();
    let mut forged: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor).unwrap()).unwrap();
    forged["updated_at"] = json!("2026-07-10T12:00:00Z");
    forged["run_id"] = json!(RUN_B);
    let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    assert!(matches!(
        journal.run_summaries(1, Some(&forged)),
        Err(RunSummaryListError::InvalidCursor)
    ));
}

#[test]
fn title_truncation_is_unicode_safe_and_bounded() {
    let mut journal = RunJournal::open(":memory:").unwrap();
    let long = "🧪".repeat(MAX_TITLE_CHARS + 5);
    journal
        .append(0, &prompt(RUN_A, &long, "2026-07-10T13:00:00Z"))
        .unwrap();
    let title = &journal.run_summaries(1, None).unwrap().summaries[0].title;
    assert_eq!(title.chars().count(), MAX_TITLE_CHARS);
    assert!(title.ends_with('…'));
}
