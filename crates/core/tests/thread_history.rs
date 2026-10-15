#![cfg(feature = "keyring")]

use std::collections::BTreeMap;
use std::time::Duration;

use muniment_core::cas::LocalCas;
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::thread_history::{
    chat_thread_open_page, chat_thread_open_page_without_prompts, load_page_prompts, run_detail,
    HistoryRuntime, RunDetail, RunDetailError, RunDetailKind, ThreadHistoryError,
    RUN_DETAIL_MAX_BYTES,
};
use serde_json::{json, Value};
use uuid::Uuid;

/// Serializes the tests that install a keyring credential builder.
static KEYRING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn journal_file() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-thread-history-{}.sqlite3",
        Uuid::new_v4()
    ))
}

fn started_event(run_id: &str, actor_id: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-08T00:00:00Z".into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: json!({}),
        },
        provenance: Provenance {
            source: "test".into(),
            source_version: "1".into(),
            actor_id: Some(actor_id.into()),
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}

#[test]
fn open_page_uses_the_webview_contract() {
    let _keyring = KEYRING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    let path = journal_file();
    let mut journal = RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let thread_id = journal
        .append_new_run("workspace", &started_event(&run_id, "owner"))
        .unwrap();

    let page = chat_thread_open_page(
        &mut journal,
        None,
        Some("owner"),
        std::path::Path::new("."),
        &thread_id,
        10,
        None,
    )
    .unwrap();
    let value = serde_json::to_value(page).unwrap();
    let entry = &value["entries"][0];

    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["entries", "nextCursor"]
    );
    assert_eq!(
        entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "appliedDiffs",
            "attachments",
            "phase",
            "prompt",
            "recalls",
            "resumable",
            "runId",
            "sentAt",
            "text",
            "toolActivity"
        ]
    );
    assert_eq!(value["nextCursor"], Value::Null);
    assert_eq!(entry["runId"], run_id);
    assert_eq!(entry["sentAt"], "2026-08-08T00:00:00Z");
    assert!(entry.get("pendingPermission").is_none());

    drop(journal);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn open_page_rejects_a_thread_owned_by_another_subject() {
    let path = journal_file();
    let mut journal = RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let thread_id = journal
        .append_new_run("workspace", &started_event(&run_id, "other"))
        .unwrap();

    assert_eq!(
        chat_thread_open_page(
            &mut journal,
            None,
            Some("owner"),
            std::path::Path::new("."),
            &thread_id,
            10,
            None,
        )
        .err(),
        Some(ThreadHistoryError::ThreadNotOwned)
    );

    drop(journal);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn a_page_without_prompts_reads_them_after_the_journal() {
    let _keyring = KEYRING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let path = journal_file();
    let mut journal = RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let thread_id = journal
        .append_new_run("workspace", &started_event(&run_id, "owner"))
        .unwrap();
    muniment_core::chat_prompt::store_prompt(&run_id, "Plan the week.", Some("owner")).unwrap();

    let mut page = chat_thread_open_page_without_prompts(
        &mut journal,
        None,
        Some("owner"),
        HistoryRuntime {
            session_root: std::path::Path::new("."),
            active_run_id: None,
        },
        &thread_id,
        10,
        None,
    )
    .unwrap();
    drop(journal);
    assert_eq!(page.entries[0].prompt, None);
    load_page_prompts(&mut page, Some("owner")).unwrap();
    assert_eq!(page.entries[0].prompt.as_deref(), Some("Plan the week."));

    std::fs::remove_file(path).unwrap();
}

fn tool_event(run_id: &str, run_seq: u64, event_type: &str, payload: Value) -> EventEnvelope {
    let mut event = started_event(run_id, "owner");
    event.run_seq = run_seq;
    event.event_type = event_type.into();
    event.payload = EventPayload::Inline {
        payload_json: payload,
    };
    event
}

#[test]
fn run_detail_answers_a_tool_output_within_its_byte_cap() {
    let path = journal_file();
    let cas_root = std::env::temp_dir().join(format!("muniment-run-detail-{}", Uuid::new_v4()));
    let cas = LocalCas::open(&cas_root).unwrap();
    let mut journal = RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
    let run_id = Uuid::now_v7().to_string();
    journal
        .append_new_run("workspace", &started_event(&run_id, "owner"))
        .unwrap();
    // Quotes and control characters escape to more bytes than they take.
    let long = "line \"one\"\t\u{1}\n".repeat(RUN_DETAIL_MAX_BYTES / 8);
    let events = [
        ("tool.effect.started", json!({"effect_id": "short"})),
        (
            "tool.effect.completed",
            json!({"effect_id": "short", "output": "two files"}),
        ),
        ("tool.effect.started", json!({"effect_id": "long"})),
        (
            "tool.effect.failed",
            json!({"effect_id": "long", "output": long}),
        ),
    ];
    for (index, (event_type, payload)) in events.into_iter().enumerate() {
        let seq = index as u64 + 2;
        journal
            .append(seq - 1, &tool_event(&run_id, seq, event_type, payload))
            .unwrap();
    }

    let read = |journal: &mut RunJournal, subject, effect_id| {
        run_detail(
            journal,
            &cas,
            subject,
            &run_id,
            effect_id,
            RunDetailKind::ToolOutput,
        )
    };
    assert_eq!(
        read(&mut journal, Some("owner"), "short"),
        Ok(RunDetail::ToolOutput {
            text: "two files".into(),
            bytes: 9,
            truncated: false,
        })
    );
    let Ok(RunDetail::ToolOutput {
        text,
        bytes,
        truncated,
    }) = read(&mut journal, Some("owner"), "long")
    else {
        panic!("the long output must answer");
    };
    assert!(truncated);
    assert_eq!(bytes, long.len());
    assert!(long.starts_with(&text));
    let answer = serde_json::to_vec(&json!({"kind": "tool_output", "text": text})).unwrap();
    assert!(answer.len() <= RUN_DETAIL_MAX_BYTES + 64);
    assert_eq!(
        read(&mut journal, Some("owner"), "missing"),
        Err(RunDetailError::NotFound)
    );
    assert_eq!(
        read(&mut journal, Some("other"), "short"),
        Err(RunDetailError::RunNotOwned)
    );

    drop(journal);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir_all(cas_root).ok();
}
