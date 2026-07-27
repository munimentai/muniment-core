use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use muniment_core::journal::{
    summaries::{RunSummaryListError, MAX_PAGE_SIZE},
    thread_summaries::ThreadSummaryListError,
    EventEnvelope, EventPayload, Provenance, RunJournal,
};
use rusqlite::{params, Connection};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

const RUN_A: &str = "0190a100-0000-7000-8000-000000000001";
const RUN_B: &str = "0190a100-0000-7000-8000-000000000002";
const RUN_C: &str = "0190a100-0000-7000-8000-000000000003";
const RUN_D: &str = "0190a100-0000-7000-8000-000000000004";

fn event(
    run_id: &str,
    seq: u64,
    event_type: &str,
    recorded_at: &str,
    payload_json: serde_json::Value,
) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq: seq,
        event_type: event_type.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: recorded_at.into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline { payload_json },
        provenance: provenance(),
        extra: BTreeMap::new(),
    }
}

fn prompt(run_id: &str, seq: u64, text: &str, recorded_at: &str) -> EventEnvelope {
    event(
        run_id,
        seq,
        "user.prompt.submitted",
        recorded_at,
        json!({"prompt": text}),
    )
}

fn provenance() -> Provenance {
    Provenance {
        source: "test".into(),
        source_version: "1".into(),
        actor_id: None,
        device_id: None,
        rpc_request_id: None,
        capability_versions: None,
        extra: BTreeMap::new(),
    }
}

fn journal_file() -> PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-thread-summaries-{}.sqlite3",
        Uuid::new_v4()
    ))
}

fn thread_for(path: &PathBuf, run_id: &str) -> String {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT thread_id FROM run_threads WHERE run_id=?1",
            [run_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn merge_run_into_thread(path: &PathBuf, run_id: &str, thread_id: &str, ordinal: u64) {
    let connection = Connection::open(path).unwrap();
    let old_thread = thread_for(path, run_id);
    connection
        .execute(
            "UPDATE run_threads SET thread_id=?1, thread_run_ordinal=?2 WHERE run_id=?3",
            params![thread_id, ordinal, run_id],
        )
        .unwrap();
    connection
        .execute("DELETE FROM thread_events WHERE thread_id=?1", [old_thread])
        .unwrap();
}

#[test]
fn pages_threads_by_combined_update_time_and_thread_id() {
    let path = journal_file();
    let mut journal = RunJournal::open(&path).unwrap();
    for (run, time) in [
        (RUN_A, "2026-07-10T12:00:00Z"),
        (RUN_B, "2026-07-10T12:00:00Z"),
        (RUN_C, "2026-07-10T11:00:00Z"),
    ] {
        journal.append(0, &prompt(run, 1, run, time)).unwrap();
    }

    let expected = journal
        .thread_summaries(10, None)
        .unwrap()
        .summaries
        .into_iter()
        .map(|summary| summary.thread_id)
        .collect::<Vec<_>>();
    let first = journal.thread_summaries(1, None).unwrap();
    let second = journal
        .thread_summaries(1, first.next_cursor.as_deref())
        .unwrap();
    let third = journal
        .thread_summaries(1, second.next_cursor.as_deref())
        .unwrap();
    assert_eq!(
        first
            .summaries
            .iter()
            .chain(&second.summaries)
            .chain(&third.summaries)
            .map(|summary| summary.thread_id.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(third.next_cursor.is_none());
    assert_eq!(first.summaries[0].updated_at, "2026-07-10T12:00:00Z");

    let first_thread = first.summaries[0].thread_id.clone();
    journal
        .append_thread_title_renamed(
            1,
            &first_thread,
            "renamed",
            "2026-07-10T14:00:00Z",
            &provenance(),
        )
        .unwrap();
    assert_eq!(
        journal.thread_summaries(1, None).unwrap().summaries[0].thread_id,
        first_thread
    );
}

#[test]
fn latest_rename_wins_and_fallback_uses_first_prompt_in_stamp_order() {
    let path = journal_file();
    let mut journal = RunJournal::open(&path).unwrap();
    journal
        .append(
            0,
            &event(RUN_A, 1, "run.started", "2026-07-10T10:00:00Z", json!({})),
        )
        .unwrap();
    journal
        .append(
            0,
            &prompt(RUN_B, 1, "  second\n run  ", "2026-07-10T11:00:00Z"),
        )
        .unwrap();
    let thread_id = thread_for(&path, RUN_A);
    merge_run_into_thread(&path, RUN_B, &thread_id, 2);

    assert_eq!(
        journal.thread_summaries(1, None).unwrap().summaries[0].title,
        "second run"
    );
    journal
        .append(
            1,
            &event(
                RUN_A,
                2,
                "user.prompt.submitted",
                "2026-07-10T11:30:00Z",
                json!({"prompt": 42}),
            ),
        )
        .unwrap();
    journal
        .append(
            2,
            &prompt(RUN_A, 3, "  first\t run  ", "2026-07-10T12:00:00Z"),
        )
        .unwrap();
    assert_eq!(
        journal.thread_summaries(1, None).unwrap().summaries[0].title,
        "first run"
    );
    journal
        .append_thread_title_renamed(
            1,
            &thread_id,
            "First name",
            "2026-07-10T13:00:00Z",
            &provenance(),
        )
        .unwrap();
    journal
        .append_thread_title_renamed(
            2,
            &thread_id,
            "Latest name",
            "2026-07-10T14:00:00Z",
            &provenance(),
        )
        .unwrap();
    assert_eq!(
        journal.thread_summaries(1, None).unwrap().summaries[0].title,
        "Latest name"
    );
}

#[test]
fn fallback_title_changes_when_first_prompt_arrives() {
    let path = journal_file();
    let mut journal = RunJournal::open(&path).unwrap();
    journal
        .append(
            0,
            &event(RUN_A, 1, "run.started", "2026-07-10T10:00:00Z", json!({})),
        )
        .unwrap();

    assert_eq!(
        journal.thread_summaries(1, None).unwrap().summaries[0].title,
        "Untitled run"
    );

    journal
        .append(
            1,
            &prompt(RUN_A, 2, "  first\n prompt  ", "2026-07-10T11:00:00Z"),
        )
        .unwrap();
    assert_eq!(
        journal.thread_summaries(1, None).unwrap().summaries[0].title,
        "first prompt"
    );
}

#[test]
fn deleted_threads_and_other_workspaces_do_not_affect_pages() {
    let path = journal_file();
    let mut journal = RunJournal::open(&path).unwrap();
    for (run, workspace, time) in [
        (RUN_A, "alpha", "2026-07-10T13:00:00Z"),
        (RUN_B, "beta", "2026-07-10T12:00:00Z"),
        (RUN_C, "alpha", "2026-07-10T11:00:00Z"),
    ] {
        journal
            .append_new_run(workspace, &prompt(run, 1, run, time))
            .unwrap();
    }
    let deleted = thread_for(&path, RUN_A);
    journal
        .append_thread_deleted(1, &deleted, "2026-07-10T14:00:00Z", &provenance())
        .unwrap();

    let page = journal
        .workspace_thread_summaries("alpha", 1, None)
        .unwrap();
    assert_eq!(page.summaries.len(), 1);
    assert_eq!(page.summaries[0].thread_id, thread_for(&path, RUN_C));
    assert!(page.next_cursor.is_none());
    assert_eq!(
        journal.thread_summaries(10, None).unwrap().summaries.len(),
        2
    );
}

#[test]
fn rejects_invalid_cross_contract_scoped_and_stale_cursors() {
    let path = journal_file();
    let mut journal = RunJournal::open(&path).unwrap();
    for (run, time) in [
        (RUN_A, "2026-07-10T13:00:00Z"),
        (RUN_B, "2026-07-10T12:00:00Z"),
        (RUN_C, "2026-07-10T11:00:00Z"),
        (RUN_D, "2026-07-10T10:00:00Z"),
    ] {
        journal
            .append_new_run("alpha", &prompt(run, 1, run, time))
            .unwrap();
    }
    assert!(matches!(
        journal.thread_summaries(0, None),
        Err(ThreadSummaryListError::InvalidLimit { .. })
    ));
    assert!(matches!(
        journal.thread_summaries(MAX_PAGE_SIZE + 1, None),
        Err(ThreadSummaryListError::InvalidLimit { .. })
    ));
    assert!(matches!(
        journal.thread_summaries(1, Some(&"a".repeat(513))),
        Err(ThreadSummaryListError::InvalidCursor)
    ));

    let run_cursor = journal.run_summaries(1, None).unwrap().next_cursor.unwrap();
    assert!(matches!(
        journal.thread_summaries(1, Some(&run_cursor)),
        Err(ThreadSummaryListError::InvalidCursor)
    ));
    let thread_cursor = journal
        .thread_summaries(1, None)
        .unwrap()
        .next_cursor
        .unwrap();
    assert!(matches!(
        journal.run_summaries(1, Some(&thread_cursor)),
        Err(RunSummaryListError::InvalidCursor)
    ));
    assert!(matches!(
        journal.workspace_thread_summaries("alpha", 1, Some(&thread_cursor)),
        Err(ThreadSummaryListError::InvalidCursor)
    ));

    let scoped = journal
        .workspace_thread_summaries("alpha", 1, None)
        .unwrap()
        .next_cursor
        .unwrap();
    assert!(matches!(
        journal.workspace_thread_summaries("beta", 1, Some(&scoped)),
        Err(ThreadSummaryListError::InvalidCursor)
    ));
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&thread_cursor).unwrap()).unwrap();
    tampered["thread_id"] = json!(thread_for(&path, RUN_D));
    let tampered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap());
    assert!(matches!(
        journal.thread_summaries(1, Some(&tampered)),
        Err(ThreadSummaryListError::InvalidCursor)
    ));

    let boundary = thread_for(&path, RUN_A);
    journal
        .append_thread_deleted(1, &boundary, "2026-07-10T14:00:00Z", &provenance())
        .unwrap();
    assert!(matches!(
        journal.thread_summaries(1, Some(&thread_cursor)),
        Err(ThreadSummaryListError::InvalidCursor)
    ));
}
