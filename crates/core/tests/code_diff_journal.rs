use muniment_code_diff::{canonical_bytes, CodeDiff};
use muniment_core::cas::{ContentHash, LocalCas};
use muniment_core::code_diff_journal::{
    stage_code_diff_proposal, DIFF_EVENT_TYPE, DIFF_MEDIA_TYPE, EVENT_VERSION,
    WRITE_PLAN_EVENT_TYPE,
};
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance, RunJournal};
use muniment_core::write_plan::{WritePlan, MEDIA_TYPE as WRITE_PLAN_MEDIA_TYPE};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use uuid::Uuid;

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("muniment-code-diff-journal-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl AsRef<Path> for TestRoot {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn initial_event(run_id: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq: 1,
        event_type: "run.started".into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: "2026-08-10T12:00:00Z".into(),
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

fn proposal() -> (WritePlan, CodeDiff) {
    (
        WritePlan::new(vec![]).unwrap(),
        CodeDiff {
            schema_version: 1,
            id: "proposal-1".into(),
            files: vec![],
            truncated: false,
        },
    )
}

#[test]
fn stores_objects_and_appends_linked_events_in_order() {
    let root = TestRoot::new();
    let database = root.as_ref().join("journal.sqlite3");
    let cas = LocalCas::open(&root.as_ref().join("cas")).unwrap();
    let mut journal = RunJournal::open(&database).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let effect_id = Uuid::now_v7().to_string();
    journal.append(0, &initial_event(&run_id)).unwrap();
    let (plan, diff) = proposal();

    stage_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id, &plan, &diff).unwrap();

    let events = journal.events(&run_id).unwrap();
    let plan_event = &events[1];
    let diff_event = &events[2];
    assert_eq!(plan_event.event_type, WRITE_PLAN_EVENT_TYPE);
    assert_eq!(diff_event.event_type, DIFF_EVENT_TYPE);
    assert_eq!(plan_event.event_version, EVENT_VERSION);
    assert_eq!(diff_event.event_version, EVENT_VERSION);
    assert_eq!(
        plan_event.correlation_id.as_deref(),
        Some(effect_id.as_str())
    );
    assert_eq!(
        diff_event.correlation_id.as_deref(),
        Some(effect_id.as_str())
    );
    assert_eq!(
        diff_event.causation_id.as_deref(),
        Some(plan_event.event_id.as_str())
    );

    let expected = [
        (plan.encode().unwrap(), WRITE_PLAN_MEDIA_TYPE),
        (canonical_bytes(&diff).unwrap(), DIFF_MEDIA_TYPE),
    ];
    for (event, (bytes, media_type)) in events[1..].iter().zip(expected) {
        let EventPayload::Cas { payload_cas } = &event.payload else {
            panic!("proposal event must use a CAS payload");
        };
        assert_eq!(payload_cas.media_type, media_type);
        assert_eq!(payload_cas.byte_length, bytes.len() as u64);
        let hash = ContentHash::from_str(&payload_cas.sha256).unwrap();
        assert_eq!(cas.get_verified(&hash).unwrap(), bytes);
    }
}

#[test]
fn journal_failure_rolls_back_both_events() {
    let root = TestRoot::new();
    let database = root.as_ref().join("journal.sqlite3");
    let cas = LocalCas::open(&root.as_ref().join("cas")).unwrap();
    let mut journal = RunJournal::open(&database).unwrap();
    let run_id = Uuid::now_v7().to_string();
    journal.append(0, &initial_event(&run_id)).unwrap();
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_diff BEFORE INSERT ON events
             WHEN NEW.event_type = 'code.diff.proposed'
             BEGIN SELECT RAISE(ABORT, 'rejected test diff'); END;",
        )
        .unwrap();
    drop(connection);
    let (plan, diff) = proposal();

    assert!(stage_code_diff_proposal(
        &mut journal,
        &cas,
        &run_id,
        &Uuid::now_v7().to_string(),
        &plan,
        &diff,
    )
    .is_err());

    let events = journal.events(&run_id).unwrap();
    assert_eq!(events.len(), 1);
}
