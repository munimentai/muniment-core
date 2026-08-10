use muniment_code_diff::{canonical_bytes, CodeDiff};
use muniment_core::cas::{ContentHash, LocalCas};
use muniment_core::code_diff_journal::{
    append_code_diff_permission_request, load_code_diff_proposal, stage_code_diff_proposal,
    AppendCodeDiffPermissionError, LoadCodeDiffError, DIFF_EVENT_TYPE, DIFF_MEDIA_TYPE,
    EVENT_VERSION, WRITE_PLAN_EVENT_TYPE,
};
use muniment_core::journal::{
    reducer::PermissionRequest, EventEnvelope, EventPayload, Provenance, RunJournal,
};
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
fn stages_and_loads_a_verified_proposal() {
    let root = TestRoot::new();
    let cas = LocalCas::open(&root.as_ref().join("cas")).unwrap();
    let mut journal = RunJournal::open(root.as_ref().join("journal.sqlite3")).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let effect_id = Uuid::now_v7().to_string();
    journal.append(0, &initial_event(&run_id)).unwrap();
    let expected = proposal();
    stage_code_diff_proposal(
        &mut journal,
        &cas,
        &run_id,
        &effect_id,
        &expected.0,
        &expected.1,
    )
    .unwrap();

    let loaded = load_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id)
        .unwrap()
        .unwrap();

    assert_eq!(loaded, expected);
    assert!(
        load_code_diff_proposal(&mut journal, &cas, &run_id, "other-effect")
            .unwrap()
            .is_none()
    );
}

#[test]
fn appends_a_permission_bound_to_the_stored_proposal_pair() {
    let root = TestRoot::new();
    let cas = LocalCas::open(&root.as_ref().join("cas")).unwrap();
    let mut journal = RunJournal::open(root.as_ref().join("journal.sqlite3")).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let effect_id = Uuid::now_v7().to_string();
    journal.append(0, &initial_event(&run_id)).unwrap();
    let (plan, diff) = proposal();
    stage_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id, &plan, &diff).unwrap();
    let proposal_events = journal.events(&run_id).unwrap();
    let EventPayload::Cas {
        payload_cas: plan_cas,
    } = &proposal_events[1].payload
    else {
        panic!("write plan must use CAS");
    };
    let EventPayload::Cas {
        payload_cas: diff_cas,
    } = &proposal_events[2].payload
    else {
        panic!("code diff must use CAS");
    };

    let gate =
        append_code_diff_permission_request(&mut journal, &cas, &run_id, &effect_id).unwrap();

    assert_eq!(
        Uuid::parse_str(&gate.gate_id).unwrap().get_version(),
        Some(uuid::Version::SortRand)
    );
    assert_eq!(
        gate.request,
        PermissionRequest::CodeDiff {
            effect_id: effect_id.clone(),
            code_diff_id: diff.id,
            diff_sha256: diff_cas.sha256.clone(),
            write_plan_sha256: plan_cas.sha256.clone(),
        }
    );
    let events = journal.events(&run_id).unwrap();
    assert_eq!(events.len(), 4);
    assert_eq!(events[3].event_type, "permission.requested");
    assert_eq!(
        events[3].causation_id.as_deref(),
        Some(events[2].event_id.as_str())
    );
    let EventPayload::Inline { payload_json } = &events[3].payload else {
        panic!("permission request must use an inline payload");
    };
    assert_eq!(serde_json::to_value(&gate).unwrap(), *payload_json);
}

#[test]
fn truncated_proposal_opens_no_permission_gate() {
    let root = TestRoot::new();
    let cas = LocalCas::open(&root.as_ref().join("cas")).unwrap();
    let mut journal = RunJournal::open(root.as_ref().join("journal.sqlite3")).unwrap();
    let run_id = Uuid::now_v7().to_string();
    let effect_id = Uuid::now_v7().to_string();
    journal.append(0, &initial_event(&run_id)).unwrap();
    let (plan, mut diff) = proposal();
    diff.truncated = true;
    stage_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id, &plan, &diff).unwrap();

    assert!(matches!(
        append_code_diff_permission_request(&mut journal, &cas, &run_id, &effect_id),
        Err(AppendCodeDiffPermissionError::Truncated)
    ));
    assert_eq!(journal.events(&run_id).unwrap().len(), 3);
}

#[test]
fn reports_missing_and_tampered_cas_objects_separately() {
    for tamper in [false, true] {
        let root = TestRoot::new();
        let cas_root = root.as_ref().join("cas");
        let cas = LocalCas::open(&cas_root).unwrap();
        let mut journal = RunJournal::open(root.as_ref().join("journal.sqlite3")).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();
        let (plan, diff) = proposal();
        stage_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id, &plan, &diff).unwrap();
        let events = journal.events(&run_id).unwrap();
        let EventPayload::Cas { payload_cas } = &events[0].payload else {
            unreachable!();
        };
        let hash = ContentHash::from_str(&payload_cas.sha256).unwrap();
        if tamper {
            let path = cas_root
                .join("objects")
                .join(&payload_cas.sha256[..2])
                .join(&payload_cas.sha256[2..]);
            fs::write(path, b"tampered").unwrap();
            assert!(matches!(
                load_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id),
                Err(LoadCodeDiffError::TamperedCasObject { .. })
            ));
        } else {
            cas.remove(&hash).unwrap();
            assert!(matches!(
                load_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id),
                Err(LoadCodeDiffError::MissingCasObject(found)) if found == hash
            ));
        }
    }
}

#[test]
fn reports_wrong_media_type_and_broken_event_link_separately() {
    for media_type_error in [true, false] {
        let root = TestRoot::new();
        let database = root.as_ref().join("journal.sqlite3");
        let cas = LocalCas::open(&root.as_ref().join("cas")).unwrap();
        let mut journal = RunJournal::open(&database).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();
        let (plan, diff) = proposal();
        stage_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id, &plan, &diff).unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        let path = if media_type_error {
            "$.payload_cas.media_type"
        } else {
            "$.causation_id"
        };
        connection
            .execute(
                "UPDATE events SET envelope_json=json_set(envelope_json, ?1, 'wrong') WHERE event_type=?2",
                (path, DIFF_EVENT_TYPE),
            )
            .unwrap();
        drop(connection);

        let error = load_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id).unwrap_err();
        if media_type_error {
            assert!(matches!(error, LoadCodeDiffError::WrongMediaType { .. }));
        } else {
            assert!(matches!(error, LoadCodeDiffError::BrokenEventLink));
        }
    }
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
