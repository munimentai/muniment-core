use muniment_core::chat_prompt::{
    fail_next_mock_prompt_delete_for_tests, load_prompt, store_prompt, use_mock_keyring_for_tests,
};
use muniment_core::journal::{EventEnvelope, EventPayload, Provenance};
use muniment_core::run_events::SharedStorage;
use muniment_core::run_preparation::{prepare_new_run_with_session_thread, SessionThreadStart};
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{apply_retention, open_profile_storage};
use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

mod common;
use common::TemporaryProfile;

fn event(run_id: &str, event_id: &str, run_seq: u64, event_type: &str, at: &str) -> EventEnvelope {
    EventEnvelope {
        event_id: event_id.into(),
        run_id: run_id.into(),
        run_seq,
        event_type: event_type.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: at.into(),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: "{}".parse().unwrap(),
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

fn prepare_recent_terminal_run(storage: &SharedStorage, run_id: &str) {
    prepare_new_run_with_session_thread(
        storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        run_id,
        "workspace-a",
        None,
        Vec::new(),
        None,
        "test",
        "1",
        || Ok(()),
    )
    .unwrap();
    let mut storage = storage.lock().unwrap();
    let started = storage.journal.events(run_id).unwrap().remove(0);
    storage
        .journal
        .append(
            1,
            &event(
                run_id,
                "01900000-0000-7000-8000-000000000004",
                2,
                "run.completed",
                &started.recorded_at,
            ),
        )
        .unwrap();
}

#[test]
fn deletes_an_expired_terminal_run_and_keeps_a_recent_run() {
    use_mock_keyring_for_tests();
    let temporary_profile = TemporaryProfile::new("retention", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();
    let expired_run = "01900000-0000-7000-8000-000000000001";
    let recent_run = "01900000-0000-7000-8000-000000000002";
    let retry_run = "01900000-0000-7000-8000-000000000003";
    let cas_failure_run = "01900000-0000-7000-8000-000000000007";
    let subject = "subject-a";
    {
        let mut storage = storage.lock().unwrap();
        storage
            .journal
            .append_batch(
                0,
                &[
                    {
                        let mut started = event(
                            expired_run,
                            "01900000-0000-7000-8000-000000000001",
                            1,
                            "run.started",
                            "2000-01-01T00:00:00Z",
                        );
                        started.provenance.actor_id = Some(subject.into());
                        started
                    },
                    event(
                        expired_run,
                        "01900000-0000-7000-8000-000000000002",
                        2,
                        "run.completed",
                        "2000-01-01T00:00:00Z",
                    ),
                ],
            )
            .unwrap();
    }
    prepare_recent_terminal_run(&storage, recent_run);
    store_prompt(expired_run, "expired prompt", Some(subject)).unwrap();

    let outcome = apply_retention(Arc::clone(&storage), 30 * 24 * 60 * 60).unwrap();

    assert_eq!(outcome.deleted_runs[0].run_id, expired_run);
    assert_eq!(outcome.deleted_runs[0].subject.as_deref(), Some(subject));
    assert_eq!(load_prompt(expired_run, Some(subject)).unwrap(), None);
    {
        let mut locked = storage.lock().unwrap();
        assert!(locked.journal.events(expired_run).unwrap().is_empty());
        assert_eq!(locked.journal.events(recent_run).unwrap().len(), 2);
    }

    {
        let mut storage = storage.lock().unwrap();
        let mut started = event(
            retry_run,
            "01900000-0000-7000-8000-000000000005",
            1,
            "run.started",
            "2000-01-01T00:00:00Z",
        );
        started.provenance.actor_id = Some(subject.into());
        storage
            .journal
            .append_batch(
                0,
                &[
                    started,
                    event(
                        retry_run,
                        "01900000-0000-7000-8000-000000000006",
                        2,
                        "run.completed",
                        "2000-01-01T00:00:00Z",
                    ),
                ],
            )
            .unwrap();
    }
    store_prompt(retry_run, "retry prompt", Some(subject)).unwrap();
    fail_next_mock_prompt_delete_for_tests();

    let error = apply_retention(Arc::clone(&storage), 30 * 24 * 60 * 60).unwrap_err();
    assert!(error.contains("injected prompt delete failure"), "{error}");
    assert_eq!(
        load_prompt(retry_run, Some(subject)).unwrap().as_deref(),
        Some("retry prompt")
    );
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .journal
            .events(retry_run)
            .unwrap()
            .len(),
        2
    );

    apply_retention(Arc::clone(&storage), 30 * 24 * 60 * 60).unwrap();
    assert_eq!(load_prompt(retry_run, Some(subject)).unwrap(), None);
    assert!(storage
        .lock()
        .unwrap()
        .journal
        .events(retry_run)
        .unwrap()
        .is_empty());

    {
        let mut storage = storage.lock().unwrap();
        let mut started = event(
            cas_failure_run,
            "01900000-0000-7000-8000-000000000007",
            1,
            "run.started",
            "2000-01-01T00:00:00Z",
        );
        started.provenance.actor_id = Some(subject.into());
        storage
            .journal
            .append_batch(
                0,
                &[
                    started,
                    event(
                        cas_failure_run,
                        "01900000-0000-7000-8000-000000000008",
                        2,
                        "run.completed",
                        "2000-01-01T00:00:00Z",
                    ),
                ],
            )
            .unwrap();
    }
    store_prompt(cas_failure_run, "CAS failure prompt", Some(subject)).unwrap();
    fs::remove_dir(profile.join("cas/objects")).unwrap();

    assert!(apply_retention(Arc::clone(&storage), 30 * 24 * 60 * 60).is_err());
    assert_eq!(load_prompt(cas_failure_run, Some(subject)).unwrap(), None);
    assert!(storage
        .lock()
        .unwrap()
        .journal
        .events(cas_failure_run)
        .unwrap()
        .is_empty());
    drop(storage);
}
