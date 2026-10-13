use std::collections::BTreeMap;
use std::sync::Arc;

use muniment_core::journal::Provenance;
use muniment_core::run_events::SharedStorage;
use muniment_core::run_preparation::{
    prepare_new_run_in_thread_after_validation, prepare_new_run_with_session_thread,
    SessionThreadStart,
};
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{
    create_thread, delete_thread, open_profile_storage, rename_thread, select_thread, thread_page,
    thread_summaries,
};

mod common;
use common::TemporaryProfile;

fn prepare_run(storage: &SharedStorage, run_id: &str, subject: &str) -> String {
    prepare_new_run_with_session_thread(
        storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        run_id,
        "workspace-a",
        Some(subject),
        Vec::new(),
        None,
        "test",
        "1",
        || Ok(()),
    )
    .unwrap();
    let thread_id = storage
        .lock()
        .unwrap()
        .journal
        .run_thread_id(run_id)
        .unwrap()
        .unwrap();
    thread_id
}

fn attach_provenance() -> Provenance {
    let mut provenance = Provenance {
        source: "test".into(),
        source_version: "1".into(),
        actor_id: None,
        device_id: None,
        rpc_request_id: None,
        capability_versions: None,
        extra: BTreeMap::new(),
    };
    provenance
        .extra
        .insert("attach_profile".into(), "profile-a".into());
    provenance
}

#[test]
fn creates_a_thread_for_a_run_and_rejects_invalid_inputs_without_events() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary_profile = TemporaryProfile::new("thread-create", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();

    assert!(create_thread(
        Arc::clone(&storage),
        String::new(),
        "profile-a".into(),
        env!("CARGO_PKG_VERSION")
    )
    .is_err());
    assert!(create_thread(
        Arc::clone(&storage),
        "workspace-a".into(),
        String::new(),
        env!("CARGO_PKG_VERSION")
    )
    .is_err());
    assert!(
        thread_summaries(Arc::clone(&storage), Some("owner".into()), 10, None)
            .unwrap()
            .summaries
            .is_empty()
    );

    let thread_id = create_thread(
        Arc::clone(&storage),
        "workspace-a".into(),
        "profile-a".into(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    let run_id = "01900000-0000-7000-8000-000000000000";
    prepare_new_run_in_thread_after_validation(
        &storage,
        run_id,
        "workspace-a",
        Some("owner"),
        Vec::new(),
        Some(attach_provenance()),
        &thread_id,
        "test",
        "1",
        || Ok(()),
    )
    .unwrap();

    let page = thread_page(
        &profile,
        Arc::clone(&storage),
        &std::sync::Mutex::new(None),
        Some("owner".into()),
        thread_id,
        10,
        None,
    )
    .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].run_id, run_id);

    drop(storage);
}

#[test]
fn thread_history_uses_runtime_ownership_for_an_open_effect() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary = TemporaryProfile::new("thread-live-effect", false);
    let storage = open_profile_storage(&temporary.profile).unwrap();
    let run_id = "01900000-0000-7000-8000-000000000009";
    let thread_id = prepare_run(&storage, run_id, "owner");
    {
        let mut storage = storage.lock().unwrap();
        let mut event = storage.journal.events(run_id).unwrap().remove(0);
        event.extra.clear();
        event.event_id = "01900000-0000-7000-8000-000000000010".into();
        event.run_seq = 2;
        event.event_type = "tool.effect.started".into();
        event.payload = muniment_core::journal::EventPayload::Inline {
            payload_json: muniment_core::serde_json::json!({"effect_id": "mcp-1"}),
        };
        storage.journal.append(1, &event).unwrap();
    }
    let activity = muniment_core::attach::RuntimeActivityRegistry::default();
    let active = std::sync::Mutex::new(Some(muniment_core::run_start::ActiveRun {
        id: run_id.into(),
        workspace: "workspace-a".into(),
        cancelled: Default::default(),
        transport: Default::default(),
        adapter: Default::default(),
        permission_answers: Default::default(),
        _activity: activity.mark_active_run(),
    }));
    let read = || {
        thread_page(
            &temporary.profile,
            Arc::clone(&storage),
            &active,
            Some("owner".into()),
            thread_id.clone(),
            10,
            None,
        )
        .unwrap()
        .entries
        .remove(0)
    };
    assert_eq!(read().phase, "thinking");
    assert!(read().failure_reason.is_none());
    muniment_core::chat_resume::clear_active_run(&active, run_id);
    let interrupted = read();
    assert_eq!(interrupted.phase, "interrupted");
    assert_eq!(
        interrupted.failure_reason.as_deref(),
        Some("unknown-effect-outcome")
    );
    assert!(!interrupted.resumable);
}

#[test]
fn lists_threads_and_opens_the_selected_thread() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary_profile = TemporaryProfile::new("threads-list", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();
    let first_run = "01900000-0000-7000-8000-000000000001";
    let second_run = "01900000-0000-7000-8000-000000000002";
    let first_thread = prepare_run(&storage, first_run, "owner");
    let second_thread = prepare_run(&storage, second_run, "owner");

    let summaries = thread_summaries(Arc::clone(&storage), Some("owner".into()), 10, None).unwrap();

    assert_eq!(summaries.summaries.len(), 2);
    assert!(summaries
        .summaries
        .iter()
        .any(|summary| summary.thread_id == first_thread));
    assert!(summaries
        .summaries
        .iter()
        .any(|summary| summary.thread_id == second_thread));
    let page = thread_page(
        &profile,
        Arc::clone(&storage),
        &std::sync::Mutex::new(None),
        Some("owner".into()),
        first_thread,
        10,
        None,
    )
    .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].run_id, first_run);

    drop(storage);
}

#[test]
fn thread_operations_report_the_poisoned_storage_lock() {
    let profile = TemporaryProfile::new("thread-lock", false);
    let storage = open_profile_storage(&profile.profile).unwrap();
    let poisoned = Arc::clone(&storage);
    assert!(std::thread::spawn(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("poison the storage lock");
    })
    .join()
    .is_err());
    let expected = format!(
        "Conversation history lock failed: {}",
        storage.lock().err().unwrap()
    );
    let errors = [
        thread_summaries(Arc::clone(&storage), None, 10, None)
            .err()
            .unwrap(),
        select_thread(Arc::clone(&storage), None, "thread".into()).unwrap_err(),
        muniment_runtime_core::create_thread(
            Arc::clone(&storage),
            "local".into(),
            "default".into(),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err(),
        rename_thread(
            Arc::clone(&storage),
            None,
            "thread".into(),
            "title".into(),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err(),
        delete_thread(
            Arc::clone(&storage),
            None,
            "thread".into(),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap_err(),
        muniment_runtime_core::apply_retention(Arc::clone(&storage), 0).unwrap_err(),
        thread_page(
            &profile.profile,
            Arc::clone(&storage),
            &std::sync::Mutex::new(None),
            None,
            "thread".into(),
            10,
            None,
        )
        .err()
        .unwrap(),
    ];
    for error in errors {
        assert_eq!(error, expected);
    }
}

#[test]
fn history_and_ownership_keep_the_underlying_journal_error() {
    let profile = TemporaryProfile::new("thread-journal-error", false);
    let storage = open_profile_storage(&profile.profile).unwrap();
    let run_id = "01900000-0000-7000-8000-000000000008";
    let thread_id = prepare_run(&storage, run_id, "owner");
    common::remove_journal_tables(&profile.profile, &["events"]);
    let ownership = select_thread(
        Arc::clone(&storage),
        Some("owner".into()),
        thread_id.clone(),
    )
    .unwrap_err();
    let history = thread_page(
        &profile.profile,
        Arc::clone(&storage),
        &std::sync::Mutex::new(None),
        Some("owner".into()),
        thread_id,
        10,
        None,
    )
    .err()
    .unwrap();
    for error in [ownership, history] {
        assert!(error.contains("FirstEnvelopeUnavailable"), "{error}");
        assert!(error.contains("no such table: events"), "{error}");
    }
    let error = muniment_core::thread_history::project_history_entry(
        &mut storage.lock().unwrap().journal,
        None,
        run_id.into(),
        Some("owner"),
        &profile.profile,
    )
    .err()
    .unwrap();
    let error = format!("{error:?}");
    assert!(error.contains("RunEventsUnavailable"), "{error}");
    assert!(error.contains("no such table: events"), "{error}");
}

#[test]
fn rejects_a_thread_owned_by_another_subject() {
    let temporary_profile = TemporaryProfile::new("thread-owner", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();
    let thread_id = prepare_run(&storage, "01900000-0000-7000-8000-000000000003", "owner");

    let error = thread_page(
        &profile,
        storage,
        &std::sync::Mutex::new(None),
        Some("other".into()),
        thread_id,
        10,
        None,
    )
    .err()
    .unwrap();

    assert_eq!(
        error,
        "Conversation history journal operation failed: ThreadNotOwned"
    );
}

#[test]
fn selects_only_an_owned_accessible_thread() {
    let temporary_profile = TemporaryProfile::new("thread-select", false);
    let storage = open_profile_storage(&temporary_profile.profile).unwrap();
    let thread_id = prepare_run(&storage, "01900000-0000-7000-8000-000000000007", "owner");

    assert!(select_thread(
        Arc::clone(&storage),
        Some("owner".into()),
        thread_id.clone(),
    )
    .unwrap());
    assert!(!select_thread(
        Arc::clone(&storage),
        Some("other".into()),
        thread_id.clone(),
    )
    .unwrap());

    delete_thread(
        Arc::clone(&storage),
        Some("owner".into()),
        thread_id.clone(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    assert!(select_thread(storage, Some("owner".into()), thread_id).is_err());
}

#[test]
fn renames_and_deletes_owned_threads() {
    let temporary_profile = TemporaryProfile::new("thread-mutations", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();
    let renamed_thread = prepare_run(&storage, "01900000-0000-7000-8000-000000000004", "owner");
    let deleted_thread = prepare_run(&storage, "01900000-0000-7000-8000-000000000005", "owner");

    rename_thread(
        Arc::clone(&storage),
        Some("owner".into()),
        renamed_thread.clone(),
        "New title".into(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    delete_thread(
        Arc::clone(&storage),
        Some("owner".into()),
        deleted_thread.clone(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();

    {
        let mut storage = storage.lock().unwrap();
        let rename_events = storage.journal.thread_events(&renamed_thread).unwrap();
        let rename_event = rename_events.last().unwrap();
        assert_eq!(rename_event.event_type, "thread.title.renamed");
        assert_eq!(rename_event.provenance.source, "muniment-runtime");
        assert_eq!(
            rename_event.provenance.source_version,
            env!("CARGO_PKG_VERSION")
        );

        let delete_events = storage.journal.thread_events(&deleted_thread).unwrap();
        let delete_event = delete_events.last().unwrap();
        assert_eq!(delete_event.event_type, "thread.deleted");
        assert_eq!(delete_event.provenance.source, "muniment-runtime");
        assert_eq!(
            delete_event.provenance.source_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    let summaries = thread_summaries(Arc::clone(&storage), Some("owner".into()), 10, None).unwrap();
    assert_eq!(summaries.summaries.len(), 1);
    assert_eq!(summaries.summaries[0].thread_id, renamed_thread);
    assert_eq!(summaries.summaries[0].title, "New title");
    assert!(!summaries
        .summaries
        .iter()
        .any(|summary| summary.thread_id == deleted_thread));

    drop(storage);
}

#[test]
fn rejects_mutations_by_another_subject_without_appending_events() {
    let temporary_profile = TemporaryProfile::new("thread-mutation-owner", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();
    let thread_id = prepare_run(&storage, "01900000-0000-7000-8000-000000000006", "owner");

    assert_eq!(
        rename_thread(
            Arc::clone(&storage),
            Some("other".into()),
            thread_id.clone(),
            "New title".into(),
            env!("CARGO_PKG_VERSION")
        )
        .unwrap_err(),
        "Conversation history journal operation failed: NotOwned"
    );
    assert_eq!(
        delete_thread(
            Arc::clone(&storage),
            Some("other".into()),
            thread_id.clone(),
            env!("CARGO_PKG_VERSION")
        )
        .unwrap_err(),
        "Conversation history journal operation failed: NotOwned"
    );
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .journal
            .last_thread_seq(&thread_id)
            .unwrap(),
        1
    );

    drop(storage);
}
