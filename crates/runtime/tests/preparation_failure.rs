use std::sync::{Arc, Mutex};

use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::journal::EventPayload;
use muniment_runtime_core::{
    accept_prompt, open_profile_storage, RuntimeChatEventTarget, RuntimeHost,
};

mod common;
use common::{fixture_grant, TemporaryProfile};

#[test]
fn memory_session_failure_ends_the_prepared_run() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary_profile = TemporaryProfile::new("preparation-failure", false);
    let profile = temporary_profile.profile.clone();
    let config = temporary_profile.config.clone();
    std::fs::write(config.join("home.json"), "invalid json").unwrap();
    let storage = open_profile_storage(&profile).unwrap();
    let active = Arc::new(Mutex::new(None));
    let runtime_activity = RuntimeActivityRegistry::new();
    let run_id = "018f0000-0000-7000-8000-000000000001";

    let result = accept_prompt(
        &RuntimeHost::default(),
        &profile,
        Arc::clone(&storage),
        Arc::new(Mutex::new(None)),
        &runtime_activity,
        &config,
        run_id.into(),
        "prompt".into(),
        None,
        &muniment_core::session_thread::SessionThread::default(),
        false,
        "token".into(),
        Some("owner".into()),
        Vec::new(),
        fixture_grant(),
        Arc::clone(&active),
        RuntimeChatEventTarget::Subscriber(None),
        None,
    );
    let error = match result {
        Ok(_) => panic!("the memory session opened with an invalid Home record"),
        Err(error) => error,
    };

    assert!(error.starts_with("Conversation history memory session failed: Io("));
    assert!(error.contains("The saved Home location is invalid."));
    assert_eq!(
        std::fs::read_to_string(config.join("home.json")).unwrap(),
        "invalid json"
    );
    assert!(active.lock().unwrap().is_none());
    let events = storage.lock().unwrap().journal.events(run_id).unwrap();
    let failed = events.last().unwrap();
    assert_eq!(failed.run_seq, 2);
    assert_eq!(failed.event_type, "run.failed");
    match &failed.payload {
        EventPayload::Inline { payload_json } => {
            assert_eq!(
                payload_json.get("reason").and_then(|value| value.as_str()),
                Some("persistence")
            );
        }
        _ => panic!("run.failed did not use an inline payload"),
    }
    drop(events);
    drop(storage);

    let reopened = open_profile_storage(&profile).unwrap();
    let events = reopened.lock().unwrap().journal.events(run_id).unwrap();
    assert!(events
        .iter()
        .all(|event| event.event_type != "run.needs_attention"));
    drop(events);
    drop(reopened);
}
