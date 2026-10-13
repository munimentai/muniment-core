#![cfg(target_os = "linux")]

use std::sync::Arc;

use muniment_core::attach::ProtocolError;
use muniment_core::run_preparation::{prepare_new_run_with_session_thread, SessionThreadStart};
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{open_profile_storage, stream_run, subscribe_run_commits};

mod common;
use common::TemporaryProfile;

#[test]
fn reads_a_run_stream_and_subscribes_to_its_commits() {
    let temporary_profile = TemporaryProfile::new("run-stream", false);
    let profile = temporary_profile.profile.clone();
    let storage = open_profile_storage(&profile).unwrap();
    let run_id = "01900000-0000-7000-8000-000000000010";

    let (current_run_seq, _) = prepare_new_run_with_session_thread(
        &storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        run_id,
        "workspace-a",
        Some("owner"),
        Vec::new(),
        None,
        "test",
        "1",
        || Ok(()),
    )
    .unwrap();

    let page = stream_run(Arc::clone(&storage), "workspace-a".into(), run_id.into(), 0).unwrap();
    assert_eq!(page.run_id, run_id);
    assert_eq!(page.current_run_seq, current_run_seq);
    assert_eq!(
        page.events
            .iter()
            .map(|event| (event.run_seq, event.event_type.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "run.started")]
    );

    let error = stream_run(
        Arc::clone(&storage),
        "workspace-a".into(),
        run_id.into(),
        current_run_seq + 1,
    )
    .unwrap_err();
    assert_eq!(error, ProtocolError::invalid_cursor());

    let subscription = subscribe_run_commits(Arc::clone(&storage), run_id.into())
        .unwrap()
        .expect("the file-backed journal should open a subscription");
    assert_eq!(subscription.committed_high_water, current_run_seq);

    drop(subscription);
    drop(storage);
}
