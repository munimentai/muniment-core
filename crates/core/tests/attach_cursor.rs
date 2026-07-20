use muniment_core::attach::*;

const _: () = assert!(MAX_RUN_STREAM_WINDOW_EVENTS > 0 && MAX_RUN_STREAM_WINDOW_BYTES > 0);

fn id(n: u128) -> Id {
    Id::new(format!("{n:032x}")).unwrap()
}

fn cursor(resume: u64, events: usize, bytes: usize) -> RunStreamCursor {
    RunStreamCursor::new(id(1), id(2), 1, resume.max(3), resume, events, bytes).unwrap()
}

#[test]
fn resumes_from_zero_and_a_committed_cursor() {
    let mut from_zero = RunStreamCursor::new(id(1), id(2), 1, 3, 0, 3, 30).unwrap();
    assert_eq!(
        from_zero.admit_event(&id(2), 1, 10).unwrap(),
        RunEventAdmission::Sent
    );
    assert_eq!(from_zero.highest_sent_run_seq(), 1);

    let mut resumed = cursor(2, 2, 20);
    assert_eq!(
        resumed.admit_event(&id(2), 3, 10).unwrap(),
        RunEventAdmission::Sent
    );
    assert_eq!(resumed.acknowledged_run_seq(), 2);
}

#[test]
fn event_and_byte_windows_pause_independently_without_consuming_the_event() {
    let mut events = cursor(0, 1, 100);
    events.admit_event(&id(2), 1, 10).unwrap();
    assert_eq!(
        events.admit_event(&id(2), 2, 10).unwrap(),
        RunEventAdmission::Paused
    );
    assert_eq!(events.highest_sent_run_seq(), 1);

    let mut bytes = cursor(0, 10, 10);
    bytes.admit_event(&id(2), 1, 6).unwrap();
    assert_eq!(
        bytes.admit_event(&id(2), 2, 5).unwrap(),
        RunEventAdmission::Paused
    );
    assert_eq!(bytes.outstanding_events(), 1);
    assert_eq!(bytes.outstanding_bytes(), 6);
}

#[test]
fn duplicate_partial_and_full_acknowledgements_release_exact_budget_and_resume() {
    let mut state = cursor(0, 3, 30);
    for (seq, bytes) in [(1, 5), (2, 10), (3, 15)] {
        state.admit_event(&id(2), seq, bytes).unwrap();
    }
    state.acknowledge(0).unwrap();
    assert_eq!(
        (state.outstanding_events(), state.outstanding_bytes()),
        (3, 30)
    );
    state.acknowledge(2).unwrap();
    assert_eq!(
        (state.outstanding_events(), state.outstanding_bytes()),
        (1, 15)
    );
    assert_eq!(
        state.admit_event(&id(2), 4, 15).unwrap(),
        RunEventAdmission::Sent
    );
    state.acknowledge(4).unwrap();
    assert_eq!(
        (state.outstanding_events(), state.outstanding_bytes()),
        (0, 0)
    );
}

#[test]
fn invalid_inputs_close_only_the_offending_subscription_without_mutation() {
    for invalid in [
        RunStreamCursor::new(id(1), id(2), 2, 3, 0, 1, 1),
        RunStreamCursor::new(id(1), id(2), 0, 3, 0, 1, 1),
        RunStreamCursor::new(id(1), id(2), 1, 3, 4, 1, 1),
        RunStreamCursor::new(id(1), id(2), 1, 3, 0, 0, 1),
        RunStreamCursor::new(id(1), id(2), 1, 3, 0, 1, 0),
    ] {
        assert_eq!(
            invalid.unwrap_err().error().code(),
            ErrorCode::InvalidCursor
        );
    }

    let mut state = cursor(0, 3, 30);
    state.admit_event(&id(2), 1, 10).unwrap();
    let snapshot = format!("{state:?}");
    for error in [
        state.acknowledge(2),
        state.admit_event(&id(2), 3, 10).map(|_| ()),
        state.admit_event(&id(99), 2, 10).map(|_| ()),
    ] {
        let error = error.unwrap_err();
        assert_eq!(error.error().code(), ErrorCode::InvalidCursor);
        assert_eq!(
            error.close(),
            StreamClose {
                code: StreamCloseCode::InvalidCursor,
                resumable: true
            }
        );
        assert_eq!(format!("{state:?}"), snapshot);
    }
    state.acknowledge(1).unwrap();
    let snapshot = format!("{state:?}");
    assert!(state.acknowledge(0).is_err());
    assert_eq!(format!("{state:?}"), snapshot);
}

#[test]
fn subscriptions_are_isolated_and_debug_and_wire_errors_are_redacted() {
    let mut first = cursor(0, 1, 10);
    let mut second = RunStreamCursor::new(id(3), id(2), 1, 3, 0, 1, 10).unwrap();
    first.admit_event(&id(2), 1, 10).unwrap();
    assert!(first.acknowledge(2).is_err());
    assert_eq!(
        second.admit_event(&id(2), 1, 10).unwrap(),
        RunEventAdmission::Sent
    );

    let error = ProtocolError::invalid_cursor();
    let text = format!("{error:?} {}", serde_json::to_string(&error).unwrap());
    for secret in ["/home", "token", "credential", "journal", "Pi"] {
        assert!(!text.contains(secret));
    }
    assert_eq!(
        serde_json::from_str::<ProtocolError>(&serde_json::to_string(&error).unwrap()).unwrap(),
        error
    );
}

#[test]
fn initial_metadata_and_limits_are_explicit_and_bounded() {
    let state = RunStreamCursor::new(id(7), id(8), 1, 0, 0, 4, 40).unwrap();
    assert_eq!(state.subscription_id(), &id(7));
    assert_eq!(state.run_id(), &id(8));
    assert_eq!(
        (state.first_available_run_seq(), state.current_run_seq()),
        (1, 0)
    );
    assert_eq!(state.window().max_events, 4);
    assert_eq!(state.window().max_bytes, 40);
}
