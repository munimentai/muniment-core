use muniment_core::attach::{
    evaluate_quiesce, DrainRefusal, DrainState, Operation, QuiesceError, RuntimeActivityRegistry,
};

#[test]
fn an_unmarked_registry_has_an_idle_snapshot() {
    assert!(evaluate_quiesce(RuntimeActivityRegistry::new().snapshot()).is_ok());
}

#[test]
fn each_mark_sets_its_runtime_activity_field() {
    let registry = RuntimeActivityRegistry::new();

    let guard = registry.mark_active_run();
    assert!(registry.snapshot().active_run);
    drop(guard);

    let guard = registry.mark_pending_permission_gate();
    assert!(registry.snapshot().pending_permission_gate);
    drop(guard);

    let guard = registry.mark_authentication_operation();
    assert!(registry.snapshot().authentication_operation);
    drop(guard);

    let guard = registry.mark_session_refresh();
    assert!(registry.snapshot().session_refresh);
    drop(guard);

    let guard = registry.mark_in_flight_external_effect();
    assert!(registry.snapshot().in_flight_external_effect);
    drop(guard);

    assert!(evaluate_quiesce(registry.snapshot()).is_ok());
}

#[test]
fn overlapping_marks_stay_busy_until_both_guards_drop() {
    let registry = RuntimeActivityRegistry::new();
    let first = registry.mark_active_run();
    let second = registry.mark_active_run();

    drop(first);
    assert!(registry.snapshot().active_run);

    drop(second);
    assert!(!registry.snapshot().active_run);
}

#[test]
fn overlapping_marks_clear_in_either_drop_order() {
    let registry = RuntimeActivityRegistry::new();
    let first = registry.mark_session_refresh();
    let second = registry.mark_session_refresh();

    drop(second);
    assert!(registry.snapshot().session_refresh);

    drop(first);
    assert!(!registry.snapshot().session_refresh);
}

#[test]
fn clones_share_marks() {
    let registry = RuntimeActivityRegistry::new();
    let clone = registry.clone();
    let guard = clone.mark_in_flight_external_effect();

    assert!(registry.snapshot().in_flight_external_effect);
    drop(guard);
    assert!(!clone.snapshot().in_flight_external_effect);
}

#[test]
fn snapshot_feeds_the_existing_quiesce_rule() {
    let registry = RuntimeActivityRegistry::new();
    let _guard = registry.mark_pending_permission_gate();

    assert_eq!(
        evaluate_quiesce(registry.snapshot()),
        Err(QuiesceError::PendingPermissionGate)
    );
}

#[test]
fn drain_state_is_shared_and_one_way() {
    let drain = DrainState::new();
    let clone = drain.clone();
    assert!(!drain.is_set());

    clone.set();
    drain.set();

    assert!(drain.is_set());
    assert!(clone.is_set());
}

#[test]
fn drain_refuses_new_blocking_work() {
    let drain = DrainState::new();
    drain.set();

    for operation in [
        Operation::RunStart,
        Operation::RunSubmit,
        Operation::RunResume,
        Operation::SessionSignIn,
    ] {
        assert_eq!(drain.admit(operation), Err(DrainRefusal));
    }
}

#[test]
fn drain_allows_work_that_finishes_or_observes_a_run() {
    let drain = DrainState::new();
    drain.set();

    for operation in [
        Operation::RunPermissionAnswer,
        Operation::RunCancel,
        Operation::ThreadOpen,
        Operation::RunStream,
    ] {
        assert_eq!(drain.admit(operation), Ok(()));
    }
}
