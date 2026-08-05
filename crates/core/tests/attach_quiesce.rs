use muniment_core::attach::{evaluate_quiesce, QuiesceError, RuntimeActivity};

#[test]
fn accepts_clear_runtime_activity() {
    assert!(evaluate_quiesce(RuntimeActivity::default()).is_ok());
}

#[test]
fn rejects_each_blocker() {
    let cases = [
        (
            RuntimeActivity {
                active_run: true,
                ..RuntimeActivity::default()
            },
            QuiesceError::ActiveRun,
            "active run",
        ),
        (
            RuntimeActivity {
                pending_permission_gate: true,
                ..RuntimeActivity::default()
            },
            QuiesceError::PendingPermissionGate,
            "pending permission gate",
        ),
        (
            RuntimeActivity {
                authentication_operation: true,
                ..RuntimeActivity::default()
            },
            QuiesceError::AuthenticationOperation,
            "authentication operation",
        ),
        (
            RuntimeActivity {
                session_refresh: true,
                ..RuntimeActivity::default()
            },
            QuiesceError::SessionRefresh,
            "session refresh",
        ),
        (
            RuntimeActivity {
                in_flight_external_effect: true,
                ..RuntimeActivity::default()
            },
            QuiesceError::InFlightExternalEffect,
            "in-flight external effect",
        ),
    ];

    for (activity, expected, display) in cases {
        let error = evaluate_quiesce(activity).unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(error.to_string(), display);
    }
}

#[test]
fn reports_the_first_blocker_in_declared_field_order() {
    let blockers = [
        RuntimeActivity {
            active_run: true,
            ..RuntimeActivity::default()
        },
        RuntimeActivity {
            pending_permission_gate: true,
            ..RuntimeActivity::default()
        },
        RuntimeActivity {
            authentication_operation: true,
            ..RuntimeActivity::default()
        },
        RuntimeActivity {
            session_refresh: true,
            ..RuntimeActivity::default()
        },
        RuntimeActivity {
            in_flight_external_effect: true,
            ..RuntimeActivity::default()
        },
    ];
    let expected = [
        QuiesceError::ActiveRun,
        QuiesceError::PendingPermissionGate,
        QuiesceError::AuthenticationOperation,
        QuiesceError::SessionRefresh,
    ];

    for (index, expected) in expected.into_iter().enumerate() {
        let mut activity = blockers[index];
        let next = blockers[index + 1];
        activity.active_run |= next.active_run;
        activity.pending_permission_gate |= next.pending_permission_gate;
        activity.authentication_operation |= next.authentication_operation;
        activity.session_refresh |= next.session_refresh;
        activity.in_flight_external_effect |= next.in_flight_external_effect;

        assert_eq!(evaluate_quiesce(activity), Err(expected));
    }
}

#[test]
fn error_is_copy_and_implements_error() {
    fn assert_copy<T: Copy>() {}
    fn assert_error<T: std::error::Error>() {}

    assert_copy::<QuiesceError>();
    assert_error::<QuiesceError>();
}
