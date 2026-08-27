#![cfg(target_os = "windows")]

use muniment_core::windows_task::SidError;
use muniment_core::windows_task_service::{
    read_observed_registration, ReadObservedRegistrationError,
};

#[test]
fn absent_runtime_task_returns_none() {
    let observed = read_observed_registration("S-1-5-999999999").unwrap();

    assert_eq!(observed, None);
}

#[test]
fn non_canonical_sid_is_rejected_before_scheduler_access() {
    let error = read_observed_registration("S-1-05-21").unwrap_err();

    assert_eq!(
        error,
        ReadObservedRegistrationError::InvalidSid(SidError::NotCanonical)
    );
}
