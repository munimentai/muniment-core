#![cfg(target_os = "windows")]

use std::time::{Duration, Instant};

use muniment_core::attach::{
    connect_windows_attach_endpoint, wait_for_windows_attach_pipe_with, WindowsAttachConnectError,
    WindowsAttachListener,
};
use windows_sys::Win32::Foundation::ERROR_SEM_TIMEOUT;

#[test]
fn connects_to_a_live_current_user_endpoint_and_bounds_a_busy_wait() {
    let listener = WindowsAttachListener::bind().unwrap();
    let stream = connect_windows_attach_endpoint(Instant::now() + Duration::from_secs(1)).unwrap();

    let busy = connect_windows_attach_endpoint(Instant::now() + Duration::from_millis(20));
    assert!(matches!(
        busy,
        Err(WindowsAttachConnectError::DeadlineExpired)
    ));

    drop(stream);
    drop(listener);
    let absent = connect_windows_attach_endpoint(Instant::now() + Duration::from_secs(1));
    assert!(matches!(
        absent,
        Err(WindowsAttachConnectError::EndpointAbsent)
    ));
}

#[test]
fn timed_out_wait_retries_while_the_deadline_remains() {
    let start = Instant::now();
    let deadline = start + Duration::from_nanos(1_000_001);
    let mut times = [start, start + Duration::from_millis(1)].into_iter();
    let mut waits = Vec::new();

    let result = wait_for_windows_attach_pipe_with(
        deadline,
        || times.next().unwrap(),
        |milliseconds| {
            waits.push(milliseconds);
            if waits.len() == 1 {
                Err(ERROR_SEM_TIMEOUT)
            } else {
                Ok(())
            }
        },
    );

    assert_eq!(result, Ok(()));
    assert_eq!(waits, [2, 1]);
}

#[test]
fn rejects_an_expired_deadline_before_opening_the_endpoint() {
    let result = connect_windows_attach_endpoint(Instant::now());

    assert!(matches!(
        result,
        Err(WindowsAttachConnectError::DeadlineExpired)
    ));
}
