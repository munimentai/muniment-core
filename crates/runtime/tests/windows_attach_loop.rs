#![cfg(unix)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use muniment_runtime_core::{
    run_windows_attach_accept_loop, WindowsAttachAcceptBoundary, WindowsAttachAcceptLoopExit,
    WindowsAttachAcceptOutcome, WindowsAttachStopSignal, MAX_CONSECUTIVE_FAILED_ACCEPTS,
};

#[derive(Clone, Copy)]
struct FakeStopSignal;

impl WindowsAttachStopSignal for FakeStopSignal {
    fn signal(&self) {}
}

struct FakeAcceptor {
    outcomes: VecDeque<WindowsAttachAcceptOutcome>,
    calls: Vec<Instant>,
}

impl WindowsAttachAcceptBoundary for FakeAcceptor {
    type StopSignal = FakeStopSignal;

    fn stop_signal(&self) -> Self::StopSignal {
        FakeStopSignal
    }

    fn serve_next(&mut self) -> WindowsAttachAcceptOutcome {
        self.calls.push(Instant::now());
        self.outcomes.pop_front().unwrap()
    }
}

#[test]
fn a_stopped_outcome_exits_the_loop() {
    let mut acceptor = FakeAcceptor {
        outcomes: VecDeque::from([WindowsAttachAcceptOutcome::Stopped]),
        calls: Vec::new(),
    };

    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::Stopped
    );
    assert_eq!(acceptor.calls.len(), 1);
}

#[test]
fn served_outcomes_start_the_next_accept_without_a_retry_delay() {
    let mut acceptor = FakeAcceptor {
        outcomes: VecDeque::from([
            WindowsAttachAcceptOutcome::Served,
            WindowsAttachAcceptOutcome::Served,
            WindowsAttachAcceptOutcome::Stopped,
        ]),
        calls: Vec::new(),
    };

    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::Stopped
    );
    assert_eq!(acceptor.calls.len(), 3);
}

#[test]
fn a_failed_outcome_delays_the_next_accept() {
    let mut acceptor = FakeAcceptor {
        outcomes: VecDeque::from([
            WindowsAttachAcceptOutcome::Failed,
            WindowsAttachAcceptOutcome::Stopped,
        ]),
        calls: Vec::new(),
    };

    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::Stopped
    );
    assert_eq!(acceptor.calls.len(), 2);
    assert!(acceptor.calls[1].duration_since(acceptor.calls[0]) >= Duration::from_millis(50));
}

#[test]
fn consecutive_failed_outcomes_reach_the_failed_exit() {
    let mut acceptor = FakeAcceptor {
        outcomes: std::iter::repeat_n(
            WindowsAttachAcceptOutcome::Failed,
            MAX_CONSECUTIVE_FAILED_ACCEPTS,
        )
        .collect(),
        calls: Vec::new(),
    };

    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::Failed
    );
    assert_eq!(acceptor.calls.len(), MAX_CONSECUTIVE_FAILED_ACCEPTS);
}

#[test]
fn the_failed_exit_keeps_the_last_accept_error() {
    use muniment_core::attach::WindowsAttachAcceptError;

    let last_error = WindowsAttachAcceptError::VerifyInstanceSecurity(Some(5));
    let mut acceptor = FakeAcceptor {
        outcomes: std::iter::repeat_n(
            WindowsAttachAcceptOutcome::AcceptFailed(WindowsAttachAcceptError::Connect(232)),
            MAX_CONSECUTIVE_FAILED_ACCEPTS - 1,
        )
        .chain([WindowsAttachAcceptOutcome::AcceptFailed(last_error)])
        .collect(),
        calls: Vec::new(),
    };
    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::AcceptFailed(last_error)
    );
    assert_eq!(acceptor.calls.len(), MAX_CONSECUTIVE_FAILED_ACCEPTS);
}

#[test]
fn a_served_outcome_resets_typed_accept_failures() {
    use muniment_core::attach::WindowsAttachAcceptError;

    let failures = std::iter::repeat_n(
        WindowsAttachAcceptOutcome::AcceptFailed(WindowsAttachAcceptError::CreateEvent(8)),
        MAX_CONSECUTIVE_FAILED_ACCEPTS - 1,
    );
    let outcomes = failures
        .clone()
        .chain([WindowsAttachAcceptOutcome::Served])
        .chain(failures)
        .chain([WindowsAttachAcceptOutcome::Stopped])
        .collect::<VecDeque<_>>();
    let count = outcomes.len();
    let mut acceptor = FakeAcceptor {
        outcomes,
        calls: Vec::new(),
    };
    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::Stopped
    );
    assert_eq!(acceptor.calls.len(), count);
}

#[test]
fn served_outcomes_reset_the_failed_accept_count() {
    let failures = std::iter::repeat_n(
        WindowsAttachAcceptOutcome::Failed,
        MAX_CONSECUTIVE_FAILED_ACCEPTS - 1,
    );
    let outcomes = failures
        .clone()
        .chain([WindowsAttachAcceptOutcome::Served])
        .chain(failures.clone())
        .chain([WindowsAttachAcceptOutcome::Served])
        .chain(failures)
        .chain([WindowsAttachAcceptOutcome::Stopped])
        .collect::<VecDeque<_>>();
    let expected_calls = outcomes.len();
    let mut acceptor = FakeAcceptor {
        outcomes,
        calls: Vec::new(),
    };

    assert_eq!(
        run_windows_attach_accept_loop(&mut acceptor),
        WindowsAttachAcceptLoopExit::Stopped
    );
    assert_eq!(acceptor.calls.len(), expected_calls);
}
