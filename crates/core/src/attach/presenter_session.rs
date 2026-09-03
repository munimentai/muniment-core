use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use super::{
    ApprovalCoordinator, ApprovalPresenterConnection, ApprovalPresenterStream, PresenterGuard,
    CHALLENGE_LIFETIME,
};

/// Holds the exclusive approval presenter claim for one connection.
pub struct ApprovalPresenterSession<S: ApprovalPresenterStream> {
    presenter: Option<PresenterGuard>,
    shutdown: S,
}

impl<S: ApprovalPresenterStream> ApprovalPresenterSession<S> {
    /// Waits until the peer closes the presenter connection.
    pub fn wait_until_closed(&self) {
        self.shutdown.wait_until_closed();
    }
}

/// Claims the coordinator and serves its approval requests over the connection.
pub fn serve_approval_presenter<S: ApprovalPresenterStream>(
    coordinator: ApprovalCoordinator,
    connection: ApprovalPresenterConnection<S>,
) -> Option<ApprovalPresenterSession<S>> {
    let shutdown = connection.try_clone_stream().ok()?;
    let connection = Mutex::new(connection);
    let decision_coordinator = coordinator.clone();
    let presenter = coordinator.claim_presenter_until(move |request, deadline| {
        let Some(mut connection) = lock_before(&connection, deadline) else {
            return false;
        };
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(CHALLENGE_LIFETIME);
        if remaining.is_zero() {
            return false;
        }
        let approve = connection.present(request, remaining);
        if Instant::now() >= deadline {
            return false;
        }
        decision_coordinator.decide(&request.challenge, approve)
    })?;
    Some(ApprovalPresenterSession {
        presenter: Some(presenter),
        shutdown,
    })
}

fn lock_before<T>(mutex: &Mutex<T>, deadline: Instant) -> Option<std::sync::MutexGuard<'_, T>> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Some(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => return None,
            Err(std::sync::TryLockError::WouldBlock) => {
                let remaining = deadline.checked_duration_since(Instant::now())?;
                thread::sleep(remaining.min(Duration::from_millis(1)));
            }
        }
    }
}

impl<S: ApprovalPresenterStream> Drop for ApprovalPresenterSession<S> {
    fn drop(&mut self) {
        self.shutdown.close_presenter_stream();
        drop(self.presenter.take());
    }
}
