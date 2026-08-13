use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use super::{ApprovalCoordinator, ApprovalPresenterConnection, PresenterGuard, CHALLENGE_LIFETIME};

/// Holds the exclusive approval presenter claim for one connection.
pub struct ApprovalPresenterSession {
    presenter: Option<PresenterGuard>,
    shutdown: UnixStream,
}

/// Claims the coordinator and serves its approval requests over the connection.
pub fn serve_approval_presenter(
    coordinator: ApprovalCoordinator,
    connection: ApprovalPresenterConnection,
) -> Option<ApprovalPresenterSession> {
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

impl Drop for ApprovalPresenterSession {
    fn drop(&mut self) {
        let _ = self.shutdown.shutdown(Shutdown::Both);
        drop(self.presenter.take());
    }
}
