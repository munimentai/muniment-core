//! Shared runtime activity tracking for migration handoff.

use super::RuntimeActivity;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
struct ActivityCounts {
    active_run: usize,
    pending_permission_gate: usize,
    authentication_operation: usize,
    session_refresh: usize,
    in_flight_external_effect: usize,
}

#[derive(Clone, Copy)]
enum ActivityKind {
    ActiveRun,
    PendingPermissionGate,
    AuthenticationOperation,
    SessionRefresh,
    InFlightExternalEffect,
}

/// Counts runtime work that can block a safe handoff.
#[derive(Clone, Default)]
pub struct RuntimeActivityRegistry {
    counts: Arc<Mutex<ActivityCounts>>,
}

/// Clears one runtime activity mark when dropped.
pub struct RuntimeActivityGuard {
    counts: Arc<Mutex<ActivityCounts>>,
    kind: ActivityKind,
}

impl RuntimeActivityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_active_run(&self) -> RuntimeActivityGuard {
        self.mark(ActivityKind::ActiveRun)
    }

    pub fn mark_pending_permission_gate(&self) -> RuntimeActivityGuard {
        self.mark(ActivityKind::PendingPermissionGate)
    }

    pub fn mark_authentication_operation(&self) -> RuntimeActivityGuard {
        self.mark(ActivityKind::AuthenticationOperation)
    }

    pub fn mark_session_refresh(&self) -> RuntimeActivityGuard {
        self.mark(ActivityKind::SessionRefresh)
    }

    pub fn mark_in_flight_external_effect(&self) -> RuntimeActivityGuard {
        self.mark(ActivityKind::InFlightExternalEffect)
    }

    /// Returns the activity that is marked at this instant.
    pub fn snapshot(&self) -> RuntimeActivity {
        let counts = self.lock_counts();
        RuntimeActivity {
            active_run: counts.active_run != 0,
            pending_permission_gate: counts.pending_permission_gate != 0,
            authentication_operation: counts.authentication_operation != 0,
            session_refresh: counts.session_refresh != 0,
            in_flight_external_effect: counts.in_flight_external_effect != 0,
        }
    }

    fn mark(&self, kind: ActivityKind) -> RuntimeActivityGuard {
        increment(&mut self.lock_counts(), kind);
        RuntimeActivityGuard {
            counts: self.counts.clone(),
            kind,
        }
    }

    fn lock_counts(&self) -> MutexGuard<'_, ActivityCounts> {
        self.counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for RuntimeActivityGuard {
    fn drop(&mut self) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = count_mut(&mut counts, self.kind);
        debug_assert!(*count > 0);
        *count -= 1;
    }
}

fn increment(counts: &mut ActivityCounts, kind: ActivityKind) {
    let count = count_mut(counts, kind);
    *count = count
        .checked_add(1)
        .expect("runtime activity count overflow");
}

fn count_mut(counts: &mut ActivityCounts, kind: ActivityKind) -> &mut usize {
    match kind {
        ActivityKind::ActiveRun => &mut counts.active_run,
        ActivityKind::PendingPermissionGate => &mut counts.pending_permission_gate,
        ActivityKind::AuthenticationOperation => &mut counts.authentication_operation,
        ActivityKind::SessionRefresh => &mut counts.session_refresh,
        ActivityKind::InFlightExternalEffect => &mut counts.in_flight_external_effect,
    }
}
