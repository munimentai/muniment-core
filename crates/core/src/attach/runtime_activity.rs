//! Shared runtime activity tracking for migration handoff.

use super::{Operation, RuntimeActivity};
use std::sync::{Arc, Mutex, MutexGuard};

/// A shared, one-way runtime drain state.
#[derive(Clone, Default)]
pub struct DrainState(Arc<Mutex<ActivityState>>);

/// A request tried to add runtime activity after draining started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainRefusal;

impl DrainState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self) {
        self.lock_state().draining = true;
    }

    pub fn is_set(&self) -> bool {
        self.lock_state().draining
    }

    pub fn admit(&self, operation: Operation) -> Result<DrainAdmissionGuard, DrainRefusal> {
        let mut state = self.lock_state();
        let starts_blocking_work = matches!(
            operation,
            Operation::RunStart
                | Operation::RunSubmit
                | Operation::RunResume
                | Operation::SessionSignIn
        );
        if state.draining && starts_blocking_work {
            return Err(DrainRefusal);
        }
        if starts_blocking_work {
            state.admissions = state
                .admissions
                .checked_add(1)
                .expect("runtime admission count overflow");
            Ok(DrainAdmissionGuard(Some(Arc::clone(&self.0))))
        } else {
            Ok(DrainAdmissionGuard(None))
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ActivityState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Default)]
struct ActivityState {
    draining: bool,
    admissions: usize,
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
    state: Arc<Mutex<ActivityState>>,
}

/// Clears one runtime activity mark when dropped.
pub struct RuntimeActivityGuard {
    state: Arc<Mutex<ActivityState>>,
    kind: ActivityKind,
}

/// Keeps an admitted request visible to quiesce until dispatch finishes.
pub struct DrainAdmissionGuard(Option<Arc<Mutex<ActivityState>>>);

impl RuntimeActivityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_drain_state(drain_state: &DrainState) -> Self {
        Self {
            state: Arc::clone(&drain_state.0),
        }
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
        let counts = self.lock_state();
        RuntimeActivity {
            active_run: counts.active_run != 0 || counts.admissions != 0,
            pending_permission_gate: counts.pending_permission_gate != 0,
            authentication_operation: counts.authentication_operation != 0,
            session_refresh: counts.session_refresh != 0,
            in_flight_external_effect: counts.in_flight_external_effect != 0,
        }
    }

    fn mark(&self, kind: ActivityKind) -> RuntimeActivityGuard {
        increment(&mut self.lock_state(), kind);
        RuntimeActivityGuard {
            state: self.state.clone(),
            kind,
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ActivityState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for RuntimeActivityGuard {
    fn drop(&mut self) {
        let mut counts = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = count_mut(&mut counts, self.kind);
        debug_assert!(*count > 0);
        *count -= 1;
    }
}

impl Drop for DrainAdmissionGuard {
    fn drop(&mut self) {
        let Some(state) = &self.0 else {
            return;
        };
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.admissions > 0);
        state.admissions -= 1;
    }
}

fn increment(counts: &mut ActivityState, kind: ActivityKind) {
    let count = count_mut(counts, kind);
    *count = count
        .checked_add(1)
        .expect("runtime activity count overflow");
}

fn count_mut(counts: &mut ActivityState, kind: ActivityKind) -> &mut usize {
    match kind {
        ActivityKind::ActiveRun => &mut counts.active_run,
        ActivityKind::PendingPermissionGate => &mut counts.pending_permission_gate,
        ActivityKind::AuthenticationOperation => &mut counts.authentication_operation,
        ActivityKind::SessionRefresh => &mut counts.session_refresh,
        ActivityKind::InFlightExternalEffect => &mut counts.in_flight_external_effect,
    }
}
