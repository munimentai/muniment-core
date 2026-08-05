//! Runtime quiesce evaluation for migration handoff.

use std::fmt;

/// Runtime work that can block a safe handoff.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeActivity {
    pub active_run: bool,
    pub pending_permission_gate: bool,
    pub authentication_operation: bool,
    pub session_refresh: bool,
    pub in_flight_external_effect: bool,
}

/// Proof that the runtime has reached a safe handoff point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeHandoffPoint(());

/// The first activity that blocks a safe handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiesceError {
    ActiveRun,
    PendingPermissionGate,
    AuthenticationOperation,
    SessionRefresh,
    InFlightExternalEffect,
}

impl fmt::Display for QuiesceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActiveRun => "active run",
            Self::PendingPermissionGate => "pending permission gate",
            Self::AuthenticationOperation => "authentication operation",
            Self::SessionRefresh => "session refresh",
            Self::InFlightExternalEffect => "in-flight external effect",
        })
    }
}

impl std::error::Error for QuiesceError {}

/// Returns proof of a safe handoff or the first blocker in field order.
pub fn evaluate_quiesce(activity: RuntimeActivity) -> Result<SafeHandoffPoint, QuiesceError> {
    if activity.active_run {
        return Err(QuiesceError::ActiveRun);
    }
    if activity.pending_permission_gate {
        return Err(QuiesceError::PendingPermissionGate);
    }
    if activity.authentication_operation {
        return Err(QuiesceError::AuthenticationOperation);
    }
    if activity.session_refresh {
        return Err(QuiesceError::SessionRefresh);
    }
    if activity.in_flight_external_effect {
        return Err(QuiesceError::InFlightExternalEffect);
    }

    Ok(SafeHandoffPoint(()))
}
