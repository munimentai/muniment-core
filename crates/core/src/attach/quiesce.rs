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
    Multiple(BlockerSet),
}

/// The runtime activities that prevent quiesce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockerSet(u8);

impl BlockerSet {
    pub fn contains(self, blocker: QuiesceError) -> bool {
        self.0 & blocker.mask() != 0
    }
}

impl QuiesceError {
    fn mask(self) -> u8 {
        match self {
            Self::ActiveRun => 1 << 0,
            Self::PendingPermissionGate => 1 << 1,
            Self::AuthenticationOperation => 1 << 2,
            Self::SessionRefresh => 1 << 3,
            Self::InFlightExternalEffect => 1 << 4,
            Self::Multiple(blockers) => blockers.0,
        }
    }
}

impl fmt::Display for QuiesceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActiveRun => "active run",
            Self::PendingPermissionGate => "pending permission gate",
            Self::AuthenticationOperation => "authentication operation",
            Self::SessionRefresh => "session refresh",
            Self::InFlightExternalEffect => "in-flight external effect",
            Self::Multiple(blockers) => {
                let mut separator = "";
                for (mask, name) in [
                    (1 << 0, "active run"),
                    (1 << 1, "pending permission gate"),
                    (1 << 2, "authentication operation"),
                    (1 << 3, "session refresh"),
                    (1 << 4, "in-flight external effect"),
                ] {
                    if blockers.0 & mask != 0 {
                        formatter.write_str(separator)?;
                        formatter.write_str(name)?;
                        separator = ", ";
                    }
                }
                return Ok(());
            }
        })
    }
}

impl std::error::Error for QuiesceError {}

/// Returns proof of a safe handoff or every blocker in field order.
pub fn evaluate_quiesce(activity: RuntimeActivity) -> Result<SafeHandoffPoint, QuiesceError> {
    let blockers = (activity.active_run as u8)
        | ((activity.pending_permission_gate as u8) << 1)
        | ((activity.authentication_operation as u8) << 2)
        | ((activity.session_refresh as u8) << 3)
        | ((activity.in_flight_external_effect as u8) << 4);
    match blockers {
        0 => Ok(SafeHandoffPoint(())),
        value if value.count_ones() > 1 => Err(QuiesceError::Multiple(BlockerSet(value))),
        1 => Err(QuiesceError::ActiveRun),
        2 => Err(QuiesceError::PendingPermissionGate),
        4 => Err(QuiesceError::AuthenticationOperation),
        8 => Err(QuiesceError::SessionRefresh),
        16 => Err(QuiesceError::InFlightExternalEffect),
        _ => unreachable!(),
    }
}
