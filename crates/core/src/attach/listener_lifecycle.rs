//! Attach listener lifecycle state.

use super::linux::AttachListenerStartFailure;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AttachListenerLifecycle {
    #[default]
    Pending,
    Listening,
    Failed(AttachListenerStartFailure),
    Stopped,
}

impl AttachListenerLifecycle {
    pub fn record_pending(&mut self) {
        *self = Self::Pending;
    }

    pub fn record_listening(&mut self) {
        *self = Self::Listening;
    }

    pub fn record_failure(&mut self, failure: AttachListenerStartFailure) {
        *self = Self::Failed(failure);
    }

    pub fn record_stopped(&mut self) {
        *self = Self::Stopped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_listener_transitions_from_pending_to_listening_and_stopped() {
        let mut lifecycle = AttachListenerLifecycle::default();

        lifecycle.record_listening();
        assert_eq!(lifecycle, AttachListenerLifecycle::Listening);

        lifecycle.record_stopped();
        assert_eq!(lifecycle, AttachListenerLifecycle::Stopped);
    }

    #[test]
    fn desktop_listener_transitions_from_pending_to_each_failure() {
        for failure in [
            AttachListenerStartFailure::Filesystem,
            AttachListenerStartFailure::InstanceLock,
            AttachListenerStartFailure::Bind,
        ] {
            let mut lifecycle = AttachListenerLifecycle::default();
            lifecycle.record_failure(failure);
            assert_eq!(lifecycle, AttachListenerLifecycle::Failed(failure));
        }
    }

    #[test]
    fn desktop_listener_transitions_from_stopped_to_pending_for_restart() {
        let mut lifecycle = AttachListenerLifecycle::Stopped;

        lifecycle.record_pending();

        assert_eq!(lifecycle, AttachListenerLifecycle::Pending);
    }

    #[test]
    fn stop_before_bind_completes_transitions_from_pending_through_listening_to_stopped() {
        let mut lifecycle = AttachListenerLifecycle::Pending;

        lifecycle.record_listening();
        assert_eq!(lifecycle, AttachListenerLifecycle::Listening);

        lifecycle.record_stopped();

        assert_eq!(lifecycle, AttachListenerLifecycle::Stopped);
    }
}
