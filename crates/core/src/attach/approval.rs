use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub challenge: String,
    pub claimed_kind: String,
    pub claimed_version: String,
}

type Presenter = dyn Fn(&ApprovalRequest) -> bool + Send + Sync;

#[derive(Default)]
struct ApprovalState {
    presenter: Option<Arc<Presenter>>,
    pending: HashMap<String, PendingDecision>,
    next_id: u64,
}

struct PendingDecision {
    id: u64,
    sender: mpsc::SyncSender<bool>,
}

#[derive(Clone, Default)]
pub struct ApprovalCoordinator {
    state: Arc<Mutex<ApprovalState>>,
}

impl ApprovalCoordinator {
    pub fn register_presenter<F>(&self, presenter: F)
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        if let Ok(mut state) = self.state.lock() {
            state.presenter = Some(Arc::new(presenter));
        }
    }

    pub fn request(&self, request: ApprovalRequest, remaining: Duration) -> bool {
        let (receiver, id, presenter) = {
            let Ok(mut state) = self.state.lock() else {
                return false;
            };
            let Some(presenter) = state.presenter.clone() else {
                return false;
            };
            if state.pending.contains_key(&request.challenge) {
                return false;
            }
            let (sender, receiver) = mpsc::sync_channel(1);
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            state
                .pending
                .insert(request.challenge.clone(), PendingDecision { id, sender });
            (receiver, id, presenter)
        };

        if !presenter(&request) {
            self.remove_pending(&request.challenge, id);
            return false;
        }

        let approved = receiver.recv_timeout(remaining).unwrap_or(false);
        self.remove_pending(&request.challenge, id);
        approved
    }

    pub fn decide(&self, challenge: &str, approve: bool) -> bool {
        let sender = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.pending.remove(challenge))
            .map(|pending| pending.sender);
        sender.is_some_and(|sender| sender.try_send(approve).is_ok())
    }

    fn remove_pending(&self, challenge: &str, id: u64) {
        if let Ok(mut state) = self.state.lock() {
            if state
                .pending
                .get(challenge)
                .is_some_and(|pending| pending.id == id)
            {
                state.pending.remove(challenge);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::thread;

    fn request(challenge: &str) -> ApprovalRequest {
        ApprovalRequest {
            challenge: challenge.into(),
            claimed_kind: "cli".into(),
            claimed_version: "1".into(),
        }
    }

    fn presented_coordinator() -> (ApprovalCoordinator, mpsc::Receiver<String>) {
        let coordinator = ApprovalCoordinator::default();
        let (sender, receiver) = channel();
        coordinator
            .register_presenter(move |request| sender.send(request.challenge.clone()).is_ok());
        (coordinator, receiver)
    }

    #[test]
    fn approves_an_explicit_decision() {
        let (coordinator, presented) = presented_coordinator();
        let waiter = coordinator.clone();
        let result =
            thread::spawn(move || waiter.request(request("approve"), Duration::from_secs(1)));
        assert_eq!(
            presented.recv_timeout(Duration::from_secs(1)).unwrap(),
            "approve"
        );
        assert!(coordinator.decide("approve", true));
        assert!(result.join().unwrap());
    }

    #[test]
    fn denies_an_explicit_decision() {
        let (coordinator, presented) = presented_coordinator();
        let waiter = coordinator.clone();
        let result = thread::spawn(move || waiter.request(request("deny"), Duration::from_secs(1)));
        presented.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(coordinator.decide("deny", false));
        assert!(!result.join().unwrap());
    }

    #[test]
    fn denies_after_timeout() {
        let (coordinator, presented) = presented_coordinator();
        let waiter = coordinator.clone();
        let result =
            thread::spawn(move || waiter.request(request("timeout"), Duration::from_millis(10)));
        presented.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!result.join().unwrap());
        assert!(!coordinator.decide("timeout", true));
    }

    #[test]
    fn denies_at_once_without_a_presenter() {
        let coordinator = ApprovalCoordinator::default();
        assert!(!coordinator.request(request("absent"), Duration::from_secs(10)));
    }

    #[test]
    fn ignores_an_unknown_challenge() {
        let coordinator = ApprovalCoordinator::default();
        assert!(!coordinator.decide("unknown", true));
    }

    #[test]
    fn ignores_a_repeated_decision() {
        let (coordinator, presented) = presented_coordinator();
        let waiter = coordinator.clone();
        let result =
            thread::spawn(move || waiter.request(request("repeat"), Duration::from_secs(1)));
        presented.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(coordinator.decide("repeat", false));
        assert!(!coordinator.decide("repeat", true));
        assert!(!result.join().unwrap());
    }
}
