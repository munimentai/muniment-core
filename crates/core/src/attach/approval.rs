use std::collections::{BTreeSet, HashMap};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use super::Approval;

#[derive(Clone, Default)]
pub struct SignedWorkspaceApproval {
    workspace: Arc<Mutex<Option<String>>>,
}

impl SignedWorkspaceApproval {
    pub fn record(&self, workspace: String) {
        *self
            .workspace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(workspace);
    }

    pub fn clear(&self) {
        *self
            .workspace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn approval(&self) -> Option<Approval> {
        let workspace = self
            .workspace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        Some(Approval {
            profile: "desktop-owner".into(),
            workspace,
            scopes: BTreeSet::from(["thread.read".into(), "run.write".into()]),
            lifetime: Duration::from_secs(60 * 60),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub challenge: String,
    pub claimed_kind: String,
    pub claimed_version: String,
    pub workspace: String,
    pub scopes: BTreeSet<String>,
}

type Presenter = dyn Fn(&ApprovalRequest, Instant) -> bool + Send + Sync;

#[derive(Default)]
struct ApprovalState {
    presenter: Option<Arc<Presenter>>,
    presenter_claimed: bool,
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

pub struct PresenterGuard {
    state: Arc<Mutex<ApprovalState>>,
}

impl ApprovalCoordinator {
    pub fn register_presenter<F>(&self, presenter: F)
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        if let Ok(mut state) = self.state.lock() {
            if !state.presenter_claimed {
                state.presenter = Some(Arc::new(move |request, _| presenter(request)));
            }
        }
    }

    pub fn claim_presenter<F>(&self, presenter: F) -> Option<PresenterGuard>
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        self.claim_presenter_until(move |request, _| presenter(request))
    }

    pub(crate) fn claim_presenter_until<F>(&self, presenter: F) -> Option<PresenterGuard>
    where
        F: Fn(&ApprovalRequest, Instant) -> bool + Send + Sync + 'static,
    {
        let mut state = self.state.lock().ok()?;
        if state.presenter_claimed {
            return None;
        }
        state.presenter = Some(Arc::new(presenter));
        state.presenter_claimed = true;
        Some(PresenterGuard {
            state: self.state.clone(),
        })
    }

    pub fn request(&self, request: ApprovalRequest, remaining: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(remaining) else {
            return false;
        };
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

        if !presenter(&request, deadline) {
            self.remove_pending(&request.challenge, id);
            return false;
        }

        let approved = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(false);
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

impl Drop for PresenterGuard {
    fn drop(&mut self) {
        let pending = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.presenter = None;
            state.presenter_claimed = false;
            std::mem::take(&mut state.pending)
        };
        for decision in pending.into_values() {
            let _ = decision.sender.try_send(false);
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
            workspace: "workspace-a".into(),
            scopes: BTreeSet::from(["thread.read".into(), "run.write".into()]),
        }
    }

    #[test]
    fn signed_workspace_approval_records_and_clears_the_owner_approval() {
        let state = SignedWorkspaceApproval::default();
        assert!(state.approval().is_none());

        state.record("workspace-a".into());
        let approval = state.approval().unwrap();
        assert_eq!(approval.profile, "desktop-owner");
        assert_eq!(approval.workspace, "workspace-a");
        assert_eq!(
            approval.scopes,
            BTreeSet::from(["thread.read".into(), "run.write".into()])
        );
        assert_eq!(approval.lifetime, Duration::from_secs(60 * 60));

        state.clear();
        assert!(state.approval().is_none());
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

    #[test]
    fn rejects_a_second_presenter_claim() {
        let coordinator = ApprovalCoordinator::default();
        let guard = coordinator.claim_presenter(|_| true).unwrap();

        assert!(coordinator.claim_presenter(|_| true).is_none());
        drop(guard);
        assert!(coordinator.claim_presenter(|_| true).is_some());
    }

    #[test]
    fn registration_does_not_replace_a_claimed_presenter() {
        let coordinator = ApprovalCoordinator::default();
        let (claimed_sender, claimed) = channel();
        let guard = coordinator
            .claim_presenter(move |_| claimed_sender.send(()).is_ok())
            .unwrap();
        coordinator.register_presenter(|_| false);

        let waiter = coordinator.clone();
        let result =
            thread::spawn(move || waiter.request(request("claimed"), Duration::from_secs(1)));
        claimed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(coordinator.decide("claimed", true));
        assert!(result.join().unwrap());
        drop(guard);
    }

    #[test]
    fn releasing_a_presenter_clears_it() {
        let coordinator = ApprovalCoordinator::default();
        let guard = coordinator.claim_presenter(|_| true).unwrap();

        drop(guard);

        assert!(!coordinator.request(request("released"), Duration::from_secs(10)));
    }

    #[test]
    fn releasing_a_presenter_denies_a_waiting_request_at_once() {
        let coordinator = ApprovalCoordinator::default();
        let (presented_sender, presented) = channel();
        let guard = coordinator
            .claim_presenter(move |_| presented_sender.send(()).is_ok())
            .unwrap();
        let waiter = coordinator.clone();
        let (result_sender, result) = channel();
        thread::spawn(move || {
            let decision = waiter.request(request("release"), Duration::from_secs(60));
            result_sender.send(decision).unwrap();
        });
        presented.recv_timeout(Duration::from_secs(1)).unwrap();

        drop(guard);

        assert!(!result.recv_timeout(Duration::from_secs(1)).unwrap());
    }
}
