use std::collections::BTreeSet;
use std::time::Duration;

use muniment_attach::{ApprovalDecision, ApprovalPresentRequest};

use super::{bounded_claim, ApprovalCoordinator, ApprovalRequest, CHALLENGE_LIFETIME};

pub fn answer_presented_approval(
    coordinator: &ApprovalCoordinator,
    presented: &ApprovalPresentRequest,
) -> ApprovalDecision {
    let request = ApprovalRequest {
        challenge: presented.challenge.clone(),
        claimed_kind: bounded_claim(&presented.claimed_kind),
        claimed_version: bounded_claim(&presented.claimed_version),
        workspace: presented.workspace.clone(),
        scopes: presented.scopes.iter().cloned().collect::<BTreeSet<_>>(),
    };
    let remaining = Duration::from_millis(presented.deadline_ms).min(CHALLENGE_LIFETIME);

    if coordinator.request(request, remaining) {
        ApprovalDecision::Approve
    } else {
        ApprovalDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, Receiver};

    use super::*;

    fn presented_request(deadline_ms: u64) -> ApprovalPresentRequest {
        ApprovalPresentRequest {
            challenge: "challenge-a".into(),
            claimed_kind: "cli\ninvalid".into(),
            claimed_version: " ".into(),
            workspace: "workspace-a".into(),
            scopes: vec!["run.write".into(), "thread.read".into(), "run.write".into()],
            deadline_ms,
        }
    }

    fn coordinator_with_decision(
        decision: Option<bool>,
    ) -> (ApprovalCoordinator, Receiver<ApprovalRequest>) {
        let coordinator = ApprovalCoordinator::default();
        let decider = coordinator.clone();
        let (sender, receiver) = mpsc::channel();
        coordinator.register_presenter(move |request| {
            sender.send(request.clone()).is_ok()
                && decision.is_none_or(|approve| decider.decide(&request.challenge, approve))
        });
        (coordinator, receiver)
    }

    #[test]
    fn approves_the_coordinator_approval() {
        let (coordinator, presented) = coordinator_with_decision(Some(true));

        let decision = answer_presented_approval(&coordinator, &presented_request(1_000));

        assert_eq!(decision, ApprovalDecision::Approve);
        let request = presented.recv().unwrap();
        assert_eq!(request.claimed_kind, "unknown");
        assert_eq!(request.claimed_version, "unknown");
        assert_eq!(
            request.scopes,
            BTreeSet::from(["run.write".into(), "thread.read".into()])
        );
    }

    #[test]
    fn denies_the_coordinator_denial() {
        let (coordinator, presented) = coordinator_with_decision(Some(false));

        let decision = answer_presented_approval(&coordinator, &presented_request(1_000));

        assert_eq!(decision, ApprovalDecision::Deny);
        presented.recv().unwrap();
    }

    #[test]
    fn denies_an_expired_deadline() {
        let (coordinator, presented) = coordinator_with_decision(None);

        let decision = answer_presented_approval(&coordinator, &presented_request(0));

        assert_eq!(decision, ApprovalDecision::Deny);
        presented.recv().unwrap();
        assert!(!coordinator.decide("challenge-a", true));
    }
}
