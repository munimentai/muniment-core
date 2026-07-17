use muniment_core::attach::*;
use std::{cell::Cell, collections::BTreeSet, rc::Rc, time::Duration};

#[derive(Clone)]
struct TestClock(Rc<Cell<Duration>>);
impl AuthorizationClock for TestClock {
    fn now(&self) -> Duration {
        self.0.get()
    }
}
impl TestClock {
    fn advance(&self, duration: Duration) {
        self.0.set(self.0.get() + duration);
    }
}

struct TestTokens(u8);
impl AuthorizationTokenGenerator for TestTokens {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), muniment_core::attach::AuthorizationRandomnessError> {
        self.0 += 1;
        bytes.fill(self.0);
        Ok(())
    }
}

fn binding() -> ConnectionBinding {
    ConnectionBinding {
        connection_id: "connection-1".into(),
        client_nonce: "client-1".into(),
        server_nonce: "server-1".into(),
        companion_identity: "uid-1".into(),
        companion_kind: "cli".into(),
    }
}

fn approval(lifetime: Duration) -> Approval {
    Approval {
        profile: "profile-1".into(),
        workspace: "workspace-1".into(),
        scopes: BTreeSet::from(["threads:read".into()]),
        lifetime,
    }
}

fn authorization() -> (
    TestClock,
    AuthorizationState<TestClock, TestTokens>,
    PairingChallenge,
) {
    let clock = TestClock(Rc::new(Cell::new(Duration::ZERO)));
    let mut state = AuthorizationState::new(clock.clone(), TestTokens(0), binding());
    let challenge = state.issue_challenge().unwrap();
    (clock, state, challenge)
}

#[test]
fn pairing_requires_approval_and_consumes_the_challenge_once() {
    let (_clock, mut state, challenge) = authorization();
    assert_eq!(
        state.validate_request(
            "anything",
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::NotAuthorized)
    );
    let (capability, _) = state
        .approve(&challenge, approval(MAX_CAPABILITY_LIFETIME))
        .unwrap();
    assert_eq!(
        state.approve(&challenge, approval(MAX_CAPABILITY_LIFETIME)),
        Err(AuthorizationError::ChallengeConsumed)
    );
    let debug = format!("{challenge:?}{capability:?}");
    assert!(!debug.contains(challenge.as_str()));
    assert!(!debug.contains(capability.as_str()));
}

#[test]
fn capability_boundaries_and_idle_refresh_are_deterministic() {
    let (clock, mut state, challenge) = authorization();
    let (capability, grant) = state
        .approve(
            &challenge,
            approval(MAX_CAPABILITY_LIFETIME + Duration::from_secs(1)),
        )
        .unwrap();
    assert_eq!(grant.expires_at, MAX_CAPABILITY_LIFETIME);

    clock.advance(CAPABILITY_IDLE_LIFETIME);
    assert!(state
        .validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        )
        .is_ok());
    clock.advance(CAPABILITY_IDLE_LIFETIME);
    assert!(state
        .validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        )
        .is_ok());
    clock.advance(CAPABILITY_IDLE_LIFETIME + Duration::from_secs(1));
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::IdleExpired)
    );
}

#[test]
fn challenge_and_absolute_expiry_accept_the_boundary_only() {
    let (clock, mut state, challenge) = authorization();
    clock.advance(CHALLENGE_LIFETIME);
    let (capability, _) = state
        .approve(&challenge, approval(MAX_CAPABILITY_LIFETIME))
        .unwrap();

    // Keep the capability active through its absolute lifetime boundary.
    for _ in 0..32 {
        clock.advance(CAPABILITY_IDLE_LIFETIME);
        assert!(state
            .validate_request(
                capability.as_str(),
                &binding(),
                "profile-1",
                "workspace-1",
                "threads:read"
            )
            .is_ok());
    }
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::Expired)
    );

    let (clock, mut state, challenge) = authorization();
    clock.advance(CHALLENGE_LIFETIME + Duration::from_secs(1));
    assert_eq!(
        state.approve(&challenge, approval(Duration::from_secs(1))),
        Err(AuthorizationError::ChallengeExpired)
    );
}

#[test]
fn rejected_requests_do_not_refresh_idle_activity_and_bindings_are_exact() {
    let (clock, mut state, challenge) = authorization();
    let (capability, _) = state
        .approve(&challenge, approval(MAX_CAPABILITY_LIFETIME))
        .unwrap();
    clock.advance(CAPABILITY_IDLE_LIFETIME);
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "write"
        ),
        Err(AuthorizationError::MissingScope)
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::IdleExpired)
    );

    let (_clock, mut state, challenge) = authorization();
    let (capability, _) = state
        .approve(&challenge, approval(Duration::from_secs(60)))
        .unwrap();
    let mut other = binding();
    other.client_nonce = "other".into();
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &other,
            "profile-1",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::WrongConnection)
    );
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &binding(),
            "other",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::WrongProfile)
    );
    assert_eq!(
        state.validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "other",
            "threads:read"
        ),
        Err(AuthorizationError::WrongWorkspace)
    );
}

#[test]
fn revocation_is_atomic_and_idempotent_for_pending_and_active_states() {
    let (_clock, mut pending, challenge) = authorization();
    pending.revoke();
    pending.revoke();
    assert_eq!(
        pending.approve(&challenge, approval(Duration::from_secs(1))),
        Err(AuthorizationError::Revoked)
    );

    let (_clock, mut active, challenge) = authorization();
    let (capability, _) = active
        .approve(&challenge, approval(Duration::from_secs(1)))
        .unwrap();
    active.revoke();
    active.revoke();
    assert_eq!(
        active.validate_request(
            capability.as_str(),
            &binding(),
            "profile-1",
            "workspace-1",
            "threads:read"
        ),
        Err(AuthorizationError::Revoked)
    );
}
