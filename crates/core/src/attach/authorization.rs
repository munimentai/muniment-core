//! Pure, connection-local authorization policy for companion attachments.

use std::{collections::BTreeSet, fmt, time::Duration};

use serde::{Serialize, Serializer};

pub const CHALLENGE_LIFETIME: Duration = Duration::from_secs(2 * 60);
pub const MAX_CAPABILITY_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
pub const CAPABILITY_IDLE_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// A monotonic clock. Values have no wire meaning and need only be comparable.
pub trait AuthorizationClock {
    fn now(&self) -> Duration;
}

/// Supplies cryptographically random bytes in production and fixed bytes in tests.
pub trait AuthorizationTokenGenerator {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), AuthorizationRandomnessError>;
}

/// Redacted failure returned when authorization token randomness is unavailable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationRandomnessError;

impl fmt::Debug for AuthorizationRandomnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizationRandomnessError([REDACTED])")
    }
}

impl fmt::Display for AuthorizationRandomnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authorization randomness is unavailable")
    }
}

impl std::error::Error for AuthorizationRandomnessError {}

#[derive(Clone, PartialEq, Eq)]
pub struct PairingChallenge(String);

#[derive(Clone, PartialEq, Eq)]
pub struct Capability(String);

macro_rules! opaque_secret {
    ($type:ty, $label:literal) => {
        impl $type {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($label, "([REDACTED])"))
            }
        }
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }
    };
}
opaque_secret!(PairingChallenge, "PairingChallenge");
opaque_secret!(Capability, "Capability");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionBinding {
    pub connection_id: String,
    pub client_nonce: String,
    pub server_nonce: String,
    pub companion_identity: String,
    pub companion_kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub profile: String,
    pub workspace: String,
    pub scopes: BTreeSet<String>,
    pub lifetime: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedGrant {
    pub profile: String,
    pub workspace: String,
    pub scopes: BTreeSet<String>,
    pub expires_at: Duration,
    pub idle_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    Randomness,
    ChallengeAlreadyIssued,
    ChallengeMismatch,
    ChallengeConsumed,
    ChallengeExpired,
    NotAuthorized,
    CapabilityMismatch,
    WrongConnection,
    WrongProfile,
    WrongWorkspace,
    MissingScope,
    Expired,
    IdleExpired,
    Revoked,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Randomness => "authorization randomness is unavailable",
            Self::ChallengeAlreadyIssued => "pairing challenge already issued",
            Self::ChallengeMismatch => "pairing challenge does not match",
            Self::ChallengeConsumed => "pairing challenge already consumed",
            Self::ChallengeExpired => "pairing challenge expired",
            Self::NotAuthorized => "connection is not authorized",
            Self::CapabilityMismatch => "capability does not match",
            Self::WrongConnection => "capability belongs to another connection",
            Self::WrongProfile => "profile is not authorized",
            Self::WrongWorkspace => "workspace is not authorized",
            Self::MissingScope => "required scope is not authorized",
            Self::Expired => "capability expired",
            Self::IdleExpired => "capability idle period expired",
            Self::Revoked => "authorization revoked",
        })
    }
}
impl std::error::Error for AuthorizationError {}

struct Pending {
    token: PairingChallenge,
    expires_at: Duration,
}
struct Active {
    token: Capability,
    binding: ConnectionBinding,
    approval: Approval,
    expires_at: Duration,
    last_activity: Duration,
}

enum State {
    PairingRequired,
    Pending(Pending),
    Active(Box<Active>),
    Revoked,
}

/// Authorization state owned by exactly one negotiated connection.
pub struct AuthorizationState<C, G> {
    clock: C,
    generator: G,
    binding: ConnectionBinding,
    state: State,
}

impl<C: AuthorizationClock, G: AuthorizationTokenGenerator> AuthorizationState<C, G> {
    pub fn new(clock: C, generator: G, binding: ConnectionBinding) -> Self {
        Self {
            clock,
            generator,
            binding,
            state: State::PairingRequired,
        }
    }

    pub fn issue_challenge(&mut self) -> Result<PairingChallenge, AuthorizationError> {
        if !matches!(self.state, State::PairingRequired) {
            return Err(if matches!(self.state, State::Revoked) {
                AuthorizationError::Revoked
            } else {
                AuthorizationError::ChallengeAlreadyIssued
            });
        }
        let token = PairingChallenge(
            generate_hex::<16>(&mut self.generator).map_err(|_| AuthorizationError::Randomness)?,
        );
        self.state = State::Pending(Pending {
            token: token.clone(),
            expires_at: self.clock.now() + CHALLENGE_LIFETIME,
        });
        Ok(token)
    }

    pub fn approve(
        &mut self,
        challenge: &PairingChallenge,
        mut approval: Approval,
    ) -> Result<(Capability, AuthorizedGrant), AuthorizationError> {
        let now = self.clock.now();
        let pending = match &self.state {
            State::Pending(pending) => pending,
            State::Active(_) => return Err(AuthorizationError::ChallengeConsumed),
            State::Revoked => return Err(AuthorizationError::Revoked),
            State::PairingRequired => return Err(AuthorizationError::NotAuthorized),
        };
        if now > pending.expires_at {
            return Err(AuthorizationError::ChallengeExpired);
        }
        if challenge != &pending.token {
            return Err(AuthorizationError::ChallengeMismatch);
        }

        approval.lifetime = approval.lifetime.min(MAX_CAPABILITY_LIFETIME);
        let expires_at = now + approval.lifetime;
        let token = Capability(
            generate_hex::<32>(&mut self.generator).map_err(|_| AuthorizationError::Randomness)?,
        );
        let grant = AuthorizedGrant {
            profile: approval.profile.clone(),
            workspace: approval.workspace.clone(),
            scopes: approval.scopes.clone(),
            expires_at,
            idle_timeout: CAPABILITY_IDLE_LIFETIME,
        };
        self.state = State::Active(Box::new(Active {
            token: token.clone(),
            binding: self.binding.clone(),
            approval,
            expires_at,
            last_activity: now,
        }));
        Ok((token, grant))
    }

    pub fn validate_request(
        &mut self,
        capability: &str,
        binding: &ConnectionBinding,
        profile: &str,
        workspace: &str,
        required_scope: &str,
    ) -> Result<(), AuthorizationError> {
        let now = self.clock.now();
        let active = match &mut self.state {
            State::Active(active) => active,
            State::Revoked => return Err(AuthorizationError::Revoked),
            _ => return Err(AuthorizationError::NotAuthorized),
        };
        // Rejected requests deliberately leave last_activity untouched.
        if capability != active.token.as_str() {
            return Err(AuthorizationError::CapabilityMismatch);
        }
        if binding != &active.binding {
            return Err(AuthorizationError::WrongConnection);
        }
        if profile != active.approval.profile {
            return Err(AuthorizationError::WrongProfile);
        }
        if workspace != active.approval.workspace {
            return Err(AuthorizationError::WrongWorkspace);
        }
        if !active.approval.scopes.contains(required_scope) {
            return Err(AuthorizationError::MissingScope);
        }
        if now > active.expires_at {
            return Err(AuthorizationError::Expired);
        }
        if now > active.last_activity + CAPABILITY_IDLE_LIFETIME {
            return Err(AuthorizationError::IdleExpired);
        }
        active.last_activity = now;
        Ok(())
    }

    /// Atomically invalidates all pairing and capability material. Idempotent.
    pub fn revoke(&mut self) {
        self.state = State::Revoked;
    }
}

fn generate_hex<const N: usize>(
    generator: &mut impl AuthorizationTokenGenerator,
) -> Result<String, AuthorizationRandomnessError> {
    let mut bytes = [0; N];
    generator.fill(&mut bytes)?;
    let mut result = String::with_capacity(N * 2);
    for byte in bytes {
        use fmt::Write;
        write!(result, "{byte:02x}").expect("writing to String");
    }
    Ok(result)
}
