//! Platform-neutral companion pairing and authorization exchange.

use std::time::{Duration, Instant};

use super::companion_session::{
    read_before, serve_requests, write_before, write_protocol_error, AuthorizedSession,
};
use super::desktop_dispatch::hex;
use super::desktop_service_message::CompanionProvenance;
use super::live_connections::LiveConnectionRegistry;
use super::thread_service::ThreadListService;
use super::{
    encode_frame, welcome, Approval, AttachSessionError, AuthorizationClock, AuthorizationError,
    AuthorizationState, AuthorizationTokenGenerator, ConnectionBinding, DeadlineStream,
    FirstMessage, NegotiationError, ProtocolError, VersionRange, CHALLENGE_LIFETIME,
    MAX_FRAME_LENGTH,
};

const DESKTOP_PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

/// The result of the explicit, visible desktop approval prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve(Approval),
    Deny,
}

/// Bounded seam for receiving desktop approval actions.
pub trait ApprovalWaiter {
    /// Returns the next action available within `remaining`, or `None` when that
    /// bound expires. Implementations must not wait longer than `remaining`.
    fn wait(
        &mut self,
        challenge: &super::PairingChallenge,
        claimed_kind: &str,
        claimed_version: &str,
        remaining: Duration,
    ) -> Option<ApprovalDecision>;
}

impl<F> ApprovalWaiter for F
where
    F: FnMut(&super::PairingChallenge, Duration) -> Option<ApprovalDecision>,
{
    fn wait(
        &mut self,
        challenge: &super::PairingChallenge,
        _: &str,
        _: &str,
        remaining: Duration,
    ) -> Option<ApprovalDecision> {
        self(challenge, remaining)
    }
}

pub struct ClaimedApprovalWaiter<F>(F);

pub fn approval_waiter_with_claims<F>(waiter: F) -> ClaimedApprovalWaiter<F> {
    ClaimedApprovalWaiter(waiter)
}

impl<F> ApprovalWaiter for ClaimedApprovalWaiter<F>
where
    F: FnMut(&super::PairingChallenge, &str, &str, Duration) -> Option<ApprovalDecision>,
{
    fn wait(
        &mut self,
        challenge: &super::PairingChallenge,
        claimed_kind: &str,
        claimed_version: &str,
        remaining: Duration,
    ) -> Option<ApprovalDecision> {
        (self.0)(challenge, claimed_kind, claimed_version, remaining)
    }
}

/// Injectable dependencies for the authorization phase of a companion session.
pub struct AuthorizationSessionDependencies<R, C, G, W> {
    pub fill_random: R,
    pub clock: C,
    pub tokens: G,
    pub approvals: W,
}

#[derive(Clone)]
pub(super) struct SessionClock(pub Instant);

impl AuthorizationClock for SessionClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

pub(super) struct SessionTokens;

impl AuthorizationTokenGenerator for SessionTokens {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), super::AuthorizationRandomnessError> {
        getrandom::fill(bytes).map_err(|_| super::AuthorizationRandomnessError)
    }
}

/// The platform peer values the exchange cannot read from the stream.
pub(super) struct PairingPeer {
    pub companion_identity: String,
    pub peer_uid: u32,
    pub peer_pid: u32,
}

/// The peer and the shared state for one pairing exchange.
pub(super) struct PairingSession<'a> {
    pub peer: PairingPeer,
    pub first_frame: Option<&'a [u8]>,
    pub registry: &'a LiveConnectionRegistry,
    pub handoff_nonce: Option<&'a str>,
}

/// Injected platform seam for a migration control detour above the exchange.
pub(super) trait MigrationDetour<S: ?Sized, H> {
    /// Answers whether the peer is a verified migration control peer.
    fn admits_peer(&self) -> bool;

    /// Serves the migration control session for an admitted peer.
    fn serve(
        self,
        stream: &mut S,
        selected: u32,
        server_nonce: String,
        fill_random: &mut dyn FnMut(&mut [u8]) -> Result<(), ()>,
        service: &mut H,
    ) -> Result<(), AttachSessionError>;
}

pub(super) struct NoMigration;

impl<S: ?Sized, H> MigrationDetour<S, H> for NoMigration {
    fn admits_peer(&self) -> bool {
        false
    }

    fn serve(
        self,
        _stream: &mut S,
        _selected: u32,
        _server_nonce: String,
        _fill_random: &mut dyn FnMut(&mut [u8]) -> Result<(), ()>,
        _service: &mut H,
    ) -> Result<(), AttachSessionError> {
        unreachable!("a rejected migration peer cannot start a migration session")
    }
}

/// Pairs a companion, authorizes it, and then serves its requests.
pub(super) fn serve_pairing_exchange<S, R, C, G, W, H, M>(
    stream: &mut S,
    session: PairingSession<'_>,
    desktop_version: &str,
    timeout: Duration,
    dependencies: AuthorizationSessionDependencies<R, C, G, W>,
    service: &mut H,
    migration: M,
) -> Result<(), AttachSessionError>
where
    S: DeadlineStream + ?Sized,
    R: FnMut(&mut [u8]) -> Result<(), ()>,
    C: AuthorizationClock + Clone,
    G: AuthorizationTokenGenerator,
    W: ApprovalWaiter,
    H: ThreadListService,
    M: MigrationDetour<S, H>,
{
    let AuthorizationSessionDependencies {
        mut fill_random,
        clock,
        tokens,
        mut approvals,
    } = dependencies;
    let PairingSession {
        peer,
        first_frame,
        registry,
        handoff_nonce,
    } = session;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(AttachSessionError::Timeout)?;
    let owned_frame;
    let frame = match first_frame {
        Some(frame) => frame,
        None => {
            let mut prefix = [0u8; 4];
            read_before(stream, &mut prefix, deadline)?;
            let length = u32::from_be_bytes(prefix) as usize;
            if length > MAX_FRAME_LENGTH {
                write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
                return Err(AttachSessionError::PayloadTooLarge);
            }
            let mut received = Vec::with_capacity(4 + length);
            received.extend_from_slice(&prefix);
            received.resize(4 + length, 0);
            read_before(stream, &mut received[4..], deadline)?;
            owned_frame = received;
            &owned_frame
        }
    };
    let message = match super::decode_frame::<FirstMessage>(frame) {
        Ok(Some((message, _))) => message,
        _ => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(AttachSessionError::MalformedFrame);
        }
    };
    let (
        client_nonce,
        authorized_client_id,
        authorized_client_credential,
        companion_kind,
        companion_version,
    ) = match &message {
        FirstMessage::Hello(hello) => (
            hello.client_nonce.clone(),
            hello.authorized_client_id.as_str().to_owned(),
            hello.authorized_client_credential.clone(),
            hello.client.kind.clone(),
            hello.client.version.clone(),
        ),
        _ => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(AttachSessionError::MalformedFrame);
        }
    };
    let selected = match super::negotiate_first(message, DESKTOP_PROTOCOL) {
        Ok(selected) => selected,
        Err(NegotiationError::Incompatible(error)) => {
            write_protocol_error(stream, error, deadline);
            return Err(AttachSessionError::ProtocolIncompatible);
        }
        Err(_) => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(AttachSessionError::MalformedFrame);
        }
    };

    let migration_peer = migration.admits_peer();

    let mut nonce = [0u8; 16];
    fill_random(&mut nonce).map_err(|_| AttachSessionError::Randomness)?;
    let server_nonce = hex(&nonce);
    let binding = ConnectionBinding {
        connection_id: server_nonce.clone(),
        client_nonce,
        server_nonce: server_nonce.clone(),
        companion_identity: peer.companion_identity,
        companion_kind: companion_kind.clone(),
    };
    if migration_peer {
        return migration.serve(stream, selected, server_nonce, &mut fill_random, service);
    }
    let reconnect = authorized_client_credential
        .as_deref()
        .and_then(|credential| {
            let approval = service.reconnect_approval()?;
            service
                .authorize_client(
                    &authorized_client_id,
                    Some(credential),
                    "",
                    &companion_kind,
                    &companion_version,
                )
                .ok()
                .map(|credential| (approval, credential))
        });
    let mut authorization = AuthorizationState::new(clock.clone(), tokens, binding.clone());
    let challenge_expires_at = clock.now() + CHALLENGE_LIFETIME;
    let challenge = authorization
        .issue_challenge()
        .map_err(|error| match error {
            AuthorizationError::Randomness => AttachSessionError::Randomness,
            _ => AttachSessionError::Authorization,
        })?;
    let authorization_deadline = Instant::now()
        .checked_add(CHALLENGE_LIFETIME)
        .ok_or(AttachSessionError::Timeout)?;
    let response = if reconnect.is_some() {
        muniment_attach::reconnect_welcome(
            selected,
            desktop_version,
            server_nonce,
            challenge.as_str(),
        )
    } else {
        welcome(selected, desktop_version, server_nonce, challenge.as_str())
    };
    let response = match handoff_nonce {
        Some(handoff_nonce) => response.with_handoff_nonce(handoff_nonce),
        None => response,
    };
    write_before(
        stream,
        &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
        deadline,
    )?;

    let (approval, reconnect_credential) = match reconnect {
        Some((approval, credential)) => (approval, Some(credential)),
        None => {
            let remaining = challenge_expires_at.saturating_sub(clock.now());
            let Some(ApprovalDecision::Approve(approval)) =
                approvals.wait(&challenge, &companion_kind, &companion_version, remaining)
            else {
                return Ok(());
            };
            (approval, None)
        }
    };
    let (capability, grant) = authorization
        .approve(&challenge, approval)
        .map_err(|error| match error {
            AuthorizationError::Randomness => AttachSessionError::Randomness,
            AuthorizationError::ChallengeExpired => AttachSessionError::Timeout,
            _ => AttachSessionError::Authorization,
        })?;
    if reconnect_credential.is_none() {
        // Reject one already-queued repeat action against the consumed challenge.
        if let Some(ApprovalDecision::Approve(approval)) = approvals.wait(
            &challenge,
            &companion_kind,
            &companion_version,
            Duration::ZERO,
        ) {
            if authorization.approve(&challenge, approval)
                != Err(AuthorizationError::ChallengeConsumed)
            {
                return Err(AttachSessionError::Authorization);
            }
        }
    }
    let remaining = grant.expires_at.saturating_sub(clock.now()).as_secs();
    let mut workspace_scopes = std::collections::BTreeMap::new();
    workspace_scopes.insert(grant.workspace.clone(), grant.scopes.clone());
    let client_credential = match reconnect_credential {
        Some(credential) => credential,
        None => {
            let mut credential_bytes = [0u8; 32];
            fill_random(&mut credential_bytes).map_err(|_| AttachSessionError::Randomness)?;
            let issued_credential = hex(&credential_bytes);
            match service.authorize_client(
                &authorized_client_id,
                authorized_client_credential.as_deref(),
                &issued_credential,
                &companion_kind,
                &companion_version,
            ) {
                Ok(credential) => credential,
                Err(error) => {
                    write_protocol_error(stream, error, authorization_deadline);
                    return Err(AttachSessionError::Authorization);
                }
            }
        }
    };
    let response = super::authorized_with_client_credential(
        &grant.profile,
        capability.as_str(),
        remaining,
        grant.idle_timeout.as_secs(),
        workspace_scopes,
        client_credential.clone(),
    );
    let connection_event_id = super::Id::new(uuid::Uuid::new_v4().to_string())
        .map_err(|_| AttachSessionError::Randomness)?;
    let connection = registry.register(
        client_credential,
        capability.as_str().to_owned(),
        connection_event_id,
    );
    write_before(
        stream,
        &encode_frame(&response).map_err(|_| AttachSessionError::MalformedFrame)?,
        authorization_deadline,
    )?;
    let provenance = CompanionProvenance {
        profile: grant.profile.clone(),
        companion_kind: binding.companion_kind.clone(),
        companion_version,
        peer_uid: peer.peer_uid,
        peer_pid: peer.peer_pid,
    };
    serve_requests(
        stream,
        timeout,
        AuthorizedSession {
            binding: &binding,
            provenance: &provenance,
            workspace: &grant.workspace,
            connection: &connection,
        },
        &mut authorization,
        service,
    )?;
    Ok(())
}
