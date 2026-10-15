//! Admission and request serving for paired remote clients.
//!
//! A remote client authenticates in its hello, either by redeeming a pairing
//! secret or with its device credential, and then speaks the desktop client
//! protocol. Each request passes the remote allow list and the device's
//! scopes before the desktop dispatch sees it. Remote clients never reach a
//! companion approval prompt.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use muniment_attach::{
    decode_frame, encode_frame, reconnect_welcome, DeviceCredential, Event, EventName,
    FirstMessage, Id, NegotiationError, Operation, ProtocolError, RemoteClientAuthorizedGrant,
    Request, VersionRange, MAX_FRAME_LENGTH, SCOPE_RUNTIME_ADMIN, SCOPE_RUN_WRITE,
    SCOPE_THREAD_READ,
};
use serde_json::Value;

use super::deadline_io::{is_timeout, write_all_before, DeadlineStream};
use super::desktop_admission::write_protocol_error;
use super::desktop_service_message::CompanionProvenance;
use super::desktop_session::{
    serve_desktop_client_requests, DesktopDispatchFailure, DesktopDispatchResult,
    DesktopSessionService,
};
use super::remote_access::{dispatch_remote_operation, RemoteAccess};
use super::thread_service::ThreadListService;
use super::{
    bounded_claim, Approval, AttachSessionError, CAPABILITY_IDLE_LIFETIME, MAX_CAPABILITY_LIFETIME,
};

const REMOTE_PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };
/// How often a live session rereads the store for a revocation made by
/// another process. A revocation in this process closes it on its next turn.
const DEVICE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// How the remote route admits one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteRule {
    /// The operation only makes sense on the runtime's own machine, or acts
    /// on the host's cloud account, so a remote client never reaches it.
    Excluded,
    /// Any paired device may send it.
    AnyScope,
    /// A device holding the named scope may send it.
    Scope(&'static str),
    /// Remote access handles it and checks the admin scope where it needs it.
    RemoteAccess,
    /// The request names a file on the runtime's own machine, which a
    /// remote device never reads. The reason tells its user why.
    Refused(&'static str),
}

/// The reader source that opens a file on the runtime's machine by path.
const FILE_READER_SOURCE: &str = "csv";
const HOST_FILE_REASON: &str = "A paired device cannot read files on the runtime's computer.";
const HOST_ATTACHMENT_REASON: &str =
    "A paired device cannot attach files to a thread on another computer yet.";

/// The remote allow list. The match is exhaustive, so a new operation stays
/// off the remote route until it is classified here.
pub fn remote_rule(operation: Operation, body: &Value) -> RemoteRule {
    match operation {
        // Paths of the client's own filesystem, the approval presenter, the
        // executable handoff, same-machine companions, and the host's cloud
        // account with its browser sign-in and phone pairing.
        Operation::WorkspaceOnboard
        | Operation::MigrationControl
        | Operation::ApprovalPresent
        | Operation::CompanionList
        | Operation::CompanionRevoke
        | Operation::SessionStatus
        | Operation::EntitlementSnapshot
        | Operation::DeviceList
        | Operation::SessionSignIn
        | Operation::SessionSignOut
        | Operation::PairingChallenge
        | Operation::PairingStatus
        | Operation::PairingRevoke
        // The listener's own settings: a remote client could turn off the
        // route it speaks over or move it.
        | Operation::RemoteSettings
        | Operation::RemoteSettingsSave => RemoteRule::Excluded,
        Operation::RequestCancel => RemoteRule::AnyScope,
        Operation::ThreadList
        | Operation::ThreadOpen
        | Operation::ThreadSummaries
        | Operation::ThreadHistory
        | Operation::ThreadContextUsage
        | Operation::RunOpen
        | Operation::RunStream
        | Operation::RunChatEvents
        | Operation::RunDetail
        | Operation::RunCursorAck
        | Operation::ArtifactFetch
        | Operation::ArtifactWindow
        | Operation::CompanyList
        | Operation::RecordSql
        | Operation::RecordKinds
        | Operation::RecordQuery
        | Operation::RecordEntity
        | Operation::RecordReport
        | Operation::ReaderQueue
        | Operation::ContextSettings => RemoteRule::Scope(SCOPE_THREAD_READ),
        // A file reader takes a path on the runtime's machine, such as its
        // credential files. Network sources read through stored secrets.
        Operation::ReaderDescribe | Operation::ReaderObjects
            if body.get("source").and_then(Value::as_str) == Some(FILE_READER_SOURCE) =>
        {
            RemoteRule::Refused(HOST_FILE_REASON)
        }
        Operation::ReaderDescribe | Operation::ReaderObjects => {
            RemoteRule::Scope(SCOPE_THREAD_READ)
        }
        // Attached files are paths the runtime reads from its own disk, so a
        // remote request carries none.
        Operation::RunSubmit
            if body
                .get("files")
                .and_then(Value::as_array)
                .is_some_and(|files| !files.is_empty()) =>
        {
            RemoteRule::Refused(HOST_ATTACHMENT_REASON)
        }
        Operation::HomeEnsure
        | Operation::ThreadCreate
        | Operation::ThreadRename
        | Operation::ThreadSelect
        | Operation::ThreadDelete
        | Operation::ThreadCompact
        | Operation::RunStart
        | Operation::RunSubmit
        | Operation::RunResume
        | Operation::RunSteer
        | Operation::RunFollowUp
        | Operation::RunCancel
        | Operation::RunPermissionAnswer
        | Operation::PermissionAnswer
        | Operation::CompanyCreate
        | Operation::CompanySelect
        | Operation::CompanyRename
        | Operation::CompanyDelete
        | Operation::RecordPropose
        | Operation::RecordCommit
        | Operation::ReaderRun
        | Operation::RetentionRecheck
        | Operation::ContextSettingsSave => RemoteRule::Scope(SCOPE_RUN_WRITE),
        // Connecting a source stores its secret on the runtime.
        Operation::ReaderConnect => RemoteRule::Scope(SCOPE_RUNTIME_ADMIN),
        // Model reads are reads. A model change can store provider keys.
        Operation::ModelsRequest => match super::ModelRequest::from_body(body) {
            Some(request) if !request.action.mutates() => RemoteRule::Scope(SCOPE_THREAD_READ),
            _ => RemoteRule::Scope(SCOPE_RUNTIME_ADMIN),
        },
        Operation::RuntimeInfo
        | Operation::RemotePairingCreate
        | Operation::RemoteDeviceList
        | Operation::RemoteDeviceRevoke
        | Operation::RuntimeUpdate => RemoteRule::RemoteAccess,
    }
}

/// Closed outcomes from remote client admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAdmissionError {
    Closed,
    Timeout,
    MalformedFrame,
    PayloadTooLarge,
    ProtocolIncompatible,
    /// The pairing secret or device credential was refused.
    Unauthorized,
    /// The store could not be read or written.
    Unavailable,
    Randomness,
}

impl RemoteAdmissionError {
    /// Whether the attempt counts toward the peer's failure backoff. A peer
    /// that never sends its hello counts too, since it held a slot.
    pub fn is_failed_attempt(self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::MalformedFrame | Self::PayloadTooLarge | Self::Timeout
        )
    }
}

/// A remote client the runtime admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRemoteClient {
    pub capability: String,
    pub device_id: String,
    pub scopes: BTreeSet<String>,
    pub workspace: String,
    pub profile: String,
    pub companion_kind: String,
    pub companion_version: String,
}

/// Admits a remote client from its first frame: negotiates the version,
/// redeems the pairing secret or checks the device credential, then writes
/// the welcome with the runtime's identity and the grant.
pub fn admit_remote_client<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    frame: &[u8],
    access: &RemoteAccess,
    approval: Option<&Approval>,
    deadline: Instant,
) -> Result<AdmittedRemoteClient, RemoteAdmissionError> {
    if frame.len() < 4
        || u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize > MAX_FRAME_LENGTH
    {
        write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
        return Err(RemoteAdmissionError::PayloadTooLarge);
    }
    let message = match decode_frame::<FirstMessage>(frame) {
        Ok(Some((message, consumed))) if consumed == frame.len() => message,
        _ => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(RemoteAdmissionError::MalformedFrame);
        }
    };
    let FirstMessage::Hello(hello) = &message else {
        write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
        return Err(RemoteAdmissionError::MalformedFrame);
    };
    let hello = hello.clone();
    let selected = match muniment_attach::negotiate_first(message, REMOTE_PROTOCOL) {
        Ok(selected) => selected,
        Err(NegotiationError::Incompatible(error)) => {
            write_protocol_error(stream, error, deadline);
            return Err(RemoteAdmissionError::ProtocolIncompatible);
        }
        Err(_) => {
            write_protocol_error(stream, ProtocolError::malformed_frame(), deadline);
            return Err(RemoteAdmissionError::MalformedFrame);
        }
    };

    let companion_kind = bounded_claim(&hello.client.kind);
    let companion_version = bounded_claim(&hello.client.version);
    let authenticated = match (&hello.pairing, &hello.authorized_client_credential) {
        (Some(pairing), None) => access
            .redeem_pairing(
                &pairing.secret,
                &companion_kind,
                pairing.device_name.as_deref(),
                pairing.scopes.as_ref(),
            )
            .map(|issued| {
                let credential =
                    Id::new(issued.device_id.as_str())
                        .ok()
                        .map(|device_id| DeviceCredential {
                            device_id,
                            secret: issued.secret,
                        });
                (issued.device_id, issued.scopes, credential)
            }),
        (None, Some(secret)) => access
            .authenticate_device(hello.authorized_client_id.as_str(), secret)
            .map(|device| (device.device_id, device.scopes, None)),
        _ => Err(ProtocolError::unauthorized()),
    };
    let (device_id, scopes, device_credential) = match authenticated {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let refused = error.code() == muniment_attach::ErrorCode::Unauthorized;
            write_protocol_error(stream, error, deadline);
            return Err(if refused {
                RemoteAdmissionError::Unauthorized
            } else {
                RemoteAdmissionError::Unavailable
            });
        }
    };

    let mut nonce = [0_u8; 16];
    let mut capability = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| RemoteAdmissionError::Randomness)?;
    getrandom::fill(&mut capability).map_err(|_| RemoteAdmissionError::Randomness)?;
    let capability = super::desktop_dispatch::hex(&capability);
    let info = access.runtime_info();
    let mut welcome = reconnect_welcome(
        selected,
        info.runtime_version.clone(),
        super::desktop_dispatch::hex(&nonce),
        "",
    );
    welcome.runtime = Some(info);

    let profile = approval.map_or_else(
        || "desktop-owner".to_owned(),
        |approval| approval.profile.clone(),
    );
    let mut workspace_scopes = BTreeMap::new();
    if let Some(approval) = approval {
        let granted: BTreeSet<String> = approval.scopes.intersection(&scopes).cloned().collect();
        if !granted.is_empty() {
            workspace_scopes.insert(approval.workspace.clone(), granted);
        }
    }
    let grant = RemoteClientAuthorizedGrant {
        profile_id: profile.clone(),
        capability: capability.clone(),
        expires_at: MAX_CAPABILITY_LIFETIME.as_secs(),
        idle_timeout_seconds: CAPABILITY_IDLE_LIFETIME.as_secs(),
        workspace_scopes,
        scopes: scopes.clone(),
        device_credential,
    };
    for frame in [encode_frame(&welcome), encode_frame(&grant)] {
        let frame = frame.map_err(|_| RemoteAdmissionError::MalformedFrame)?;
        write_all_before(stream, &frame, deadline).map_err(|error| {
            if is_timeout(&error) {
                RemoteAdmissionError::Timeout
            } else {
                RemoteAdmissionError::Closed
            }
        })?;
    }

    Ok(AdmittedRemoteClient {
        capability,
        device_id,
        scopes,
        workspace: approval.map_or_else(String::new, |approval| approval.workspace.clone()),
        profile,
        companion_kind,
        companion_version,
    })
}

/// Serves an admitted remote client's requests until it disconnects, its
/// capability expires or idles out, or its device is revoked.
pub fn serve_remote_client<S, H>(
    stream: &mut S,
    admitted: &AdmittedRemoteClient,
    access: &RemoteAccess,
    service: &mut H,
) -> Result<(), AttachSessionError>
where
    S: DeadlineStream + ?Sized,
    H: ThreadListService,
{
    service.bind_authorized_client(&admitted.device_id);
    let now = Instant::now();
    let mut session = RemoteSession {
        service,
        access: access.clone(),
        device_id: admitted.device_id.clone(),
        scopes: admitted.scopes.clone(),
        expires: now + MAX_CAPABILITY_LIFETIME,
        idle: CAPABILITY_IDLE_LIFETIME,
        last_activity: now,
        next_device_check: now + DEVICE_CHECK_INTERVAL,
    };
    serve_desktop_client_requests(
        stream,
        &admitted.capability,
        &admitted.workspace,
        CompanionProvenance {
            profile: admitted.profile.clone(),
            companion_kind: admitted.companion_kind.clone(),
            companion_version: admitted.companion_version.clone(),
            peer_uid: 0,
            peer_pid: 0,
        },
        &mut session,
    )
}

/// The desktop session service seen through the remote allow list, the
/// device's scopes, the capability lifetime and revocation.
pub(super) struct RemoteSession<'a, H> {
    pub(super) service: &'a mut H,
    pub(super) access: RemoteAccess,
    pub(super) device_id: String,
    pub(super) scopes: BTreeSet<String>,
    pub(super) expires: Instant,
    pub(super) idle: Duration,
    pub(super) last_activity: Instant,
    pub(super) next_device_check: Instant,
}

impl<H> RemoteSession<'_, H> {
    /// Fails once the capability expired or idled out or the device was
    /// revoked. The session loop then writes the error and closes.
    fn check_authority(&mut self) -> Result<(), ProtocolError> {
        let now = Instant::now();
        if now >= self.expires
            || now.saturating_duration_since(self.last_activity) >= self.idle
            || self.access.revoked_here(&self.device_id)
        {
            return Err(ProtocolError::unauthorized());
        }
        if now >= self.next_device_check {
            self.next_device_check = now + DEVICE_CHECK_INTERVAL;
            if !self.access.device_paired(&self.device_id) {
                return Err(ProtocolError::unauthorized());
            }
        }
        Ok(())
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl<H: ThreadListService> DesktopSessionService for RemoteSession<'_, H> {
    type State = <H as DesktopSessionService>::State;
    type Provenance = CompanionProvenance;

    fn new_session_state(&self) -> Self::State {
        DesktopSessionService::new_session_state(&*self.service)
    }

    fn poll_run_streams(&mut self, state: &mut Self::State) -> Result<Vec<Event>, ProtocolError> {
        self.check_authority()?;
        let events = DesktopSessionService::poll_run_streams(self.service, state)?;
        if !events.is_empty() {
            self.touch();
        }
        Ok(events)
    }

    fn has_chat_subscription(&self, state: &Self::State) -> bool {
        DesktopSessionService::has_chat_subscription(&*self.service, state)
    }

    fn chat_snapshot_chunks(&self, state: &Self::State) -> bool {
        DesktopSessionService::chat_snapshot_chunks(&*self.service, state)
    }

    #[cfg(target_os = "linux")]
    fn record_chat_delivery_failure(&mut self, run_id: &str, cause: &str) {
        DesktopSessionService::record_chat_delivery_failure(self.service, run_id, cause);
    }

    fn drain_chat_events(
        &mut self,
        state: &mut Self::State,
        wait: Duration,
    ) -> Result<(Vec<Event>, bool), AttachSessionError> {
        let (mut events, closed) =
            DesktopSessionService::drain_chat_events(self.service, state, wait)?;
        // Update requests reach the owner's local desktop, whose host runs
        // the updater, and never a remote device.
        events.retain(|event| event.event != EventName::RuntimeUpdateRequested);
        if !events.is_empty() {
            self.touch();
        }
        Ok((events, closed))
    }

    fn dispatch_request(
        &mut self,
        request: Request,
        workspace: &str,
        provenance: Self::Provenance,
        state: &mut Self::State,
    ) -> Result<DesktopDispatchResult, DesktopDispatchFailure> {
        let refuse = |error: ProtocolError| DesktopDispatchFailure {
            error,
            events: Vec::new(),
        };
        self.check_authority().map_err(refuse)?;
        self.touch();
        match remote_rule(request.operation, &request.body) {
            RemoteRule::Excluded => Err(refuse(ProtocolError::unsupported_operation())),
            RemoteRule::Refused(reason) => {
                Err(refuse(ProtocolError::invalid_request_with_reason(reason)))
            }
            RemoteRule::Scope(scope) if !self.scopes.contains(scope) => {
                Err(refuse(ProtocolError::unauthorized()))
            }
            RemoteRule::RemoteAccess => {
                dispatch_remote_operation(&self.access, &request, &self.scopes, &self.device_id)
                    .map(|body| DesktopDispatchResult {
                        body,
                        events: Vec::new(),
                    })
                    .map_err(refuse)
            }
            RemoteRule::AnyScope | RemoteRule::Scope(_) => DesktopSessionService::dispatch_request(
                self.service,
                request,
                workspace,
                provenance,
                state,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::{PairingLinkRequest, RemoteAccessOptions};
    use muniment_attach::{InstallKind, Protocol, PAIRING_SECRET_HEX_LENGTH};
    use serde_json::json;

    struct Owner(RemoteAccess);

    impl ThreadListService for Owner {
        fn remote_access(&self) -> Option<RemoteAccess> {
            Some(self.0.clone())
        }
    }

    /// The owner's service with the remote route and a chat-event stream.
    struct RoutedOwner {
        route: std::sync::Arc<crate::attach::RemoteRoute>,
        _chat: std::sync::mpsc::Sender<crate::run_events::ChatEvent>,
        chat: Option<std::sync::mpsc::Receiver<crate::run_events::ChatEvent>>,
    }

    impl RoutedOwner {
        fn new(access: RemoteAccess) -> Self {
            let serve: crate::attach::RemoteServe =
                std::sync::Arc::new(|_, _, _| Ok::<(), crate::attach::RemoteListenerError>(()));
            let (sender, receiver) = std::sync::mpsc::channel();
            Self {
                route: std::sync::Arc::new(crate::attach::RemoteRoute::new(
                    access,
                    crate::attach::RemoteSettingsOverrides::default(),
                    serve,
                )),
                _chat: sender,
                chat: Some(receiver),
            }
        }
    }

    impl ThreadListService for RoutedOwner {
        fn remote_access(&self) -> Option<RemoteAccess> {
            Some(self.route.access().clone())
        }

        fn remote_route(&self) -> Option<std::sync::Arc<crate::attach::RemoteRoute>> {
            Some(std::sync::Arc::clone(&self.route))
        }

        fn subscribe_chat_events(
            &mut self,
        ) -> Result<crate::run_events::ChatEventSubscription, ProtocolError> {
            self.chat
                .take()
                .map(crate::run_events::ChatEventSubscription::detached)
                .ok_or_else(ProtocolError::invalid_request)
        }
    }

    struct Plain;

    impl ThreadListService for Plain {}

    fn access(directory: &std::path::Path) -> RemoteAccess {
        RemoteAccess::open(
            directory,
            RemoteAccessOptions {
                runtime_name: Some("Owner box".into()),
                runtime_version: "2.0.0".into(),
                install_kind: InstallKind::Desktop,
            },
        )
        .unwrap()
    }

    fn request(operation: Operation, body: Value) -> Request {
        Request {
            protocol: Protocol,
            request_id: Id::new(uuid::Uuid::now_v7().to_string()).unwrap(),
            operation,
            capability: String::new(),
            idempotency_key: None,
            body,
        }
    }

    fn provenance() -> CompanionProvenance {
        CompanionProvenance {
            profile: "desktop-owner".into(),
            companion_kind: "desktop-client".into(),
            companion_version: "1.0.0".into(),
            peer_uid: 0,
            peer_pid: 0,
        }
    }

    fn dispatch<S: DesktopSessionService<Provenance = CompanionProvenance>>(
        service: &mut S,
        request: Request,
    ) -> Result<Value, ProtocolError> {
        let mut state = service.new_session_state();
        service
            .dispatch_request(request, "", provenance(), &mut state)
            .map(|result| result.body)
            .map_err(|failure| failure.error)
    }

    #[test]
    fn the_local_owner_route_pairs_lists_and_revokes_with_every_scope() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-owner-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        let mut owner = Owner(access.clone());
        let created = dispatch(
            &mut owner,
            request(
                Operation::RemotePairingCreate,
                json!({"scopes": ["thread.read", "runtime.admin"], "endpoints": ["198.51.100.2:7443"]}),
            ),
        )
        .unwrap();
        let link = muniment_attach::PairingLink::parse(created["link"].as_str().unwrap()).unwrap();
        assert_eq!(link.endpoints, vec!["198.51.100.2:7443".to_owned()]);
        assert_eq!(link.secret.len(), PAIRING_SECRET_HEX_LENGTH);
        assert_eq!(created["scopes"], json!(["runtime.admin", "thread.read"]));

        let issued = access
            .redeem_pairing(&link.secret, "cli", None, None)
            .unwrap();
        let devices =
            dispatch(&mut owner, request(Operation::RemoteDeviceList, json!({}))).unwrap();
        assert_eq!(devices["devices"][0]["device_id"], issued.device_id);
        assert_eq!(devices["devices"][0]["name"], "cli");
        assert!(!devices.to_string().contains(&issued.secret));
        let info = dispatch(&mut owner, request(Operation::RuntimeInfo, json!({}))).unwrap();
        assert_eq!(info["runtime_name"], "Owner box");
        assert_eq!(info["install_kind"], "desktop");
        let revoked = dispatch(
            &mut owner,
            request(
                Operation::RemoteDeviceRevoke,
                json!({"device_id": issued.device_id}),
            ),
        )
        .unwrap();
        assert_eq!(revoked, json!({"revoked": true}));
        assert!(access
            .authenticate_device(&issued.device_id, &issued.secret)
            .is_err());

        // Keys are refused, since a replayed answer would hold a secret.
        let mut keyed = request(Operation::RemotePairingCreate, json!({}));
        keyed.idempotency_key = Some(Id::new(uuid::Uuid::now_v7().to_string()).unwrap());
        assert_eq!(
            dispatch(&mut owner, keyed).unwrap_err().code(),
            muniment_attach::ErrorCode::IdempotencyKeyForbidden
        );
        // A link names at least one endpoint.
        assert_eq!(
            dispatch(
                &mut owner,
                request(Operation::RemotePairingCreate, json!({}))
            )
            .unwrap_err()
            .code(),
            muniment_attach::ErrorCode::InvalidRequest
        );
        assert_eq!(
            dispatch(&mut Plain, request(Operation::RuntimeInfo, json!({})))
                .unwrap_err()
                .code(),
            muniment_attach::ErrorCode::UnsupportedOperation
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn remote_settings_are_served_on_the_local_owner_route_only() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-settings-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        let mut owner = RoutedOwner::new(access.clone());
        let read = dispatch(&mut owner, request(Operation::RemoteSettings, json!({}))).unwrap();
        assert_eq!(read["settings"]["enabled"], false);
        assert_eq!(read["runtime_id"], access.runtime_info().runtime_id);
        assert_eq!(
            read["certificate_sha256"],
            access.certificate_fingerprint().to_hex()
        );
        let saved = dispatch(
            &mut owner,
            request(
                Operation::RemoteSettingsSave,
                json!({"enabled": true, "listen": "127.0.0.1:0", "endpoints": ["198.51.100.2:7443"]}),
            ),
        )
        .unwrap();
        assert_eq!(saved["settings"]["enabled"], true);
        assert_eq!(saved["settings"]["listen"], "127.0.0.1:0");
        assert!(saved["listening"].is_string());
        assert_eq!(
            saved["endpoints"],
            json!([{"endpoint": "198.51.100.2:7443", "kind": "configured"}])
        );
        for body in [
            json!({"enabled": true, "extra": 1}),
            json!({"enabled": true, "listen": "not an address"}),
            json!({"listen": null}),
        ] {
            assert_eq!(
                dispatch(&mut owner, request(Operation::RemoteSettingsSave, body))
                    .unwrap_err()
                    .code(),
                muniment_attach::ErrorCode::InvalidRequest
            );
        }
        assert_eq!(
            dispatch(&mut Plain, request(Operation::RemoteSettings, json!({})))
                .unwrap_err()
                .code(),
            muniment_attach::ErrorCode::UnsupportedOperation
        );

        // A paired admin device reaches neither operation.
        for operation in [Operation::RemoteSettings, Operation::RemoteSettingsSave] {
            assert_eq!(remote_rule(operation, &json!({})), RemoteRule::Excluded);
        }
        let mut session = RemoteSession {
            service: &mut owner,
            access: access.clone(),
            device_id: uuid::Uuid::now_v7().to_string(),
            scopes: crate::attach::remote_access::all_scopes(),
            expires: Instant::now() + Duration::from_secs(60),
            idle: Duration::from_secs(60),
            last_activity: Instant::now(),
            next_device_check: Instant::now() + Duration::from_secs(60),
        };
        for (operation, body) in [
            (Operation::RemoteSettings, json!({})),
            (
                Operation::RemoteSettingsSave,
                json!({"enabled": false, "listen": null, "endpoints": []}),
            ),
        ] {
            assert_eq!(
                dispatch(&mut session, request(operation, body))
                    .unwrap_err()
                    .code(),
                muniment_attach::ErrorCode::UnsupportedOperation
            );
        }
        assert_eq!(
            owner.route.status().settings.listen,
            Some("127.0.0.1:0".parse().unwrap())
        );
        owner.route.stop();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_update_request_reaches_the_local_owner_subscription_and_no_remote_device() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-update-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        let mut owner = RoutedOwner::new(access.clone());
        let mut state = owner.new_session_state();
        owner
            .dispatch_request(
                request(Operation::RunChatEvents, json!({})),
                "",
                provenance(),
                &mut state,
            )
            .map_err(|failure| failure.error)
            .unwrap();
        access.request_update("2.1.0", "local").unwrap();
        let (events, _) = owner
            .drain_chat_events(&mut state, Duration::from_millis(10))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, EventName::RuntimeUpdateRequested);
        assert_eq!(events[0].body["version"], "2.1.0");
        assert_eq!(events[0].body["requested_by"], "local");

        let mut remote_owner = RoutedOwner::new(access.clone());
        let mut session = RemoteSession {
            service: &mut remote_owner,
            access: access.clone(),
            device_id: uuid::Uuid::now_v7().to_string(),
            scopes: crate::attach::remote_access::all_scopes(),
            expires: Instant::now() + Duration::from_secs(60),
            idle: Duration::from_secs(60),
            last_activity: Instant::now(),
            next_device_check: Instant::now() + Duration::from_secs(60),
        };
        let mut remote_state = session.new_session_state();
        session
            .dispatch_request(
                request(Operation::RunChatEvents, json!({})),
                "",
                provenance(),
                &mut remote_state,
            )
            .map_err(|failure| failure.error)
            .unwrap();
        access.request_update("2.2.0", "local").unwrap();
        let (events, _) = session
            .drain_chat_events(&mut remote_state, Duration::from_millis(10))
            .unwrap();
        assert!(events.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_redemptions_of_one_link_issue_one_device() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-race-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        access
            .set_advertised_endpoints(vec!["198.51.100.2:7443".into()])
            .unwrap();
        let secret = access
            .create_pairing_link(PairingLinkRequest::default())
            .unwrap()
            .link
            .secret;
        let redeemed: Vec<bool> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| access.redeem_pairing(&secret, "cli", None, None).is_ok()))
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect()
        });
        assert_eq!(redeemed.iter().filter(|redeemed| **redeemed).count(), 1);
        assert_eq!(access.list_devices().unwrap().len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn outstanding_links_are_bounded() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-bounded-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        access
            .set_advertised_endpoints(vec!["198.51.100.2:7443".into()])
            .unwrap();
        for _ in 0..crate::attach::MAX_OUTSTANDING_PAIRINGS {
            access
                .create_pairing_link(PairingLinkRequest::default())
                .unwrap();
        }
        assert!(access
            .create_pairing_link(PairingLinkRequest::default())
            .is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_session_refuses_work_after_its_capability_idles_out_or_expires() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-idle-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        access
            .set_advertised_endpoints(vec!["198.51.100.2:7443".into()])
            .unwrap();
        let link = access
            .create_pairing_link(PairingLinkRequest::default())
            .unwrap()
            .link;
        let issued = access
            .redeem_pairing(&link.secret, "cli", None, None)
            .unwrap();
        let mut plain = Plain;
        let now = Instant::now();
        let mut session = RemoteSession {
            service: &mut plain,
            access,
            device_id: issued.device_id,
            scopes: issued.scopes,
            expires: now + Duration::from_secs(60),
            idle: Duration::from_secs(60),
            last_activity: now,
            next_device_check: now,
        };
        assert!(session.check_authority().is_ok());
        session.last_activity = now - Duration::from_secs(61);
        assert!(session.check_authority().is_err());
        session.last_activity = Instant::now();
        session.expires = Instant::now();
        assert!(session.check_authority().is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn host_files_stay_off_the_remote_route() {
        let refused = |operation, body: Value| {
            matches!(remote_rule(operation, &body), RemoteRule::Refused(_))
        };
        assert!(refused(
            Operation::ReaderDescribe,
            json!({"source": "csv", "object": "/data/credentials/a/b"})
        ));
        assert!(refused(Operation::ReaderObjects, json!({"source": "csv"})));
        assert_eq!(
            remote_rule(
                Operation::ReaderDescribe,
                &json!({"source": "stripe", "object": "customers"})
            ),
            RemoteRule::Scope(SCOPE_THREAD_READ)
        );
        assert!(refused(
            Operation::RunSubmit,
            json!({"text": "read this", "files": ["/etc/hosts"], "thread_id": null})
        ));
        assert_eq!(
            remote_rule(
                Operation::RunSubmit,
                &json!({"text": "hello", "files": [], "thread_id": null})
            ),
            RemoteRule::Scope(SCOPE_RUN_WRITE)
        );

        let directory =
            std::env::temp_dir().join(format!("muniment-remote-files-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        let mut owner = Owner(access.clone());
        let mut session = RemoteSession {
            service: &mut owner,
            access,
            device_id: uuid::Uuid::now_v7().to_string(),
            scopes: crate::attach::remote_access::all_scopes(),
            expires: Instant::now() + Duration::from_secs(60),
            idle: Duration::from_secs(60),
            last_activity: Instant::now(),
            next_device_check: Instant::now() + Duration::from_secs(60),
        };
        let mut state = session.new_session_state();
        let answer = session.dispatch_request(
            request(
                Operation::ReaderDescribe,
                json!({"source": "csv", "object": "/etc/hosts"}),
            ),
            "",
            provenance(),
            &mut state,
        );
        let Err(failure) = answer else {
            panic!("A host file read must be refused.");
        };
        assert_eq!(
            failure.error.code(),
            muniment_attach::ErrorCode::InvalidRequest
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_update_needs_the_update_scope_and_a_newer_version() {
        use crate::attach::remote_access::dispatch_remote_operation;
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-upd-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        let scopes = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        let update = |version: &str, granted: &BTreeSet<String>| {
            dispatch_remote_operation(
                &access,
                &request(Operation::RuntimeUpdate, json!({"version": version})),
                granted,
                "device",
            )
        };
        assert!(muniment_attach::default_pairing_scopes()
            .contains(muniment_attach::SCOPE_RUNTIME_UPDATE));
        assert!(!muniment_attach::default_pairing_scopes().contains(SCOPE_RUNTIME_ADMIN));
        assert_eq!(
            update("2.1.0", &scopes(&[SCOPE_THREAD_READ, SCOPE_RUN_WRITE]))
                .unwrap_err()
                .code(),
            muniment_attach::ErrorCode::Unauthorized
        );
        let updater = scopes(&[muniment_attach::SCOPE_RUNTIME_UPDATE]);
        assert_eq!(update("2.1.0", &updater).unwrap()["version"], "2.1.0");
        // The runtime announces 2.0.0, so the same or an older version is refused.
        for version in ["2.0.0", "1.9.9", "2.0.0-beta.1"] {
            assert_eq!(
                update(version, &updater).unwrap_err().code(),
                muniment_attach::ErrorCode::InvalidRequest,
                "{version}"
            );
        }
        assert!(update("2.0.1", &scopes(&[SCOPE_RUNTIME_ADMIN])).is_ok());
        // A release follows its own pre-releases.
        let candidate = RemoteAccess::open(
            directory.join("candidate"),
            RemoteAccessOptions {
                runtime_name: None,
                runtime_version: "2.1.0-rc.1".into(),
                install_kind: InstallKind::Server,
            },
        )
        .unwrap();
        assert!(candidate.request_update("2.1.0", "device").is_ok());
        assert!(candidate
            .request_update("2.1.0-rc.2+build.5", "device")
            .is_err());
        drop(candidate);
        // After the update the saved request no longer counts.
        let updated = RemoteAccess::open(
            directory.join("candidate"),
            RemoteAccessOptions {
                runtime_name: None,
                runtime_version: "2.1.0".into(),
                install_kind: InstallKind::Server,
            },
        )
        .unwrap();
        assert_eq!(updated.requested_update(), None);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_device_revokes_itself_without_the_admin_scope_but_not_another() {
        use crate::attach::remote_access::dispatch_remote_operation;
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-rev-{}", uuid::Uuid::now_v7()));
        let access = access(&directory);
        let reader: BTreeSet<String> = [SCOPE_THREAD_READ, SCOPE_RUN_WRITE]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let me = uuid::Uuid::now_v7().to_string();
        let other = uuid::Uuid::now_v7().to_string();
        let revoke = |device_id: &str, granted: &BTreeSet<String>| {
            dispatch_remote_operation(
                &access,
                &request(
                    Operation::RemoteDeviceRevoke,
                    json!({"device_id": device_id}),
                ),
                granted,
                &me,
            )
        };
        assert_eq!(
            revoke(&other, &reader).unwrap_err().code(),
            muniment_attach::ErrorCode::Unauthorized
        );
        assert!(revoke(&me, &reader).is_ok());
        assert!(access.revoked_here(&me));
        assert!(!access.revoked_here(&other));
        let admin: BTreeSet<String> = [SCOPE_RUNTIME_ADMIN.to_owned()].into();
        assert!(revoke(&other, &admin).is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
