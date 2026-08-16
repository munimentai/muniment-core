//! Generic desktop attach service seam.

#![cfg(target_os = "linux")]

use super::linux::{
    CompanionProvenance, EntitlementSnapshotResult, MigrationControlRequest,
    PermissionAnswerAccepted, PermissionAnswerRequest, PermissionDecision, RunCancelAccepted,
    RunCancelRequest, RunMessageAccepted, RunMessageRequest, RunPermissionAnswerAccepted,
    RunPermissionAnswerRequest, RunResumeAccepted, RunResumeRequest, RunStartAccepted,
    RunStartRequest as AttachRunStartRequest, RunStreamPage, RunSubmitAccepted, RunSubmitRequest,
    ThreadCreateAccepted, ThreadListPage, ThreadListRequest, ThreadListService, ThreadOpenPage,
    ThreadOpenRequest,
};
use super::{
    bounded_claim, onboard_workspace_context,
    save_client_credentials as persist_client_credentials, Approval, ClientCredential,
    CommittedResult, Id, IdempotencyOutcome, IdempotencyStore, Operation, Protocol, ProtocolError,
    Request as AttachRequest, WorkspaceContextMap, WorkspaceOnboardRequest, WorkspaceOnboarded,
};
use crate::active_run::ChatDelivery;
use crate::journal::Provenance;
use crate::permission_gate::ChatPermissionAnswer;
use crate::run_start::{
    prepare_desktop_run, RunAttachBoundaries, RunStartBoundaries, RunStartRequest,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(not(test))]
const PERMISSION_COMMIT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const PERMISSION_COMMIT_TIMEOUT: Duration = Duration::from_millis(50);

pub type WorkspaceContexts = Arc<Mutex<WorkspaceContextMap>>;

/// Production adapter from the authorized Linux attach seam into the desktop coordinator.
pub trait RunStartIdempotency {
    fn execute<A, W>(
        &mut self,
        profile: &str,
        request: &AttachRequest,
        canonical_input: &Value,
        authorize: A,
        work: W,
    ) -> Result<IdempotencyOutcome, ProtocolError>
    where
        A: FnOnce() -> Result<(), ProtocolError>,
        W: FnOnce() -> Result<CommittedResult, ProtocolError>;
}

impl RunStartIdempotency for IdempotencyStore {
    fn execute<A, W>(
        &mut self,
        profile: &str,
        request: &AttachRequest,
        canonical_input: &Value,
        authorize: A,
        work: W,
    ) -> Result<IdempotencyOutcome, ProtocolError>
    where
        A: FnOnce() -> Result<(), ProtocolError>,
        W: FnOnce() -> Result<CommittedResult, ProtocolError>,
    {
        IdempotencyStore::execute(self, profile, request, canonical_input, authorize, |_| {
            work()
        })
    }
}

pub struct DesktopAttachService<B, I = IdempotencyStore> {
    pub boundaries: B,
    pub idempotency: I,
    pub home: PathBuf,
    pub workspace_contexts: WorkspaceContexts,
    pub client_credentials: Arc<Mutex<HashMap<String, ClientCredential>>>,
    pub credential_path: Option<PathBuf>,
    pub client_identity: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn queue_run_message<B: RunAttachBoundaries, I: RunStartIdempotency>(
    boundaries: &B,
    idempotency: &mut I,
    operation: Operation,
    delivery: ChatDelivery,
    workspace: &str,
    request: RunMessageRequest,
    request_id: &Id,
    idempotency_key: &Id,
    companion: CompanionProvenance,
) -> Result<RunMessageAccepted, ProtocolError> {
    let canonical_input = json!({
        "workspace": workspace,
        "run_id": &request.run_id,
        "text": &request.text,
    });
    let ledger_request = AttachRequest {
        protocol: Protocol,
        request_id: request_id.clone(),
        operation,
        capability: String::new(),
        idempotency_key: Some(idempotency_key.clone()),
        body: canonical_input.clone(),
    };
    let outcome = idempotency.execute(
        &companion.profile,
        &ledger_request,
        &canonical_input,
        || Ok(()),
        || {
            boundaries
                .queue_attach_message(workspace, &request.run_id, delivery, &request.text)
                .map_err(|error| error.protocol_error())?;
            Ok(CommittedResult {
                body: json!({
                    "run_id": request.run_id,
                    "accepted_at": chrono::Utc::now().to_rfc3339_opts(
                        chrono::SecondsFormat::AutoSi,
                        true,
                    ),
                }),
                cursor: None,
            })
        },
    )?;
    let committed = match outcome {
        IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
    };
    serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
}

#[cfg(target_os = "linux")]
impl<B: RunStartBoundaries + RunAttachBoundaries, I: RunStartIdempotency> ThreadListService
    for DesktopAttachService<B, I>
{
    fn bind_authorized_client(&mut self, client_identity: &str) {
        self.client_identity = Some(client_identity.to_owned());
    }

    fn reconnect_approval(&self) -> Option<Approval> {
        self.boundaries.attach_approval()
    }

    fn list_companions(&mut self) -> Result<Vec<super::CompanionRecord>, ProtocolError> {
        self.boundaries.list_companions()
    }

    fn revoke_companion(
        &mut self,
        client_identity: &str,
        request_id: &Id,
        idempotency_key: &Id,
        provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        let canonical_input = json!({"client_identity": client_identity});
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::CompanionRevoke,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        self.idempotency.execute(
            &provenance.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                self.boundaries.revoke_companion(client_identity)?;
                Ok(CommittedResult {
                    body: json!({}),
                    cursor: None,
                })
            },
        )?;
        Ok(())
    }

    fn authorize_client(
        &mut self,
        client_identity: &str,
        presented_credential: Option<&str>,
        issued_credential: &str,
        claimed_kind: &str,
        claimed_version: &str,
    ) -> Result<String, ProtocolError> {
        let mut credentials = self
            .client_credentials
            .lock()
            .map_err(|_| ProtocolError::unauthorized())?;
        let credential = match credentials.get(client_identity) {
            Some(expected) if presented_credential == Some(expected.credential.as_str()) => {
                expected.credential.clone()
            }
            Some(_) => return Err(ProtocolError::unauthorized()),
            None if presented_credential.is_none() => {
                credentials.insert(
                    client_identity.to_owned(),
                    ClientCredential {
                        credential: issued_credential.to_owned(),
                        claimed_kind: bounded_claim(claimed_kind),
                        claimed_version: bounded_claim(claimed_version),
                        approved_at: Some(
                            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
                        ),
                    },
                );
                if let Some(path) = &self.credential_path {
                    if persist_client_credentials(path, &credentials).is_err() {
                        credentials.remove(client_identity);
                        return Err(ProtocolError::persistence_failed());
                    }
                }
                issued_credential.to_owned()
            }
            None => return Err(ProtocolError::unauthorized()),
        };
        self.client_identity = Some(client_identity.to_owned());
        Ok(credential)
    }

    fn onboard_workspace(
        &mut self,
        workspace: &str,
        request: WorkspaceOnboardRequest,
    ) -> Result<WorkspaceOnboarded, ProtocolError> {
        let identity = self
            .client_identity
            .as_ref()
            .ok_or_else(ProtocolError::unauthorized)?;
        onboard_workspace_context(&self.workspace_contexts, identity, workspace, request)
    }

    fn ensure_home(&mut self) -> Result<(), ProtocolError> {
        crate::ensure_cross_project_home(&self.home)
            .map_err(|_| ProtocolError::persistence_failed())
    }

    fn session_status(&mut self) -> Result<crate::auth::AuthStatus, ProtocolError> {
        self.boundaries.session_status()
    }

    fn entitlement_snapshot(&mut self) -> Result<EntitlementSnapshotResult, ProtocolError> {
        self.boundaries.entitlement_snapshot()
    }

    fn sign_in(
        &mut self,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<crate::auth::AuthStatus, ProtocolError> {
        let canonical_input = json!({});
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::SessionSignIn,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let provenance = attach_provenance(request_id, idempotency_key, &companion);
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let status = self.boundaries.sign_in(provenance)?;
                Ok(CommittedResult {
                    body: serde_json::to_value(status)
                        .map_err(|_| ProtocolError::persistence_failed())?,
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn sign_out(
        &mut self,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<crate::auth::AuthStatus, ProtocolError> {
        let canonical_input = json!({});
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::SessionSignOut,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let provenance = attach_provenance(request_id, idempotency_key, &companion);
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let status = self.boundaries.sign_out(provenance)?;
                Ok(CommittedResult {
                    body: serde_json::to_value(status)
                        .map_err(|_| ProtocolError::persistence_failed())?,
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn list_devices(&mut self) -> Result<crate::auth::NativeDeviceList, ProtocolError> {
        self.boundaries.list_devices()
    }

    fn control_migration(
        &mut self,
        request: MigrationControlRequest,
        provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        self.boundaries
            .control_migration(request, provenance.peer_pid)
    }

    fn authorized_workspace(&self, session_workspace: &str, workspace: &str) -> Option<String> {
        let Some(identity) = &self.client_identity else {
            return None;
        };
        let canonical = PathBuf::from(workspace).canonicalize().ok()?;
        self.workspace_contexts
            .lock()
            .ok()?
            .authorized_directory(identity, session_workspace, &canonical)
            .map(|directory| directory.to_string_lossy().into_owned())
    }

    fn list_threads(
        &mut self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        self.boundaries.list_threads(workspace, request)
    }

    fn open_thread(
        &mut self,
        workspace: &str,
        request: ThreadOpenRequest,
    ) -> Result<ThreadOpenPage, ProtocolError> {
        self.boundaries.open_thread(workspace, request)
    }

    fn thread_summaries(
        &mut self,
        request: ThreadListRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        serde_json::to_value(self.boundaries.thread_summaries(request)?)
            .map_err(|_| ProtocolError::persistence_failed())
    }

    #[cfg(feature = "keyring")]
    fn thread_history(
        &mut self,
        request: ThreadOpenRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        serde_json::to_value(self.boundaries.thread_history(request)?)
            .map_err(|_| ProtocolError::persistence_failed())
    }

    fn create_thread(
        &mut self,
        workspace: &str,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<ThreadCreateAccepted, ProtocolError> {
        let canonical_input = json!({"workspace": workspace});
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::ThreadCreate,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let mut extra = BTreeMap::new();
        extra.insert("attach_profile".into(), json!(&companion.profile));
        extra.insert("companion_kind".into(), json!(companion.companion_kind));
        extra.insert(
            "companion_version".into(),
            json!(companion.companion_version),
        );
        extra.insert("peer_uid".into(), json!(companion.peer_uid));
        extra.insert("peer_pid".into(), json!(companion.peer_pid));
        extra.insert("idempotency_key".into(), json!(idempotency_key.as_str()));
        let provenance = Provenance {
            source: "muniment-attach".into(),
            source_version: env!("CARGO_PKG_VERSION").into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: Some(request_id.as_str().to_owned()),
            capability_versions: None,
            extra,
        };
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let thread_id = self.boundaries.create_thread(workspace, provenance)?;
                Ok(CommittedResult {
                    body: json!({"thread_id": thread_id}),
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn rename_thread(
        &mut self,
        workspace: &str,
        thread_id: &Id,
        title: &str,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        let canonical_input = json!({
            "workspace": workspace,
            "thread_id": thread_id.as_str(),
            "title": title,
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::ThreadRename,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let provenance = attach_provenance(request_id, idempotency_key, &companion);
        self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                self.boundaries
                    .rename_thread(thread_id.as_str(), title, provenance)?;
                Ok(CommittedResult {
                    body: json!({}),
                    cursor: None,
                })
            },
        )?;
        Ok(())
    }

    fn delete_thread(
        &mut self,
        workspace: &str,
        thread_id: &Id,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        let canonical_input = json!({
            "workspace": workspace,
            "thread_id": thread_id.as_str(),
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::ThreadDelete,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let provenance = attach_provenance(request_id, idempotency_key, &companion);
        self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                self.boundaries
                    .delete_thread(thread_id.as_str(), provenance)?;
                Ok(CommittedResult {
                    body: json!({}),
                    cursor: None,
                })
            },
        )?;
        Ok(())
    }

    fn start_run(
        &mut self,
        workspace: &str,
        execution_root: &str,
        request: AttachRunStartRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunStartAccepted, ProtocolError> {
        if request.context.is_some() {
            return Err(ProtocolError::unsupported_operation());
        }
        let canonical_input = json!({
            "workspace": workspace,
            "execution_root": execution_root,
            "text": &request.text,
            "context": &request.context,
            "thread_id": &request.thread_id,
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::RunStart,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let mut extra = BTreeMap::new();
        let profile = companion.profile.clone();
        extra.insert("attach_profile".into(), json!(&companion.profile));
        extra.insert("companion_kind".into(), json!(companion.companion_kind));
        extra.insert(
            "companion_version".into(),
            json!(companion.companion_version),
        );
        extra.insert("peer_uid".into(), json!(companion.peer_uid));
        extra.insert("peer_pid".into(), json!(companion.peer_pid));
        extra.insert("idempotency_key".into(), json!(idempotency_key.as_str()));
        let instructions = self
            .workspace_contexts
            .lock()
            .map_err(|_| ProtocolError::persistence_failed())?
            .instructions(
                self.client_identity
                    .as_ref()
                    .ok_or_else(ProtocolError::unauthorized)?,
                workspace,
                &PathBuf::from(execution_root),
            )
            .map(str::to_owned);
        if let Some(instructions) = instructions {
            extra.insert("repository_instructions".into(), json!(instructions));
        }
        let provenance = Provenance {
            source: "muniment-attach".into(),
            source_version: env!("CARGO_PKG_VERSION").into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: Some(request_id.as_str().to_owned()),
            capability_versions: None,
            extra,
        };
        let mut pending_launch = None;
        let outcome = self.idempotency.execute(
            &profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let (result, launch) = prepare_desktop_run(
                    &self.boundaries,
                    RunStartRequest {
                        prompt: request.text,
                        files: Vec::new(),
                        workspace: Some(workspace.to_owned()),
                        provenance: Some(provenance),
                        thread_id: request.thread_id,
                    },
                )
                .map_err(|error| error.protocol_error())?;
                pending_launch = Some(launch);
                let thread_id = self
                    .boundaries
                    .run_thread_id(&result.run_id)
                    .map_err(|error| error.protocol_error())?;
                Ok(CommittedResult {
                    body: json!({
                        "run_id": result.run_id,
                        "thread_id": thread_id,
                        "committed_seq": result.committed_seq,
                        "accepted_at": result.accepted_at,
                    }),
                    cursor: None,
                })
            },
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(launch) = pending_launch {
                    let _ = self.boundaries.fail_prepared_run(&launch);
                    self.boundaries.clear_active_run(&launch.run_id);
                }
                return Err(error);
            }
        };
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) => {
                let launch = pending_launch.ok_or_else(ProtocolError::persistence_failed)?;
                self.boundaries.launch(launch);
                result
            }
            IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn answer_permission(
        &mut self,
        workspace: &str,
        request: PermissionAnswerRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<PermissionAnswerAccepted, ProtocolError> {
        let canonical_input = json!({
            "workspace": workspace,
            "run_id": &request.run_id,
            "gate_id": &request.gate_id,
            "decision": request.decision,
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::PermissionAnswer,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let commits = self.boundaries.subscribe_run_commits(&request.run_id)?;
                let high_water = commits.committed_high_water;
                if high_water == 0 {
                    return Err(ProtocolError::invalid_request());
                }
                let page = self.boundaries.stream_run(
                    workspace,
                    &request.run_id,
                    high_water.saturating_sub(1),
                )?;
                let pending = page.events.last().and_then(|event| {
                    (event.event_type == "permission.requested")
                        .then_some(event.pending_permission.as_ref())
                        .flatten()
                });
                if pending.is_none_or(|gate| !gate.valid || gate.gate_id != request.gate_id) {
                    return Err(ProtocolError::invalid_request());
                }
                let answer = match request.decision {
                    PermissionDecision::Allow => ChatPermissionAnswer::Confirm(true),
                    PermissionDecision::Deny => ChatPermissionAnswer::Confirm(false),
                };
                let resolved = self
                    .boundaries
                    .queue_attach_permission_answer(
                        workspace,
                        &request.run_id,
                        &request.gate_id,
                        answer,
                    )
                    .map_err(|error| error.protocol_error())?;
                let deadline = std::time::Instant::now() + PERMISSION_COMMIT_TIMEOUT;
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or_else(ProtocolError::persistence_failed)?;
                let expected_seq = resolved
                    .recv_timeout(remaining)
                    .map_err(|_| ProtocolError::persistence_failed())?
                    .ok_or_else(ProtocolError::invalid_request)?;
                let committed_seq = loop {
                    let remaining = deadline
                        .checked_duration_since(std::time::Instant::now())
                        .ok_or_else(ProtocolError::persistence_failed)?;
                    let hint = commits
                        .recv_timeout(remaining)
                        .map_err(|_| ProtocolError::persistence_failed())?;
                    if hint.run_id != request.run_id || hint.run_seq != expected_seq {
                        continue;
                    }
                    let page = self.boundaries.stream_run(
                        workspace,
                        &request.run_id,
                        hint.run_seq.saturating_sub(1),
                    )?;
                    if page.events.first().is_some_and(|event| {
                        event.run_seq == hint.run_seq && event.event_type == "permission.resolved"
                    }) {
                        break hint.run_seq;
                    }
                };
                Ok(CommittedResult {
                    body: json!({
                        "run_id": request.run_id,
                        "gate_id": request.gate_id,
                        "decision": request.decision,
                        "committed_seq": committed_seq,
                        "accepted_at": chrono::Utc::now().to_rfc3339_opts(
                            chrono::SecondsFormat::AutoSi,
                            true,
                        ),
                    }),
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn submit_run(
        &mut self,
        workspace: &str,
        request: RunSubmitRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunSubmitAccepted, ProtocolError> {
        let canonical_input = json!({
            "workspace": workspace,
            "text": &request.text,
            "files": &request.files,
            "thread_id": &request.thread_id,
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::RunSubmit,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let accepted = self
                    .boundaries
                    .submit_run(
                        workspace,
                        request.text,
                        request
                            .files
                            .into_iter()
                            .map(|path| crate::chat_view::SelectedFile {
                                path: PathBuf::from(path),
                            })
                            .collect(),
                        request.thread_id,
                    )
                    .map_err(|error| error.protocol_error())?;
                Ok(CommittedResult {
                    body: serde_json::to_value(accepted)
                        .map_err(|_| ProtocolError::persistence_failed())?,
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn resume_run(
        &mut self,
        workspace: &str,
        request: RunResumeRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunResumeAccepted, ProtocolError> {
        let canonical_input = json!({
            "workspace": workspace,
            "run_id": &request.run_id,
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::RunResume,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let accepted = self
                    .boundaries
                    .resume_run(workspace, &request.run_id)
                    .map_err(|error| error.protocol_error())?;
                Ok(CommittedResult {
                    body: serde_json::to_value(accepted)
                        .map_err(|_| ProtocolError::persistence_failed())?,
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn steer_run(
        &mut self,
        workspace: &str,
        request: RunMessageRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        queue_run_message(
            &self.boundaries,
            &mut self.idempotency,
            Operation::RunSteer,
            ChatDelivery::Steer,
            workspace,
            request,
            request_id,
            idempotency_key,
            companion,
        )
    }

    fn follow_up_run(
        &mut self,
        workspace: &str,
        request: RunMessageRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        queue_run_message(
            &self.boundaries,
            &mut self.idempotency,
            Operation::RunFollowUp,
            ChatDelivery::FollowUp,
            workspace,
            request,
            request_id,
            idempotency_key,
            companion,
        )
    }

    fn answer_run_permission(
        &mut self,
        workspace: &str,
        request: RunPermissionAnswerRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunPermissionAnswerAccepted, ProtocolError> {
        let canonical_input = json!({
            "workspace": workspace,
            "run_id": &request.run_id,
            "gate_id": &request.gate_id,
            "answer": &request.answer,
        });
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::RunPermissionAnswer,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                let commits = self.boundaries.subscribe_run_commits(&request.run_id)?;
                if commits.committed_high_water == 0 {
                    return Err(ProtocolError::invalid_request());
                }
                let resolved = self
                    .boundaries
                    .queue_attach_permission_answer(
                        workspace,
                        &request.run_id,
                        &request.gate_id,
                        request.answer.clone(),
                    )
                    .map_err(|error| error.protocol_error())?;
                let deadline = std::time::Instant::now() + PERMISSION_COMMIT_TIMEOUT;
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or_else(ProtocolError::persistence_failed)?;
                let expected_seq = resolved
                    .recv_timeout(remaining)
                    .map_err(|_| ProtocolError::persistence_failed())?
                    .ok_or_else(ProtocolError::invalid_request)?;
                let committed_seq = loop {
                    let remaining = deadline
                        .checked_duration_since(std::time::Instant::now())
                        .ok_or_else(ProtocolError::persistence_failed)?;
                    let hint = commits
                        .recv_timeout(remaining)
                        .map_err(|_| ProtocolError::persistence_failed())?;
                    if hint.run_id != request.run_id || hint.run_seq != expected_seq {
                        continue;
                    }
                    let page = self.boundaries.stream_run(
                        workspace,
                        &request.run_id,
                        hint.run_seq.saturating_sub(1),
                    )?;
                    if page.events.first().is_some_and(|event| {
                        event.run_seq == hint.run_seq && event.event_type == "permission.resolved"
                    }) {
                        break hint.run_seq;
                    }
                };
                Ok(CommittedResult {
                    body: json!({
                        "run_id": request.run_id,
                        "gate_id": request.gate_id,
                        "answer": request.answer,
                        "committed_seq": committed_seq,
                        "accepted_at": chrono::Utc::now().to_rfc3339_opts(
                            chrono::SecondsFormat::AutoSi,
                            true,
                        ),
                    }),
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn cancel_run(
        &mut self,
        workspace: &str,
        request: RunCancelRequest,
        request_id: &Id,
        idempotency_key: &Id,
        companion: CompanionProvenance,
    ) -> Result<RunCancelAccepted, ProtocolError> {
        let canonical_input = json!({"workspace": workspace, "run_id": &request.run_id});
        let ledger_request = AttachRequest {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::RunCancel,
            capability: String::new(),
            idempotency_key: Some(idempotency_key.clone()),
            body: canonical_input.clone(),
        };
        let outcome = self.idempotency.execute(
            &companion.profile,
            &ledger_request,
            &canonical_input,
            || Ok(()),
            || {
                self.boundaries
                    .cancel_run(workspace, &request.run_id)
                    .map_err(|error| error.protocol_error())?;
                Ok(CommittedResult {
                    body: json!({
                        "run_id": request.run_id,
                        "accepted_at": chrono::Utc::now().to_rfc3339_opts(
                            chrono::SecondsFormat::AutoSi,
                            true,
                        ),
                    }),
                    cursor: None,
                })
            },
        )?;
        let committed = match outcome {
            IdempotencyOutcome::Committed(result) | IdempotencyOutcome::Replayed(result) => result,
        };
        serde_json::from_value(committed.body).map_err(|_| ProtocolError::persistence_failed())
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<RunStreamPage, ProtocolError> {
        self.boundaries.stream_run(workspace, run_id, after_run_seq)
    }

    fn subscribe_run_commits(
        &mut self,
        run_id: &str,
    ) -> Result<Option<crate::journal::CommitSubscription>, ProtocolError> {
        self.boundaries.subscribe_run_commits(run_id).map(Some)
    }

    fn subscribe_chat_events(
        &mut self,
    ) -> Result<crate::run_events::ChatEventSubscription, ProtocolError> {
        self.boundaries.subscribe_chat_events()
    }
}

fn attach_provenance(
    request_id: &Id,
    idempotency_key: &Id,
    companion: &CompanionProvenance,
) -> Provenance {
    let mut extra = BTreeMap::new();
    extra.insert("attach_profile".into(), json!(&companion.profile));
    extra.insert("companion_kind".into(), json!(&companion.companion_kind));
    extra.insert(
        "companion_version".into(),
        json!(&companion.companion_version),
    );
    extra.insert("peer_uid".into(), json!(companion.peer_uid));
    extra.insert("peer_pid".into(), json!(companion.peer_pid));
    extra.insert("idempotency_key".into(), json!(idempotency_key.as_str()));
    Provenance {
        source: "muniment-attach".into(),
        source_version: env!("CARGO_PKG_VERSION").into(),
        actor_id: None,
        device_id: None,
        rpc_request_id: Some(request_id.as_str().to_owned()),
        capability_versions: None,
        extra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[cfg(target_os = "linux")]
    use crate::attach::linux::{
        RunStreamPage, ThreadListPage, ThreadListRequest, ThreadListService, ThreadOpenPage,
        ThreadOpenRequest,
    };
    #[cfg(target_os = "linux")]
    use crate::attach::{ErrorCode, ProtocolError};
    use crate::attach::{RuntimeActivityGuard, RuntimeActivityRegistry};
    use crate::auth::TokenSet;
    use crate::chat_grant::ChatGrant;
    use crate::chat_view::{chat_attachments, ChatAttachment, SelectedFile};
    use crate::journal::reducer::{reduce, ChatProjector};
    #[cfg(target_os = "linux")]
    use crate::journal::RunJournal;
    use crate::journal::{EventEnvelope, JournalCommitHint, Provenance};
    use crate::permission_gate::ChatPermissionAnswer;
    use serde_json::json;
    use serde_json::Value;

    use crate::run_start::{
        ActiveRun, RunAttachBoundaries, RunStartBoundaries, RunStartError, RunStartLaunch,
    };

    use crate::pi_execution::attachment_error;
    use uuid::Uuid;

    fn event_envelope(
        run_id: &str,
        run_seq: u64,
        kind: &str,
        payload: Value,
        subject: Option<&str>,
    ) -> EventEnvelope {
        crate::run_preparation::event_envelope(
            run_id,
            run_seq,
            kind,
            payload,
            subject,
            "muniment-desktop",
            env!("CARGO_PKG_VERSION"),
        )
    }

    fn append_test_event(
        journal: &mut crate::journal::RunJournal,
        run_id: &str,
        seq: u64,
        kind: &str,
        payload: Value,
        subject: Option<&str>,
    ) {
        journal
            .append(
                seq - 1,
                &event_envelope(run_id, seq, kind, payload, subject),
            )
            .unwrap();
    }

    struct FakeRunStartBoundaries {
        active: bool,
        granted_workspaces: Vec<String>,
        auth_calls: AtomicUsize,
        prompt_protection_calls: AtomicUsize,
        prepare_calls: AtomicUsize,
        launch_calls: AtomicUsize,
        launched_run: Mutex<Option<String>>,
        auth_error: Option<String>,
        configure_error: Option<String>,
        protect_error: Option<String>,
        install_error: Option<String>,
        prepare_error: Option<String>,
        thread_id_error: Option<String>,
        memory_error: Option<String>,
        projection_error: Option<String>,
        prepared_provenance: Mutex<Option<Provenance>>,
        journaled_events: Mutex<BTreeMap<String, Vec<EventEnvelope>>>,
        clear_calls: AtomicUsize,
        cancel_calls: AtomicUsize,
        submit_calls: AtomicUsize,
        resume_calls: AtomicUsize,
        active_run: Mutex<Option<(String, String)>>,
        runtime_activity: RuntimeActivityRegistry,
        #[cfg(target_os = "linux")]
        queued_messages: Mutex<Vec<(ChatDelivery, String)>>,
        #[cfg(target_os = "linux")]
        queued_permission_answers: Mutex<Vec<(String, ChatPermissionAnswer)>>,
        #[cfg(target_os = "linux")]
        permission_auto_commit: bool,
        #[cfg(target_os = "linux")]
        permission_competing_answer: bool,
        #[cfg(target_os = "linux")]
        permission_resolution_sender: Mutex<Option<std::sync::mpsc::SyncSender<Option<u64>>>>,
        #[cfg(target_os = "linux")]
        permission_commit_sender: Mutex<Option<std::sync::mpsc::SyncSender<JournalCommitHint>>>,
        #[cfg(target_os = "linux")]
        journal: Mutex<RunJournal>,
    }

    impl FakeRunStartBoundaries {
        fn accepting() -> Self {
            Self {
                active: false,
                granted_workspaces: vec!["workspace-a".into()],
                auth_calls: AtomicUsize::new(0),
                prompt_protection_calls: AtomicUsize::new(0),
                prepare_calls: AtomicUsize::new(0),
                launch_calls: AtomicUsize::new(0),
                launched_run: Mutex::new(None),
                auth_error: None,
                configure_error: None,
                protect_error: None,
                install_error: None,
                prepare_error: None,
                thread_id_error: None,
                memory_error: None,
                projection_error: None,
                prepared_provenance: Mutex::new(None),
                journaled_events: Mutex::new(BTreeMap::new()),
                clear_calls: AtomicUsize::new(0),
                cancel_calls: AtomicUsize::new(0),
                submit_calls: AtomicUsize::new(0),
                resume_calls: AtomicUsize::new(0),
                active_run: Mutex::new(None),
                runtime_activity: RuntimeActivityRegistry::new(),
                #[cfg(target_os = "linux")]
                queued_messages: Mutex::new(Vec::new()),
                #[cfg(target_os = "linux")]
                queued_permission_answers: Mutex::new(Vec::new()),
                #[cfg(target_os = "linux")]
                permission_auto_commit: true,
                #[cfg(target_os = "linux")]
                permission_competing_answer: false,
                #[cfg(target_os = "linux")]
                permission_resolution_sender: Mutex::new(None),
                #[cfg(target_os = "linux")]
                permission_commit_sender: Mutex::new(None),
                #[cfg(target_os = "linux")]
                journal: Mutex::new(RunJournal::open(":memory:").unwrap()),
            }
        }
    }

    impl RunAttachBoundaries for FakeRunStartBoundaries {
        fn submit_run(
            &self,
            _workspace: &str,
            _text: String,
            files: Vec<SelectedFile>,
            thread_id: Option<String>,
        ) -> Result<crate::run_start::AttachPromptAccepted, RunStartError> {
            self.submit_calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::run_start::AttachPromptAccepted {
                run_id: "0190a100-0000-7000-8000-000000000001".into(),
                thread_id: thread_id
                    .unwrap_or_else(|| "0190a100-0000-7000-8000-000000000002".into()),
                attachments: files
                    .into_iter()
                    .map(|file| ChatAttachment {
                        display_name: file.path.to_string_lossy().into_owned(),
                        byte_length: 1,
                        media_type: None,
                    })
                    .collect(),
                committed_seq: 1,
                accepted_at: "2026-08-16T00:00:00Z".into(),
            })
        }

        fn resume_run(
            &self,
            _workspace: &str,
            run_id: &str,
        ) -> Result<crate::run_start::AttachResumeAccepted, RunStartError> {
            self.resume_calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::run_start::AttachResumeAccepted {
                run_id: run_id.into(),
                thread_id: "0190a100-0000-7000-8000-000000000002".into(),
                committed_seq: 2,
                accepted_at: "2026-08-16T00:00:00Z".into(),
            })
        }

        #[cfg(target_os = "linux")]
        fn queue_attach_message(
            &self,
            workspace: &str,
            run_id: &str,
            delivery: ChatDelivery,
            message: &str,
        ) -> Result<(), RunStartError> {
            if !self
                .active_run
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|active| active.0 == run_id && active.1 == workspace)
            {
                return Err(RunStartError::InvalidRequest(
                    "That reply is no longer active.".into(),
                ));
            }
            self.queued_messages
                .lock()
                .unwrap()
                .push((delivery, message.to_owned()));
            Ok(())
        }

        #[cfg(target_os = "linux")]
        fn list_threads(
            &self,
            workspace: &str,
            request: ThreadListRequest,
        ) -> Result<ThreadListPage, ProtocolError> {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| ProtocolError::persistence_failed())?;
            ThreadListService::list_threads(&mut *journal, workspace, request)
        }

        #[cfg(target_os = "linux")]
        fn open_thread(
            &self,
            workspace: &str,
            request: ThreadOpenRequest,
        ) -> Result<ThreadOpenPage, ProtocolError> {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| ProtocolError::persistence_failed())?;
            ThreadListService::open_thread(&mut *journal, workspace, request)
        }

        #[cfg(target_os = "linux")]
        fn create_thread(
            &self,
            workspace: &str,
            provenance: Provenance,
        ) -> Result<String, ProtocolError> {
            self.journal
                .lock()
                .map_err(|_| ProtocolError::persistence_failed())?
                .create_thread(workspace, "2026-01-01T00:00:00Z", provenance)
                .map_err(|_| ProtocolError::persistence_failed())
        }

        #[cfg(target_os = "linux")]
        fn rename_thread(
            &self,
            thread_id: &str,
            title: &str,
            provenance: Provenance,
        ) -> Result<(), ProtocolError> {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| ProtocolError::persistence_failed())?;
            crate::journal::thread_mutation::append_thread_rename(
                &mut journal,
                Some("owner"),
                thread_id,
                title,
                "2026-01-01T00:00:01Z",
                &provenance,
            )
            .map_err(|_| ProtocolError::persistence_failed())
        }

        #[cfg(target_os = "linux")]
        fn delete_thread(
            &self,
            thread_id: &str,
            provenance: Provenance,
        ) -> Result<(), ProtocolError> {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| ProtocolError::persistence_failed())?;
            crate::journal::thread_mutation::append_thread_delete(
                &mut journal,
                Some("owner"),
                thread_id,
                "2026-01-01T00:00:01Z",
                &provenance,
            )
            .map_err(|_| ProtocolError::persistence_failed())
        }

        #[cfg(target_os = "linux")]
        fn stream_run(
            &self,
            workspace: &str,
            run_id: &str,
            after_run_seq: u64,
        ) -> Result<RunStreamPage, ProtocolError> {
            ThreadListService::stream_run(
                &mut *self
                    .journal
                    .lock()
                    .map_err(|_| ProtocolError::persistence_failed())?,
                workspace,
                run_id,
                after_run_seq,
            )
        }

        #[cfg(target_os = "linux")]
        fn subscribe_run_commits(
            &self,
            run_id: &str,
        ) -> Result<crate::journal::CommitSubscription, ProtocolError> {
            let high_water = self
                .journal
                .lock()
                .map_err(|_| ProtocolError::persistence_failed())?
                .run_event_types()
                .map_err(|_| ProtocolError::persistence_failed())?
                .into_iter()
                .rfind(|event| event.run_id == run_id)
                .map_or(0, |event| event.run_seq);
            let (sender, receiver) = std::sync::mpsc::sync_channel(4);
            *self.permission_commit_sender.lock().unwrap() = Some(sender);
            Ok(crate::journal::CommitSubscription::detached(
                high_water, receiver,
            ))
        }

        #[cfg(target_os = "linux")]
        fn queue_attach_permission_answer(
            &self,
            workspace: &str,
            run_id: &str,
            gate_id: &str,
            answer: ChatPermissionAnswer,
        ) -> Result<std::sync::mpsc::Receiver<Option<u64>>, RunStartError> {
            if !self
                .active_run
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|active| active.0 == run_id && active.1 == workspace)
            {
                return Err(RunStartError::InvalidRequest(
                    "That reply is no longer active.".into(),
                ));
            }
            let (resolved_sender, resolved_receiver) = std::sync::mpsc::sync_channel(1);
            self.queued_permission_answers
                .lock()
                .unwrap()
                .push((gate_id.to_owned(), answer.clone()));
            if !self.permission_auto_commit {
                *self.permission_resolution_sender.lock().unwrap() = Some(resolved_sender);
                return Ok(resolved_receiver);
            }
            let mut journal = self.journal.lock().unwrap();
            let seq = journal
                .run_event_types()
                .unwrap()
                .into_iter()
                .rfind(|event| event.run_id == run_id)
                .unwrap()
                .run_seq
                + 1;
            journal
            .append(
                seq - 1,
                &event_envelope(
                    run_id,
                    seq,
                    "permission.resolved",
                    json!({
                        "gate_id": gate_id,
                        "decision": if self.permission_competing_answer {
                            ChatPermissionAnswer::Confirm(!matches!(answer, ChatPermissionAnswer::Confirm(true))).decision()
                        } else {
                            answer.decision()
                        }
                    }),
                    None,
                ),
            )
            .unwrap();
            drop(journal);
            if let Some(sender) = self.permission_commit_sender.lock().unwrap().as_ref() {
                sender
                    .send(JournalCommitHint {
                        run_id: run_id.to_owned(),
                        run_seq: seq,
                    })
                    .unwrap();
            }
            resolved_sender
                .send((!self.permission_competing_answer).then_some(seq))
                .unwrap();
            Ok(resolved_receiver)
        }
    }

    impl RunStartBoundaries for FakeRunStartBoundaries {
        fn mark_active_run(&self) -> RuntimeActivityGuard {
            self.runtime_activity.mark_active_run()
        }

        fn active_run_exists(&self) -> bool {
            self.active
        }

        fn fresh_tokens(&self) -> Result<TokenSet, RunStartError> {
            self.auth_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = &self.auth_error {
                return Err(RunStartError::Unauthorized(error.clone()));
            }
            Ok(TokenSet {
                access_token: "access-token".into(),
                refresh_token: None,
                expires_at: None,
                subject: Some("owner".into()),
            })
        }

        fn configure_run(
            &self,
            _run_id: &str,
            _prompt: &str,
            _tokens: &TokenSet,
            requested_workspace: Option<&str>,
        ) -> Result<ChatGrant, RunStartError> {
            if requested_workspace
                .is_some_and(|workspace| !self.granted_workspaces.iter().any(|g| g == workspace))
            {
                return Err(RunStartError::Unauthorized(
                    "sensitive workspace detail".into(),
                ));
            }
            if let Some(error) = &self.configure_error {
                return Err(RunStartError::Persistence(error.clone()));
            }
            // Model the gateway granting exactly the workspace that was
            // requested (and authorized), so the capability check
            // `requested == grant.workspace` holds for every granted workspace.
            let workspace = requested_workspace
                .map(str::to_owned)
                .or_else(|| self.granted_workspaces.first().cloned())
                .unwrap_or_default();
            Ok(ChatGrant {
                workspace,
                gateway_url: "https://gateway.invalid".into(),
                virtual_key: "virtual-key".into(),
                model: None,
                minimum_cacheable_prefix_characters: 8_192,
                receipt_url: "https://receipt.invalid".into(),
            })
        }

        fn install_active_run(&self, run: ActiveRun) -> Result<(), RunStartError> {
            if let Some(error) = &self.install_error {
                return Err(RunStartError::InvalidRequest(error.clone()));
            }
            *self.active_run.lock().unwrap() = Some((run.id, run.workspace));
            Ok(())
        }

        fn prepare_run(
            &self,
            run_id: &str,
            _prompt: &str,
            grant: &ChatGrant,
            tokens: &TokenSet,
            _files: Vec<SelectedFile>,
            provenance: Option<Provenance>,
            thread_id: Option<&str>,
        ) -> Result<(u64, ChatProjector), RunStartError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            *self.prepared_provenance.lock().unwrap() = provenance.clone();
            if let Some(error) = &self.prepare_error {
                return Err(RunStartError::Persistence(error.clone()));
            }
            let mut projector = ChatProjector::new();
            let mut started = event_envelope(
                run_id,
                1,
                "run.started",
                json!({}),
                tokens.subject.as_deref(),
            );
            if let Some(provenance) = provenance {
                started.provenance = Provenance {
                    actor_id: provenance
                        .actor_id
                        .or_else(|| tokens.subject.as_deref().map(str::to_owned)),
                    ..provenance
                };
            }
            projector.apply(&started).unwrap();
            let mut events = vec![started.clone()];
            let mut committed_seq = 1;
            #[cfg(target_os = "linux")]
            if let Some(thread_id) = thread_id {
                let mut journal = self
                    .journal
                    .lock()
                    .map_err(|_| RunStartError::Persistence(attachment_error()))?;
                let protect = || {
                    self.prompt_protection_calls.fetch_add(1, Ordering::SeqCst);
                    self.protect_error
                        .as_ref()
                        .map_or(Ok(()), |error| Err(error.clone()))
                };
                let protection = journal
                    .append_new_run_in_thread_after_validation(
                        &grant.workspace,
                        thread_id,
                        &started,
                        protect,
                    )
                    .map_err(|error| {
                        if matches!(error, crate::journal::JournalError::InvalidEnvelope(_)) {
                            RunStartError::ThreadNotFound
                        } else {
                            RunStartError::Persistence(attachment_error())
                        }
                    })?;
                protection.map_err(RunStartError::Persistence)?;
                let prompt = event_envelope(
                    run_id,
                    2,
                    "user.prompt.submitted",
                    json!({"prompt": "hello"}),
                    tokens.subject.as_deref(),
                );
                projector.apply(&prompt).unwrap();
                journal
                    .append(1, &prompt)
                    .map_err(|_| RunStartError::Persistence(attachment_error()))?;
                events.push(prompt);
                committed_seq = 2;
            } else {
                self.prompt_protection_calls.fetch_add(1, Ordering::SeqCst);
                if let Some(error) = &self.protect_error {
                    return Err(RunStartError::Persistence(error.clone()));
                }
            }
            self.journaled_events
                .lock()
                .unwrap()
                .insert(run_id.to_owned(), events);
            Ok((committed_seq, projector))
        }

        fn run_thread_id(&self, run_id: &str) -> Result<String, RunStartError> {
            if let Some(error) = &self.thread_id_error {
                return Err(RunStartError::Persistence(error.clone()));
            }
            #[cfg(target_os = "linux")]
            if let Some(thread_id) = self
                .journal
                .lock()
                .map_err(|_| RunStartError::Persistence(attachment_error()))?
                .run_thread_id(run_id)
                .map_err(|_| RunStartError::Persistence(attachment_error()))?
            {
                return Ok(thread_id);
            }
            Ok("0190a100-0000-7000-8000-000000000002".into())
        }

        fn open_memory_session(
            &self,
            _run_id: &str,
            _thread_id: &str,
            _minimum_cacheable_prefix_characters: usize,
        ) -> Result<(), RunStartError> {
            self.memory_error.as_ref().map_or(Ok(()), |error| {
                Err(RunStartError::Persistence(error.clone()))
            })
        }

        fn close_memory_session(&self, _run_id: &str) {}

        fn project_attachments(
            &self,
            projector: &ChatProjector,
        ) -> Result<Vec<ChatAttachment>, RunStartError> {
            if let Some(error) = &self.projection_error {
                return Err(RunStartError::Persistence(error.clone()));
            }
            projector
                .projection()
                .map(|projection| chat_attachments(&projection.attachments))
                .map_err(|_| RunStartError::Persistence(attachment_error()))
        }

        fn fail_prepared_run(&self, launch: &RunStartLaunch) -> Result<(), RunStartError> {
            self.journaled_events
                .lock()
                .unwrap()
                .get_mut(&launch.run_id)
                .unwrap()
                .push(event_envelope(
                    &launch.run_id,
                    launch.prepared.0 + 1,
                    "run.failed",
                    json!({"reason": "persistence"}),
                    launch.tokens.subject.as_deref(),
                ));
            Ok(())
        }

        fn clear_active_run(&self, _run_id: &str) {
            self.clear_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn cancel_run(&self, workspace: &str, run_id: &str) -> Result<(), RunStartError> {
            let active = self.active_run.lock().unwrap();
            if active
                .as_ref()
                .is_none_or(|(id, active_workspace)| id != run_id || active_workspace != workspace)
            {
                return Err(RunStartError::InvalidRequest(
                    "That reply is no longer active.".into(),
                ));
            }
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn launch(&self, launch: RunStartLaunch) {
            self.launch_calls.fetch_add(1, Ordering::SeqCst);
            *self.launched_run.lock().unwrap() = Some(launch.run_id);
        }
    }
    #[cfg(target_os = "linux")]
    struct FailingFinalization;

    #[cfg(target_os = "linux")]
    impl RunStartIdempotency for FailingFinalization {
        fn execute<A, W>(
            &mut self,
            _profile: &str,
            _request: &AttachRequest,
            _canonical_input: &Value,
            authorize: A,
            work: W,
        ) -> Result<IdempotencyOutcome, ProtocolError>
        where
            A: FnOnce() -> Result<(), ProtocolError>,
            W: FnOnce() -> Result<CommittedResult, ProtocolError>,
        {
            authorize()?;
            let _ = work()?;
            Err(ProtocolError::persistence_failed())
        }
    }

    #[cfg(target_os = "linux")]
    fn attach_start(
        boundaries: FakeRunStartBoundaries,
        context: Option<Value>,
    ) -> (
        Result<RunStartAccepted, ProtocolError>,
        DesktopAttachService<FakeRunStartBoundaries>,
    ) {
        let mut service = DesktopAttachService {
            boundaries,
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let result = service.start_run(
            "workspace-a",
            "workspace-a",
            AttachRunStartRequest {
                text: "hello".into(),
                context,
                thread_id: None,
            },
            &Id::new("018f0000-0000-7000-8000-000000000001").unwrap(),
            &Id::new("018f0000-0000-7000-8000-000000000002").unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "cli".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        );
        (result, service)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_thread_create_replays_and_rejects_changed_workspace() {
        let database_path = std::env::temp_dir().join(format!(
            "muniment-attach-thread-create-{}.sqlite3",
            Uuid::now_v7()
        ));
        let mut boundaries = FakeRunStartBoundaries::accepting();
        boundaries.journal = Mutex::new(RunJournal::open(&database_path).unwrap());
        let mut service = DesktopAttachService {
            boundaries,
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let key = Id::new("018f0000-0000-7000-8000-000000000002").unwrap();
        let companion = CompanionProvenance {
            profile: "default".into(),
            companion_kind: "cli".into(),
            companion_version: "1.2.3".into(),
            peer_uid: 1000,
            peer_pid: 42,
        };

        let first = service
            .create_thread(
                "workspace-a",
                &Id::new("018f0000-0000-7000-8000-000000000001").unwrap(),
                &key,
                companion.clone(),
            )
            .unwrap();
        let replay = service
            .create_thread(
                "workspace-a",
                &Id::new("018f0000-0000-7000-8000-000000000003").unwrap(),
                &key,
                companion.clone(),
            )
            .unwrap();
        let conflict = service
            .create_thread(
                "workspace-b",
                &Id::new("018f0000-0000-7000-8000-000000000004").unwrap(),
                &key,
                companion,
            )
            .unwrap_err();

        assert_eq!(replay.thread_id, first.thread_id);
        assert_eq!(conflict.code(), ErrorCode::IdempotencyConflict);
        let mut journal = service.boundaries.journal.lock().unwrap();
        let event_count = rusqlite::Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM thread_events WHERE event_type='thread.created'",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
        let page = ThreadListService::list_threads(
            &mut *journal,
            "workspace-a",
            ThreadListRequest {
                cursor: None,
                limit: 50,
            },
        )
        .unwrap();
        assert!(page.threads.is_empty());
        let other_page = ThreadListService::list_threads(
            &mut *journal,
            "workspace-b",
            ThreadListRequest {
                cursor: None,
                limit: 50,
            },
        )
        .unwrap();
        assert!(other_page.threads.is_empty());
        drop(journal);
        drop(service);
        std::fs::remove_file(database_path).unwrap();
    }

    fn test_companion_provenance() -> CompanionProvenance {
        CompanionProvenance {
            profile: "default".into(),
            companion_kind: "desktop".into(),
            companion_version: "1.0.0".into(),
            peer_uid: 1000,
            peer_pid: 42,
        }
    }

    #[test]
    fn attach_submit_replays_and_rejects_conflicting_input_without_second_boundary_call() {
        let mut service = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let request_id = Id::new("018f0000-0000-7000-8000-000000000001").unwrap();
        let key = Id::new("018f0000-0000-7000-8000-000000000002").unwrap();
        let request = RunSubmitRequest {
            text: "hello".into(),
            files: vec!["main.rs".into()],
            thread_id: None,
        };

        let first = service
            .submit_run(
                "workspace-a",
                request.clone(),
                &request_id,
                &key,
                test_companion_provenance(),
            )
            .unwrap();
        let replay = service
            .submit_run(
                "workspace-a",
                request,
                &request_id,
                &key,
                test_companion_provenance(),
            )
            .unwrap();
        assert_eq!(replay.run_id, first.run_id);
        assert_eq!(replay.thread_id, first.thread_id);
        assert_eq!(replay.attachments, first.attachments);
        assert_eq!(replay.committed_seq, first.committed_seq);
        assert_eq!(replay.accepted_at, first.accepted_at);
        assert_eq!(service.boundaries.submit_calls.load(Ordering::SeqCst), 1);

        let conflict = service
            .submit_run(
                "workspace-a",
                RunSubmitRequest {
                    text: "changed".into(),
                    files: vec!["main.rs".into()],
                    thread_id: None,
                },
                &request_id,
                &key,
                test_companion_provenance(),
            )
            .unwrap_err();
        assert_eq!(conflict.code(), ErrorCode::IdempotencyConflict);
        assert_eq!(service.boundaries.submit_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn attach_resume_replays_and_rejects_conflicting_input_without_second_boundary_call() {
        let mut service = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let request_id = Id::new("018f0000-0000-7000-8000-000000000001").unwrap();
        let key = Id::new("018f0000-0000-7000-8000-000000000002").unwrap();
        let request = RunResumeRequest {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
        };

        let first = service
            .resume_run(
                "workspace-a",
                request.clone(),
                &request_id,
                &key,
                test_companion_provenance(),
            )
            .unwrap();
        let replay = service
            .resume_run(
                "workspace-a",
                request,
                &request_id,
                &key,
                test_companion_provenance(),
            )
            .unwrap();
        assert_eq!(replay.run_id, first.run_id);
        assert_eq!(replay.thread_id, first.thread_id);
        assert_eq!(replay.committed_seq, first.committed_seq);
        assert_eq!(replay.accepted_at, first.accepted_at);
        assert_eq!(service.boundaries.resume_calls.load(Ordering::SeqCst), 1);

        let conflict = service
            .resume_run(
                "workspace-a",
                RunResumeRequest {
                    run_id: "0190a100-0000-7000-8000-000000000099".into(),
                },
                &request_id,
                &key,
                test_companion_provenance(),
            )
            .unwrap_err();
        assert_eq!(conflict.code(), ErrorCode::IdempotencyConflict);
        assert_eq!(service.boundaries.resume_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    fn cancel_request(
        service: &mut DesktopAttachService<FakeRunStartBoundaries>,
        workspace: &str,
        run_id: &str,
        request_id: &str,
        key: &str,
    ) -> Result<RunCancelAccepted, ProtocolError> {
        service.cancel_run(
            workspace,
            RunCancelRequest {
                run_id: run_id.into(),
            },
            &Id::new(request_id).unwrap(),
            &Id::new(key).unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "cli".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn permission_service(
        boundaries: FakeRunStartBoundaries,
        active: Option<(&str, &str)>,
    ) -> DesktopAttachService<FakeRunStartBoundaries> {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let started = event_envelope(run_id, 1, "run.started", json!({}), None);
        boundaries
            .journal
            .lock()
            .unwrap()
            .append_new_run("workspace-a", &started)
            .unwrap();
        append_test_event(
            &mut boundaries.journal.lock().unwrap(),
            run_id,
            2,
            "permission.requested",
            json!({
                "gate_id": "gate-1",
                "kind": "confirm",
                "title": "Allow?",
                "message": "Proceed?"
            }),
            None,
        );
        *boundaries.active_run.lock().unwrap() =
            active.map(|(run, workspace)| (run.to_owned(), workspace.to_owned()));
        DesktopAttachService {
            boundaries,
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        }
    }

    #[cfg(target_os = "linux")]
    fn permission_request(
        service: &mut DesktopAttachService<FakeRunStartBoundaries>,
        workspace: &str,
        run_id: &str,
        gate_id: &str,
        decision: PermissionDecision,
        request_id: &str,
        key: &str,
    ) -> Result<PermissionAnswerAccepted, ProtocolError> {
        service.answer_permission(
            workspace,
            PermissionAnswerRequest {
                run_id: run_id.into(),
                gate_id: gate_id.into(),
                decision,
            },
            &Id::new(request_id).unwrap(),
            &Id::new(key).unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "cli".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn run_permission_request(
        service: &mut DesktopAttachService<FakeRunStartBoundaries>,
        answer: ChatPermissionAnswer,
        request_id: &str,
        key: &str,
    ) -> Result<RunPermissionAnswerAccepted, ProtocolError> {
        service.answer_run_permission(
            "workspace-a",
            RunPermissionAnswerRequest {
                run_id: "0190a100-0000-7000-8000-000000000001".into(),
                gate_id: "gate-1".into(),
                answer,
            },
            &Id::new(request_id).unwrap(),
            &Id::new(key).unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "desktop-client".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn message_request(
        service: &mut DesktopAttachService<FakeRunStartBoundaries>,
        operation: Operation,
        text: &str,
        request_id: &str,
        key: &str,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        let request = RunMessageRequest {
            run_id: "0190a100-0000-7000-8000-000000000001".into(),
            text: text.into(),
        };
        let request_id = Id::new(request_id).unwrap();
        let key = Id::new(key).unwrap();
        let provenance = CompanionProvenance {
            profile: "default".into(),
            companion_kind: "desktop-client".into(),
            companion_version: "1.2.3".into(),
            peer_uid: 1000,
            peer_pid: 42,
        };
        if operation == Operation::RunSteer {
            service.steer_run("workspace-a", request, &request_id, &key, provenance)
        } else {
            service.follow_up_run("workspace-a", request, &request_id, &key, provenance)
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_run_messages_replay_exact_retries_and_reject_conflicts_without_queueing() {
        for (index, operation) in [Operation::RunSteer, Operation::RunFollowUp]
            .into_iter()
            .enumerate()
        {
            let run_id = "0190a100-0000-7000-8000-000000000001";
            let mut service = permission_service(
                FakeRunStartBoundaries::accepting(),
                Some((run_id, "workspace-a")),
            );
            let key = format!("018f0000-0000-7000-8000-{:012x}", 50 + index);
            let first = message_request(
                &mut service,
                operation,
                "hello",
                "018f0000-0000-7000-8000-000000000060",
                &key,
            )
            .unwrap();
            let replay = message_request(
                &mut service,
                operation,
                "hello",
                "018f0000-0000-7000-8000-000000000061",
                &key,
            )
            .unwrap();
            assert_eq!(replay, first);
            assert_eq!(service.boundaries.queued_messages.lock().unwrap().len(), 1);

            let conflict = message_request(
                &mut service,
                operation,
                "changed",
                "018f0000-0000-7000-8000-000000000062",
                &key,
            )
            .unwrap_err();
            assert_eq!(
                serde_json::to_value(conflict).unwrap()["code"],
                "idempotency_conflict"
            );
            assert_eq!(service.boundaries.queued_messages.lock().unwrap().len(), 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_run_permission_replays_exact_retry_and_rejects_conflict_without_queueing() {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let mut service = permission_service(
            FakeRunStartBoundaries::accepting(),
            Some((run_id, "workspace-a")),
        );
        let key = "018f0000-0000-7000-8000-000000000070";
        let first = run_permission_request(
            &mut service,
            ChatPermissionAnswer::Confirm(true),
            "018f0000-0000-7000-8000-000000000071",
            key,
        )
        .unwrap();
        let replay = run_permission_request(
            &mut service,
            ChatPermissionAnswer::Confirm(true),
            "018f0000-0000-7000-8000-000000000072",
            key,
        )
        .unwrap();
        assert_eq!(replay.run_id, first.run_id);
        assert_eq!(replay.gate_id, first.gate_id);
        assert_eq!(replay.committed_seq, first.committed_seq);
        assert_eq!(replay.accepted_at, first.accepted_at);
        assert!(matches!(replay.answer, ChatPermissionAnswer::Confirm(true)));
        assert_eq!(
            service
                .boundaries
                .queued_permission_answers
                .lock()
                .unwrap()
                .len(),
            1
        );

        let conflict = run_permission_request(
            &mut service,
            ChatPermissionAnswer::Confirm(false),
            "018f0000-0000-7000-8000-000000000073",
            key,
        )
        .unwrap_err();
        assert_eq!(
            serde_json::to_value(conflict).unwrap()["code"],
            "idempotency_conflict"
        );
        assert_eq!(
            service
                .boundaries
                .queued_permission_answers
                .lock()
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_permission_answer_resolves_and_replays_from_idempotency() {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let mut service = permission_service(
            FakeRunStartBoundaries::accepting(),
            Some((run_id, "workspace-a")),
        );
        let key = "018f0000-0000-7000-8000-000000000002";
        let first = permission_request(
            &mut service,
            "workspace-a",
            run_id,
            "gate-1",
            PermissionDecision::Allow,
            "018f0000-0000-7000-8000-000000000003",
            key,
        )
        .unwrap();
        let replay = permission_request(
            &mut service,
            "workspace-a",
            run_id,
            "gate-1",
            PermissionDecision::Allow,
            "018f0000-0000-7000-8000-000000000004",
            key,
        )
        .unwrap();

        assert_eq!(first.committed_seq, 3);
        assert_eq!(replay, first);
        let queued = service.boundaries.queued_permission_answers.lock().unwrap();
        assert_eq!(queued.len(), 1);
        assert!(matches!(queued[0].1, ChatPermissionAnswer::Confirm(true)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_permission_answer_maps_deny_to_false() {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let mut service = permission_service(
            FakeRunStartBoundaries::accepting(),
            Some((run_id, "workspace-a")),
        );
        permission_request(
            &mut service,
            "workspace-a",
            run_id,
            "gate-1",
            PermissionDecision::Deny,
            "018f0000-0000-7000-8000-000000000003",
            "018f0000-0000-7000-8000-000000000002",
        )
        .unwrap();
        let queued = service.boundaries.queued_permission_answers.lock().unwrap();
        assert!(matches!(queued[0].1, ChatPermissionAnswer::Confirm(false)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_permission_answer_rejects_run_workspace_and_gate_mismatches() {
        let requested_run = "0190a100-0000-7000-8000-000000000001";
        let other_run = "0190a100-0000-7000-8000-000000000009";
        let cases = [
            (None, "workspace-a", requested_run, "gate-1"),
            (
                Some((other_run, "workspace-a")),
                "workspace-a",
                requested_run,
                "gate-1",
            ),
            (
                Some((requested_run, "workspace-b")),
                "workspace-a",
                requested_run,
                "gate-1",
            ),
            (
                Some((requested_run, "workspace-b")),
                "workspace-b",
                requested_run,
                "gate-1",
            ),
            (
                Some((requested_run, "workspace-a")),
                "workspace-a",
                requested_run,
                "gate-2",
            ),
            (
                Some((requested_run, "workspace-a")),
                "workspace-a",
                other_run,
                "gate-1",
            ),
        ];
        for (index, (active, workspace, run_id, gate_id)) in cases.into_iter().enumerate() {
            let mut service = permission_service(FakeRunStartBoundaries::accepting(), active);
            assert!(permission_request(
                &mut service,
                workspace,
                run_id,
                gate_id,
                PermissionDecision::Allow,
                &format!("018f0000-0000-7000-8000-{:012x}", index + 10),
                &format!("018f0000-0000-7000-8000-{:012x}", index + 20),
            )
            .is_err());
            assert!(service
                .boundaries
                .queued_permission_answers
                .lock()
                .unwrap()
                .is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_permission_answer_returns_an_error_when_commit_wait_expires() {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let boundaries = FakeRunStartBoundaries {
            permission_auto_commit: false,
            ..FakeRunStartBoundaries::accepting()
        };
        let mut service = permission_service(boundaries, Some((run_id, "workspace-a")));
        assert!(permission_request(
            &mut service,
            "workspace-a",
            run_id,
            "gate-1",
            PermissionDecision::Allow,
            "018f0000-0000-7000-8000-000000000003",
            "018f0000-0000-7000-8000-000000000002",
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_permission_answer_rejects_a_settled_run_without_queueing() {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let mut service = permission_service(
            FakeRunStartBoundaries::accepting(),
            Some((run_id, "workspace-a")),
        );
        append_test_event(
            &mut service.boundaries.journal.lock().unwrap(),
            run_id,
            3,
            "permission.resolved",
            json!({"gate_id": "gate-1", "decision": {"type": "confirm", "value": true}}),
            None,
        );

        assert!(permission_request(
            &mut service,
            "workspace-a",
            run_id,
            "gate-1",
            PermissionDecision::Allow,
            "018f0000-0000-7000-8000-000000000013",
            "018f0000-0000-7000-8000-000000000012",
        )
        .is_err());
        assert!(service
            .boundaries
            .queued_permission_answers
            .lock()
            .unwrap()
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_permission_answer_rejects_a_competing_desktop_resolution() {
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let boundaries = FakeRunStartBoundaries {
            permission_competing_answer: true,
            ..FakeRunStartBoundaries::accepting()
        };
        let mut service = permission_service(boundaries, Some((run_id, "workspace-a")));

        assert!(permission_request(
            &mut service,
            "workspace-a",
            run_id,
            "gate-1",
            PermissionDecision::Allow,
            "018f0000-0000-7000-8000-000000000023",
            "018f0000-0000-7000-8000-000000000022",
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_cancel_replays_without_a_second_cancellation() {
        let boundaries = FakeRunStartBoundaries::accepting();
        *boundaries.active_run.lock().unwrap() = Some((
            "0190a100-0000-7000-8000-000000000001".into(),
            "workspace-a".into(),
        ));
        let mut service = DesktopAttachService {
            boundaries,
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let run_id = "0190a100-0000-7000-8000-000000000001";
        let key = "018f0000-0000-7000-8000-000000000002";
        let first = cancel_request(
            &mut service,
            "workspace-a",
            run_id,
            "018f0000-0000-7000-8000-000000000003",
            key,
        )
        .unwrap();
        let replay = cancel_request(
            &mut service,
            "workspace-a",
            run_id,
            "018f0000-0000-7000-8000-000000000004",
            key,
        )
        .unwrap();
        assert_eq!(replay, first);
        assert_eq!(service.boundaries.cancel_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_cancel_rejects_unknown_settled_and_other_workspace_runs() {
        for active in [
            None,
            Some((
                "0190a100-0000-7000-8000-000000000002".into(),
                "workspace-a".into(),
            )),
            Some((
                "0190a100-0000-7000-8000-000000000001".into(),
                "workspace-b".into(),
            )),
        ] {
            let boundaries = FakeRunStartBoundaries::accepting();
            *boundaries.active_run.lock().unwrap() = active;
            let mut service = DesktopAttachService {
                boundaries,
                idempotency: IdempotencyStore::open(":memory:").unwrap(),
                home: PathBuf::new(),
                workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
                client_credentials: Arc::new(Mutex::new(HashMap::new())),
                credential_path: None,
                client_identity: Some("default".into()),
            };
            assert!(cancel_request(
                &mut service,
                "workspace-a",
                "0190a100-0000-7000-8000-000000000001",
                "018f0000-0000-7000-8000-000000000003",
                "018f0000-0000-7000-8000-000000000002",
            )
            .is_err());
            assert_eq!(service.boundaries.cancel_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[cfg(target_os = "linux")]
    fn attach_start_on(
        service: &mut DesktopAttachService<FakeRunStartBoundaries>,
        text: &str,
        request_id: &str,
        idempotency_key: &str,
        thread_id: Option<&str>,
    ) -> Result<RunStartAccepted, ProtocolError> {
        service.start_run(
            "workspace-a",
            "workspace-a",
            AttachRunStartRequest {
                text: text.into(),
                context: None,
                thread_id: thread_id.map(str::to_owned),
            },
            &Id::new(request_id).unwrap(),
            &Id::new(idempotency_key).unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "cli".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn attach_service_with_thread() -> (DesktopAttachService<FakeRunStartBoundaries>, String, String)
    {
        let boundaries = FakeRunStartBoundaries::accepting();
        let first_run_id = "0190a100-0000-7000-8000-000000000010".to_owned();
        let mut first = event_envelope(
            &first_run_id,
            1,
            "user.prompt.submitted",
            json!({"prompt": "first"}),
            Some("owner"),
        );
        first
            .provenance
            .extra
            .insert("attach_profile".into(), json!("default"));
        let thread_id = boundaries
            .journal
            .lock()
            .unwrap()
            .append_new_run("workspace-a", &first)
            .unwrap();
        (
            DesktopAttachService {
                boundaries,
                idempotency: IdempotencyStore::open(":memory:").unwrap(),
                home: PathBuf::new(),
                workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
                client_credentials: Arc::new(Mutex::new(HashMap::new())),
                credential_path: None,
                client_identity: Some("default".into()),
            },
            thread_id,
            first_run_id,
        )
    }

    #[cfg(target_os = "linux")]
    fn attach_test_provenance() -> Provenance {
        Provenance {
            source: "test".into(),
            source_version: "1".into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_thread_mutations_replay_without_second_events() {
        let (mut service, thread_id, _) = attach_service_with_thread();
        let thread_id = Id::new(thread_id).unwrap();
        let rename_key = Id::new("018f0000-0000-7000-8000-000000000030").unwrap();
        let delete_key = Id::new("018f0000-0000-7000-8000-000000000031").unwrap();
        let companion = CompanionProvenance {
            profile: "default".into(),
            companion_kind: "cli".into(),
            companion_version: "1.2.3".into(),
            peer_uid: 1000,
            peer_pid: 42,
        };

        for request_id in [
            "018f0000-0000-7000-8000-000000000032",
            "018f0000-0000-7000-8000-000000000033",
        ] {
            service
                .rename_thread(
                    "workspace-a",
                    &thread_id,
                    "New title",
                    &Id::new(request_id).unwrap(),
                    &rename_key,
                    companion.clone(),
                )
                .unwrap();
        }
        assert_eq!(
            service
                .boundaries
                .journal
                .lock()
                .unwrap()
                .last_thread_seq(thread_id.as_str())
                .unwrap(),
            2
        );

        for request_id in [
            "018f0000-0000-7000-8000-000000000034",
            "018f0000-0000-7000-8000-000000000035",
        ] {
            service
                .delete_thread(
                    "workspace-a",
                    &thread_id,
                    &Id::new(request_id).unwrap(),
                    &delete_key,
                    companion.clone(),
                )
                .unwrap();
        }
        assert_eq!(
            service
                .boundaries
                .journal
                .lock()
                .unwrap()
                .last_thread_seq(thread_id.as_str())
                .unwrap(),
            3
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_returns_receipt_and_records_companion_provenance() {
        let (result, service) = attach_start(FakeRunStartBoundaries::accepting(), None);
        let accepted = result.unwrap();

        assert_eq!(accepted.committed_seq, 1);
        assert!(chrono::DateTime::parse_from_rfc3339(&accepted.accepted_at).is_ok());
        assert_eq!(
            service.boundaries.launched_run.lock().unwrap().as_deref(),
            Some(accepted.run_id.as_str())
        );
        let provenance = service
            .boundaries
            .prepared_provenance
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            provenance.rpc_request_id.as_deref(),
            Some("018f0000-0000-7000-8000-000000000001")
        );
        assert_eq!(
            provenance.extra["idempotency_key"],
            "018f0000-0000-7000-8000-000000000002"
        );
        assert_eq!(provenance.extra["companion_kind"], "cli");
        assert_eq!(provenance.extra["peer_uid"], 1000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_lists_and_opens_only_requested_workspace_threads() {
        let root = std::env::temp_dir().join(format!("muniment-attach-threads-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let mut boundaries = FakeRunStartBoundaries::accepting();
        boundaries.journal = Mutex::new(RunJournal::open(root.join("runs.sqlite3")).unwrap());
        {
            let mut journal = boundaries.journal.lock().unwrap();
            for (run_id, workspace, prompt, reply) in [
                (
                    "018f0000-0000-7000-8000-0000000000a1",
                    "workspace-a",
                    "first prompt",
                    "first reply",
                ),
                (
                    "018f0000-0000-7000-8000-0000000000a2",
                    "workspace-a",
                    "second prompt",
                    "second reply",
                ),
                (
                    "018f0000-0000-7000-8000-0000000000b1",
                    "workspace-b",
                    "hidden prompt",
                    "hidden reply",
                ),
            ] {
                journal
                    .append_new_run(
                        workspace,
                        &event_envelope(run_id, 1, "run.started", json!({}), Some("owner")),
                    )
                    .unwrap();
                journal
                    .append(
                        1,
                        &event_envelope(
                            run_id,
                            2,
                            "user.prompt.submitted",
                            json!({"prompt": prompt}),
                            Some("owner"),
                        ),
                    )
                    .unwrap();
                journal
                    .append(
                        2,
                        &event_envelope(
                            run_id,
                            3,
                            "model.stream.delta",
                            json!({"text": reply, "content_disclosure": "released"}),
                            Some("owner"),
                        ),
                    )
                    .unwrap();
            }
        }
        let mut service = DesktopAttachService {
            boundaries,
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };

        let first = service
            .list_threads(
                "workspace-a",
                ThreadListRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap();
        assert_eq!(first.threads.len(), 1);
        assert!(first.next_cursor.is_some());
        let second = service
            .list_threads(
                "workspace-a",
                ThreadListRequest {
                    limit: 1,
                    cursor: first.next_cursor,
                },
            )
            .unwrap();
        assert_eq!(second.threads.len(), 1);
        assert_ne!(first.threads[0].thread_id, second.threads[0].thread_id);
        assert!(second.next_cursor.is_none());

        let thread_id = first.threads[0].thread_id.clone();
        let opened = service
            .open_thread(
                "workspace-a",
                ThreadOpenRequest {
                    thread_id: thread_id.clone(),
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap();
        assert_eq!(opened.entries.len(), 1);
        assert!(opened.next_cursor.is_some());
        let rest = service
            .open_thread(
                "workspace-a",
                ThreadOpenRequest {
                    thread_id,
                    limit: 10,
                    cursor: opened.next_cursor,
                },
            )
            .unwrap();
        assert_eq!(rest.entries.len(), 1);
        assert!(rest.next_cursor.is_none());
        assert!(service
            .list_threads(
                "workspace-b",
                ThreadListRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap()
            .threads
            .iter()
            .all(|thread| thread.thread_id != first.threads[0].thread_id
                && thread.thread_id != second.threads[0].thread_id));

        assert_eq!(
            service
                .list_threads(
                    "workspace-a",
                    ThreadListRequest {
                        limit: 0,
                        cursor: None,
                    },
                )
                .unwrap_err()
                .code(),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            service
                .list_threads(
                    "workspace-a",
                    ThreadListRequest {
                        limit: 1,
                        cursor: Some("invalid".into()),
                    },
                )
                .unwrap_err()
                .code(),
            ErrorCode::InvalidCursor
        );
        assert_eq!(
            service
                .open_thread(
                    "workspace-a",
                    ThreadOpenRequest {
                        thread_id: first.threads[0].thread_id.clone(),
                        limit: 1,
                        cursor: Some("invalid".into()),
                    },
                )
                .unwrap_err()
                .code(),
            ErrorCode::InvalidCursor
        );

        drop(service);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_onboarding_context_survives_connections_and_keys_distinct_external_roots() {
        let root = std::env::temp_dir().join(format!("muniment-attach-context-{}", Uuid::now_v7()));
        let first = root.join("repo-one");
        let second = root.join("repo-two");
        let first_memory = root.join("memory-one");
        let second_memory = root.join("memory-two");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("AGENTS.md"), "first instructions").unwrap();
        std::fs::write(second.join("AGENTS.md"), "second instructions").unwrap();
        let contexts = Arc::new(Mutex::new(WorkspaceContextMap::default()));
        let mut first_connection = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: contexts.clone(),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        first_connection
            .onboard_workspace(
                "workspace-a",
                WorkspaceOnboardRequest {
                    opened_directory: first.to_string_lossy().into_owned(),
                    memory_location: first_memory.to_string_lossy().into_owned(),
                },
            )
            .unwrap();
        drop(first_connection);

        let first_canonical = first.canonicalize().unwrap().to_string_lossy().into_owned();
        let mut second_connection = DesktopAttachService {
            boundaries: FakeRunStartBoundaries {
                granted_workspaces: vec!["workspace-a".into()],
                ..FakeRunStartBoundaries::accepting()
            },
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: contexts.clone(),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        second_connection
            .onboard_workspace(
                "workspace-b",
                WorkspaceOnboardRequest {
                    opened_directory: second.to_string_lossy().into_owned(),
                    memory_location: second_memory.to_string_lossy().into_owned(),
                },
            )
            .unwrap();

        let guard = contexts.lock().unwrap();
        assert_eq!(
            guard.instructions("default", "workspace-a", &first.canonicalize().unwrap()),
            Some("first instructions")
        );
        assert_eq!(
            guard.instructions("default", "workspace-b", &second.canonicalize().unwrap()),
            Some("second instructions")
        );
        assert_eq!(
            guard.instructions(
                "default",
                "workspace-a",
                &first_memory.canonicalize().unwrap()
            ),
            Some("first instructions")
        );
        // Release the shared `contexts` lock before the client-b/second/third
        // connections call back into the service -- those methods re-lock the
        // same mutex, so holding the guard here would deadlock (dropping the
        // former `stored` reference was a no-op that left the guard live).
        drop(guard);
        let client_b = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: contexts.clone(),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("client-b".into()),
        };
        // Grants are bound to the authorizing client: a second identity cannot
        // borrow another client's onboarded workspaces. `authorized_workspace`
        // is the gate the dispatcher applies before a run is ever started, so it
        // resolves nothing for client-b even though the contexts are shared.
        for workspace in [&first, &first_memory] {
            assert!(client_b
                .authorized_workspace("workspace-a", &workspace.to_string_lossy())
                .is_none());
        }
        assert!(client_b
            .boundaries
            .prepared_provenance
            .lock()
            .unwrap()
            .is_none());
        // The onboarding client resolves its own repository through the same
        // gate (canonicalizing the request) before starting the run.
        let first_authorized = second_connection
            .authorized_workspace("workspace-a", &first.to_string_lossy())
            .unwrap();
        assert_eq!(first_authorized, first_canonical);
        assert!(second_connection
            .authorized_workspace("workspace-b", &first.to_string_lossy())
            .is_none());
        let run = second_connection
            .start_run(
                "workspace-a",
                &first_authorized,
                AttachRunStartRequest {
                    text: "use repository context".into(),
                    context: None,
                    thread_id: None,
                },
                &Id::new("018f0000-0000-7000-8000-000000000011").unwrap(),
                &Id::new("018f0000-0000-7000-8000-000000000012").unwrap(),
                CompanionProvenance {
                    profile: "default".into(),
                    companion_kind: "editor-extension".into(),
                    companion_version: "1.2.3".into(),
                    peer_uid: 1000,
                    peer_pid: 42,
                },
            )
            .unwrap();
        assert!(!run.run_id.is_empty());
        let provenance = second_connection
            .boundaries
            .prepared_provenance
            .lock()
            .unwrap();
        assert_eq!(
            provenance.as_ref().unwrap().extra["repository_instructions"],
            "first instructions"
        );
        drop(provenance);
        assert_eq!(
            second_connection
                .boundaries
                .active_run
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .1,
            "workspace-a"
        );
        let second_memory_canonical = second_memory
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut third_connection = DesktopAttachService {
            boundaries: FakeRunStartBoundaries {
                granted_workspaces: vec!["workspace-b".into()],
                ..FakeRunStartBoundaries::accepting()
            },
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: contexts.clone(),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let second_memory_authorized = third_connection
            .authorized_workspace("workspace-b", &second_memory.to_string_lossy())
            .unwrap();
        assert_eq!(second_memory_authorized, second_memory_canonical);
        third_connection
            .start_run(
                "workspace-b",
                &second_memory_authorized,
                AttachRunStartRequest {
                    text: "second context".into(),
                    context: None,
                    thread_id: None,
                },
                &Id::new("018f0000-0000-7000-8000-000000000021").unwrap(),
                &Id::new("018f0000-0000-7000-8000-000000000022").unwrap(),
                CompanionProvenance {
                    profile: "default".into(),
                    companion_kind: "editor-extension".into(),
                    companion_version: "1.2.3".into(),
                    peer_uid: 1000,
                    peer_pid: 42,
                },
            )
            .unwrap();
        assert_eq!(
            third_connection
                .boundaries
                .prepared_provenance
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .extra["repository_instructions"],
            "second instructions"
        );
        assert_eq!(
            third_connection
                .boundaries
                .active_run
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .1,
            "workspace-b"
        );
        assert!(!root.join("home").exists());
        second_connection.ensure_home().unwrap();
        for child in ["memory", "agents", "projects", "sessions"] {
            assert!(root.join("home").join(child).join("README.md").is_file());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_replays_exact_retry_without_second_coordinator_run() {
        let (mut service, thread_id, _) = attach_service_with_thread();
        let key = "018f0000-0000-7000-8000-000000000002";
        let first = attach_start_on(
            &mut service,
            "hello",
            "018f0000-0000-7000-8000-000000000001",
            key,
            Some(&thread_id),
        )
        .unwrap();
        service
            .boundaries
            .journal
            .lock()
            .unwrap()
            .append_thread_deleted(
                1,
                &thread_id,
                "2026-08-03T00:00:00Z",
                &attach_test_provenance(),
            )
            .unwrap();
        let replay = attach_start_on(
            &mut service,
            "hello",
            "018f0000-0000-7000-8000-000000000003",
            key,
            Some(&thread_id),
        )
        .unwrap();

        assert_eq!(replay, first);
        assert_eq!(
            service
                .boundaries
                .prompt_protection_calls
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(service.boundaries.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(service.boundaries.launch_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_rejects_conflicting_key_without_second_coordinator_run() {
        let (mut service, thread_id, _) = attach_service_with_thread();
        let key = "018f0000-0000-7000-8000-000000000002";
        attach_start_on(
            &mut service,
            "hello",
            "018f0000-0000-7000-8000-000000000001",
            key,
            Some(&thread_id),
        )
        .unwrap();
        let conflict = attach_start_on(
            &mut service,
            "hello",
            "018f0000-0000-7000-8000-000000000003",
            key,
            None,
        )
        .unwrap_err();

        assert_eq!(
            serde_json::to_value(conflict).unwrap()["code"],
            "idempotency_conflict"
        );
        assert_eq!(
            service
                .boundaries
                .prompt_protection_calls
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(service.boundaries.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(service.boundaries.launch_calls.load(Ordering::SeqCst), 1);

        let changed = attach_start_on(
            &mut service,
            "hello",
            "018f0000-0000-7000-8000-000000000004",
            key,
            Some("0190a100-0000-7000-8000-000000000099"),
        )
        .unwrap_err();
        assert_eq!(
            serde_json::to_value(changed).unwrap()["code"],
            "idempotency_conflict"
        );
        assert_eq!(service.boundaries.prepare_calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_thread_binding_uses_next_ordinal_and_opens_both_runs() {
        let (mut service, thread_id, first_run_id) = attach_service_with_thread();
        let accepted = attach_start_on(
            &mut service,
            "hello",
            "018f0000-0000-7000-8000-000000000001",
            "018f0000-0000-7000-8000-000000000002",
            Some(&thread_id),
        )
        .unwrap();

        assert_eq!(accepted.thread_id, thread_id);
        let run_page = service
            .boundaries
            .journal
            .lock()
            .unwrap()
            .thread_run_ids(&thread_id, 10, None)
            .unwrap();
        assert_eq!(run_page.run_ids, [first_run_id, accepted.run_id.clone()]);
        let opened = service
            .open_thread(
                "workspace-a",
                ThreadOpenRequest {
                    thread_id: thread_id.clone(),
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap();
        assert_eq!(opened.thread_id, thread_id);
        assert_eq!(opened.entries.len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_thread_binding_rejections_leave_the_journal_unchanged() {
        for case in [
            "unknown",
            "tombstoned",
            "wrong-workspace",
            "foreign-profile",
        ] {
            let (mut service, thread_id, first_run_id) = attach_service_with_thread();
            if case == "tombstoned" {
                service
                    .boundaries
                    .journal
                    .lock()
                    .unwrap()
                    .append_thread_deleted(
                        1,
                        &thread_id,
                        "2026-08-03T00:00:00Z",
                        &attach_test_provenance(),
                    )
                    .unwrap();
            }
            let event_count = service
                .boundaries
                .journal
                .lock()
                .unwrap()
                .run_event_types()
                .unwrap()
                .len();
            if case == "wrong-workspace" {
                service
                    .boundaries
                    .granted_workspaces
                    .push("workspace-b".into());
            }
            let selected = if case == "unknown" {
                "0190a100-0000-7000-8000-000000000099"
            } else {
                &thread_id
            };
            let workspace = if case == "wrong-workspace" {
                "workspace-b"
            } else {
                "workspace-a"
            };
            let result = service.start_run(
                workspace,
                workspace,
                AttachRunStartRequest {
                    text: "hello".into(),
                    context: None,
                    thread_id: Some(selected.into()),
                },
                &Id::new("018f0000-0000-7000-8000-000000000001").unwrap(),
                &Id::new("018f0000-0000-7000-8000-000000000002").unwrap(),
                CompanionProvenance {
                    profile: if case == "foreign-profile" {
                        "another-profile"
                    } else {
                        "default"
                    }
                    .into(),
                    companion_kind: "cli".into(),
                    companion_version: "1.2.3".into(),
                    peer_uid: 1000,
                    peer_pid: 42,
                },
            );
            assert_eq!(
                serde_json::to_value(result.unwrap_err()).unwrap()["code"],
                "thread_not_found",
                "{case}"
            );
            let mut journal = service.boundaries.journal.lock().unwrap();
            assert_eq!(journal.events(&first_run_id).unwrap().len(), 1, "{case}");
            assert_eq!(
                journal.run_event_types().unwrap().len(),
                event_count,
                "{case}"
            );
            assert_eq!(service.boundaries.launch_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                service
                    .boundaries
                    .prompt_protection_calls
                    .load(Ordering::SeqCst),
                0,
                "{case}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prompt_protection_failure_leaves_bound_and_new_thread_ordinals_unchanged() {
        for bound in [false, true] {
            let (mut service, thread_id, first_run_id) = attach_service_with_thread();
            service.boundaries.protect_error = Some("keyring failed".into());
            let before = service
                .boundaries
                .journal
                .lock()
                .unwrap()
                .run_event_types()
                .unwrap();

            let result = attach_start_on(
                &mut service,
                "hello",
                "018f0000-0000-7000-8000-000000000001",
                "018f0000-0000-7000-8000-000000000002",
                bound.then_some(thread_id.as_str()),
            );

            assert_eq!(
                serde_json::to_value(result.unwrap_err()).unwrap()["code"],
                "persistence_failed"
            );
            let mut journal = service.boundaries.journal.lock().unwrap();
            assert_eq!(journal.run_event_types().unwrap(), before, "bound={bound}");
            let page = journal.thread_run_ids(&thread_id, 10, None).unwrap();
            assert_eq!(page.run_ids, [first_run_id], "bound={bound}");
            assert_eq!(
                service
                    .boundaries
                    .prompt_protection_calls
                    .load(Ordering::SeqCst),
                1
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_rejects_in_flight_and_unsupported_context() {
        let boundaries = FakeRunStartBoundaries {
            active: true,
            ..FakeRunStartBoundaries::accepting()
        };
        let (in_flight, _) = attach_start(boundaries, None);
        assert_eq!(
            serde_json::to_value(in_flight.unwrap_err()).unwrap()["code"],
            "invalid_request"
        );

        let (context, service) = attach_start(
            FakeRunStartBoundaries::accepting(),
            Some(json!({"cwd": "/private/path"})),
        );
        assert_eq!(
            serde_json::to_value(context.unwrap_err()).unwrap()["code"],
            "unsupported_operation"
        );
        assert_eq!(service.boundaries.auth_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_rejects_a_grant_for_another_workspace() {
        let mut service = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let result = service.start_run(
            "workspace-b",
            "workspace-b",
            AttachRunStartRequest {
                text: "hello".into(),
                context: None,
                thread_id: None,
            },
            &Id::new("018f0000-0000-7000-8000-000000000001").unwrap(),
            &Id::new("018f0000-0000-7000-8000-000000000002").unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "cli".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        );

        assert_eq!(
            serde_json::to_value(result.unwrap_err()).unwrap()["code"],
            "unauthorized"
        );
        assert_eq!(
            service
                .boundaries
                .prompt_protection_calls
                .load(Ordering::SeqCst),
            0
        );
        assert!(service.boundaries.launched_run.lock().unwrap().is_none());
        assert!(service
            .boundaries
            .prepared_provenance
            .lock()
            .unwrap()
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_redacts_coordinator_failure_and_clears_active_run() {
        let boundaries = FakeRunStartBoundaries {
            prepare_error: Some(
                "token secret-token path /private/work sidecar socket unavailable".into(),
            ),
            ..FakeRunStartBoundaries::accepting()
        };
        let (result, service) = attach_start(boundaries, None);
        let encoded = serde_json::to_string(&result.unwrap_err()).unwrap();

        assert!(encoded.contains("persistence_failed"));
        assert!(!encoded.contains("secret-token"));
        assert!(!encoded.contains("/private/work"));
        assert!(!encoded.contains("sidecar"));
        assert_eq!(service.boundaries.clear_calls.load(Ordering::SeqCst), 1);
        assert!(service.boundaries.launched_run.lock().unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_does_not_launch_when_receipt_finalization_fails() {
        let mut service = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: FailingFinalization,
            home: PathBuf::new(),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(HashMap::new())),
            credential_path: None,
            client_identity: Some("default".into()),
        };
        let result = service.start_run(
            "workspace-a",
            "workspace-a",
            AttachRunStartRequest {
                text: "private prompt".into(),
                context: None,
                thread_id: None,
            },
            &Id::new("018f0000-0000-7000-8000-000000000001").unwrap(),
            &Id::new("018f0000-0000-7000-8000-000000000002").unwrap(),
            CompanionProvenance {
                profile: "default".into(),
                companion_kind: "cli".into(),
                companion_version: "1.2.3".into(),
                peer_uid: 1000,
                peer_pid: 42,
            },
        );

        let encoded = serde_json::to_string(&result.unwrap_err()).unwrap();
        assert!(encoded.contains("persistence_failed"));
        assert!(!encoded.contains("private prompt"));
        assert_eq!(service.boundaries.launch_calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.boundaries.clear_calls.load(Ordering::SeqCst), 1);
        let journaled_events = service.boundaries.journaled_events.lock().unwrap();
        let events = journaled_events.values().next().unwrap();
        assert_eq!(events.last().unwrap().event_type, "run.failed");
        assert!(reduce(events).unwrap().is_terminal());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_adapter_classifies_and_redacts_every_coordinator_failure_stage() {
        const DETAIL: &str =
            "prompt private-prompt token secret-token path /private/work sidecar socket";
        let cases = [
            (
                "unauthorized",
                FakeRunStartBoundaries {
                    auth_error: Some(DETAIL.into()),
                    ..FakeRunStartBoundaries::accepting()
                },
            ),
            (
                "persistence_failed",
                FakeRunStartBoundaries {
                    configure_error: Some(DETAIL.into()),
                    ..FakeRunStartBoundaries::accepting()
                },
            ),
            (
                "invalid_request",
                FakeRunStartBoundaries {
                    install_error: Some(DETAIL.into()),
                    ..FakeRunStartBoundaries::accepting()
                },
            ),
            (
                "persistence_failed",
                FakeRunStartBoundaries {
                    prepare_error: Some(DETAIL.into()),
                    ..FakeRunStartBoundaries::accepting()
                },
            ),
            (
                "persistence_failed",
                FakeRunStartBoundaries {
                    projection_error: Some(DETAIL.into()),
                    ..FakeRunStartBoundaries::accepting()
                },
            ),
        ];

        for (expected_code, boundaries) in cases {
            let (result, _) = attach_start(boundaries, None);
            let encoded = serde_json::to_string(&result.unwrap_err()).unwrap();
            assert!(encoded.contains(expected_code), "{encoded}");
            for secret in ["private-prompt", "secret-token", "/private/work", "sidecar"] {
                assert!(!encoded.contains(secret), "leaked {secret}: {encoded}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_credentials_reject_impersonation_and_canonical_grants_reject_retargeting() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("muniment-attach-grants-{}", Uuid::now_v7()));
        let first = root.join("first");
        let second = root.join("second");
        let memory = root.join("memory");
        let alias = root.join("alias");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        symlink(&first, &alias).unwrap();
        let contexts = Arc::new(Mutex::new(WorkspaceContextMap::default()));
        let credentials = Arc::new(Mutex::new(HashMap::new()));
        let make_service = || DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: contexts.clone(),
            client_credentials: credentials.clone(),
            credential_path: None,
            client_identity: None,
        };

        let mut client = make_service();
        assert_eq!(
            client
                .authorize_client("client-a", None, &"aa".repeat(32), "cli", "1.2.3")
                .unwrap(),
            "aa".repeat(32)
        );
        client
            .onboard_workspace(
                "workspace-a",
                WorkspaceOnboardRequest {
                    opened_directory: alias.to_string_lossy().into_owned(),
                    memory_location: memory.to_string_lossy().into_owned(),
                },
            )
            .unwrap();
        assert_eq!(
            client.authorized_workspace("workspace-a", &alias.to_string_lossy()),
            Some(first.to_string_lossy().into_owned())
        );
        assert!(client
            .authorized_workspace("workspace-a", &root.join("missing").to_string_lossy())
            .is_none());
        std::fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        assert!(client
            .authorized_workspace("workspace-a", &alias.to_string_lossy())
            .is_none());

        let mut impersonator = make_service();
        for credential in [None, Some("cc".repeat(32))] {
            assert_eq!(
                impersonator
                    .authorize_client(
                        "client-a",
                        credential.as_deref(),
                        &"bb".repeat(32),
                        "cli",
                        "1.2.3",
                    )
                    .unwrap_err()
                    .code(),
                ErrorCode::Unauthorized
            );
        }
        assert!(impersonator.client_identity.is_none());
        assert!(impersonator
            .boundaries
            .prepared_provenance
            .lock()
            .unwrap()
            .is_none());

        let mut reconnect = make_service();
        assert_eq!(
            reconnect
                .authorize_client(
                    "client-a",
                    Some(&"aa".repeat(32)),
                    &"dd".repeat(32),
                    "cli",
                    "1.2.3",
                )
                .unwrap(),
            "aa".repeat(32)
        );
        assert_eq!(
            reconnect.authorized_workspace("workspace-a", &first.to_string_lossy()),
            Some(first.to_string_lossy().into_owned())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn attach_client_credentials_survive_restart_and_unsafe_state_fails_closed() {
        use crate::attach::load_client_credentials;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("muniment-attach-credentials-{}", Uuid::now_v7()));
        let path = root.join("credentials.json");
        let identity = "018f0000-0000-7000-8000-000000000099";
        let credential = "ab".repeat(32);
        let make_service = |credentials| DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(credentials)),
            credential_path: Some(path.clone()),
            client_identity: None,
        };

        let mut initial = make_service(HashMap::new());
        assert_eq!(
            initial
                .authorize_client(identity, None, &credential, "cli", "1.2.3")
                .unwrap(),
            credential
        );
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(initial);
        let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored["version"], 1);
        assert_eq!(stored["companions"][identity]["credential"], credential);
        assert_eq!(stored["companions"][identity]["claimed_kind"], "cli");
        assert_eq!(stored["companions"][identity]["claimed_version"], "1.2.3");
        let approved_at = stored["companions"][identity]["approved_at"]
            .as_str()
            .unwrap();
        assert!(approved_at.ends_with('Z'));
        assert!(chrono::DateTime::parse_from_rfc3339(approved_at).is_ok());

        let mut restarted = make_service(load_client_credentials(&path).unwrap());
        assert_eq!(
            restarted
                .authorize_client(
                    identity,
                    Some(&credential),
                    &"cd".repeat(32),
                    "changed",
                    "9.9.9"
                )
                .unwrap(),
            credential
        );
        for presented in [None, Some("00".repeat(32))] {
            let mut rejected = make_service(load_client_credentials(&path).unwrap());
            assert_eq!(
                rejected
                    .authorize_client(
                        identity,
                        presented.as_deref(),
                        &"ef".repeat(32),
                        "cli",
                        "1.2.3"
                    )
                    .unwrap_err()
                    .code(),
                ErrorCode::Unauthorized
            );
            assert!(rejected.client_identity.is_none());
        }
        let mut unknown = make_service(load_client_credentials(&path).unwrap());
        assert_eq!(
            unknown
                .authorize_client(
                    "018f0000-0000-7000-8000-000000000100",
                    Some(&credential),
                    &"ef".repeat(32),
                    "cli",
                    "1.2.3"
                )
                .unwrap_err()
                .code(),
            ErrorCode::Unauthorized
        );

        let mut unsupported = stored.clone();
        unsupported["version"] = json!(2);
        std::fs::write(&path, serde_json::to_vec(&unsupported).unwrap()).unwrap();
        assert!(load_client_credentials(&path).is_err());
        let mut incomplete = stored;
        incomplete["companions"][identity]
            .as_object_mut()
            .unwrap()
            .remove("approved_at");
        std::fs::write(&path, serde_json::to_vec(&incomplete).unwrap()).unwrap();
        assert!(load_client_credentials(&path).is_err());
        std::fs::write(&path, b"not-json").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_client_credentials(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"{}").unwrap();
        symlink(&target, &path).unwrap();
        assert!(load_client_credentials(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_attach_credentials_authenticate_with_unknown_claims() {
        use crate::attach::load_client_credentials;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("muniment-attach-legacy-{}", Uuid::now_v7()));
        let path = root.join("credentials.json");
        let identity = "018f0000-0000-7000-8000-000000000099";
        let credential = "ab".repeat(32);
        let new_identity = "018f0000-0000-7000-8000-000000000100";
        let new_credential = "cd".repeat(32);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &path,
            serde_json::to_vec(&HashMap::from([(identity, &credential)])).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let credentials = load_client_credentials(&path).unwrap();
        assert_eq!(credentials[identity].claimed_kind, "unknown");
        assert_eq!(credentials[identity].claimed_version, "unknown");
        assert_eq!(credentials[identity].approved_at, None);
        let mut service = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(credentials)),
            credential_path: Some(path.clone()),
            client_identity: None,
        };
        assert_eq!(
            service
                .authorize_client(identity, Some(&credential), "", "changed", "9.9.9")
                .unwrap(),
            credential
        );
        assert_eq!(
            service
                .authorize_client(new_identity, None, &new_credential, "desktop", "1.0.0")
                .unwrap(),
            new_credential
        );
        drop(service);
        let loaded = load_client_credentials(&path).unwrap();
        assert_eq!(loaded[identity].claimed_kind, "unknown");
        assert_eq!(loaded[new_identity].claimed_kind, "desktop");
        assert!(loaded[new_identity].approved_at.is_some());
        let mut restarted = DesktopAttachService {
            boundaries: FakeRunStartBoundaries::accepting(),
            idempotency: IdempotencyStore::open(":memory:").unwrap(),
            home: root.join("home"),
            workspace_contexts: Arc::new(Mutex::new(WorkspaceContextMap::default())),
            client_credentials: Arc::new(Mutex::new(loaded)),
            credential_path: Some(path.clone()),
            client_identity: None,
        };
        assert!(restarted
            .authorize_client(identity, Some(&credential), "", "changed", "9.9.9")
            .is_ok());
        assert!(restarted
            .authorize_client(new_identity, Some(&new_credential), "", "changed", "9.9.9")
            .is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
