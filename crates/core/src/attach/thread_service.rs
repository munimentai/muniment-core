//! Platform-neutral thread service seam.

use std::collections::BTreeMap;

use super::desktop_service_message::{
    ArtifactFetchResult, CompanionProvenance, MigrationControlRequest, PermissionAnswerAccepted,
    PermissionAnswerRequest, RunCancelAccepted, RunCancelRequest, RunMessageAccepted,
    RunMessageRequest, RunPermissionAnswerAccepted, RunPermissionAnswerRequest, RunResumeAccepted,
    RunResumeRequest, RunStartAccepted, RunStreamPage, RunSubmitAccepted, RunSubmitRequest,
    ThreadCreateAccepted,
};
use super::{
    Approval, EntitlementSnapshotResult, ProtocolError, WorkspaceOnboardRequest,
    WorkspaceOnboarded, MAX_FRAME_LENGTH,
};
use super::{MAX_RUN_STREAM_WINDOW_BYTES, MAX_RUN_STREAM_WINDOW_EVENTS};
use crate::journal::{thread_summaries::ThreadSummaryListError, RunEventPageError, RunJournal};

const MAX_CURSOR_LENGTH: usize = 1024;
const MAX_RESPONSE_BODY_LENGTH: usize = MAX_FRAME_LENGTH - 4096;

/// A companion row that excludes its secret credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompanionRecord {
    pub identity: String,
    pub claimed_kind: String,
    pub claimed_version: String,
    pub approved_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadListRequest {
    pub limit: u8,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedactedThreadSummary {
    pub thread_id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreadListPage {
    pub threads: Vec<RedactedThreadSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadOpenRequest {
    pub thread_id: String,
    pub limit: u8,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedactedThreadEntry {
    pub run_seq: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreadOpenPage {
    pub thread_id: String,
    pub entries: Vec<RedactedThreadEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunStartRequest {
    pub text: String,
    pub context: Option<serde_json::Value>,
    pub thread_id: Option<String>,
}

/// Deterministic desktop service seam for authorized attach requests.
pub trait ThreadListService {
    fn drain_state(&self) -> Option<&super::DrainState> {
        None
    }

    fn bind_authorized_client(&mut self, _client_identity: &str) {}

    fn reconnect_approval(&self) -> Option<Approval> {
        None
    }

    fn authorize_client(
        &mut self,
        client_identity: &str,
        _presented_credential: Option<&str>,
        issued_credential: &str,
        _claimed_kind: &str,
        _claimed_version: &str,
    ) -> Result<String, ProtocolError> {
        self.bind_authorized_client(client_identity);
        Ok(issued_credential.to_owned())
    }

    fn onboard_workspace(
        &mut self,
        _workspace: &str,
        _request: WorkspaceOnboardRequest,
    ) -> Result<WorkspaceOnboarded, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn ensure_home(&mut self) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn session_status(&mut self) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn entitlement_snapshot(&mut self) -> Result<EntitlementSnapshotResult, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn list_devices(&mut self) -> Result<crate::auth::NativeDeviceList, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn list_companions(&mut self) -> Result<Vec<super::CompanionRecord>, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn revoke_companion(
        &mut self,
        _client_identity: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn list_companies(&mut self) -> Result<Vec<crate::record::CompanySummary>, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn create_company(
        &mut self,
        _name: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<crate::record::CompanySummary, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn select_company(
        &mut self,
        _company_id: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<crate::record::CompanySummary, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn rename_company(
        &mut self,
        _company_id: &str,
        _name: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<crate::record::CompanySummary, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn record_sql(
        &mut self,
        _body: serde_json::Value,
        _provenance: CompanionProvenance,
    ) -> Result<serde_json::Value, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn record_propose(
        &mut self,
        _body: serde_json::Value,
        _provenance: CompanionProvenance,
    ) -> Result<serde_json::Value, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn record_commit(
        &mut self,
        _body: serde_json::Value,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<serde_json::Value, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn record_kinds(
        &mut self,
        _body: serde_json::Value,
        _provenance: CompanionProvenance,
    ) -> Result<serde_json::Value, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn sign_in(
        &mut self,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn sign_out(
        &mut self,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn control_migration(
        &mut self,
        _request: MigrationControlRequest,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn authorized_workspace(&self, _session_workspace: &str, _workspace: &str) -> Option<String> {
        None
    }

    fn list_threads(
        &mut self,
        _workspace: &str,
        _request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn open_thread(
        &mut self,
        _workspace: &str,
        _request: ThreadOpenRequest,
    ) -> Result<ThreadOpenPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn thread_summaries(
        &mut self,
        _request: ThreadListRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn select_thread(&mut self, _thread_id: &super::Id) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn recheck_retention(&mut self) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn thread_history(
        &mut self,
        _request: ThreadOpenRequest,
    ) -> Result<serde_json::Value, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn create_thread(
        &mut self,
        _workspace: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<ThreadCreateAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn rename_thread(
        &mut self,
        _workspace: &str,
        _thread_id: &super::Id,
        _title: &str,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn delete_thread(
        &mut self,
        _workspace: &str,
        _thread_id: &super::Id,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn start_run(
        &mut self,
        _workspace: &str,
        _execution_root: &str,
        _request: RunStartRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunStartAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn submit_run(
        &mut self,
        _workspace: &str,
        _request: RunSubmitRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunSubmitAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn resume_run(
        &mut self,
        _workspace: &str,
        _request: RunResumeRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunResumeAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn answer_permission(
        &mut self,
        _workspace: &str,
        _request: PermissionAnswerRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<PermissionAnswerAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn steer_run(
        &mut self,
        _workspace: &str,
        _request: RunMessageRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn follow_up_run(
        &mut self,
        _workspace: &str,
        _request: RunMessageRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunMessageAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn answer_run_permission(
        &mut self,
        _workspace: &str,
        _request: RunPermissionAnswerRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunPermissionAnswerAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn cancel_run(
        &mut self,
        _workspace: &str,
        _request: RunCancelRequest,
        _request_id: &super::Id,
        _idempotency_key: &super::Id,
        _provenance: CompanionProvenance,
    ) -> Result<RunCancelAccepted, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn stream_run(
        &mut self,
        _workspace: &str,
        _run_id: &str,
        _after_run_seq: u64,
    ) -> Result<RunStreamPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn fetch_artifact(
        &mut self,
        _workspace: &str,
        _artifact_id: &super::Id,
    ) -> Result<ArtifactFetchResult, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn read_artifact_range(
        &mut self,
        _workspace: &str,
        _artifact_id: &super::Id,
        _offset: u64,
        _length: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }

    fn subscribe_run_commits(
        &mut self,
        _run_id: &str,
    ) -> Result<Option<crate::journal::CommitSubscription>, ProtocolError> {
        Ok(None)
    }

    #[cfg(target_os = "linux")]
    fn record_chat_delivery_failure(&mut self, _run_id: &str, _cause: &str) {}

    fn subscribe_chat_events(
        &mut self,
    ) -> Result<crate::run_events::ChatEventSubscription, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
}

impl<F> ThreadListService for F
where
    F: FnMut(&str, ThreadListRequest) -> Result<ThreadListPage, ProtocolError>,
{
    fn list_threads(
        &mut self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        self(workspace, request)
    }
}

impl ThreadListService for RunJournal {
    fn subscribe_run_commits(
        &mut self,
        run_id: &str,
    ) -> Result<Option<crate::journal::CommitSubscription>, ProtocolError> {
        if self.path.is_none() {
            return Ok(None);
        }
        self.subscribe_commits(run_id)
            .map(Some)
            .map_err(|_| ProtocolError::persistence_failed())
    }

    fn stream_run(
        &mut self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<RunStreamPage, ProtocolError> {
        let mut page = self
            .workspace_catch_up(
                workspace,
                run_id,
                after_run_seq,
                MAX_RUN_STREAM_WINDOW_EVENTS,
                MAX_RUN_STREAM_WINDOW_BYTES,
            )
            .map_err(|error| match error {
                RunEventPageError::InvalidCursor => ProtocolError::invalid_cursor(),
                RunEventPageError::NotFoundOrInaccessible => ProtocolError::invalid_request(),
                RunEventPageError::InvalidLimit => ProtocolError::invalid_request(),
                RunEventPageError::Journal(_) => ProtocolError::persistence_failed(),
            })?;
        let projected = self
            .projected_run_stream_text(workspace, run_id, page.current_run_seq)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let projected_len = page
            .events
            .iter()
            .take_while(|event| projected.contains_key(&event.run_seq))
            .count();
        if projected_len != page.events.len() {
            page.events.truncate(projected_len);
            page.exhausted = false;
        }
        for event in &mut page.events {
            if event.event_type == "model.stream.delta" {
                event.text = match projected.get(&event.run_seq) {
                    Some(crate::assistant_text::stream::AssistantText::Released(text)) => {
                        Some(text.clone())
                    }
                    _ => None,
                };
            }
        }
        Ok(RunStreamPage {
            run_id: run_id.to_owned(),
            first_available_run_seq: page.first_available_run_seq,
            current_run_seq: page.current_run_seq,
            events: page.events,
            exhausted: page.exhausted,
        })
    }

    fn list_threads(
        &mut self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        let page = self
            .workspace_thread_summaries(
                workspace,
                usize::from(request.limit),
                request.cursor.as_deref(),
            )
            .map_err(|error| match error {
                ThreadSummaryListError::InvalidLimit { .. } => ProtocolError::invalid_request(),
                ThreadSummaryListError::InvalidCursor => ProtocolError::invalid_cursor(),
                ThreadSummaryListError::Journal(_) => ProtocolError::persistence_failed(),
            })?;
        Ok(ThreadListPage {
            threads: page
                .summaries
                .into_iter()
                .map(|summary| RedactedThreadSummary {
                    thread_id: summary.thread_id,
                    title: summary.title,
                    updated_at: summary.updated_at,
                })
                .collect(),
            next_cursor: page.next_cursor,
        })
    }

    fn open_thread(
        &mut self,
        workspace: &str,
        request: ThreadOpenRequest,
    ) -> Result<ThreadOpenPage, ProtocolError> {
        let mut boundary = self
            .ledger_thread_projection_boundary(
                workspace,
                &request.thread_id,
                request.cursor.as_deref(),
            )
            .map_err(|error| match error {
                RunEventPageError::InvalidLimit => ProtocolError::invalid_request(),
                RunEventPageError::InvalidCursor => ProtocolError::invalid_cursor(),
                RunEventPageError::NotFoundOrInaccessible => ProtocolError::invalid_request(),
                RunEventPageError::Journal(_) => ProtocolError::persistence_failed(),
            })?;
        let projected = self
            .ledger_thread_projection_entries(
                workspace,
                &request.thread_id,
                &boundary,
                usize::from(request.limit) + 1,
            )
            .map_err(|error| match error {
                RunEventPageError::InvalidCursor => ProtocolError::invalid_cursor(),
                RunEventPageError::NotFoundOrInaccessible => ProtocolError::invalid_request(),
                _ => ProtocolError::persistence_failed(),
            })?;
        let mut assistant_text = BTreeMap::new();
        for entry in &projected {
            if entry.kind == "assistant_message"
                && !assistant_text.contains_key(&(entry.run_id.clone(), entry.snapshot_seq))
            {
                let ordinals = projected
                    .iter()
                    .filter(|candidate| {
                        candidate.kind == "assistant_message"
                            && candidate.run_id == entry.run_id
                            && candidate.snapshot_seq == entry.snapshot_seq
                    })
                    .map(|candidate| candidate.entry_ordinal)
                    .collect::<Vec<_>>();
                let projection = self
                    .projected_assistant_text(
                        workspace,
                        &entry.run_id,
                        entry.snapshot_seq,
                        &ordinals,
                    )
                    .map_err(|_| ProtocolError::persistence_failed())?;
                assistant_text.insert((entry.run_id.clone(), entry.snapshot_seq), projection);
            }
        }
        let mut expanded = projected
            .into_iter()
            .map(|entry| {
                let text = if entry.kind == "assistant_message" {
                    assistant_text
                        .get(&(entry.run_id.clone(), entry.snapshot_seq))
                        .and_then(|projection| projection.get(&entry.entry_ordinal))
                        .cloned()
                        .flatten()
                } else {
                    entry.text
                };
                (
                    (entry.run_ordinal, entry.run_seq, entry.entry_ordinal),
                    RedactedThreadEntry {
                        run_seq: entry.run_seq,
                        kind: entry.kind,
                        text,
                    },
                )
            })
            .collect::<Vec<_>>();
        if request.cursor.is_some() && expanded.is_empty() {
            return Err(ProtocolError::invalid_cursor());
        }
        let has_more = expanded.len() > usize::from(request.limit);
        expanded.truncate(usize::from(request.limit));
        let mut entries = Vec::new();
        let mut emitted_position = None;
        let mut page_length = serde_json::to_vec(&ThreadOpenPage {
            thread_id: request.thread_id.clone(),
            entries: Vec::new(),
            next_cursor: Some("x".repeat(MAX_CURSOR_LENGTH)),
        })
        .map_err(|_| ProtocolError::persistence_failed())?
        .len();
        for (position, entry) in expanded.iter() {
            let entry_length = serde_json::to_vec(entry)
                .map_err(|_| ProtocolError::persistence_failed())?
                .len();
            let separator_length = usize::from(!entries.is_empty());
            if page_length + separator_length + entry_length > MAX_RESPONSE_BODY_LENGTH {
                break;
            }
            page_length += separator_length + entry_length;
            entries.push(entry.clone());
            emitted_position = Some(*position);
        }
        let next_cursor = if has_more || entries.len() < expanded.len() {
            let (run_ordinal, run_seq, entry_ordinal) =
                emitted_position.ok_or_else(ProtocolError::persistence_failed)?;
            boundary.last_run_ordinal = run_ordinal;
            boundary.last_run_seq = run_seq;
            boundary.last_entry_ordinal = entry_ordinal;
            Some(
                self.ledger_thread_projection_cursor(&request.thread_id, workspace, &boundary)
                    .map_err(|_| ProtocolError::persistence_failed())?,
            )
        } else {
            None
        };
        Ok(ThreadOpenPage {
            thread_id: request.thread_id,
            entries,
            next_cursor,
        })
    }
}
