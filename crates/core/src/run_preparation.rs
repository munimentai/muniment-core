use std::collections::BTreeMap;

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::attachment::{ingest_attachment, AttachmentMetadata};
use crate::journal::reducer::ChatProjector;
use crate::journal::{EventEnvelope, EventPayload, JournalError, Provenance, RunJournal};
use crate::owned_threads::newest_owned_workspace_thread;
use crate::pi_execution::attachment_error;
use crate::run_events::{ChatStorage, SharedStorage};
use crate::session_thread::{OfferedThread, SessionThread};

pub struct OpenSelectedFile {
    pub file: std::fs::File,
    pub display_name: String,
    pub byte_length: u64,
}

#[derive(Clone, Copy)]
pub struct SessionThreadStart<'a> {
    pub tracker: &'a SessionThread,
    pub continue_existing: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_new_run_with_session_thread<F>(
    storage: &SharedStorage,
    session_thread: SessionThreadStart<'_>,
    run_id: &str,
    workspace: &str,
    subject: Option<&str>,
    files: Vec<OpenSelectedFile>,
    provenance: Option<Provenance>,
    source: &str,
    source_version: &str,
    after_validation: F,
) -> Result<(u64, ChatProjector), String>
where
    F: FnOnce() -> Result<(), String>,
{
    prepare_opened_run(
        storage,
        session_thread,
        run_id,
        workspace,
        subject,
        files,
        provenance,
        None,
        source,
        source_version,
        after_validation,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_new_run_in_thread_after_validation<F>(
    storage: &SharedStorage,
    run_id: &str,
    workspace: &str,
    subject: Option<&str>,
    files: Vec<OpenSelectedFile>,
    provenance: Option<Provenance>,
    thread_id: &str,
    source: &str,
    source_version: &str,
    after_validation: F,
) -> Result<(u64, ChatProjector), String>
where
    F: FnOnce() -> Result<(), String>,
{
    prepare_opened_run(
        storage,
        SessionThreadStart {
            tracker: &SessionThread::default(),
            continue_existing: false,
        },
        run_id,
        workspace,
        subject,
        files,
        provenance,
        Some(thread_id),
        source,
        source_version,
        after_validation,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_opened_run<F>(
    storage: &SharedStorage,
    session_thread: SessionThreadStart<'_>,
    run_id: &str,
    workspace: &str,
    subject: Option<&str>,
    files: Vec<OpenSelectedFile>,
    provenance: Option<Provenance>,
    requested_thread_id: Option<&str>,
    source: &str,
    source_version: &str,
    after_validation: F,
) -> Result<(u64, ChatProjector), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let mut storage = storage.lock().map_err(|_| attachment_error())?;
    let ChatStorage { journal, cas } = &mut *storage;
    let mut projector = ChatProjector::new();
    let mut seq = 1;
    let mut started = event_envelope(
        run_id,
        seq,
        "run.started",
        json!({}),
        subject,
        source,
        source_version,
    );
    if let Some(provenance) = provenance {
        started.provenance = Provenance {
            actor_id: provenance.actor_id.or_else(|| subject.map(str::to_owned)),
            ..provenance
        };
    }
    projector.apply(&started).map_err(|_| attachment_error())?;
    let mut after_validation = Some(after_validation);
    if !workspace.is_empty() {
        let thread_id = if let Some(thread_id) = requested_thread_id {
            journal
                .append_new_run_in_thread_after_validation(workspace, thread_id, &started, || {
                    after_validation.take().unwrap()()
                })
                .and_then(|result| result.map_err(|_| JournalError::Corrupt(attachment_error())))
                .map(|()| thread_id.to_owned())
        } else {
            after_validation.take().unwrap()()?;
            if session_thread.continue_existing {
                let offered = match session_thread.tracker.offered(workspace, subject) {
                    OfferedThread::AdoptNewest => {
                        newest_owned_workspace_thread(journal, workspace, subject)
                            .ok()
                            .flatten()
                    }
                    OfferedThread::Selected(thread_id) => Some(thread_id),
                    OfferedThread::Fresh => None,
                };
                match offered {
                    Some(thread_id) => journal
                        .append_new_run_in_thread(workspace, &thread_id, &started)
                        .map(|()| thread_id)
                        .or_else(|_| journal.append_new_run(workspace, &started)),
                    None => journal.append_new_run(workspace, &started),
                }
            } else {
                journal.append_new_run(workspace, &started)
            }
        }
        .map_err(|error| {
            if requested_thread_id.is_some() && matches!(error, JournalError::InvalidEnvelope(_)) {
                "thread_not_found".to_owned()
            } else {
                attachment_error()
            }
        })?;
        if session_thread.continue_existing {
            session_thread.tracker.record(thread_id, workspace, subject);
        }
    } else {
        after_validation.take().unwrap()()?;
        journal
            .append(0, &started)
            .map_err(|_| attachment_error())?;
    }

    for mut selected in files {
        let next_seq = seq + 1;
        let envelope_subject = subject.map(str::to_owned);
        let attachment = match ingest_attachment(
            cas,
            journal,
            seq,
            &mut selected.file,
            AttachmentMetadata {
                display_name: &selected.display_name,
                byte_length: selected.byte_length,
                media_type: None,
            },
            |attachment| {
                let mut envelope = event_envelope(
                    run_id,
                    next_seq,
                    "chat.attachment.ingested",
                    json!({}),
                    envelope_subject.as_deref(),
                    source,
                    source_version,
                );
                envelope.payload = EventPayload::Attachment { attachment };
                envelope
            },
        ) {
            Ok(attachment) => attachment,
            Err(_) => {
                record_preparation_failure(
                    journal,
                    &mut projector,
                    run_id,
                    seq,
                    subject,
                    source,
                    source_version,
                );
                return Err(attachment_error());
            }
        };
        let attachment_event = match journal
            .events(run_id)
            .ok()
            .and_then(|events| events.last().cloned())
        {
            Some(event) => event,
            None => {
                record_preparation_failure(
                    journal,
                    &mut projector,
                    run_id,
                    seq,
                    subject,
                    source,
                    source_version,
                );
                return Err(attachment_error());
            }
        };
        if projector.apply(&attachment_event).is_err() {
            record_preparation_failure(
                journal,
                &mut projector,
                run_id,
                seq,
                subject,
                source,
                source_version,
            );
            return Err(attachment_error());
        }
        seq = next_seq;
        if cas.verify(attachment.sha256()).is_err() {
            record_preparation_failure(
                journal,
                &mut projector,
                run_id,
                seq,
                subject,
                source,
                source_version,
            );
            return Err(attachment_error());
        }
    }
    Ok((seq, projector))
}

pub fn record_preparation_failure(
    journal: &mut RunJournal,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: u64,
    subject: Option<&str>,
    source: &str,
    source_version: &str,
) {
    let failed = event_envelope(
        run_id,
        seq + 1,
        "run.failed",
        json!({"reason": "attachment"}),
        subject,
        source,
        source_version,
    );
    if projector.apply(&failed).is_ok() {
        let _ = journal.append(seq, &failed);
    }
}

pub fn record_persistence_failure(
    journal: &mut RunJournal,
    projector: &mut ChatProjector,
    run_id: &str,
    seq: u64,
    subject: Option<&str>,
    source: &str,
    source_version: &str,
) {
    let failed = event_envelope(
        run_id,
        seq + 1,
        "run.failed",
        json!({"reason": "persistence"}),
        subject,
        source,
        source_version,
    );
    if projector.apply(&failed).is_ok() {
        let _ = journal.append(seq, &failed);
    }
}

pub fn append_prepared_run_persistence_failure(
    journal: &mut RunJournal,
    run_id: &str,
    seq: u64,
    subject: Option<&str>,
    source: &str,
    source_version: &str,
) -> Result<(), JournalError> {
    let failed = event_envelope(
        run_id,
        seq + 1,
        "run.failed",
        json!({"reason": "persistence"}),
        subject,
        source,
        source_version,
    );
    journal.append(seq, &failed)
}

pub fn event_envelope(
    run_id: &str,
    run_seq: u64,
    kind: &str,
    payload: Value,
    subject: Option<&str>,
    source: &str,
    source_version: &str,
) -> EventEnvelope {
    EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq,
        event_type: kind.into(),
        event_version: 1,
        envelope_version: 1,
        recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        occurred_at: None,
        correlation_id: None,
        causation_id: None,
        payload: EventPayload::Inline {
            payload_json: payload,
        },
        provenance: desktop_provenance(subject, source, source_version),
        extra: BTreeMap::new(),
    }
}

pub fn desktop_provenance(subject: Option<&str>, source: &str, source_version: &str) -> Provenance {
    Provenance {
        source: source.into(),
        source_version: source_version.into(),
        actor_id: subject.map(str::to_owned),
        device_id: None,
        rpc_request_id: None,
        capability_versions: None,
        extra: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_uses_the_supplied_desktop_values() {
        let provenance = desktop_provenance(Some("owner"), "muniment-desktop", "desktop-version");

        assert_eq!(provenance.source, "muniment-desktop");
        assert_eq!(provenance.source_version, "desktop-version");
        assert_eq!(provenance.actor_id.as_deref(), Some("owner"));
    }
}
