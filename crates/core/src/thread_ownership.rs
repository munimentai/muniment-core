use crate::journal::RunJournal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadOwnershipError {
    ThreadRunsUnavailable,
    MissingFirstRun,
    FirstEnvelopeUnavailable,
}

pub fn subject_owns_first_run(
    journal: &mut RunJournal,
    thread_id: &str,
    subject: Option<&str>,
) -> Result<bool, ThreadOwnershipError> {
    let first_run = journal
        .thread_run_ids(thread_id, 1, None)
        .map_err(|_| ThreadOwnershipError::ThreadRunsUnavailable)?
        .run_ids
        .into_iter()
        .next()
        .ok_or(ThreadOwnershipError::MissingFirstRun)?;
    let first = journal
        .first_envelope(&first_run)
        .map_err(|_| ThreadOwnershipError::FirstEnvelopeUnavailable)?;
    Ok(!matches!(
        first.provenance.actor_id.as_deref(),
        Some(owner) if Some(owner) != subject
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{EventEnvelope, EventPayload, Provenance};
    use rusqlite::Connection;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn journal_file() -> PathBuf {
        std::env::temp_dir().join(format!(
            "muniment-thread-ownership-{}.sqlite3",
            Uuid::new_v4()
        ))
    }

    fn event(actor_id: Option<&str>) -> EventEnvelope {
        EventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            run_id: Uuid::now_v7().to_string(),
            run_seq: 1,
            event_type: "run.started".into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at: "2026-08-05T00:00:00Z".into(),
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: json!({}),
            },
            provenance: Provenance {
                source: "test".into(),
                source_version: "1".into(),
                actor_id: actor_id.map(str::to_owned),
                device_id: None,
                rpc_request_id: None,
                capability_versions: None,
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        }
    }

    fn journal_with_thread(actor_id: Option<&str>) -> (PathBuf, RunJournal, String) {
        let path = journal_file();
        let mut journal = RunJournal::open(&path).unwrap();
        let event = event(actor_id);
        journal.append_new_run("workspace", &event).unwrap();
        let thread_id = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT thread_id FROM run_threads WHERE run_id=?1",
                [&event.run_id],
                |row| row.get(0),
            )
            .unwrap();
        (path, journal, thread_id)
    }

    #[test]
    fn accepts_subject_owned_thread() {
        let (_path, mut journal, thread_id) = journal_with_thread(Some("owner"));
        assert_eq!(
            subject_owns_first_run(&mut journal, &thread_id, Some("owner")),
            Ok(true)
        );
    }

    #[test]
    fn rejects_another_subjects_thread() {
        let (_path, mut journal, thread_id) = journal_with_thread(Some("owner"));
        assert_eq!(
            subject_owns_first_run(&mut journal, &thread_id, Some("other")),
            Ok(false)
        );
    }

    #[test]
    fn accepts_unowned_first_envelope() {
        let (_path, mut journal, thread_id) = journal_with_thread(None);
        assert_eq!(
            subject_owns_first_run(&mut journal, &thread_id, Some("subject")),
            Ok(true)
        );
    }

    #[test]
    fn rejects_thread_with_no_run() {
        let (path, mut journal, thread_id) = journal_with_thread(None);
        Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM run_threads WHERE thread_id=?1", [&thread_id])
            .unwrap();
        assert_eq!(
            subject_owns_first_run(&mut journal, &thread_id, None),
            Err(ThreadOwnershipError::MissingFirstRun)
        );
    }
}
