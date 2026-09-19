use crate::journal::RunJournal;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadOwnershipError {
    ThreadRunsUnavailable(String),
    MissingFirstRun,
    FirstEnvelopeUnavailable(String),
}

pub fn subject_owns_first_run(
    journal: &mut RunJournal,
    thread_id: &str,
    subject: Option<&str>,
) -> Result<bool, ThreadOwnershipError> {
    let first_run = journal
        .thread_run_ids(thread_id, 1, None)
        .map_err(|error| ThreadOwnershipError::ThreadRunsUnavailable(format!("{error:?}")))?
        .run_ids
        .into_iter()
        .next();
    let Some(first_run) = first_run else {
        // Explicitly created chats can have no first reply yet. Use their
        // creation owner without treating broken run-backed threads as empty.
        let events = journal
            .thread_events(thread_id)
            .map_err(|error| ThreadOwnershipError::FirstEnvelopeUnavailable(error.to_string()))?;
        let created = events
            .first()
            .filter(|event| {
                event.event_type == "thread.created"
                    && event
                        .provenance
                        .extra
                        .get("attach_profile")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|profile| !profile.is_empty())
            })
            .ok_or(ThreadOwnershipError::MissingFirstRun)?;
        return Ok(!events
            .iter()
            .any(|event| event.event_type == "thread.deleted")
            && created.provenance.actor_id.as_deref() == subject);
    };
    let first = journal
        .first_envelope(&first_run)
        .map_err(|error| ThreadOwnershipError::FirstEnvelopeUnavailable(error.to_string()))?;
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
    use std::time::Duration;
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
        let mut journal =
            RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
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
    fn empty_explicit_threads_use_the_creation_owner_and_remain_readable() {
        for owner in [None, Some("owner")] {
            let path = journal_file();
            let mut journal =
                RunJournal::open_with_busy_timeout(&path, Duration::from_secs(60)).unwrap();
            let mut provenance = event(owner).provenance;
            provenance
                .extra
                .insert("attach_profile".into(), "desktop-owner".into());
            let thread_id = journal
                .create_thread("local", "2026-08-05T00:00:00Z", provenance)
                .unwrap();
            assert_eq!(
                subject_owns_first_run(&mut journal, &thread_id, owner),
                Ok(true)
            );
            assert_eq!(
                subject_owns_first_run(&mut journal, &thread_id, Some("other")),
                Ok(false)
            );
            let page =
                crate::owned_threads::chat_thread_summaries_page(&mut journal, owner, 20, None)
                    .unwrap();
            assert_eq!(page.summaries.len(), 1);
            #[cfg(feature = "keyring")]
            {
                let history = crate::thread_history::chat_thread_open_page(
                    &mut journal,
                    None,
                    owner,
                    path.parent().unwrap(),
                    &thread_id,
                    20,
                    None,
                )
                .unwrap();
                assert!(history.entries.is_empty());
            }
        }
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
