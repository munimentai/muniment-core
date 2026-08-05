use crate::journal::thread_summaries::ThreadSummaryPage;
use crate::journal::RunJournal;
use crate::thread_ownership::subject_owns_first_run;

pub const MAX_THREAD_SUMMARY_CORE_PAGES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedThreadsError {
    InvalidLimit,
    ThreadSummariesUnavailable,
    ThreadOwnershipUnavailable,
}

pub fn newest_owned_workspace_thread(
    journal: &mut RunJournal,
    workspace: &str,
    subject: Option<&str>,
) -> Result<Option<String>, OwnedThreadsError> {
    let mut cursor = None;
    for _ in 0..MAX_THREAD_SUMMARY_CORE_PAGES {
        let page = journal
            .workspace_thread_summaries(workspace, 100, cursor.as_deref())
            .map_err(|_| OwnedThreadsError::ThreadSummariesUnavailable)?;
        for summary in page.summaries {
            if subject_owns_first_run(journal, &summary.thread_id, subject)
                .map_err(|_| OwnedThreadsError::ThreadOwnershipUnavailable)?
            {
                return Ok(Some(summary.thread_id));
            }
        }
        match page.next_cursor {
            Some(next_cursor) => cursor = Some(next_cursor),
            None => return Ok(None),
        }
    }
    Ok(None)
}

pub fn chat_thread_summaries_page(
    journal: &mut RunJournal,
    subject: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<ThreadSummaryPage, OwnedThreadsError> {
    if !(1..=100).contains(&limit) {
        return Err(OwnedThreadsError::InvalidLimit);
    }
    let mut summaries = Vec::with_capacity(limit);
    let mut next_cursor = cursor.map(str::to_owned);
    for _ in 0..MAX_THREAD_SUMMARY_CORE_PAGES {
        let page = journal
            .thread_summaries(limit - summaries.len(), next_cursor.as_deref())
            .map_err(|_| OwnedThreadsError::ThreadSummariesUnavailable)?;
        for summary in page.summaries {
            if subject_owns_first_run(journal, &summary.thread_id, subject)
                .map_err(|_| OwnedThreadsError::ThreadOwnershipUnavailable)?
            {
                summaries.push(summary);
            }
        }
        next_cursor = page.next_cursor;
        if summaries.len() == limit || next_cursor.is_none() {
            break;
        }
    }
    Ok(ThreadSummaryPage {
        summaries,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{EventEnvelope, EventPayload, Provenance};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn journal_file() -> PathBuf {
        std::env::temp_dir().join(format!("muniment-owned-threads-{}.sqlite3", Uuid::new_v4()))
    }

    fn append_thread(journal: &mut RunJournal, run_id: &str, actor_id: &str, recorded_at: String) {
        let event = EventEnvelope {
            event_id: Uuid::now_v7().to_string(),
            run_id: run_id.into(),
            run_seq: 1,
            event_type: "run.started".into(),
            event_version: 1,
            envelope_version: 1,
            recorded_at,
            occurred_at: None,
            correlation_id: None,
            causation_id: None,
            payload: EventPayload::Inline {
                payload_json: json!({}),
            },
            provenance: Provenance {
                source: "test".into(),
                source_version: "1".into(),
                actor_id: Some(actor_id.into()),
                device_id: None,
                rpc_request_id: None,
                capability_versions: None,
                extra: BTreeMap::new(),
            },
            extra: BTreeMap::new(),
        };
        journal.append_new_run("workspace", &event).unwrap();
    }

    #[test]
    fn returns_an_owned_thread() {
        let path = journal_file();
        let mut journal = RunJournal::open(&path).unwrap();
        append_thread(
            &mut journal,
            "01900000-0000-7000-8000-000000000001",
            "owner",
            "2026-08-05T00:00:00Z".into(),
        );

        let thread_id = newest_owned_workspace_thread(&mut journal, "workspace", Some("owner"))
            .unwrap()
            .unwrap();

        assert_eq!(
            subject_owns_first_run(&mut journal, &thread_id, Some("owner")),
            Ok(true)
        );
    }

    #[test]
    fn rejects_a_thread_owned_by_another_subject() {
        let path = journal_file();
        let mut journal = RunJournal::open(&path).unwrap();
        append_thread(
            &mut journal,
            "01900000-0000-7000-8000-000000000001",
            "other",
            "2026-08-05T00:00:00Z".into(),
        );

        assert_eq!(
            newest_owned_workspace_thread(&mut journal, "workspace", Some("owner")),
            Ok(None)
        );
    }

    #[test]
    fn walks_across_more_than_one_summary_page() {
        let path = journal_file();
        let mut journal = RunJournal::open(&path).unwrap();
        for index in 0..3 {
            append_thread(
                &mut journal,
                &format!("01900000-0000-7000-8000-{index:012x}"),
                if index == 2 { "owner" } else { "other" },
                format!("2026-08-05T00:00:0{}Z", 3 - index),
            );
        }

        let page = chat_thread_summaries_page(&mut journal, Some("owner"), 1, None).unwrap();

        assert_eq!(page.summaries.len(), 1);
        assert_eq!(
            subject_owns_first_run(&mut journal, &page.summaries[0].thread_id, Some("owner")),
            Ok(true)
        );
    }

    #[test]
    fn rejects_limits_outside_one_through_one_hundred() {
        let path = journal_file();
        let mut journal = RunJournal::open(&path).unwrap();

        assert_eq!(
            chat_thread_summaries_page(&mut journal, None, 0, None),
            Err(OwnedThreadsError::InvalidLimit)
        );
        assert_eq!(
            chat_thread_summaries_page(&mut journal, None, 101, None),
            Err(OwnedThreadsError::InvalidLimit)
        );
    }
}
