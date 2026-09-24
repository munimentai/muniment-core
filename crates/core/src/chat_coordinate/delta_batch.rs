//! Text-delta batching for the coordinate loop.
//!
//! The loop holds model text for at most one window and commits it as one
//! journal transaction. Every other event flushes the held text first, so the
//! journal order matches the stream order and each gate, effect and receipt
//! commits at once.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::code_diff_journal::{load_applied_code_diffs_cached, load_pending_code_diff_cached};
use crate::journal::reducer::ChatProjector;
use crate::journal::{EventEnvelope, EventPayload};
use crate::run_events::{
    chat_event, event_envelope, subscription_generation, text_delta, ChatEventSink, ChatStorage,
    SharedStorage,
};

/// The longest a text delta waits for its commit and delivery.
pub(super) const DELTA_WINDOW: Duration = Duration::from_millis(50);
/// A burst this long commits without waiting for the window.
const MAX_HELD_DELTAS: usize = 256;

/// Model text deltas that wait for one batched commit.
#[derive(Default)]
pub(super) struct HeldDeltas {
    payloads: Vec<Value>,
    since: Option<Instant>,
}

impl HeldDeltas {
    pub(super) fn push(&mut self, payload: Value) {
        if self.payloads.is_empty() {
            self.since = Some(Instant::now());
        }
        self.payloads.push(payload);
    }

    /// True when the held text has waited its window or fills a batch.
    pub(super) fn due(&self) -> bool {
        self.payloads.len() >= MAX_HELD_DELTAS
            || self
                .since
                .is_some_and(|since| since.elapsed() >= DELTA_WINDOW)
    }

    /// Bounds a wait for the next stream event so held text commits within
    /// its window.
    pub(super) fn wait_bound(&self, wait: Duration) -> Duration {
        match self.since {
            Some(since) => wait
                .min(DELTA_WINDOW.saturating_sub(since.elapsed()))
                .max(Duration::from_millis(1)),
            None => wait,
        }
    }

    /// Commits the held deltas in one transaction and delivers them as one
    /// chat event: a text delta when the run's delivery allows one, else the
    /// whole state. On failure nothing commits and `seq` and `projector` keep
    /// the last committed state.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn flush(
        &mut self,
        sink: &impl ChatEventSink,
        storage: &SharedStorage,
        projector: &mut ChatProjector,
        run_id: &str,
        seq: &mut u64,
        subject: Option<&str>,
    ) -> Result<(), ()> {
        if self.payloads.is_empty() {
            return Ok(());
        }
        self.since = None;
        let committed = *seq;
        let envelopes: Vec<_> = std::mem::take(&mut self.payloads)
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                event_envelope(
                    sink,
                    run_id,
                    committed + 1 + index as u64,
                    "model.stream.delta",
                    payload,
                    subject,
                )
            })
            .collect();
        let event = {
            let mut storage = storage.lock().map_err(|_| ())?;
            let text_start = projector.text_utf16_len();
            // Text deltas change only the text and the reducer state, so one
            // checkpoint before the first delta restores the whole batch.
            let checkpoint = projector.checkpoint(&envelopes[0]);
            let applied = envelopes
                .iter()
                .try_for_each(|envelope| projector.apply(envelope))
                .map_err(|_| ())
                .and_then(|()| {
                    storage
                        .journal
                        .append_batch(committed, &envelopes)
                        .map_err(|_| ())
                });
            if applied.is_err() {
                projector.restore(checkpoint);
                return Err(());
            }
            *seq = committed + envelopes.len() as u64;
            let generation = subscription_generation();
            match text_delta(projector, &joined(&envelopes), text_start, generation) {
                Some(event) => event,
                None => {
                    let projection = projector.projection().map_err(|_| ())?;
                    let gate = projection.pending_permission.clone();
                    let ChatStorage { journal, cas } = &mut *storage;
                    let code_diff = load_pending_code_diff_cached(
                        journal,
                        cas,
                        run_id,
                        &gate,
                        &mut projector.code_diffs,
                    );
                    let applied_diffs = load_applied_code_diffs_cached(
                        journal,
                        cas,
                        run_id,
                        projection.applied_diffs.clone(),
                        &mut projector.code_diffs,
                    );
                    projector.delivery.delivered_snapshot(generation);
                    chat_event(run_id, projection, code_diff, applied_diffs)
                }
            }
        };
        sink.deliver(event)
    }
}

/// One delta envelope that carries the batch's joined text, for delivery only.
fn joined(envelopes: &[EventEnvelope]) -> EventEnvelope {
    let text: String = envelopes
        .iter()
        .filter_map(|envelope| match &envelope.payload {
            EventPayload::Inline { payload_json } => payload_json.get("text")?.as_str(),
            _ => None,
        })
        .collect();
    let mut last = envelopes[envelopes.len() - 1].clone();
    last.payload = EventPayload::Inline {
        payload_json: serde_json::json!({ "text": text }),
    };
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::LocalCas;
    use crate::journal::RunJournal;
    use crate::run_events::{ChatEvent, ChatStorage};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct Recorder(Mutex<Vec<ChatEvent>>);

    impl ChatEventSink for Recorder {
        fn provenance(&self) -> (&str, &str) {
            ("delta-batch-test", "1")
        }

        fn deliver(&self, event: ChatEvent) -> Result<(), ()> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[test]
    fn held_deltas_commit_in_one_transaction_in_stream_order() {
        let root = std::env::temp_dir().join(format!("delta-batch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let storage: SharedStorage = Arc::new(Mutex::new(ChatStorage {
            journal: RunJournal::open(root.join("runs.sqlite3")).unwrap(),
            cas: LocalCas::open(&root.join("cas")).unwrap(),
        }));
        let sink = Recorder(Mutex::new(Vec::new()));
        let run_id = uuid::Uuid::now_v7().to_string();
        let mut projector = ChatProjector::new();
        let started = event_envelope(&sink, &run_id, 1, "run.started", json!({}), None);
        storage
            .lock()
            .unwrap()
            .journal
            .append_new_run("local", &started)
            .unwrap();
        projector.apply(&started).unwrap();
        let mut seq = 1;
        let mut subscription = storage
            .lock()
            .unwrap()
            .journal
            .subscribe_commits(&run_id)
            .unwrap();

        let mut held = HeldDeltas::default();
        assert!(!held.due());
        for text in ["Hel", "lo ", "world"] {
            held.push(json!({ "text": text }));
        }
        assert!(held.wait_bound(Duration::from_millis(100)) <= DELTA_WINDOW);
        held.flush(&sink, &storage, &mut projector, &run_id, &mut seq, None)
            .unwrap();

        assert_eq!(seq, 4);
        let hint = subscription.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(hint.run_seq, 4);
        assert!(subscription.try_recv().is_err());
        let events = storage.lock().unwrap().journal.events(&run_id).unwrap();
        let seqs: Vec<_> = events.iter().map(|event| event.run_seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4]);
        let delivered = sink.0.lock().unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].text, "Hello world");
        drop(delivered);

        // A later append sees the committed sequence.
        held.flush(&sink, &storage, &mut projector, &run_id, &mut seq, None)
            .unwrap();
        assert_eq!(seq, 4);
        subscription = storage
            .lock()
            .unwrap()
            .journal
            .subscribe_commits(&run_id)
            .unwrap();
        assert_eq!(subscription.committed_high_water, 4);
        drop(subscription);
        drop(storage);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_full_burst_is_due_before_its_window() {
        let mut held = HeldDeltas::default();
        for _ in 0..MAX_HELD_DELTAS {
            held.push(json!({ "text": "x" }));
        }
        assert!(held.due());
    }
}
