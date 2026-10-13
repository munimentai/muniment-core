//! The runtime's view of each thread's context: the last usage read, a read
//! in progress, and the last manual compaction. A read can start the engine,
//! so it runs on its own thread and the attach answer never waits for it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{CompactionOutcome, ContextUsage};

/// A read younger than this answers without a new read.
const FRESH: Duration = Duration::from_secs(3);

/// The phase of a manual compaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionPhase {
    Running,
    Completed,
    Failed,
}

/// The last manual compaction of a thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionState {
    pub run_id: String,
    pub state: CompactionPhase,
    pub tokens_before: Option<u64>,
    pub estimated_tokens_after: Option<u64>,
    pub error: Option<String>,
}

/// What a context read answers: the `thread.context_usage` wire body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThreadContextSnapshot {
    /// The last usage read. `None` means no read finished, or the thread has
    /// no saved conversation yet.
    pub usage: Option<ContextUsage>,
    /// True while a read runs. The answer then carries the previous read.
    pub reading: bool,
    /// Why the last read failed.
    pub error: Option<String>,
    /// True while a manual compaction of the thread runs.
    pub compacting: bool,
    pub compaction: Option<CompactionState>,
}

#[derive(Default)]
struct ThreadContext {
    usage: Option<ContextUsage>,
    read_at: Option<Instant>,
    reading: bool,
    error: Option<String>,
    compaction: Option<CompactionState>,
}

impl ThreadContext {
    fn snapshot(&self) -> ThreadContextSnapshot {
        ThreadContextSnapshot {
            usage: self.usage.clone(),
            reading: self.reading,
            error: self.error.clone(),
            compacting: self
                .compaction
                .as_ref()
                .is_some_and(|compaction| compaction.state == CompactionPhase::Running),
            compaction: self.compaction.clone(),
        }
    }
}

/// Every thread's context, shared by the runtime's attach sessions.
#[derive(Clone, Default)]
pub struct ThreadContexts {
    threads: Arc<Mutex<BTreeMap<String, ThreadContext>>>,
}

impl ThreadContexts {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, thread_id: &str, step: impl FnOnce(&mut ThreadContext) -> T) -> T {
        let mut threads = self
            .threads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        step(threads.entry(thread_id.to_owned()).or_default())
    }

    /// Answers the thread's context. When the last read is not fresh and no
    /// read runs, `read` starts on its own thread, and the answer reports it.
    pub fn read(
        &self,
        thread_id: &str,
        read: impl FnOnce() -> Result<Option<ContextUsage>, String> + Send + 'static,
    ) -> ThreadContextSnapshot {
        let start = self.with(thread_id, |context| {
            let stale = context
                .read_at
                .is_none_or(|read_at| read_at.elapsed() >= FRESH);
            let start = stale && !context.reading;
            if start {
                context.reading = true;
            }
            start
        });
        if start {
            let contexts = self.clone();
            let thread = thread_id.to_owned();
            let spawned = std::thread::Builder::new()
                .name("thread-context-read".into())
                .spawn(move || {
                    let result = read();
                    contexts.with(&thread, |context| {
                        context.reading = false;
                        context.read_at = Some(Instant::now());
                        match result {
                            Ok(usage) => {
                                context.usage = usage;
                                context.error = None;
                            }
                            Err(error) => context.error = Some(error),
                        }
                    });
                });
            if spawned.is_err() {
                self.with(thread_id, |context| {
                    context.reading = false;
                    context.error = Some("The context usage could not be read.".into());
                });
            }
        }
        self.with(thread_id, |context| context.snapshot())
    }

    /// Whether a manual compaction of the thread runs.
    pub fn compacting(&self, thread_id: &str) -> bool {
        self.with(thread_id, |context| context.snapshot().compacting)
    }

    /// Records the start of a manual compaction. It refuses while another
    /// compaction of the thread runs.
    pub fn begin_compaction(&self, thread_id: &str, run_id: &str) -> Result<(), String> {
        self.with(thread_id, |context| {
            if context
                .compaction
                .as_ref()
                .is_some_and(|compaction| compaction.state == CompactionPhase::Running)
            {
                return Err("This thread is already compacting.".to_string());
            }
            context.compaction = Some(CompactionState {
                run_id: run_id.to_owned(),
                state: CompactionPhase::Running,
                tokens_before: None,
                estimated_tokens_after: None,
                error: None,
            });
            Ok(())
        })
    }

    /// Records how a manual compaction ended. The next read reads again.
    pub fn finish_compaction(
        &self,
        thread_id: &str,
        run_id: &str,
        result: Result<CompactionOutcome, String>,
    ) {
        self.with(thread_id, |context| {
            let Some(compaction) = context
                .compaction
                .as_mut()
                .filter(|compaction| compaction.run_id == run_id)
            else {
                return;
            };
            match result {
                Ok(outcome) => {
                    compaction.state = CompactionPhase::Completed;
                    compaction.tokens_before = Some(outcome.tokens_before);
                    compaction.estimated_tokens_after = outcome.estimated_tokens_after;
                }
                Err(error) => {
                    compaction.state = CompactionPhase::Failed;
                    compaction.error = Some(error);
                }
            }
            context.read_at = None;
        });
    }

    /// Marks the thread's last read stale, such as after a reply ends.
    pub fn invalidate(&self, thread_id: &str) {
        self.with(thread_id, |context| context.read_at = None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(tokens: u64) -> ContextUsage {
        ContextUsage {
            tokens: Some(tokens),
            context_window: Some(200_000),
            percent: Some(tokens as f64 / 2_000.0),
            estimated: false,
            window_known: true,
            provider: Some("local".into()),
            model: Some("model".into()),
            auto_compact: true,
            compact_at: Some(183_616),
        }
    }

    fn settled(contexts: &ThreadContexts, thread: &str) -> ThreadContextSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = contexts.read(thread, || panic!("a fresh read reads once"));
            if !snapshot.reading {
                return snapshot;
            }
            assert!(Instant::now() < deadline, "the read did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_read_runs_once_off_the_answer_and_a_fresh_one_answers_at_once() {
        let contexts = ThreadContexts::new();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let first = contexts.read("thread", move || {
            wait.recv().unwrap();
            Ok(Some(usage(60_000)))
        });
        assert!(first.reading);
        assert_eq!(first.usage, None);
        assert!(
            contexts
                .read("thread", || panic!("one read at a time"))
                .reading
        );
        release.send(()).unwrap();
        let snapshot = settled(&contexts, "thread");
        assert_eq!(snapshot.usage, Some(usage(60_000)));
        assert_eq!(snapshot.error, None);
        assert!(!snapshot.compacting);
    }

    #[test]
    fn a_failed_read_keeps_the_previous_usage_and_names_the_failure() {
        let contexts = ThreadContexts::new();
        contexts.read("thread", || Ok(Some(usage(1_000))));
        settled(&contexts, "thread");
        contexts.invalidate("thread");
        contexts.read("thread", || Err("The agent runtime is unavailable.".into()));
        let snapshot = settled(&contexts, "thread");
        assert_eq!(snapshot.usage, Some(usage(1_000)));
        assert_eq!(
            snapshot.error.as_deref(),
            Some("The agent runtime is unavailable.")
        );
    }

    #[test]
    fn a_compaction_refuses_a_second_start_and_reports_its_outcome() {
        let contexts = ThreadContexts::new();
        contexts.begin_compaction("thread", "run-1").unwrap();
        assert!(contexts.compacting("thread"));
        assert!(!contexts.compacting("other"));
        assert_eq!(
            contexts.begin_compaction("thread", "run-2").unwrap_err(),
            "This thread is already compacting."
        );
        contexts.read("thread", || Ok(None));
        assert!(settled(&contexts, "thread").compacting);
        contexts.finish_compaction("thread", "run-2", Err("ignored".into()));
        contexts.finish_compaction(
            "thread",
            "run-1",
            Ok(CompactionOutcome {
                tokens_before: 152_400,
                estimated_tokens_after: Some(31_900),
            }),
        );
        contexts.read("thread", || Ok(Some(usage(31_900))));
        let snapshot = settled(&contexts, "thread");
        assert!(!snapshot.compacting);
        assert_eq!(
            snapshot.compaction,
            Some(CompactionState {
                run_id: "run-1".into(),
                state: CompactionPhase::Completed,
                tokens_before: Some(152_400),
                estimated_tokens_after: Some(31_900),
                error: None,
            })
        );
        assert_eq!(snapshot.usage, Some(usage(31_900)));
        contexts.begin_compaction("thread", "run-3").unwrap();
        contexts.finish_compaction("thread", "run-3", Err("Nothing to compact".into()));
        let snapshot = contexts.read("thread", || Ok(None));
        assert_eq!(
            snapshot.compaction.unwrap().error.as_deref(),
            Some("Nothing to compact")
        );
    }
}
