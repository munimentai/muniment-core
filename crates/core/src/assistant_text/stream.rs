//! Ordered run-event projection for assistant text streams.

use super::projector::{Projection, Projector, ProjectorError};
use serde_json::Value;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

/// The assistant text carried by an emittable event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssistantText {
    NotDelta,
    Released(String),
    Withheld,
}

/// One committed event that the run stream may now emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittableEvent {
    pub run_seq: u64,
    pub assistant_text: AssistantText,
}

/// Stable failures from run-stream projection input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    InvalidRunSequence,
    MissingDeltaText,
    Projector(ProjectorError),
}

impl From<ProjectorError> for StreamError {
    fn from(error: ProjectorError) -> Self {
        Self::Projector(error)
    }
}

#[derive(Debug)]
enum PendingEvent {
    Other(u64),
    Delta {
        run_seq: u64,
        projection: Option<Projection>,
    },
}

/// Projects one run's committed events while preserving their journal order.
pub struct RunStreamProjector<C> {
    projector: Projector<C>,
    pending: VecDeque<PendingEvent>,
    last_run_seq: u64,
    finished: bool,
}

impl<C> RunStreamProjector<C> {
    pub fn new(approved_workspace: impl Into<PathBuf>, canonicalize: C) -> Self {
        Self {
            projector: Projector::new(approved_workspace, canonicalize),
            pending: VecDeque::new(),
            last_run_seq: 0,
            finished: false,
        }
    }

    /// Consumes the next committed event and returns the newly emittable prefix.
    pub fn push<E>(
        &mut self,
        run_seq: u64,
        event_type: &str,
        payload: &Value,
    ) -> Result<Vec<EmittableEvent>, StreamError>
    where
        C: FnMut(&Path) -> Result<PathBuf, E>,
    {
        if self.finished {
            return Err(StreamError::Projector(ProjectorError::Finished));
        }
        if run_seq
            != self
                .last_run_seq
                .checked_add(1)
                .ok_or(StreamError::InvalidRunSequence)?
        {
            return Err(StreamError::InvalidRunSequence);
        }

        let projections = if event_type == "model.stream.delta" {
            let text = payload
                .get("text")
                .and_then(Value::as_str)
                .ok_or(StreamError::MissingDeltaText)?;
            let projections = self.projector.push(run_seq, text, payload)?;
            self.pending.push_back(PendingEvent::Delta {
                run_seq,
                projection: None,
            });
            projections
        } else {
            let projections = if is_terminal(event_type) {
                let projections = self.projector.finish()?;
                self.finished = true;
                projections
            } else {
                Vec::new()
            };
            self.pending.push_back(PendingEvent::Other(run_seq));
            projections
        };
        self.last_run_seq = run_seq;
        self.apply(projections)?;
        Ok(self.drain_emittable())
    }

    fn apply(&mut self, projections: Vec<Projection>) -> Result<(), StreamError> {
        for projection in projections {
            let Some(pending) = self.pending.iter_mut().find(|pending| {
                matches!(pending, PendingEvent::Delta { run_seq, .. } if *run_seq == projection.run_seq)
            }) else {
                return Err(StreamError::InvalidRunSequence);
            };
            let PendingEvent::Delta {
                projection: slot, ..
            } = pending
            else {
                unreachable!();
            };
            if slot.replace(projection).is_some() {
                return Err(StreamError::InvalidRunSequence);
            }
        }
        Ok(())
    }

    fn drain_emittable(&mut self) -> Vec<EmittableEvent> {
        let mut events = Vec::new();
        loop {
            let event = match self.pending.front() {
                Some(PendingEvent::Other(run_seq)) => EmittableEvent {
                    run_seq: *run_seq,
                    assistant_text: AssistantText::NotDelta,
                },
                Some(PendingEvent::Delta {
                    projection: Some(projection),
                    ..
                }) => EmittableEvent {
                    run_seq: projection.run_seq,
                    assistant_text: match &projection.text {
                        Some(text) => AssistantText::Released(text.clone()),
                        None => AssistantText::Withheld,
                    },
                },
                Some(PendingEvent::Delta {
                    projection: None, ..
                })
                | None => break,
            };
            self.pending.pop_front();
            events.push(event);
        }
        events
    }
}

fn is_terminal(event_type: &str) -> bool {
    matches!(event_type, "run.completed" | "run.cancelled" | "run.failed")
}
