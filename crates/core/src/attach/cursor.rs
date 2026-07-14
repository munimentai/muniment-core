use std::collections::VecDeque;

use super::{Id, ProtocolError};

/// Hard caps keep every subscription bounded even when its caller chooses limits.
pub const MAX_RUN_STREAM_WINDOW_EVENTS: usize = 1_024;
pub const MAX_RUN_STREAM_WINDOW_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunStreamWindow {
    pub max_events: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCloseCode {
    InvalidCursor,
    InvalidArtifactCursor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamClose {
    pub code: StreamCloseCode,
    pub resumable: bool,
}

/// A closed, redacted failure which instructs the transport to close only this stream.
#[derive(Debug, Clone, PartialEq)]
pub struct RunStreamError {
    error: ProtocolError,
    close: StreamClose,
}

impl RunStreamError {
    fn invalid_cursor() -> Self {
        Self {
            error: ProtocolError::invalid_cursor(),
            close: StreamClose {
                code: StreamCloseCode::InvalidCursor,
                resumable: true,
            },
        }
    }

    pub fn error(&self) -> &ProtocolError {
        &self.error
    }

    pub fn close(&self) -> StreamClose {
        self.close
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEventAdmission {
    Sent,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutstandingEvent {
    run_seq: u64,
    projected_bytes: usize,
}

/// SQLite-free flow-control state for one `run.stream` subscription.
#[derive(Debug, Clone)]
pub struct RunStreamCursor {
    subscription_id: Id,
    run_id: Id,
    first_available_run_seq: u64,
    current_run_seq: u64,
    acknowledged_run_seq: u64,
    highest_sent_run_seq: u64,
    window: RunStreamWindow,
    outstanding_bytes: usize,
    outstanding: VecDeque<OutstandingEvent>,
}

impl RunStreamCursor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subscription_id: Id,
        run_id: Id,
        first_available_run_seq: u64,
        current_run_seq: u64,
        resume_after_run_seq: u64,
        max_events: usize,
        max_bytes: usize,
    ) -> Result<Self, RunStreamError> {
        let empty = first_available_run_seq == current_run_seq.saturating_add(1);
        let bounds_valid = first_available_run_seq > 0
            && (first_available_run_seq <= current_run_seq || empty)
            && resume_after_run_seq >= first_available_run_seq.saturating_sub(1)
            && resume_after_run_seq <= current_run_seq;
        let window_valid = max_events > 0
            && max_events <= MAX_RUN_STREAM_WINDOW_EVENTS
            && max_bytes > 0
            && max_bytes <= MAX_RUN_STREAM_WINDOW_BYTES;
        if !bounds_valid || !window_valid {
            return Err(RunStreamError::invalid_cursor());
        }
        Ok(Self {
            subscription_id,
            run_id,
            first_available_run_seq,
            current_run_seq,
            acknowledged_run_seq: resume_after_run_seq,
            highest_sent_run_seq: resume_after_run_seq,
            window: RunStreamWindow {
                max_events,
                max_bytes,
            },
            outstanding_bytes: 0,
            outstanding: VecDeque::with_capacity(max_events),
        })
    }

    pub fn subscription_id(&self) -> &Id {
        &self.subscription_id
    }
    pub fn run_id(&self) -> &Id {
        &self.run_id
    }
    pub fn first_available_run_seq(&self) -> u64 {
        self.first_available_run_seq
    }
    pub fn current_run_seq(&self) -> u64 {
        self.current_run_seq
    }
    pub fn acknowledged_run_seq(&self) -> u64 {
        self.acknowledged_run_seq
    }
    pub fn highest_sent_run_seq(&self) -> u64 {
        self.highest_sent_run_seq
    }
    pub fn window(&self) -> RunStreamWindow {
        self.window
    }
    pub fn outstanding_events(&self) -> usize {
        self.outstanding.len()
    }
    pub fn outstanding_bytes(&self) -> usize {
        self.outstanding_bytes
    }

    pub fn admit_event(
        &mut self,
        run_id: &Id,
        run_seq: u64,
        projected_bytes: usize,
    ) -> Result<RunEventAdmission, RunStreamError> {
        let next_run_seq = self.highest_sent_run_seq.checked_add(1);
        if run_id != &self.run_id || Some(run_seq) != next_run_seq {
            return Err(RunStreamError::invalid_cursor());
        }
        if self.outstanding.len() == self.window.max_events
            || projected_bytes > self.window.max_bytes.saturating_sub(self.outstanding_bytes)
        {
            return Ok(RunEventAdmission::Paused);
        }
        self.outstanding.push_back(OutstandingEvent {
            run_seq,
            projected_bytes,
        });
        self.outstanding_bytes += projected_bytes;
        self.highest_sent_run_seq = run_seq;
        self.current_run_seq = self.current_run_seq.max(run_seq);
        Ok(RunEventAdmission::Sent)
    }

    pub fn acknowledge(&mut self, through_run_seq: u64) -> Result<(), RunStreamError> {
        if through_run_seq < self.acknowledged_run_seq
            || through_run_seq > self.highest_sent_run_seq
        {
            return Err(RunStreamError::invalid_cursor());
        }
        if through_run_seq == self.acknowledged_run_seq {
            return Ok(());
        }
        while self
            .outstanding
            .front()
            .is_some_and(|event| event.run_seq <= through_run_seq)
        {
            let event = self.outstanding.pop_front().expect("front existed");
            self.outstanding_bytes -= event.projected_bytes;
        }
        self.acknowledged_run_seq = through_run_seq;
        Ok(())
    }
}
