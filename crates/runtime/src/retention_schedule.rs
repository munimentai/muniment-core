//! Periodic application of the recorded retention choice.

use std::sync::{mpsc, mpsc::Receiver, mpsc::Sender, Arc};
use std::time::Duration;

use crate::RuntimeAttachState;

/// A command to a running retention schedule.
pub enum RetentionScheduleCommand {
    /// Applies the recorded retention choice now.
    Recheck,
    /// Ends the schedule.
    Stop,
}

/// Applies the recorded retention choice at start and every `interval`, and
/// checks agent schedules between, until a stop arrives. `checked` hears each
/// retention pass. The schedule starts once the runtime owns its endpoint, so
/// it also starts the model router its record turns on and the web search
/// server, and stops both when it ends.
pub fn start_retention_schedule(
    state: Arc<RuntimeAttachState>,
    interval: Duration,
    commands: Receiver<RetentionScheduleCommand>,
    checked: Option<Sender<()>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        state.models().restore_router();
        state.models().restore_search();
        apply_recorded_retention(&state, checked.as_ref());
        let mut retention_checked_at = std::time::Instant::now();
        loop {
            if let Err(error) = state.check_agent_schedules() {
                eprintln!("agent_schedule: {error}");
            }
            match commands.recv_timeout(interval.min(Duration::from_secs(15))) {
                Ok(RetentionScheduleCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    state.models().stop();
                    break;
                }
                Ok(RetentionScheduleCommand::Recheck) => {
                    apply_recorded_retention(&state, checked.as_ref());
                    retention_checked_at = std::time::Instant::now();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if retention_checked_at.elapsed() >= interval {
                        apply_recorded_retention(&state, checked.as_ref());
                        retention_checked_at = std::time::Instant::now();
                    }
                }
            }
        }
    })
}

fn apply_recorded_retention(state: &RuntimeAttachState, checked: Option<&Sender<()>>) {
    let _ = state.apply_recorded_retention();
    if let Some(checked) = checked {
        let _ = checked.send(());
    }
}
