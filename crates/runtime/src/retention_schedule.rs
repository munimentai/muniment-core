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

/// How often a runtime asks the model vault for fresh leases.
const VAULT_LEASE_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Keeps the model vault's leases fresh while the runtime runs: at once, then
/// every five minutes. A runtime that reads no vault makes no call.
fn start_vault_leases(state: std::sync::Weak<RuntimeAttachState>) {
    std::thread::spawn(move || loop {
        let Some(live) = state.upgrade() else {
            return;
        };
        let agent = live.models().agent_directory().to_path_buf();
        if let Err(error) =
            muniment_core::shared_models::refresh_vault_leases(&agent, || live.cloud_session())
        {
            eprintln!("model_vault: {error}");
        }
        drop(live);
        std::thread::sleep(VAULT_LEASE_INTERVAL);
    });
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
        let models = Arc::downgrade(state.models());
        muniment_core::shared_models::set_on_change(move || {
            if let Some(models) = models.upgrade() {
                models.apply_router();
            }
        });
        state.models().restore_search();
        start_vault_leases(Arc::downgrade(&state));
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
