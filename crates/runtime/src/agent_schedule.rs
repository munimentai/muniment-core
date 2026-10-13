//! Executes local agent routines through the same run boundaries as interactive work.
use crate::RuntimeAttachState;
use muniment_core::{
    agents,
    run_start::{RunAttachBoundaries, RunStartBoundaries},
};

impl RuntimeAttachState {
    pub(crate) fn check_agent_schedules(&self) -> Result<(), String> {
        self.check_agent_schedules_with(self.boundaries())
    }

    /// Checks persisted routines using a caller-selected runtime artifact.
    #[doc(hidden)]
    pub fn check_agent_schedules_with(
        &self,
        boundaries: crate::RuntimeAttachBoundaries,
    ) -> Result<(), String> {
        let profile = self.agent_profile();
        if muniment_core::home::configured_home(profile)
            .map_err(|e| e.to_string())?
            .is_none()
        {
            return Ok(());
        }
        let listing = agents::list(profile)?;
        // One local runtime executes one reply at a time. Due routines stay queued.
        for agent in listing.agents {
            let result = agents::with_state(profile, |state| {
                let agent = agents::get(profile, &agent.id)?;
                let mut run = state.runs.get(&agent.id).cloned().unwrap_or_default();
                let schedule_key = agents::schedule_key(&agent);
                if run.schedule_key.as_deref() != Some(&schedule_key) {
                    run.next_run = agent
                        .schedule
                        .as_ref()
                        .filter(|s| s.enabled)
                        .map(agents::next)
                        .transpose()?;
                    run.schedule_key = Some(schedule_key);
                    state.runs.insert(agent.id.clone(), run.clone());
                }
                if matches!(run.status.as_str(), "running" | "waiting") {
                    if let Some(id) = &run.run_id {
                        let events = self.agent_events(id)?;
                        let terminal = events.iter().rev().find(|e| {
                            matches!(
                                e.event_type.as_str(),
                                "run.completed" | "run.failed" | "run.cancelled"
                            )
                        });
                        if let Some(event) = terminal {
                            run.status = event.event_type.trim_start_matches("run.").into();
                        } else if boundaries.active_run_exists() {
                            run.status = if events
                                .iter()
                                .rev()
                                .find(|e| e.event_type.starts_with("permission."))
                                .is_some_and(|e| e.event_type == "permission.requested")
                            {
                                "waiting"
                            } else {
                                "running"
                            }
                            .into();
                        } else {
                            run.status = "interrupted".into();
                            run.error = Some("The runtime stopped before this run finished. Open its thread to review it.".into());
                        }
                    } else {
                        // An interrupted dispatch is never retried without review.
                        run.status = "interrupted".into();
                        run.error = Some("The run could not be confirmed. Review its thread before running it again.".into());
                    }
                    state.runs.insert(agent.id.clone(), run.clone());
                }
                let due = run.status == "queued"
                    || agent.schedule.as_ref().is_some_and(|s| s.enabled)
                        && run.next_run.is_some_and(|time| time <= agents::now());
                if !due || boundaries.active_run_exists() {
                    return Ok(());
                }
                let workspace = boundaries
                    .signed_workspace_approval()
                    .approval()
                    .map(|a| a.workspace)
                    .ok_or("Open Muniment and connect a model before running agents.")?;
                let thread = match agents::ensure_primary(state, &agent.id) {
                    Some(thread) => thread,
                    None => crate::service::create_thread(
                        self.agent_storage(),
                        workspace.clone(),
                        "desktop-owner".into(),
                    )?,
                };
                state
                    .primary_threads
                    .insert(agent.id.clone(), thread.clone());
                if let Some(project) = &agent.project_id {
                    muniment_core::projects::assign(profile, &thread, project)?;
                }
                muniment_core::projects::workspace(profile, &thread)?;
                // Persist the dispatch before launch. A restart reports uncertainty instead of repeating a side effect.
                state.threads.insert(thread.clone(), agent.id.clone());
                run.thread_id = Some(thread.clone());
                run.run_id = None;
                run.last_run = Some(agents::now());
                run.status = "running".into();
                run.error = None;
                run.next_run = agent
                    .schedule
                    .as_ref()
                    .filter(|s| s.enabled)
                    .map(agents::next)
                    .transpose()?;
                state.runs.insert(agent.id.clone(), run.clone());
                agents::persist_state(profile, state)?;
                match boundaries.submit_run(&workspace, "Carry out your saved agent instructions. Return the result and links to any files you create.".into(), Vec::new(), Some(thread)) {
                    Ok(accepted) => { run.run_id = Some(accepted.run_id); }
                    Err(error) => { run.status = "failed".into(); run.error = Some(error.into_message()); }
                }
                state.runs.insert(agent.id.clone(), run);
                Ok(())
            });
            if let Err(error) = result {
                agents::with_state(profile, |state| {
                    if !state.runs.contains_key(&agent.id) {
                        return Ok(());
                    }
                    let run = state.runs.get_mut(&agent.id).expect("existing run");
                    run.status = "failed".into();
                    run.error = Some(error);
                    run.next_run = agent
                        .schedule
                        .as_ref()
                        .filter(|s| s.enabled)
                        .map(agents::next)
                        .transpose()?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
}
