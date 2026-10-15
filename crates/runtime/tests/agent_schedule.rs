#![cfg(unix)]
use muniment_core::agents::{self, Agent};
use muniment_core::run_start::RunStartBoundaries;
use muniment_runtime_core::{RuntimeAttachState, RuntimeHost};
use std::time::{Duration, Instant};
mod common;

#[test]
fn queued_agent_runs_once_in_its_project_and_records_completion() {
    let temporary = common::TemporaryProfile::new("agent-schedule", false);
    let profile = &temporary.profile;
    muniment_core::home::confirm_home(profile, &temporary.root.join("muniment")).unwrap();
    std::fs::write(
        profile.join(muniment_core::local_mode::LOCAL_MODE_MARKER),
        "1",
    )
    .unwrap();
    common::use_test_prompt_store();
    let artifact = common::stage_pi_stub(profile);
    let arguments = temporary.root.join("arguments.txt");
    std::env::set_var("PI_RESUME_STUB_ARGS", &arguments);
    muniment_core::memory_files::profile_save(profile, "Call the user Alex.").unwrap();
    let project = muniment_core::projects::create(profile, "Briefs").unwrap();
    let agent = agents::save(
        profile,
        Agent {
            name: "Scout".into(),
            instructions: "Create a sourced brief.".into(),
            project_id: Some(project.clone()),
            ..Agent::default()
        },
    )
    .unwrap();
    agents::queue_run(profile, &agent.id).unwrap();
    assert!(agents::queue_run(profile, &agent.id).is_err());
    let state = RuntimeAttachState::open(RuntimeHost::default(), profile, profile).unwrap();
    state
        .check_agent_schedules_with(state.boundaries().with_pi_artifact(artifact))
        .unwrap();
    let accepted = agents::state(profile).unwrap().runs[&agent.id].clone();
    assert_eq!(accepted.status, "running", "{:?}", accepted.error);
    let thread = accepted.thread_id.as_ref().unwrap();
    assert_eq!(
        muniment_core::projects::workspace(profile, thread).unwrap(),
        muniment_core::projects::folder(profile, &project).unwrap()
    );
    assert_eq!(
        agents::thread_instructions(profile, thread).unwrap(),
        Some(agent.instructions)
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while state.boundaries().active_run_exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !state.boundaries().active_run_exists(),
        "the fixture run did not finish"
    );
    state
        .check_agent_schedules_with(state.boundaries().with_pi_artifact(artifact))
        .unwrap();
    let completed = agents::state(profile).unwrap().runs[&agent.id].clone();
    assert_eq!(completed.status, "completed", "{:?}", completed.error);
    assert_eq!(completed.run_id, accepted.run_id);
    assert_eq!(completed.thread_id, accepted.thread_id);
    agents::queue_run(profile, &agent.id).unwrap();
    state
        .check_agent_schedules_with(state.boundaries().with_pi_artifact(artifact))
        .unwrap();
    let second = agents::state(profile).unwrap().runs[&agent.id].clone();
    assert_eq!(second.thread_id, accepted.thread_id);
    assert_ne!(second.run_id, accepted.run_id);
    let deadline = Instant::now() + Duration::from_secs(30);
    while state.boundaries().active_run_exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    state
        .check_agent_schedules_with(state.boundaries().with_pi_artifact(artifact))
        .unwrap();
    let catalog = agents::state(profile).unwrap();
    assert_eq!(catalog.primary_threads[&agent.id], *thread);
    assert_eq!(catalog.history[&agent.id].len(), 2);
    assert!(catalog.history[&agent.id]
        .iter()
        .all(|run| run.status == "completed"));
    // A due routine outside a project uses its persistent agent workspace.
    let scheduled = agents::save(
        profile,
        Agent {
            name: "Daily scout".into(),
            instructions: "Prepare the daily brief.".into(),
            schedule: Some(agents::Schedule {
                enabled: true,
                cadence: "daily".into(),
                time: "09:00".into(),
                weekday: 0,
            }),
            ..Agent::default()
        },
    )
    .unwrap();
    agents::with_state(profile, |current| {
        current.runs.get_mut(&scheduled.id).unwrap().next_run = Some(agents::now() - 60);
        Ok(())
    })
    .unwrap();
    state
        .check_agent_schedules_with(state.boundaries().with_pi_artifact(artifact))
        .unwrap();
    let due = agents::state(profile).unwrap().runs[&scheduled.id].clone();
    assert_eq!(due.status, "running");
    let session =
        muniment_core::projects::workspace(profile, due.thread_id.as_ref().unwrap()).unwrap();
    assert_eq!(session, agents::folder(profile, &scheduled.id).unwrap());
    assert!(session.is_dir());
    assert!(due.next_run.unwrap() > agents::now());
    let deadline = Instant::now() + Duration::from_secs(30);
    while state.boundaries().active_run_exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    state
        .check_agent_schedules_with(state.boundaries().with_pi_artifact(artifact))
        .unwrap();
    assert_eq!(
        agents::state(profile).unwrap().runs[&scheduled.id].run_id,
        due.run_id
    );
    assert_eq!(
        agents::state(profile).unwrap().runs[&scheduled.id].status,
        "completed"
    );
    let mut paused = scheduled;
    paused.schedule.as_mut().unwrap().enabled = false;
    agents::save(profile, paused.clone()).unwrap();
    assert!(agents::state(profile).unwrap().runs[&paused.id]
        .next_run
        .is_none());
    let prompt = std::fs::read_to_string(&arguments).unwrap();
    assert!(prompt.contains("Prepare the daily brief."));
    assert!(prompt.contains("Call the user Alex."));
    assert!(prompt.contains("agent-save"));
    std::env::remove_var("PI_RESUME_STUB_ARGS");
    std::env::remove_var("MUNIMENT_PI_ROOT");
}
