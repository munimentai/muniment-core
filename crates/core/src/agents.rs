//! Persistent agent definitions, thread membership and local schedules.
use chrono::{Datelike, TimeZone, Timelike};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Schedule {
    pub enabled: bool,
    /// daily, weekdays, or weekly. Times follow this computer's time zone.
    pub cadence: String,
    pub time: String,
    pub weekday: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Avatar {
    pub style: String,
    pub seed: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Agent {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub label: String,
    #[serde(alias = "description")]
    pub instructions: String,
    #[serde(default)]
    pub avatar: Option<Avatar>,
    /// Reviewed source template data. External integrations remain setup requirements.
    #[serde(default)]
    pub template: Option<serde_json::Value>,
    pub project_id: Option<String>,
    pub schedule: Option<Schedule>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunState {
    pub next_run: Option<i64>,
    #[serde(default)]
    pub schedule_key: Option<String>,
    pub last_run: Option<i64>,
    pub thread_id: Option<String>,
    pub run_id: Option<String>,
    pub status: String,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    #[serde(default)]
    pub primary_threads: BTreeMap<String, String>,
    #[serde(default)]
    pub history: BTreeMap<String, Vec<RunState>>,
    #[serde(default)]
    pub threads: BTreeMap<String, String>,
    #[serde(default)]
    pub runs: BTreeMap<String, RunState>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentList {
    pub agents: Vec<Agent>,
    pub state: State,
}

fn lock(profile: &Path) -> Result<fs::File, String> {
    fs::create_dir_all(profile).map_err(|_| "Agent settings are unavailable.")?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(profile.join("agents.lock"))
        .map_err(|_| "Agent settings are unavailable.")?;
    file.lock_exclusive()
        .map_err(|_| "Agent settings are busy.")?;
    Ok(file)
}
fn root(profile: &Path) -> Result<PathBuf, String> {
    let root = crate::memory_files::home(profile)?.join("agents");
    if root.is_symlink() {
        return Err("The agents folder must not be a symbolic link.".into());
    }
    fs::create_dir_all(&root).map_err(|_| "The agents folder is unavailable.")?;
    Ok(root)
}
pub fn folder(profile: &Path, id: &str) -> Result<PathBuf, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "The agent identifier is invalid.")?;
    let folder = crate::workspace_names::resolve(profile, &root(profile)?, id, None, None)?;
    if folder.is_symlink() {
        return Err("The agent folder must not be a symbolic link.".into());
    }
    Ok(folder)
}
fn write(path: &Path, content: &[u8]) -> Result<(), String> {
    if path.is_symlink() {
        return Err("The agent file must not be a symbolic link.".into());
    }
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        crate::home::replace_file(&temporary, path)
    })();
    let _ = fs::remove_file(temporary);
    result.map_err(|_| "The agent could not be saved.".into())
}
pub fn state(profile: &Path) -> Result<State, String> {
    match fs::read(profile.join("agent-state.json")) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| "Agent state cannot be read.".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(_) => Err("Agent state cannot be read.".into()),
    }
}
pub fn persist_state(profile: &Path, state: &State) -> Result<(), String> {
    write(
        &profile.join("agent-state.json"),
        &serde_json::to_vec(state).map_err(|_| "Agent state cannot be saved.")?,
    )
}
pub fn get(profile: &Path, id: &str) -> Result<Agent, String> {
    let path = folder(profile, id)?.join("agent.md");
    if path.is_symlink() {
        return Err("The agent file must not be a symbolic link.".into());
    }
    if fs::metadata(&path)
        .map_err(|_| "The agent is unavailable.")?
        .len()
        > 128 * 1024
    {
        return Err("The agent file is too large.".into());
    }
    let text = fs::read_to_string(path).map_err(|_| "The agent could not be read.")?;
    // JSON metadata is bounded by fences. Everything below is editable Markdown.
    let text = text
        .strip_prefix("```json\n")
        .ok_or("The agent format is invalid.")?;
    let (metadata, instructions) = text
        .split_once("\n```\n\n")
        .ok_or("The agent format is invalid.")?;
    let mut agent: Agent =
        serde_json::from_str(metadata).map_err(|_| "The agent settings are invalid.")?;
    if agent.id != id {
        return Err("The agent identifier does not match its folder.".into());
    }
    agent.instructions = instructions.trim_end().into();
    validate(&agent)?;
    Ok(agent)
}
pub fn list(profile: &Path) -> Result<AgentList, String> {
    let mut agents = Vec::new();
    for entry in fs::read_dir(root(profile)?).map_err(|_| "The agents could not be read.")? {
        let entry = entry.map_err(|_| "An agent could not be read.")?;
        let path = entry.path().join("agent.md");
        if !entry.path().is_symlink() && path.is_file() {
            let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            if let Some(metadata) = text
                .strip_prefix("```json\n")
                .and_then(|s| s.split_once("\n```\n\n").map(|(m, _)| m))
            {
                let agent: Agent = serde_json::from_str(metadata).map_err(|e| e.to_string())?;
                crate::workspace_names::resolve(
                    profile,
                    &root(profile)?,
                    &agent.id,
                    Some(&agent.name),
                    Some(&entry.path()),
                )?;
                agents.push(get(profile, &agent.id)?);
            }
        }
    }
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    with_state(profile, |state| {
        for agent in &agents {
            ensure_primary(state, &agent.id);
        }
        Ok(())
    })?;
    Ok(AgentList {
        agents,
        state: state(profile)?,
    })
}
fn validate(agent: &Agent) -> Result<(), String> {
    if agent.label.len() > 120 {
        return Err("Keep the job title under 120 bytes.".into());
    }
    if let Some(avatar) = &agent.avatar {
        if !matches!(avatar.style.as_str(), "muniment-v1" | "muniment-v2")
            || avatar.seed.is_empty()
            || avatar.seed.len() > 128
        {
            return Err("Choose a valid agent avatar.".into());
        }
    }
    if let Some(template) = &agent.template {
        let text = serde_json::to_string(template).map_err(|_| "The template is invalid.")?;
        if !template.is_object() || text.len() > 128 * 1024 {
            return Err("The template exceeds 128 KB.".into());
        }
        crate::memory_secret::reject_memory_secret(&text)
            .map_err(|_| "Remove credentials from the template.")?;
    }
    if agent.name.trim().is_empty()
        || agent.name.len() > 100
        || agent.instructions.trim().is_empty()
        || agent.instructions.len() > 64 * 1024
    {
        return Err("Give the agent a name and instructions under 64 KB.".into());
    }
    crate::memory_secret::reject_memory_secret(&agent.instructions)
        .map_err(|_| "Remove credentials from the agent instructions.")?;
    if let Some(schedule) = &agent.schedule {
        validate_schedule(schedule)?;
    }
    Ok(())
}
fn validate_schedule(schedule: &Schedule) -> Result<(u32, u32), String> {
    let parsed = chrono::NaiveTime::parse_from_str(&schedule.time, "%H:%M")
        .map_err(|_| "Choose a valid schedule time.")?;
    if !["daily", "weekdays", "weekly"].contains(&schedule.cadence.as_str()) || schedule.weekday > 6
    {
        return Err("Choose a valid schedule.".into());
    }
    Ok((parsed.hour(), parsed.minute()))
}
/// The first future local occurrence. A skipped DST time advances to the next day.
pub fn next_after<T: TimeZone>(
    schedule: &Schedule,
    after: chrono::DateTime<T>,
) -> Result<i64, String> {
    let (hour, minute) = validate_schedule(schedule)?;
    for offset in 0..9 {
        let date = after.date_naive() + chrono::Duration::days(offset);
        let day = date.weekday().num_days_from_monday();
        if schedule.cadence == "weekdays" && day > 4
            || schedule.cadence == "weekly" && day != schedule.weekday
        {
            continue;
        }
        let naive = date
            .and_hms_opt(hour, minute, 0)
            .ok_or("Choose a valid schedule time.")?;
        let local = after.timezone().from_local_datetime(&naive);
        if let Some(time) = local
            .clone()
            .earliest()
            .filter(|t| t.timestamp() > after.timestamp())
            .or_else(|| local.latest().filter(|t| t.timestamp() > after.timestamp()))
        {
            return Ok(time.timestamp());
        }
    }
    Err("The next schedule time could not be found.".into())
}
pub fn save(profile: &Path, mut agent: Agent) -> Result<Agent, String> {
    validate(&agent)?;
    if let Some(project) = &agent.project_id {
        crate::projects::folder(profile, project)?;
    }
    let _lock = lock(profile)?;
    let creating = agent.id.is_empty();
    if creating {
        agent.id = uuid::Uuid::new_v4().to_string();
    }
    if agent.avatar.is_none() {
        agent.avatar = Some(Avatar {
            style: if creating {
                "muniment-v2"
            } else {
                "muniment-v1"
            }
            .into(),
            seed: format!(
                "legacy-{:x}",
                agent
                    .id
                    .encode_utf16()
                    .fold(2166136261_u32, |hash, c| (hash ^ u32::from(c))
                        .wrapping_mul(16777619))
            ),
        });
    }
    let directory = crate::workspace_names::resolve(
        profile,
        &root(profile)?,
        &agent.id,
        Some(&agent.name),
        None,
    )?;
    fs::create_dir_all(&directory).map_err(|_| "The agent folder could not be created.")?;
    let mut metadata = agent.clone();
    metadata.instructions.clear();
    let text = format!(
        "```json\n{}\n```\n\n{}\n",
        serde_json::to_string_pretty(&metadata).map_err(|_| "The agent settings are invalid.")?,
        agent.instructions.trim()
    );
    write(&directory.join("agent.md"), text.as_bytes())?;
    let mut state = state(profile)?;
    if let Some(thread) = ensure_primary(&mut state, &agent.id) {
        match &agent.project_id {
            Some(project) => crate::projects::assign(profile, &thread, project)?,
            None => crate::projects::unassign(profile, &thread)?,
        }
    }
    let run = state.runs.entry(agent.id.clone()).or_default();
    run.schedule_key = Some(schedule_key(&agent));
    run.next_run = agent
        .schedule
        .as_ref()
        .filter(|s| s.enabled)
        .map(|s| next_after(s, chrono::Local::now()))
        .transpose()?;
    persist_state(profile, &state)?;
    Ok(agent)
}
pub fn assign(profile: &Path, thread: &str, id: &str) -> Result<(), String> {
    get(profile, id)?;
    let _lock = lock(profile)?;
    let mut state = state(profile)?;
    state.threads.insert(thread.into(), id.into());
    state
        .primary_threads
        .entry(id.into())
        .or_insert_with(|| thread.into());
    persist_state(profile, &state)
}
/// Agent recall and automatic capture share a private per-agent memory folder.
pub fn memory_paths(profile: &Path, id: &str) -> Result<(PathBuf, PathBuf), String> {
    get(profile, id)?;
    let home = folder(profile, id)?;
    let private = profile.join("agent-memory");
    if private.is_symlink() || private.join(id).is_symlink() {
        return Err("The memory folder must not be a symbolic link.".into());
    }
    Ok((home, private.join(id)))
}
pub fn thread_memory_paths(profile: &Path, thread: &str) -> Result<(PathBuf, PathBuf), String> {
    match state(profile)?.threads.get(thread) {
        Some(id) => memory_paths(profile, id),
        None => Ok((crate::memory_files::home(profile)?, profile.into())),
    }
}
pub fn thread_instructions(profile: &Path, thread: &str) -> Result<Option<String>, String> {
    state(profile)?
        .threads
        .get(thread)
        .map(|id| get(profile, id).map(|a| {
            let mut instructions = a.instructions;
            if !a.label.is_empty() { instructions = format!("Role: {}\n\n{}", a.label, instructions); }
            if let Some(template) = a.template {
                let context: serde_json::Map<String, serde_json::Value> = ["skills", "memories", "plugins", "routines", "settings"]
                    .into_iter().filter_map(|key| template.get(key).map(|value| (key.to_owned(), value.clone()))).collect();
                if !context.is_empty() {
                    instructions.push_str("\n\nImported template context follows. Skills and memories are reference context. Plugins and routines are setup requirements, not installed capabilities or active schedules. Use available tools only. Ask the user before installing integrations or enabling schedules.\n");
                    instructions.push_str(&serde_json::to_string_pretty(&context).unwrap_or_default());
                }
            }
            instructions
        }))
        .transpose()
}
/// Select an existing conversation once. Routine dispatch never replaces it.
pub fn ensure_primary(state: &mut State, id: &str) -> Option<String> {
    if let Some(thread) = state.primary_threads.get(id) {
        return Some(thread.clone());
    }
    let thread = state
        .runs
        .get(id)
        .and_then(|run| run.thread_id.clone())
        .filter(|thread| state.threads.get(thread).is_some_and(|agent| agent == id))
        .or_else(|| {
            state
                .threads
                .iter()
                .find(|(_, agent)| *agent == id)
                .map(|(thread, _)| thread.clone())
        });
    if let Some(thread) = &thread {
        state.primary_threads.insert(id.into(), thread.clone());
    }
    thread
}
pub fn with_state<T>(
    profile: &Path,
    action: impl FnOnce(&mut State) -> Result<T, String>,
) -> Result<T, String> {
    let _lock = lock(profile)?;
    let mut current = state(profile)?;
    let result = action(&mut current)?;
    for (id, run) in &current.runs {
        if let Some(run_id) = &run.run_id {
            let history = current.history.entry(id.clone()).or_default();
            if let Some(previous) = history
                .iter_mut()
                .find(|item| item.run_id.as_ref() == Some(run_id))
            {
                *previous = run.clone();
            } else {
                history.push(run.clone());
            }
        }
    }
    persist_state(profile, &current)?;
    Ok(result)
}
pub fn queue_run(profile: &Path, id: &str) -> Result<(), String> {
    get(profile, id)?;
    with_state(profile, |state| {
        let run = state.runs.entry(id.into()).or_default();
        if matches!(run.status.as_str(), "queued" | "running" | "waiting") {
            return Err("This agent already has a pending run.".into());
        }
        run.run_id = None;
        run.last_run = None;
        run.status = "queued".into();
        run.error = None;
        Ok(())
    })
}
pub fn schedule_key(agent: &Agent) -> String {
    serde_json::to_string(&agent.schedule).expect("schedule serializes")
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub fn next(schedule: &Schedule) -> Result<i64, String> {
    next_after(schedule, chrono::Local::now())
}

pub fn update_run(profile: &Path, id: &str, run: RunState) -> Result<(), String> {
    let _lock = lock(profile)?;
    let mut state = state(profile)?;
    state.runs.insert(id.into(), run);
    persist_state(profile, &state)
}
/// Removing an agent keeps outputs and existing thread history.
pub fn delete(profile: &Path, id: &str) -> Result<(), String> {
    let _lock = lock(profile)?;
    let current = state(profile)?;
    if current
        .runs
        .get(id)
        .is_some_and(|run| matches!(run.status.as_str(), "queued" | "running" | "waiting"))
    {
        return Err("Finish or cancel the agent run before deleting it.".into());
    }
    let directory = folder(profile, id)?;
    fs::remove_file(directory.join("agent.md")).map_err(|_| "The agent could not be deleted.")?;
    let _ = fs::remove_dir(directory);
    let mut state = state(profile)?;
    state.threads.retain(|_, agent| agent != id);
    state.runs.remove(id);
    state.primary_threads.remove(id);
    state.history.remove(id);
    persist_state(profile, &state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primary_selection_survives_later_runs_and_project_changes() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&root).unwrap();
        let profile = root.join("private");
        crate::home::confirm_home(&profile, &root.join("muniment")).unwrap();
        let mut agent = save(
            &profile,
            Agent {
                name: "Scout".into(),
                instructions: "Find sources.".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assign(&profile, "first-chat", &agent.id).unwrap();
        assign(&profile, "older-run", &agent.id).unwrap();
        with_state(&profile, |state| {
            state.runs.get_mut(&agent.id).unwrap().thread_id = Some("older-run".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            list(&profile).unwrap().state.primary_threads[&agent.id],
            "first-chat"
        );
        let project = crate::projects::create(&profile, "Reports").unwrap();
        agent.project_id = Some(project.clone());
        save(&profile, agent.clone()).unwrap();
        assert_eq!(
            crate::projects::list(&profile).unwrap().threads["first-chat"],
            project
        );
        agent.project_id = None;
        save(&profile, agent).unwrap();
        assert!(!crate::projects::list(&profile)
            .unwrap()
            .threads
            .contains_key("first-chat"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn weekday_and_weekly_schedules_use_local_calendar() {
        let friday = chrono::FixedOffset::west_opt(4 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 9, 18, 10, 0, 0)
            .unwrap();
        let mut s = Schedule {
            enabled: true,
            cadence: "weekdays".into(),
            time: "09:00".into(),
            weekday: 0,
        };
        assert_eq!(
            next_after(&s, friday).unwrap(),
            friday
                .timezone()
                .with_ymd_and_hms(2026, 9, 21, 9, 0, 0)
                .unwrap()
                .timestamp()
        );
        s.cadence = "weekly".into();
        s.weekday = 4;
        assert_eq!(
            next_after(&s, friday).unwrap(),
            friday
                .timezone()
                .with_ymd_and_hms(2026, 9, 25, 9, 0, 0)
                .unwrap()
                .timestamp()
        );
    }
    #[test]
    fn grok_profile_and_template_context_survive_save_and_enter_the_agent_chat() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&root).unwrap();
        let profile = root.join("private");
        crate::home::confirm_home(&profile, &root.join("muniment")).unwrap();
        let agent: Agent = serde_json::from_value(serde_json::json!({
            "name":"Scout", "label":"Researcher", "description":"Find sources.",
            "template":{"skills":[{"name":"Check","description":"Check dates."}],"plugins":["github"],"custom":"keep"},
            "avatar":{"style":"muniment-v1","seed":"happy"}
        })).unwrap();
        let mut saved = save(&profile, agent).unwrap();
        let avatar = saved.avatar.as_ref().unwrap().seed.clone();
        saved.name = "Renamed".into();
        save(&profile, saved.clone()).unwrap();
        let read = get(&profile, &saved.id).unwrap();
        assert_eq!(read.label, "Researcher");
        assert_eq!(read.avatar.unwrap().seed, avatar);
        assert_eq!(read.template.unwrap()["custom"], "keep");
        assign(&profile, "chat", &saved.id).unwrap();
        let context = thread_instructions(&profile, "chat").unwrap().unwrap();
        assert!(context.contains("Role: Researcher"));
        assert!(context.contains("Check dates."));
        assert!(context.contains("not installed capabilities or active schedules"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn definition_and_thread_assignment_survive_edits() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&root).unwrap();
        let profile = root.join("private");
        crate::home::confirm_home(&profile, &root.join("muniment")).unwrap();
        let mut agent = save(
            &profile,
            Agent {
                name: "Scout".into(),
                instructions: "Read sources.".into(),
                ..Agent::default()
            },
        )
        .unwrap();
        assign(&profile, "thread-a", &agent.id).unwrap();
        agent.name = "Researcher".into();
        agent.instructions = "Cite sources.".into();
        save(&profile, agent.clone()).unwrap();
        assert_eq!(
            thread_instructions(&profile, "thread-a").unwrap(),
            Some("Cite sources.".into())
        );
        assert_eq!(list(&profile).unwrap().agents.len(), 1);
        fs::write(
            folder(&profile, &agent.id).unwrap().join("reference.txt"),
            "keep",
        )
        .unwrap();
        delete(&profile, &agent.id).unwrap();
        assert_eq!(
            fs::read_to_string(folder(&profile, &agent.id).unwrap().join("reference.txt")).unwrap(),
            "keep"
        );
        assert!(list(&profile).unwrap().agents.is_empty());
        assert!(thread_instructions(&profile, "thread-a").unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
