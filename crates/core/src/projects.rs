//! Local project folders and stable thread membership.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

static WRITE: Mutex<()> = Mutex::new(());

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub projects: BTreeMap<String, String>,
    pub threads: BTreeMap<String, String>,
}

fn read(profile: &Path) -> Result<Catalog, String> {
    match fs::read(profile.join("projects.json")) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|_| "The project catalog cannot be read.".into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Catalog::default()),
        Err(_) => Err("The project catalog cannot be read.".into()),
    }
}
fn save(profile: &Path, catalog: &Catalog) -> Result<(), String> {
    fs::create_dir_all(profile).map_err(|_| "The project catalog cannot be saved.")?;
    let temporary = profile.join(format!("projects.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        fs::write(
            &temporary,
            serde_json::to_vec(catalog).map_err(|_| "The project catalog cannot be saved.")?,
        )
        .map_err(|_| "The project catalog cannot be saved.")?;
        fs::rename(&temporary, profile.join("projects.json"))
            .map_err(|_| "The project catalog cannot be saved.")
    })();
    let _ = fs::remove_file(temporary);
    result.map_err(str::to_owned)
}
pub fn root(profile: &Path) -> Result<PathBuf, String> {
    let home = crate::home::configured_home(profile)
        .map_err(|e| e.to_string())?
        .ok_or("Choose a Home folder before creating projects.")?;
    let root = home.join("projects");
    if root.is_symlink() {
        return Err("The projects folder must not be a symbolic link.".into());
    }
    fs::create_dir_all(&root).map_err(|_| "The projects folder cannot be opened.")?;
    Ok(root)
}
fn name(value: &str) -> Result<&str, String> {
    let value = value.trim();
    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    if value.is_empty()
        || value.chars().count() > 80
        || value.starts_with('.')
        || value.ends_with('.')
        || value
            .chars()
            .any(|c| c.is_control() || "/\\<>:\"|?*".contains(c))
        || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
    {
        return Err("Use a project name without path separators or reserved characters.".into());
    }
    Ok(value)
}
pub fn list(profile: &Path) -> Result<Catalog, String> {
    let _guard = WRITE.lock().map_err(|_| "The project catalog is busy.")?;
    let mut catalog = read(profile)?;
    let root = root(profile)?;
    let known = catalog
        .projects
        .iter()
        .map(|(id, title)| {
            crate::workspace_names::resolve(
                profile,
                &root,
                id,
                Some(title),
                Some(&root.join(title)),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut changed = false;
    for entry in fs::read_dir(&root).map_err(|_| "The projects folder cannot be read.")? {
        let entry = entry.map_err(|_| "A project folder cannot be read.")?;
        if !entry
            .file_type()
            .map_err(|_| "A project folder cannot be read.")?
            .is_dir()
        {
            continue;
        }
        let folder = entry.file_name().to_string_lossy().into_owned();
        if name(&folder).is_ok()
            && !known.contains(&entry.path())
            && !catalog.projects.values().any(|n| n == &folder)
        {
            catalog
                .projects
                .insert(uuid::Uuid::new_v4().to_string(), folder);
            changed = true;
        }
    }
    if changed {
        save(profile, &catalog)?;
    }
    Ok(catalog)
}
pub fn create(profile: &Path, value: &str) -> Result<String, String> {
    let value = name(value)?;
    let _guard = WRITE.lock().map_err(|_| "The project catalog is busy.")?;
    let mut catalog = read(profile)?;
    let folder = root(profile)?.join(value);
    if catalog
        .projects
        .values()
        .any(|n| n.eq_ignore_ascii_case(value))
        || folder.exists()
    {
        return Err("A project with that name already exists.".into());
    }
    fs::create_dir(&folder).map_err(|_| "The project folder could not be created.")?;
    let id = uuid::Uuid::new_v4().to_string();
    catalog.projects.insert(id.clone(), value.into());
    if let Err(error) = save(profile, &catalog) {
        let _ = fs::remove_dir(folder);
        return Err(error);
    }
    Ok(id)
}
pub fn folder(profile: &Path, id: &str) -> Result<PathBuf, String> {
    folder_with_config(profile, profile, id)
}

fn folder_with_config(profile: &Path, config: &Path, id: &str) -> Result<PathBuf, String> {
    let catalog = read(profile)?;
    let value = catalog
        .projects
        .get(id)
        .ok_or("The project does not exist.")?;
    let root = root(config)?;
    let folder = crate::workspace_names::resolve(
        config,
        &root,
        id,
        Some(name(value)?),
        Some(&root.join(value)),
    )?;
    if folder.is_symlink() || !folder.is_dir() {
        return Err("The project folder is unavailable.".into());
    }
    Ok(folder)
}
pub fn rename(profile: &Path, id: &str, value: &str) -> Result<(), String> {
    let value = name(value)?;
    let _guard = WRITE.lock().map_err(|_| "The project catalog is busy.")?;
    let mut catalog = read(profile)?;
    let old = catalog
        .projects
        .get(id)
        .ok_or("The project does not exist.")?
        .clone();
    if old == value {
        return Ok(());
    }
    if catalog
        .projects
        .iter()
        .any(|(key, n)| key != id && n.eq_ignore_ascii_case(value))
    {
        return Err("A project with that name already exists.".into());
    }
    let source = folder(profile, id)?;
    let target = root(profile)?.join(crate::workspace_names::basename(value, id));
    if target.exists() && !old.eq_ignore_ascii_case(value) {
        return Err("A folder with that name already exists.".into());
    }
    crate::workspace_names::resolve(profile, &root(profile)?, id, Some(value), Some(&source))?;
    catalog.projects.insert(id.into(), value.into());
    if let Err(error) = save(profile, &catalog) {
        crate::workspace_names::resolve(profile, &root(profile)?, id, Some(&old), Some(&target))?;
        return Err(error);
    }
    Ok(())
}
pub fn assign(profile: &Path, thread: &str, project: &str) -> Result<(), String> {
    folder(profile, project)?;
    let _guard = WRITE.lock().map_err(|_| "The project catalog is busy.")?;
    let mut catalog = read(profile)?;
    catalog.threads.insert(thread.into(), project.into());
    save(profile, &catalog)
}
pub fn unassign(profile: &Path, thread: &str) -> Result<(), String> {
    let _guard = WRITE.lock().map_err(|_| "The project catalog is busy.")?;
    let mut catalog = read(profile)?;
    catalog.threads.remove(thread);
    save(profile, &catalog)
}
pub fn thread_folder(profile: &Path, thread: &str) -> Result<Option<PathBuf>, String> {
    read(profile)?
        .threads
        .get(thread)
        .map(|id| folder(profile, id))
        .transpose()
}

/// Resolves every thread to its project or its own visible output folder.
pub fn workspace(profile: &Path, thread: &str) -> Result<PathBuf, String> {
    workspace_with_config(profile, profile, thread)
}

pub fn workspace_with_config(
    profile: &Path,
    config: &Path,
    thread: &str,
) -> Result<PathBuf, String> {
    if let Some(id) = crate::agents::state(profile)?.threads.get(thread) {
        let agent = crate::agents::get(config, id)?;
        if let Some(project) = agent.project_id {
            return folder_with_config(profile, config, &project);
        }
        return crate::agents::folder(config, id);
    }
    if let Some(project) = read(profile)?.threads.get(thread) {
        let folder = folder_with_config(profile, config, project)?;
        migrate_workspace_metadata(&folder)?;
        return Ok(folder);
    }
    if thread.is_empty()
        || thread.len() > 128
        || !thread
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err("The thread identifier is invalid.".into());
    }
    let home = crate::home::configured_home(config)
        .map_err(|e| e.to_string())?
        .ok_or("The Home folder is unavailable.")?;
    let sessions = home.join("sessions");
    let folder = crate::workspace_names::resolve(config, &sessions, thread, None, None)?;
    if sessions.is_symlink() || folder.is_symlink() {
        return Err("The session folder must not be a symbolic link.".into());
    }
    fs::create_dir_all(&folder).map_err(|_| "The session folder cannot be opened.")?;
    migrate_workspace_metadata(&folder)?;
    Ok(folder)
}

/// Converts legacy session directories using the journal's visible thread titles.
pub fn migrate_session_names(profile: &Path) -> Result<(), String> {
    let Some(home) = crate::home::configured_home(profile).map_err(|e| e.to_string())? else { return Ok(()) };
    let root = home.join("sessions");
    if !root.is_dir() || root.is_symlink() { return Ok(()) }
    let ids = fs::read_dir(&root).map_err(|e| e.to_string())?.filter_map(Result::ok).filter_map(|entry| {
        let id = entry.file_name().to_string_lossy().into_owned();
        (uuid::Uuid::parse_str(&id).is_ok() && entry.path().is_dir() && !entry.path().is_symlink()).then_some(id)
    }).collect::<Vec<_>>();
    if ids.is_empty() { return Ok(()) }
    let mut titles = BTreeMap::new();
    if profile.join("runs.sqlite3").exists() {
        let mut journal = crate::journal::RunJournal::open(profile.join("runs.sqlite3")).map_err(|e| e.to_string())?;
        let mut cursor = None;
        loop {
            let page = journal.thread_summaries(100, cursor.as_deref()).map_err(|e| e.to_string())?;
            for summary in page.summaries { titles.insert(summary.thread_id, summary.title); }
            cursor = page.next_cursor;
            if cursor.is_none() { break }
        }
    }
    for id in ids { crate::workspace_names::resolve(profile, &root, &id, Some(titles.get(&id).map(String::as_str).unwrap_or("Thread")), None)?; }
    Ok(())
}

fn migrate_workspace_metadata(folder: &Path) -> Result<(), String> {
    let old = folder.join(".pi");
    let new = folder.join(".muniment");
    if !old.exists() && !old.is_symlink() {
        return Ok(());
    }
    if old.is_symlink() || !old.is_dir() || new.exists() || new.is_symlink() {
        return Err(
            "The session metadata folder cannot be renamed without overwriting existing files."
                .into(),
        );
    }
    fs::rename(old, new).map_err(|_| "The session metadata folder could not be renamed.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("muniment-project-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&root).unwrap();
            crate::home::confirm_home(&root.join("profile"), &root.join("muniment")).unwrap();
            Self(root)
        }
        fn profile(&self) -> PathBuf {
            self.0.join("profile")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn unassigned_threads_use_separate_session_folders() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let first = workspace(&profile, "thread-one").unwrap();
        assert!(first
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("Untitled-"));
        fs::write(first.join("result.txt"), "kept").unwrap();
        fs::create_dir_all(first.join(".pi/tasks")).unwrap();
        fs::write(first.join(".pi/tasks/result.txt"), "task output").unwrap();
        assert_ne!(first, workspace(&profile, "thread-two").unwrap());
        assert_eq!(first, workspace(&profile, "thread-one").unwrap());
        assert!(!first.join(".pi").exists());
        assert_eq!(
            fs::read_to_string(first.join(".muniment/tasks/result.txt")).unwrap(),
            "task output"
        );
        assert!(workspace(&profile, "../outside").is_err());
        let project = create(&profile, "Research").unwrap();
        assign(&profile, "thread-two", &project).unwrap();
        assert_eq!(
            workspace(&profile, "thread-two").unwrap(),
            folder(&profile, &project).unwrap()
        );
        assert_eq!(
            fs::read_to_string(first.join("result.txt")).unwrap(),
            "kept"
        );
    }
    #[test]
    fn metadata_migration_preserves_conflicting_directories() {
        let fixture = Fixture::new();
        let folder = workspace(&fixture.profile(), "thread-one").unwrap();
        fs::create_dir(folder.join(".pi")).unwrap();
        fs::create_dir(folder.join(".muniment")).unwrap();
        fs::write(folder.join(".pi/old.txt"), "old").unwrap();
        fs::write(folder.join(".muniment/new.txt"), "new").unwrap();
        assert!(workspace(&fixture.profile(), "thread-one").is_err());
        assert_eq!(
            fs::read_to_string(folder.join(".pi/old.txt")).unwrap(),
            "old"
        );
        assert_eq!(
            fs::read_to_string(folder.join(".muniment/new.txt")).unwrap(),
            "new"
        );
    }

    #[test]
    fn rename_preserves_files_and_thread_membership() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        let id = create(&profile, "Contracts").unwrap();
        assign(&profile, "thread-one", &id).unwrap();
        fs::write(folder(&profile, &id).unwrap().join("draft.txt"), "draft").unwrap();
        rename(&profile, &id, "Agreements").unwrap();
        let renamed = thread_folder(&profile, "thread-one").unwrap().unwrap();
        assert!(renamed
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("Agreements-"));
        assert_eq!(
            fs::read_to_string(renamed.join("draft.txt")).unwrap(),
            "draft"
        );
        assert!(!root(&profile).unwrap().join("Contracts").exists());
        assert_eq!(list(&profile).unwrap().threads["thread-one"], id);
        rename(&profile, &id, "agreements").unwrap();
        assert!(thread_folder(&profile, "thread-one")
            .unwrap()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("agreements-"));
    }
    #[test]
    fn discovers_existing_folders_and_rejects_collisions_and_escapes() {
        let fixture = Fixture::new();
        let profile = fixture.profile();
        fs::create_dir(root(&profile).unwrap().join("Research")).unwrap();
        assert!(list(&profile)
            .unwrap()
            .projects
            .values()
            .any(|name| name == "Research"));
        let id = create(&profile, "Reports").unwrap();
        assert!(rename(&profile, &id, "Research").is_err());
        for name in ["../outside", "one/two", "one\\two", ".hidden", "CON", ""] {
            assert!(create(&profile, name).is_err());
        }
        assign(&profile, "thread-two", &id).unwrap();
        fs::remove_dir(folder(&profile, &id).unwrap()).unwrap();
        assert!(thread_folder(&profile, "thread-two").is_err());
        assert_eq!(thread_folder(&profile, "unassigned").unwrap(), None);
    }
}
