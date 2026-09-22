//! Chat goals and outputs for artifact and agent threads.
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Creation {
    pub thread_id: String,
    pub kind: String,
    pub goal: String,
    pub output: String,
    #[serde(default)]
    pub result_id: Option<String>,
}
fn record_path(profile: &Path, thread: &str) -> Result<PathBuf, String> {
    uuid::Uuid::parse_str(thread).map_err(|_| "Invalid thread.")?;
    Ok(profile
        .join("creation-threads")
        .join(format!("{thread}.json")))
}
pub fn read(profile: &Path, thread: &str) -> Result<Option<Creation>, String> {
    if uuid::Uuid::parse_str(thread).is_err() {
        return Ok(None);
    }
    match fs::read(record_path(profile, thread)?) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
pub fn save(profile: &Path, mut item: Creation) -> Result<Creation, String> {
    if !matches!(item.kind.as_str(), "agent" | "artifact")
        || item.goal.trim().is_empty()
        || item.output.trim().is_empty()
        || item.goal.len() > 16000
        || item.output.len() > 4000
    {
        return Err("Specify an agent or artifact goal and expected output.".into());
    }
    item.goal = item.goal.trim().into();
    item.output = item.output.trim().into();
    let path = record_path(profile, &item.thread_id)?;
    fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    write_json(&path, &item)?;
    Ok(item)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        fs::write(&temp, serde_json::to_vec(value).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        crate::atomic_file::replace(&temp, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
pub fn list(profile: &Path) -> Result<Vec<Creation>, String> {
    let root = profile.join("creation-threads");
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            result.push(
                serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(result)
}
#[derive(Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub name: String,
    pub html: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub source_path: Option<PathBuf>,
}
pub fn publish(
    profile: &Path,
    thread: &str,
    path: &Path,
    name: Option<&str>,
) -> Result<Artifact, String> {
    record_path(profile, thread)?;
    let workspace = crate::projects::workspace(profile, thread)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        workspace.join(path)
    }
    .canonicalize()
    .map_err(|e| e.to_string())?;
    if !path.starts_with(&workspace)
        || !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("html" | "htm")
        )
    {
        return Err("Save an HTML file inside this thread workspace.".into());
    }
    let file = fs::File::open(&path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Choose a regular HTML file.".into());
    }
    let mut html = String::new();
    file.take(2_000_001)
        .read_to_string(&mut html)
        .map_err(|e| e.to_string())?;
    if html.len() > 2_000_000 {
        return Err("The artifact exceeds 2 MB.".into());
    }
    let root = profile.join("browser/artifacts");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".publish.lock"))
        .map_err(|e| e.to_string())?;
    lock.lock_exclusive().map_err(|e| e.to_string())?;
    let mut id = None;
    let mut saved_name = None;
    for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
        let candidate = entry.map_err(|e| e.to_string())?.path();
        if candidate.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(item) =
            serde_json::from_slice::<Artifact>(&fs::read(candidate).map_err(|e| e.to_string())?)
        {
            if item.thread_id.as_deref() == Some(thread) && item.source_path.as_ref() == Some(&path)
            {
                saved_name = Some(item.name);
                id = Some(item.id)
            }
        }
    }
    let item = Artifact {
        id: id.unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
        name: name
            .filter(|n| !n.trim().is_empty())
            .map(str::to_owned)
            .or(saved_name)
            .unwrap_or_else(|| path.file_name().unwrap().to_string_lossy().into_owned()),
        html,
        thread_id: Some(thread.into()),
        source_path: Some(path),
    };
    write_json(&root.join(format!("{}.json", item.id)), &item)?;
    let folder = export_artifact(profile, &item)?;
    fs::write(folder.join("index.html"), &item.html).map_err(|e| e.to_string())?;
    let mut plan = read(profile, thread)?.unwrap_or(Creation {
        thread_id: thread.into(),
        kind: "artifact".into(),
        goal: format!("Create {}", item.name),
        output: "An interactive HTML artifact".into(),
        result_id: None,
    });
    if plan.kind == "artifact" {
        plan.result_id = Some(item.id.clone());
        save(profile, plan)?;
    }
    Ok(item)
}

/// Remove the catalog entry, preserving chat history and workspace files.
pub fn remove(profile: &Path, thread: &str) -> Result<(), String> {
    match fs::remove_file(record_path(profile, thread)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn artifact_folder(profile: &Path, id: &str) -> Result<PathBuf, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "Invalid artifact.")?;
    let item: Artifact = serde_json::from_slice(
        &fs::read(profile.join("browser/artifacts").join(format!("{id}.json")))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    export_artifact(profile, &item)
}
fn export_artifact(profile: &Path, item: &Artifact) -> Result<PathBuf, String> {
    let home = crate::memory_files::home(profile)?;
    let folder = crate::workspace_names::resolve(
        profile,
        &home.join("artifacts"),
        &item.id,
        Some(&item.name),
        None,
    )?;
    let path = folder.join("index.html");
    if !path.exists() {
        fs::write(&path, &item.html).map_err(|e| e.to_string())?;
    }
    Ok(folder)
}

pub fn edit_artifact(profile: &Path, id: &str, name: Option<&str>) -> Result<(), String> {
    uuid::Uuid::parse_str(id).map_err(|_| "Invalid artifact.")?;
    let root = profile.join("browser/artifacts");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".publish.lock"))
        .map_err(|e| e.to_string())?;
    lock.lock_exclusive().map_err(|e| e.to_string())?;
    let path = root.join(format!("{id}.json"));
    let mut item: Artifact = serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if let Some(name) = name {
        if name.trim().is_empty() || name.len() > 640 {
            return Err("Enter an artifact name.".into());
        }
        item.name = name.trim().into();
        export_artifact(profile, &item)?;
        write_json(&path, &item)
    } else {
        fs::remove_file(path).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_updates_one_output_and_preserves_its_name() {
        let root = std::env::temp_dir().join(format!("creation-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let profile = root.join("profile");
        crate::home::confirm_home(&profile, &root.join("home")).unwrap();
        let thread = uuid::Uuid::new_v4().to_string();
        let workspace = crate::projects::workspace(&profile, &thread).unwrap();
        let path = workspace.join("index.html");
        fs::write(&path, "<h1>First</h1>").unwrap();
        let first = publish(&profile, &thread, &path, Some("Report")).unwrap();
        fs::write(&path, "<h1>Second</h1>").unwrap();
        let second = publish(&profile, &thread, &path, None).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(second.name, "Report");
        assert!(second.html.contains("Second"));
        let plans = list(&profile).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].result_id.as_deref(), Some(first.id.as_str()));
        let outside = root.join("outside.html");
        fs::write(&outside, "outside").unwrap();
        assert!(publish(&profile, &thread, &outside, None).is_err());
        edit_artifact(&profile, &first.id, Some("Renamed report")).unwrap();
        let path = profile
            .join("browser/artifacts")
            .join(format!("{}.json", first.id));
        let renamed: Artifact = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(renamed.name, "Renamed report");
        assert!(edit_artifact(&profile, "../outside", None).is_err());
        assert!(edit_artifact(&profile, &first.id, Some(" ")).is_err());
        edit_artifact(&profile, &first.id, None).unwrap();
        assert!(!path.exists());
        assert!(workspace.join("index.html").exists());
        remove(&profile, &thread).unwrap();
        assert!(list(&profile).unwrap().is_empty());
        remove(&profile, &thread).unwrap();
        assert!(remove(&profile, "../outside").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
