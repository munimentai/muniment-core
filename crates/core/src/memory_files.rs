//! Editable, file-backed profile and durable facts. The search index is disposable.
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

static WRITE: Mutex<()> = Mutex::new(());
const MAX_TEXT: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fact {
    pub id: String,
    pub title: String,
    pub content: String,
    pub source: String,
}

fn lock(profile: &Path) -> Result<fs::File, String> {
    fs::create_dir_all(profile).map_err(|_| "Memory is unavailable.")?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(profile.join("memory-files.lock"))
        .map_err(|_| "Memory is unavailable.")?;
    file.lock_exclusive().map_err(|_| "Memory is busy.")?;
    Ok(file)
}

pub fn home(profile: &Path) -> Result<PathBuf, String> {
    crate::home::configured_home(profile)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "The Home folder is unavailable.".into())
}

fn checked_path(home: &Path, relative: &str) -> Result<PathBuf, String> {
    let mut path = home.to_owned();
    for part in Path::new(relative).components() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err("The memory path is invalid.".into());
        }
        path.push(part);
        if path.is_symlink() {
            return Err("The memory path must not be a symbolic link.".into());
        }
    }
    Ok(path)
}
fn read(home: &Path, relative: &str) -> Result<String, String> {
    let path = checked_path(home, relative)?;
    match fs::metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Ok(m) if m.len() <= MAX_TEXT as u64 && m.is_file() => {}
        _ => return Err("The memory file cannot be read.".into()),
    }
    fs::read_to_string(path).map_err(|_| "The memory file cannot be read.".into())
}
fn write(home: &Path, relative: &str, content: &str) -> Result<(), String> {
    if content.len() > MAX_TEXT {
        return Err("Keep the memory file under 64 KB.".into());
    }
    crate::memory_secret::reject_memory_secret(content)
        .map_err(|_| "Remove credentials before saving this memory.")?;
    let destination = checked_path(home, relative)?;
    let parent = destination.parent().ok_or("The memory path is invalid.")?;
    fs::create_dir_all(parent).map_err(|_| "The memory folder cannot be created.")?;
    let temporary = parent.join(format!(".memory-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        crate::home::replace_file(&temporary, &destination)
    })();
    let _ = fs::remove_file(temporary);
    result.map_err(|_| "The memory file could not be saved.".into())
}
pub fn profile_read(profile: &Path) -> Result<String, String> {
    read(&home(profile)?, "memory/profile.md")
}
pub fn profile_save(profile: &Path, content: &str) -> Result<(), String> {
    let _guard = WRITE.lock().map_err(|_| "Memory is busy.")?;
    let _file_lock = lock(profile)?;
    write(&home(profile)?, "memory/profile.md", content)
}
fn fact_path(id: &str) -> Result<String, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "The memory identifier is invalid.")?;
    Ok(format!("memory/facts/{id}.md"))
}
pub fn facts(profile: &Path) -> Result<Vec<Fact>, String> {
    list_at(&home(profile)?, "memory/facts")
}
pub fn deleted_facts(profile: &Path) -> Result<Vec<Fact>, String> {
    list_at(profile, "memory-trash")
}
fn list_at(home: &Path, relative: &str) -> Result<Vec<Fact>, String> {
    let directory = checked_path(home, relative)?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| "The memories could not be read.")? {
        let entry = entry.map_err(|_| "A memory could not be read.")?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("The memory identifier is invalid.")?;
        fact_path(id)?;
        let text = read(home, &format!("{relative}/{id}.md"))?;
        let (heading, body) = text
            .split_once("\n\n")
            .ok_or("The memory format is invalid.")?;
        let (source, content) = body
            .split_once("\n\n")
            .ok_or("The memory format is invalid.")?;
        result.push(Fact {
            id: id.into(),
            title: heading.strip_prefix("# ").unwrap_or(heading).into(),
            source: source.strip_prefix("Source: ").unwrap_or(source).into(),
            content: content.trim_end().into(),
        });
    }
    result.sort_by(|a, b| a.title.cmp(&b.title));
    Ok(result)
}
pub fn fact_save(profile: &Path, fact: Fact) -> Result<Fact, String> {
    fact_save_in(profile, &home(profile)?, fact)
}
pub fn facts_in(home: &Path) -> Result<Vec<Fact>, String> {
    list_at(home, "memory/facts")
}
pub fn fact_save_in(profile: &Path, home: &Path, mut fact: Fact) -> Result<Fact, String> {
    let _guard = WRITE.lock().map_err(|_| "Memory is busy.")?;
    let _file_lock = lock(profile)?;
    fact.title = fact.title.trim().into();
    fact.content = fact.content.trim().into();
    fact.source = fact.source.trim().into();
    if fact.title.is_empty()
        || fact.title.len() > 200
        || fact.title.contains(['\r', '\n'])
        || fact.content.is_empty()
        || fact.source.is_empty()
        || fact.source.contains(['\r', '\n'])
        || fact.source.len() > 2000
    {
        return Err("Give the memory a title, fact and source.".into());
    }
    if fact.id.is_empty() {
        // Repeated capture of the same fact does not create another file.
        if let Some(existing) = facts_in(home)?
            .into_iter()
            .find(|f| f.content == fact.content)
        {
            return Ok(existing);
        }
        fact.id = uuid::Uuid::new_v4().to_string();
    }
    write(
        home,
        &fact_path(&fact.id)?,
        &format!(
            "# {}\n\nSource: {}\n\n{}\n",
            fact.title, fact.source, fact.content
        ),
    )?;
    Ok(fact)
}
pub fn fact_delete(profile: &Path, id: &str) -> Result<(), String> {
    fact_delete_in(profile, &home(profile)?, id)
}
pub fn fact_delete_in(profile: &Path, home: &Path, id: &str) -> Result<(), String> {
    let _guard = WRITE.lock().map_err(|_| "Memory is busy.")?;
    let _file_lock = lock(profile)?;
    let relative = fact_path(id)?;
    let source = checked_path(home, &relative)?;
    if !source.is_file() {
        return Err("The memory does not exist.".into());
    }
    let content = read(home, &relative)?;
    // Recovery files live outside Home, so the search index never recalls them.
    write(profile, &format!("memory-trash/{id}.md"), &content)?;
    fs::remove_file(source).map_err(|_| "The memory could not be deleted.".into())
}
pub fn fact_restore(profile: &Path, id: &str) -> Result<(), String> {
    fact_restore_in(profile, &home(profile)?, id)
}
pub fn fact_restore_in(profile: &Path, home: &Path, id: &str) -> Result<(), String> {
    let _guard = WRITE.lock().map_err(|_| "Memory is busy.")?;
    let _file_lock = lock(profile)?;
    let relative = fact_path(id)?;
    let archive = format!("memory-trash/{id}.md");
    let source = checked_path(profile, &archive)?;
    if !source.is_file() {
        return Err("The deleted memory does not exist.".into());
    }
    if checked_path(home, &relative)?.exists() {
        return Err("An active memory has this identifier. Review it before restoring.".into());
    }
    write(home, &relative, &read(profile, &archive)?)?;
    fs::remove_file(source).map_err(|_| "The deleted copy could not be removed.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn files_round_trip_and_duplicate_capture_is_idempotent() {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir_all(&root).unwrap();
        let profile = root.join("private");
        crate::home::confirm_home(&profile, &root.join("muniment")).unwrap();
        profile_save(&profile, "# Profile\n\nCall me Alex.").unwrap();
        assert!(profile_read(&profile).unwrap().contains("Alex"));
        profile_save(&profile, "Call me Sam.").unwrap();
        assert_eq!(profile_read(&profile).unwrap(), "Call me Sam.");
        let input = Fact {
            id: String::new(),
            title: "Preferred language".into(),
            content: "Use English.".into(),
            source: "thread:abc".into(),
        };
        let saved = fact_save(&profile, input.clone()).unwrap();
        assert_eq!(saved.id, fact_save(&profile, input).unwrap().id);
        assert_eq!(facts(&profile).unwrap().len(), 1);
        assert!(fact_delete(&profile, "../profile").is_err());
        fact_delete(&profile, &saved.id).unwrap();
        assert!(facts(&profile).unwrap().is_empty());
        assert_eq!(deleted_facts(&profile).unwrap().len(), 1);
        fact_restore(&profile, &saved.id).unwrap();
        assert_eq!(facts(&profile).unwrap().len(), 1);
        assert!(deleted_facts(&profile).unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
