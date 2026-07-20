use std::{fs, io, path::Path};

const WORKSPACE_REPORT: &[u8] = b"# Muniment workspace onboarding report\n\nThis opened directory is the workspace memory location. User-level Home remains lazy until cross-project context is needed. Repository instructions are loaded from the nearest `AGENTS.md`.\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceOnboardRequest {
    pub opened_directory: String,
    pub memory_location: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOnboarded {
    pub opened_directory: String,
    pub memory_location: String,
    pub instructions: Option<String>,
}

pub fn ensure_scaffold_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "memory path is not a directory",
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path),
        Err(error) => Err(error),
    }
}

pub fn write_scaffold_file_if_missing(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    static NEXT_TEMPORARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if path.exists() {
        return validate_scaffold_file(path);
    }
    let sequence = NEXT_TEMPORARY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = path.with_extension(format!("muniment-{}-{sequence}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                validate_scaffold_file(path)
            }
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(temporary);
    result
}

pub fn onboard_companion_workspace(
    opened: &Path,
    memory_root: &Path,
) -> io::Result<Option<String>> {
    let opened = opened.canonicalize()?;
    ensure_requested_directory(memory_root)?;
    let memory_root = memory_root.canonicalize()?;
    if !opened.is_dir() || !memory_root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace is not a directory",
        ));
    }
    let memory = memory_root.join("memory");
    ensure_scaffold_directory(&memory)?;
    write_scaffold_file_if_missing(
        &memory.join("README.md"),
        b"# Memory\n\nDurable context for this workspace.\n",
    )?;
    write_scaffold_file_if_missing(&memory.join("ONBOARDING.md"), WORKSPACE_REPORT)?;
    let agents = opened
        .ancestors()
        .map(|path| path.join("AGENTS.md"))
        .find(|path| path.is_file());
    agents.map(fs::read_to_string).transpose()
}

pub fn ensure_cross_project_home(home: &Path) -> io::Result<()> {
    ensure_requested_directory(home)?;
    for name in ["memory", "agents", "projects", "sessions"] {
        let directory = home.join(name);
        ensure_scaffold_directory(&directory)?;
        write_scaffold_file_if_missing(
            &directory.join("README.md"),
            format!("# {}\n", name[..1].to_uppercase() + &name[1..]).as_bytes(),
        )?;
    }
    Ok(())
}

fn ensure_requested_directory(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "workspace is not a directory",
                ));
            }
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current.parent().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "workspace has no parent")
                })?;
            }
            Err(error) => return Err(error),
        }
    }
    for directory in missing.into_iter().rev() {
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace is not a directory",
            ));
        }
    }
    Ok(())
}

fn validate_scaffold_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "memory seed is not a regular file",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn temp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("muniment-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn existing_scaffold_file_is_not_overwritten() {
        let p = temp("atomic-scaffold");
        let file = p.join("README.md");
        fs::write(&file, "mine").unwrap();
        write_scaffold_file_if_missing(&file, b"seed").unwrap();
        assert_eq!(fs::read_to_string(file).unwrap(), "mine");
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn racing_scaffold_writers_publish_one_complete_file() {
        let p = temp("racing-scaffold");
        let file = p.join("ONBOARDING.md");
        let writers = [
            b"first complete report".as_slice(),
            b"second complete report".as_slice(),
        ]
        .into_iter()
        .map(|contents| {
            let file = file.clone();
            std::thread::spawn(move || write_scaffold_file_if_missing(&file, contents).unwrap())
        })
        .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }
        let contents = fs::read(file).unwrap();
        assert!(contents == b"first complete report" || contents == b"second complete report");
        fs::remove_dir_all(p).unwrap();
    }
}
