use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    fs::OpenOptions,
    io,
    path::{Component, Path, PathBuf},
};

const CONFIG_FILE: &str = "home.json";
const HOME_DIRECTORIES: [&str; 4] = ["memory", "agents", "projects", "sessions"];

#[derive(Debug)]
pub struct HomeError {
    message: &'static str,
    source: Option<io::Error>,
}

impl HomeError {
    fn io(message: &'static str, source: io::Error) -> Self {
        Self {
            message,
            source: Some(source),
        }
    }

    fn invalid(message: &'static str) -> Self {
        Self {
            message,
            source: None,
        }
    }
}

impl fmt::Display for HomeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for HomeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Deserialize, Serialize)]
struct HomeConfig {
    location: PathBuf,
}

pub fn configured_home(config_dir: &Path) -> Result<Option<PathBuf>, HomeError> {
    let bytes = match fs::read(config_dir.join(CONFIG_FILE)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HomeError::io(
                "The saved Home location could not be read.",
                error,
            ))
        }
    };
    let config: HomeConfig = serde_json::from_slice(&bytes)
        .map_err(|_| HomeError::invalid("The saved Home location is invalid."))?;
    validate_home(&config.location)?;
    Ok(Some(config.location))
}

pub fn confirm_home(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    validate_home(home)?;
    validate_config_location(config_dir, home)?;
    scaffold_home(home)?;
    persist_home(config_dir, home)
}

fn validate_config_location(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    let config_dir = normalized_absolute(config_dir)?;
    let home = normalized_absolute(home)?;
    if config_dir.starts_with(&home) {
        return Err(HomeError::invalid(
            "Muniment Home cannot contain the app configuration folder.",
        ));
    }
    Ok(())
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, HomeError> {
    if !path.is_absolute() {
        return Err(HomeError::invalid("The folder location is invalid."));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(HomeError::invalid("The folder location is invalid."));
                }
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    let mut existing = normalized.as_path();
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(existing) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(
                    existing
                        .file_name()
                        .ok_or_else(|| HomeError::invalid("The folder location is invalid."))?,
                );
                existing = existing
                    .parent()
                    .ok_or_else(|| HomeError::invalid("The folder location is invalid."))?;
            }
            Err(error) => {
                return Err(HomeError::io(
                    "The folder location could not be inspected.",
                    error,
                ))
            }
        }
    }
}

pub fn scaffold_home(home: &Path) -> Result<(), HomeError> {
    create_visible_directory(home)?;
    for name in HOME_DIRECTORIES {
        create_visible_directory(&home.join(name))?;
    }
    Ok(())
}

fn validate_home(home: &Path) -> Result<(), HomeError> {
    if !home.is_absolute() || home.parent().is_none() {
        return Err(HomeError::invalid(
            "Choose an absolute folder other than a filesystem root.",
        ));
    }
    let name = home
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| HomeError::invalid("The Home folder location is invalid."))?;
    if name.starts_with('.') {
        return Err(HomeError::invalid(
            "Muniment Home must be a visible folder, not a dot-directory.",
        ));
    }
    Ok(())
}

fn create_visible_directory(path: &Path) -> Result<(), HomeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            HomeError::invalid("A Muniment Home scaffold path is not a directory."),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(path)
            .map_err(|error| HomeError::io("Muniment Home could not be created.", error)),
        Err(error) => Err(HomeError::io(
            "Muniment Home could not be inspected.",
            error,
        )),
    }
}

fn persist_home(config_dir: &Path, home: &Path) -> Result<(), HomeError> {
    fs::create_dir_all(config_dir)
        .map_err(|error| HomeError::io("The Home selection could not be saved.", error))?;
    let contents = serde_json::to_vec_pretty(&HomeConfig {
        location: home.to_path_buf(),
    })
    .map_err(|_| HomeError::invalid("The Home selection could not be saved."))?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(config_dir.join("home.lock"))
        .map_err(|error| HomeError::io("The Home selection could not be saved.", error))?;
    lock.lock_exclusive()
        .map_err(|error| HomeError::io("The Home selection could not be saved.", error))?;

    let destination = config_dir.join(CONFIG_FILE);
    let temporary = config_dir.join(format!("home.json.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        io::Write::write_all(&mut file, &contents)?;
        file.sync_all()?;
        replace_file(&temporary, &destination)?;
        sync_directory(config_dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| HomeError::io("The Home selection could not be saved.", error))
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(not(target_os = "windows"))]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        // Windows rename does not replace an existing file atomically.
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let replaced = unsafe {
            ReplaceFileW(
                destination.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if replaced == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    } else {
        fs::rename(source, destination)
    }
}

#[cfg(target_os = "windows")]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::replace_file;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn failed_replacement_preserves_the_previous_file() {
        let root = std::env::temp_dir().join(format!(
            "muniment-home-replace-failure-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let destination = root.join("home.json");
        fs::write(&destination, b"previous configuration").unwrap();

        assert!(replace_file(&root.join("missing.tmp"), &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"previous configuration");
        fs::remove_dir_all(root).unwrap();
    }
}
