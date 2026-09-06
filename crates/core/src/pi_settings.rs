use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::sidecar::pi_install::{PiArtifactDescriptor, PI_CANDIDATE_ARTIFACT};

pub fn pi_agent_directory(home: &Path, agent_directory: Option<&OsStr>) -> io::Result<PathBuf> {
    let Some(value) = agent_directory.filter(|value| !value.is_empty()) else {
        return Ok(home.join(".pi").join("agent"));
    };
    let Some(value) = value.to_str() else {
        return Ok(PathBuf::from(value));
    };
    // This matches normalizePath in Pi v0.85.1 utils/paths.ts with its default options.
    let value = normalize_shell_path(value, cfg!(windows));
    if value == "~" {
        return Ok(home.to_owned());
    }
    if value.starts_with("~/") || (cfg!(windows) && value.starts_with("~\\")) {
        // Node's join does not replace the home when the suffix starts with another separator.
        let mut expanded = home.as_os_str().to_os_string();
        expanded.push(std::path::MAIN_SEPARATOR_STR);
        expanded.push(&value[2..]);
        return Ok(normalize_components(Path::new(&expanded)));
    }
    if value.starts_with("file://") {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The Pi directory URL is invalid.",
            )
        };
        let url = url::Url::parse(&value).map_err(|_| invalid())?;
        // Node rejects encoded separators, invalid escapes, and invalid UTF-8 in the URL path.
        let lower = url.path().to_ascii_lowercase();
        if lower.contains("%2f") || (cfg!(windows) && lower.contains("%5c")) {
            return Err(invalid());
        }
        let mut bytes = url.path().bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%'
                && !(bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                    && bytes.next().is_some_and(|b| b.is_ascii_hexdigit()))
            {
                return Err(invalid());
            }
        }
        let path = url.to_file_path().map_err(|_| invalid())?;
        if path.to_str().is_none() {
            return Err(invalid());
        }
        return Ok(normalize_components(&path));
    }
    Ok(normalize_components(Path::new(&value)))
}

// Pi joins settings filenames lexically before the filesystem follows symlinks.
fn normalize_components(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match result.components().next_back() {
                Some(Component::Normal(_)) => {
                    result.pop();
                }
                Some(Component::RootDir) => {}
                _ => result.push(component),
            },
            _ => result.push(component),
        }
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}

fn normalize_shell_path(value: &str, windows: bool) -> String {
    if windows && value.starts_with('/') && !value.starts_with("//") && !value.contains('\\') {
        let lower = value.to_ascii_lowercase();
        let drive_path = if lower.starts_with("/mnt/") {
            &value[5..]
        } else if lower.starts_with("/cygdrive/") {
            &value[10..]
        } else {
            &value[1..]
        };
        let mut parts = drive_path.splitn(2, '/');
        let drive = parts.next().unwrap_or("");
        if drive.len() == 1 && drive.as_bytes()[0].is_ascii_alphabetic() {
            return format!(
                "{}:\\{}",
                drive.to_ascii_uppercase(),
                parts.next().unwrap_or("").replace('/', "\\")
            );
        }
    }
    value.to_owned()
}

pub fn prepare_pi_settings(artifact: PiArtifactDescriptor, executable: &Path) -> io::Result<()> {
    if artifact.version != PI_CANDIDATE_ARTIFACT.version {
        return Ok(());
    }
    let home = std::env::home_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Cannot locate the Pi home directory.",
        )
    })?;
    let agent_directory = std::env::var_os("PI_CODING_AGENT_DIR");
    let directory = pi_agent_directory(&home, agent_directory.as_deref())?;
    store_pi_settings(&directory.join("settings.json"), artifact)?;
    crate::pi_packages::prepare_pi_packages(&directory, executable)
}

// proper-lockfile defaults to a 10-second stale threshold and a 5-second heartbeat.
const LOCK_STALE: Duration = Duration::from_secs(10);
const LOCK_UPDATE: Duration = Duration::from_secs(5);

pub struct SettingsLock {
    path: PathBuf,
    modified: Arc<Mutex<SystemTime>>,
    stop: mpsc::Sender<()>,
    heartbeat: Option<std::thread::JoinHandle<()>>,
}

impl SettingsLock {
    pub fn check(&self) -> io::Result<()> {
        let modified = self.modified.lock().unwrap();
        if fs::metadata(&self.path)?.modified()? != *modified {
            return Err(io::Error::other("Pi settings lock changed owners."));
        }
        Ok(())
    }
}

impl Drop for SettingsLock {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        if self.check().is_ok() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn directory_handle(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Windows needs read/write attribute access and backup semantics to open a directory.
        options.access_mode(0x180).custom_flags(0x02000000);
    }
    options.open(path)
}

pub fn lock_settings(path: &Path) -> io::Result<SettingsLock> {
    lock_settings_with_timeout(path, Duration::from_secs(30))
}

fn lock_settings_with_timeout(path: &Path, timeout: Duration) -> io::Result<SettingsLock> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let path = PathBuf::from(name);
    let deadline = Instant::now() + timeout;
    loop {
        match fs::create_dir(&path) {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                match fs::metadata(&path).and_then(|metadata| metadata.modified()) {
                    Ok(modified) if modified.elapsed().is_ok_and(|age| age > LOCK_STALE) => {
                        // Recheck the heartbeat before removing an abandoned directory.
                        if fs::metadata(&path)?.modified()? == modified {
                            match fs::remove_dir(&path) {
                                Ok(()) => continue,
                                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                    _ => {}
                }
                if Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
    let setup = (|| {
        let directory = directory_handle(&path)?;
        let modified = Arc::new(Mutex::new(directory.metadata()?.modified()?));
        let shared = modified.clone();
        let heartbeat_path = path.clone();
        let (stop, wait) = mpsc::channel();
        let heartbeat = std::thread::Builder::new().spawn(move || {
            while wait.recv_timeout(LOCK_UPDATE) == Err(mpsc::RecvTimeoutError::Timeout) {
                let mut modified = shared.lock().unwrap();
                if fs::metadata(&heartbeat_path)
                    .and_then(|m| m.modified())
                    .ok()
                    != Some(*modified)
                {
                    break;
                }
                if directory.set_modified(SystemTime::now()).is_err() {
                    break;
                }
                match directory.metadata().and_then(|m| m.modified()) {
                    Ok(time) => *modified = time,
                    Err(_) => break,
                }
            }
        })?;
        Ok(SettingsLock {
            path: path.clone(),
            modified,
            stop,
            heartbeat: Some(heartbeat),
        })
    })();
    if setup.is_err() {
        let _ = fs::remove_dir(&path);
    }
    setup
}

pub fn store_pi_settings(path: &Path, artifact: PiArtifactDescriptor) -> io::Result<()> {
    if artifact.version != PI_CANDIDATE_ARTIFACT.version {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let lock = lock_settings(path)?;
    let mut settings: Map<String, Value> = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Map::new(),
        Err(error) => return Err(error),
    };
    let original = settings.clone();
    merge_pi_settings(&mut settings, artifact);
    if settings == original {
        return Ok(());
    }
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(&settings)?)?;
        file.sync_all()?;
        lock.check()?;
        crate::atomic_file::replace(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// The candidate owns packages and defaultTools and preserves all other settings.
pub fn merge_pi_settings(settings: &mut Map<String, Value>, artifact: PiArtifactDescriptor) {
    if artifact.version != PI_CANDIDATE_ARTIFACT.version {
        return;
    }
    settings.insert(
        "packages".into(),
        json!(
            crate::pi_packages::PI_PACKAGES.map(|(name, version)| format!("npm:{name}@{version}"))
        ),
    );
    // v0.85.1: packages/coding-agent/src/core/tools/index.ts:96-105, allToolNames.
    settings.insert(
        "defaultTools".into(),
        json!([
            "read",
            "bash",
            "powershell",
            "edit",
            "write",
            "grep",
            "find",
            "ls"
        ]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::pi_install::PI_ARTIFACT;

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("muniment-pi-settings-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn resolves_pis_directory_overrides() {
        let home = temporary_directory();
        for (input, expected) in [
            (None, home.join(".pi/agent")),
            (Some(""), home.join(".pi/agent")),
            (Some("~"), home.clone()),
            (Some("~/agent"), home.join("agent")),
            (Some("~//agent"), home.join("agent")),
            (Some("~/nested/../agent"), home.join("agent")),
            (Some("nested/../agent"), PathBuf::from("agent")),
            (Some("nested/.."), PathBuf::from(".")),
            (Some("../../agent"), PathBuf::from("../../agent")),
            (Some("relative/agent"), PathBuf::from("relative/agent")),
            (Some(" spaced "), PathBuf::from(" spaced ")),
        ] {
            assert_eq!(
                pi_agent_directory(&home, input.map(OsStr::new)).unwrap(),
                expected
            );
        }
        let target = home.join("agent with spaces");
        let url = url::Url::from_file_path(&target).unwrap();
        assert_eq!(
            pi_agent_directory(&home, Some(OsStr::new(url.as_str()))).unwrap(),
            target
        );
        for invalid in ["file:///tmp/a%2Fb", "file:///tmp/a%ZZ", "file:///tmp/a%FF"] {
            assert!(pi_agent_directory(&home, Some(OsStr::new(invalid))).is_err());
        }
        let url_with_query = format!("{url}?ignored=%2f");
        assert_eq!(
            pi_agent_directory(&home, Some(OsStr::new(&url_with_query))).unwrap(),
            target
        );
        #[cfg(not(windows))]
        {
            assert_eq!(
                pi_agent_directory(&home, Some(OsStr::new("file:///tmp/agent"))).unwrap(),
                Path::new("/tmp/agent")
            );
            assert!(pi_agent_directory(&home, Some(OsStr::new("file://remote/agent"))).is_err());
            assert_eq!(
                pi_agent_directory(&home, Some(OsStr::new("~\\agent"))).unwrap(),
                Path::new("~\\agent")
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(
                pi_agent_directory(&home, Some(OsStr::new("~\\agent"))).unwrap(),
                home.join("agent")
            );
            for input in [
                "/c/agent",
                "/mnt/c/agent",
                "/cygdrive/c/agent",
                "file:///C:/agent",
            ] {
                assert_eq!(
                    pi_agent_directory(&home, Some(OsStr::new(input))).unwrap(),
                    Path::new("C:\\agent")
                );
            }
        }
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn normalizes_windows_shell_drive_paths_only_on_windows() {
        for (input, expected) in [
            ("/c/agent", "C:\\agent"),
            ("/mnt/d/agent/sub", "D:\\agent\\sub"),
            ("/MNT/d/agent", "D:\\agent"),
            ("/cygdrive/E", "E:\\"),
            ("/z/", "Z:\\"),
            ("//server/share", "//server/share"),
            ("/home/agent", "/home/agent"),
            ("/c/a\\b", "/c/a\\b"),
            ("/mnt/cc/agent", "/mnt/cc/agent"),
        ] {
            assert_eq!(normalize_shell_path(input, true), expected);
            assert_eq!(normalize_shell_path(input, false), input);
        }
    }

    #[test]
    fn recovers_an_abandoned_pi_lock() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        let lock_path = root.join("settings.json.lock");
        fs::create_dir(&lock_path).unwrap();
        directory_handle(&lock_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).unwrap();
        assert!(path.is_file());
        assert!(!lock_path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn excludes_a_live_pi_writer_and_keeps_its_lock() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        let lock_path = root.join("settings.json.lock");
        fs::create_dir(&lock_path).unwrap();
        let modified = fs::metadata(&lock_path).unwrap().modified().unwrap();
        assert!(
            matches!(lock_settings_with_timeout(&path, Duration::from_millis(40)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(
            fs::metadata(&lock_path).unwrap().modified().unwrap(),
            modified
        );
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refreshes_a_live_desktop_lock_past_pis_stale_threshold() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        let lock = lock_settings(&path).unwrap();
        let initial = *lock.modified.lock().unwrap();
        std::thread::sleep(LOCK_STALE + Duration::from_millis(100));
        assert!(*lock.modified.lock().unwrap() > initial);
        assert!(matches!(lock_settings_with_timeout(&path, Duration::ZERO),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
        drop(lock);
        assert!(!root.join("settings.json.lock").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn does_not_release_a_replacement_lock() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        let lock = lock_settings(&path).unwrap();
        directory_handle(&lock.path)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(60))
            .unwrap();
        assert!(lock.check().is_err());
        drop(lock);
        assert!(root.join("settings.json.lock").is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persists_candidate_settings_and_keeps_provider_and_foreign_keys() {
        let root = temporary_directory();
        let path = root.join("agent/settings.json");
        store_pi_settings(&path, PI_ARTIFACT).unwrap();
        assert!(!path.exists());
        store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).unwrap();
        let rendered: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rendered["packages"].as_array().unwrap().len(), 4);
        assert_eq!(rendered["defaultTools"].as_array().unwrap().len(), 8);
        fs::write(
            &path,
            br#"{"defaultProvider":"ollama","foreign":{"nested":42}}"#,
        )
        .unwrap();
        store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).unwrap();
        let bytes = fs::read(&path).unwrap();
        let rendered: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rendered["defaultProvider"], "ollama");
        assert_eq!(rendered["foreign"], json!({"nested": 42}));
        store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        store_pi_settings(&path, PI_ARTIFACT).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_invalid_settings_without_overwriting_or_leaving_a_lock() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        for invalid in ["", "null", "[]", "42", "{", "{\"foreign\":true,}"] {
            fs::write(&path, invalid).unwrap();
            assert!(store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        }
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_pis_bom_prefixed_settings() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        fs::write(&path, "\u{feff}{\"defaultProvider\":\"ollama\"}").unwrap();
        store_pi_settings(&path, PI_CANDIDATE_ARTIFACT).unwrap();
        let rendered: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rendered["defaultProvider"], "ollama");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reads_settings_after_the_other_writer_releases_pis_lock() {
        let root = temporary_directory();
        let path = root.join("settings.json");
        let lock = lock_settings(&path).unwrap();
        let writer_path = path.clone();
        let (started, wait) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started.send(()).unwrap();
            store_pi_settings(&writer_path, PI_CANDIDATE_ARTIFACT).unwrap();
        });
        wait.recv().unwrap();
        fs::write(
            &path,
            br#"{"defaultProvider":"ollama","foreign":"concurrent"}"#,
        )
        .unwrap();
        drop(lock);
        writer.join().unwrap();
        let rendered: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rendered["foreign"], "concurrent");
        assert_eq!(rendered["defaultProvider"], "ollama");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn candidate_renders_exact_packages_and_full_registry() {
        let mut settings = Map::new();
        merge_pi_settings(&mut settings, PI_CANDIDATE_ARTIFACT);
        let rendered = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&rendered).unwrap(),
            json!({
                "packages": [
                    "npm:pi-web-access@0.28.0",
                    "npm:pi-subagents@0.65.1",
                    "npm:pi-background-tasks@2.5.0",
                    "npm:pi-mcp-adapter@2.32.1"
                ],
                "defaultTools": ["read", "bash", "powershell", "edit", "write", "grep", "find", "ls"]
            })
        );
    }

    #[test]
    fn production_renders_neither_key() {
        let mut settings = Map::new();
        settings.insert("defaultProvider".into(), json!("ollama"));
        merge_pi_settings(&mut settings, PI_ARTIFACT);
        assert_eq!(
            serde_json::to_value(settings).unwrap(),
            json!({"defaultProvider": "ollama"})
        );
    }

    #[test]
    fn preserves_foreign_keys_and_replaces_only_candidate_owned_values() {
        let original = json!({
            "defaultProvider": "ollama",
            "defaultModel": "local-model",
            "foreign": {"nested": [null, true, 42]},
            "packages": ["npm:pi-web-access@0.1.0"],
            "defaultTools": ["read"]
        });
        let mut settings = original.as_object().unwrap().clone();
        merge_pi_settings(&mut settings, PI_ARTIFACT);
        assert_eq!(Value::Object(settings.clone()), original);
        merge_pi_settings(&mut settings, PI_CANDIDATE_ARTIFACT);
        for key in ["defaultProvider", "defaultModel", "foreign"] {
            assert_eq!(settings[key], original[key]);
        }
        let merged = settings.clone();
        merge_pi_settings(&mut settings, PI_CANDIDATE_ARTIFACT);
        assert_eq!(settings, merged);
        assert_eq!(settings["packages"].as_array().unwrap().len(), 4);
        assert_eq!(settings["defaultTools"].as_array().unwrap().len(), 8);
    }
}
