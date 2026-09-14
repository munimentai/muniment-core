//! One root for every file the app, the runtime and the agent harness keep on
//! a machine: `~/.muniment`, or the directory `MUNIMENT_STATE_DIR` names.
//!
//! The user's document folder, Home, stays under `~/Documents/Muniment` and is
//! a different thing. Logs keep their platform paths so the operating system's
//! own log tools find them.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const STATE_DIRECTORY_OVERRIDE: &str = "MUNIMENT_STATE_DIR";
pub const STATE_DIRECTORY_NAME: &str = ".muniment";
/// The agent harness reads its settings, provider routes and keys here.
pub const AGENT_DIRECTORY_NAME: &str = "agent";
/// The agent harness executable revisions and their pointer.
pub const HARNESS_DIRECTORY_NAME: &str = "harness";
/// The agent harness session logs.
pub const SESSIONS_DIRECTORY_NAME: &str = "sessions";

/// The files a hand-run harness keeps that the app's own harness reads too.
const AGENT_FILES: [&str; 3] = ["settings.json", "models.json", "auth.json"];
/// Written once adoption has run, so a later launch moves nothing.
const ADOPTED_MARKER: &str = ".adopted";

pub fn state_directory_from(
    override_value: Option<&OsStr>,
    home_value: Option<&OsStr>,
) -> Option<PathBuf> {
    override_value
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home_value
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join(STATE_DIRECTORY_NAME))
        })
}

/// The process's home: `USERPROFILE` on Windows, `HOME` elsewhere.
pub fn home_directory_value() -> Option<OsString> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
    }
}

pub fn state_directory() -> Option<PathBuf> {
    state_directory_from(
        std::env::var_os(STATE_DIRECTORY_OVERRIDE).as_deref(),
        home_directory_value().as_deref(),
    )
}

pub fn agent_directory(state: &Path) -> PathBuf {
    state.join(AGENT_DIRECTORY_NAME)
}

/// The roots an install before this layout wrote: the runtime's data root, the
/// desktop's config root, and the harness's own agent directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyRoots {
    pub data: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub agent: Option<PathBuf>,
}

const LEGACY_IDENTIFIER: &str = "ai.muniment.desktop";

fn absolute(value: Option<&OsStr>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

pub fn legacy_roots_from(
    home: Option<&OsStr>,
    xdg_data: Option<&OsStr>,
    xdg_config: Option<&OsStr>,
    app_data: Option<&OsStr>,
    pi_agent: Option<&OsStr>,
) -> LegacyRoots {
    let home = absolute(home);
    let agent = absolute(pi_agent).or_else(|| home.as_ref().map(|home| home.join(".pi/agent")));
    let (data, config) = if cfg!(windows) {
        let roaming = absolute(app_data).map(|root| root.join(LEGACY_IDENTIFIER));
        (roaming.clone(), roaming)
    } else {
        let data = absolute(xdg_data)
            .or_else(|| home.as_ref().map(|home| home.join(".local/share")))
            .map(|root| root.join(LEGACY_IDENTIFIER));
        let config_root = if cfg!(target_os = "macos") {
            "Library/Application Support"
        } else {
            ".config"
        };
        let config = absolute(xdg_config)
            .or_else(|| home.as_ref().map(|home| home.join(config_root)))
            .map(|root| root.join(LEGACY_IDENTIFIER));
        (data, config)
    };
    LegacyRoots {
        data,
        config,
        agent,
    }
}

pub fn legacy_roots() -> LegacyRoots {
    legacy_roots_from(
        home_directory_value().as_deref(),
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("APPDATA").as_deref(),
        std::env::var_os("PI_CODING_AGENT_DIR").as_deref(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adoption {
    /// The state directory already existed, so nothing moved.
    Present,
    /// No earlier install existed, so the directory is new and empty.
    Created,
    /// An earlier install's files now live under the state directory.
    Moved,
}

fn create_owner_only(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

fn exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

fn move_entries_into(source: &Path, state: &Path, outcome: &mut Adoption) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = state.join(entry.file_name());
        if exists(&target) {
            continue;
        }
        if fs::rename(entry.path(), &target).is_ok() {
            *outcome = Adoption::Moved;
        }
    }
    // Only an emptied directory goes.
    let _ = fs::remove_dir(source);
    Ok(())
}

/// Moves an earlier install's files under `state` the first time this layout
/// runs, and records that it ran. A second caller, the desktop beside the
/// runtime, finds the record and changes nothing. A root that already exists
/// without the record still receives the earlier files it lacks, one entry at
/// a time, and a file that already exists at its new place is left as it is.
pub fn adopt_legacy_state(state: &Path, legacy: &LegacyRoots) -> io::Result<Adoption> {
    if state.join(ADOPTED_MARKER).is_file() {
        return Ok(Adoption::Present);
    }
    let mut outcome = Adoption::Created;
    let data = legacy
        .data
        .as_deref()
        .filter(|data| data.is_dir() && *data != state);
    if let Some(data) = data {
        if exists(state) {
            move_entries_into(data, state, &mut outcome)?;
        } else {
            match fs::rename(data, state) {
                Ok(()) => outcome = Adoption::Moved,
                Err(_) if exists(state) => move_entries_into(data, state, &mut outcome)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    create_owner_only(state)?;
    #[cfg(unix)]
    {
        // A renamed root keeps the mode it had, so set the owner-only mode here.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(state, fs::Permissions::from_mode(0o700))?;
    }
    for (old, new) in [
        ("pi", HARNESS_DIRECTORY_NAME),
        ("pi-sessions", SESSIONS_DIRECTORY_NAME),
    ] {
        let (old, new) = (state.join(old), state.join(new));
        if old.is_dir() && !exists(&new) && fs::rename(&old, &new).is_ok() {
            outcome = Adoption::Moved;
        }
    }
    let config = legacy
        .config
        .as_deref()
        .filter(|config| config.is_dir() && *config != state && Some(*config) != data);
    if let Some(config) = config {
        move_entries_into(config, state, &mut outcome)?;
    }
    if let Some(agent) = legacy.agent.as_deref().filter(|agent| agent.is_dir()) {
        let target = agent_directory(state);
        create_owner_only(&target)?;
        for name in AGENT_FILES {
            let source = agent.join(name);
            let destination = target.join(name);
            if !source.is_file() || exists(&destination) {
                continue;
            }
            fs::copy(&source, &destination)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
            }
            outcome = Adoption::Moved;
        }
    }
    fs::write(state.join(ADOPTED_MARKER), b"")?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "muniment-state-root-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn resolves_the_override_before_the_home_dotdir() {
        assert_eq!(
            state_directory_from(
                Some(OsStr::new("/srv/muniment")),
                Some(OsStr::new("/home/p"))
            ),
            Some(PathBuf::from("/srv/muniment"))
        );
        assert_eq!(
            state_directory_from(Some(OsStr::new("relative")), Some(OsStr::new("/home/p"))),
            Some(PathBuf::from("/home/p/.muniment"))
        );
        assert_eq!(
            state_directory_from(None, Some(OsStr::new("/home/p"))),
            Some(PathBuf::from("/home/p/.muniment"))
        );
        assert_eq!(state_directory_from(None, Some(OsStr::new("home"))), None);
        assert_eq!(state_directory_from(None, None), None);
        assert_eq!(
            agent_directory(Path::new("/home/p/.muniment")),
            Path::new("/home/p/.muniment/agent")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn names_the_earlier_roots_from_the_home() {
        let roots = legacy_roots_from(Some(OsStr::new("/home/p")), None, None, None, None);
        assert_eq!(
            roots.data,
            Some(PathBuf::from("/home/p/.local/share/ai.muniment.desktop"))
        );
        let config_root = if cfg!(target_os = "macos") {
            "/home/p/Library/Application Support/ai.muniment.desktop"
        } else {
            "/home/p/.config/ai.muniment.desktop"
        };
        assert_eq!(roots.config, Some(PathBuf::from(config_root)));
        assert_eq!(roots.agent, Some(PathBuf::from("/home/p/.pi/agent")));
        let overridden = legacy_roots_from(
            Some(OsStr::new("/home/p")),
            Some(OsStr::new("/xdg/data")),
            Some(OsStr::new("/xdg/config")),
            None,
            Some(OsStr::new("/elsewhere/agent")),
        );
        assert_eq!(
            overridden.data,
            Some(PathBuf::from("/xdg/data/ai.muniment.desktop"))
        );
        assert_eq!(
            overridden.config,
            Some(PathBuf::from("/xdg/config/ai.muniment.desktop"))
        );
        assert_eq!(overridden.agent, Some(PathBuf::from("/elsewhere/agent")));
    }

    #[test]
    fn adopts_an_earlier_install_once_and_keeps_what_is_already_there() {
        let root = temporary_directory();
        let data = root.join("data/ai.muniment.desktop");
        let config = root.join("config/ai.muniment.desktop");
        let agent = root.join("pi/agent");
        for directory in [
            data.join("pi/revisions"),
            data.join("pi-sessions"),
            data.join("cas"),
            config.join("models"),
            agent.clone(),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(data.join("runs.sqlite3"), b"journal").unwrap();
        fs::write(data.join("pi-sessions/one.jsonl"), b"{}").unwrap();
        fs::write(config.join("home.json"), b"{}").unwrap();
        fs::write(config.join("local-mode"), b"").unwrap();
        fs::write(agent.join("settings.json"), b"{\"a\":1}").unwrap();
        fs::write(agent.join("auth.json"), b"{}").unwrap();
        fs::write(agent.join("sessions.jsonl"), b"not copied").unwrap();
        let state = root.join("home/.muniment");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        let legacy = LegacyRoots {
            data: Some(data.clone()),
            config: Some(config.clone()),
            agent: Some(agent.clone()),
        };

        assert_eq!(
            adopt_legacy_state(&state, &legacy).unwrap(),
            Adoption::Moved
        );

        assert_eq!(fs::read(state.join("runs.sqlite3")).unwrap(), b"journal");
        assert!(state.join("harness/revisions").is_dir());
        assert!(state.join("sessions/one.jsonl").is_file());
        assert!(!state.join("pi").exists());
        assert!(!state.join("pi-sessions").exists());
        assert!(state.join("home.json").is_file());
        assert!(state.join("local-mode").is_file());
        assert!(state.join("models").is_dir());
        assert!(!config.exists());
        assert!(!data.exists());
        assert_eq!(
            fs::read(state.join("agent/settings.json")).unwrap(),
            b"{\"a\":1}"
        );
        assert!(state.join("agent/auth.json").is_file());
        assert!(!state.join("agent/sessions.jsonl").exists());
        // The hand-run harness keeps its own files.
        assert!(agent.join("settings.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&state).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(state.join("agent/auth.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        fs::write(agent.join("models.json"), b"later").unwrap();
        assert_eq!(
            adopt_legacy_state(&state, &legacy).unwrap(),
            Adoption::Present
        );
        assert!(!state.join("agent/models.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fills_a_root_another_process_created_before_the_record_exists() {
        let root = temporary_directory();
        let data = root.join("data/ai.muniment.desktop");
        fs::create_dir_all(data.join("pi-sessions")).unwrap();
        fs::write(data.join("runs.sqlite3"), b"journal").unwrap();
        let state = root.join(".muniment");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("home.json"), b"{}").unwrap();
        let legacy = LegacyRoots {
            data: Some(data.clone()),
            config: None,
            agent: None,
        };

        assert_eq!(
            adopt_legacy_state(&state, &legacy).unwrap(),
            Adoption::Moved
        );

        assert_eq!(fs::read(state.join("runs.sqlite3")).unwrap(), b"journal");
        assert!(state.join("sessions").is_dir());
        assert_eq!(fs::read(state.join("home.json")).unwrap(), b"{}");
        assert!(!data.exists());
        assert!(state.join(ADOPTED_MARKER).is_file());
        assert_eq!(
            adopt_legacy_state(&state, &legacy).unwrap(),
            Adoption::Present
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn creates_an_empty_root_when_no_earlier_install_exists() {
        let root = temporary_directory();
        let state = root.join(".muniment");
        let legacy = LegacyRoots {
            data: Some(root.join("absent-data")),
            config: Some(root.join("absent-config")),
            agent: Some(root.join("absent-agent")),
        };
        assert_eq!(
            adopt_legacy_state(&state, &legacy).unwrap(),
            Adoption::Created
        );
        assert!(state.is_dir());
        assert!(!state.join("agent").exists());
        assert_eq!(
            adopt_legacy_state(&state, &legacy).unwrap(),
            Adoption::Present
        );
        fs::remove_dir_all(root).unwrap();
    }
}
