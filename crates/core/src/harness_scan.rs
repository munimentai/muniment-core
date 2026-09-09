//! Name-only discovery of durable assistant memory in user-level roots.
//! Obsidian's vault registry is the sole metadata file whose contents discovery reads.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub type Environment = BTreeMap<OsString, OsString>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Roots {
    Home(&'static [&'static str]),
    HomeFile(&'static str),
    HomeWithWindowsLocal {
        home: &'static str,
        windows: &'static str,
    },
    ObsidianVaults,
}

#[derive(Debug)]
pub struct Assistant {
    pub id: &'static str,
    pub display_name: &'static str,
    pub roots: Roots,
    pub override_variable: Option<&'static str>,
    pub macos_linux_only: bool,
    pub counted: &'static [&'static str],
    /// Patterns are root-relative. Home-prefixed exclusions describe paths outside the roots.
    pub never: &'static [&'static str],
}

pub const REGISTRY: &[Assistant] = &[
    Assistant {
        id: "claude-code",
        display_name: "Claude Code",
        roots: Roots::Home(&[".claude"]),
        override_variable: Some("CLAUDE_CONFIG_DIR"),
        macos_linux_only: false,
        counted: &[
            "CLAUDE.md",
            "rules/*.md",
            "projects/*/memory/*.md",
            "agent-memory/**/*.md",
        ],
        never: &[".credentials.json", "settings*.json", "*.jsonl"],
    },
    Assistant {
        id: "codex",
        display_name: "Codex CLI",
        roots: Roots::Home(&[".codex"]),
        override_variable: Some("CODEX_HOME"),
        macos_linux_only: false,
        counted: &["AGENTS.md", "AGENTS.override.md", "memories/**/*.md"],
        never: &["auth.json", "config.toml", "sessions/", "history.jsonl"],
    },
    Assistant {
        id: "grok-build",
        display_name: "Grok Build",
        roots: Roots::Home(&[".grok"]),
        override_variable: Some("GROK_HOME"),
        macos_linux_only: false,
        counted: &["skills/**"],
        never: &["auth.json", "config.toml", "sessions/"],
    },
    Assistant {
        id: "hermes",
        display_name: "Hermes",
        roots: Roots::HomeWithWindowsLocal {
            home: ".hermes",
            windows: "hermes",
        },
        override_variable: Some("HERMES_HOME"),
        macos_linux_only: false,
        counted: &["SOUL.md", "memories/*.md", "skills/*/"],
        never: &[".env", "auth.json", "state.db"],
    },
    Assistant {
        id: "pi",
        display_name: "Pi",
        roots: Roots::Home(&[".pi/agent"]),
        override_variable: Some("PI_CODING_AGENT_DIR"),
        macos_linux_only: false,
        counted: &[
            "AGENTS.md",
            "SYSTEM.md",
            "APPEND_SYSTEM.md",
            "prompts/",
            "skills/",
        ],
        never: &["auth.json", "settings.json", "sessions/"],
    },
    Assistant {
        id: "gemini",
        display_name: "Gemini CLI",
        roots: Roots::Home(&[".gemini"]),
        override_variable: Some("GEMINI_CLI_HOME"),
        macos_linux_only: false,
        counted: &["GEMINI.md"],
        never: &["oauth_creds.json", "settings.json", "tmp/"],
    },
    Assistant {
        id: "copilot",
        display_name: "Copilot CLI",
        roots: Roots::Home(&[".copilot"]),
        override_variable: Some("COPILOT_HOME"),
        macos_linux_only: false,
        counted: &["copilot-instructions.md", "instructions/*.md"],
        never: &["config.json", "mcp-secrets/", "session-state/"],
    },
    Assistant {
        id: "obsidian",
        display_name: "Obsidian",
        roots: Roots::ObsidianVaults,
        override_variable: None,
        macos_linux_only: false,
        counted: &["**/*.md"],
        never: &[".obsidian/", ".trash/"],
    },
    Assistant {
        id: "opencode",
        display_name: "OpenCode",
        roots: Roots::Home(&[".config/opencode"]),
        override_variable: None,
        macos_linux_only: true,
        counted: &["AGENTS.md", "agents/", "commands/", "skills/"],
        never: &["opencode.db"],
    },
    Assistant {
        id: "goose",
        display_name: "Goose",
        roots: Roots::Home(&[".config/goose"]),
        override_variable: None,
        macos_linux_only: true,
        counted: &[".goosehints", "memory/*"],
        never: &["secrets.yaml", "sessions.db"],
    },
    Assistant {
        id: "continue",
        display_name: "Continue",
        roots: Roots::Home(&[".continue"]),
        override_variable: None,
        macos_linux_only: false,
        counted: &["rules/*.md", "prompts/*"],
        never: &["config.yaml", "sessions/"],
    },
    Assistant {
        id: "cline",
        display_name: "Cline",
        roots: Roots::Home(&[
            "Documents/Cline/Rules",
            "Documents/Cline/Workflows",
            ".cline/skills",
        ]),
        override_variable: None,
        macos_linux_only: false,
        counted: &["**/*.md"],
        never: &["~/.cline/data/"],
    },
    Assistant {
        id: "windsurf",
        display_name: "Windsurf",
        roots: Roots::Home(&[".codeium/windsurf/memories"]),
        override_variable: None,
        macos_linux_only: false,
        counted: &["global_rules.md", "**/*"],
        never: &["~/.codeium/**"],
    },
    Assistant {
        id: "amp",
        display_name: "Amp",
        roots: Roots::HomeFile(".config/AGENTS.md"),
        override_variable: None,
        macos_linux_only: false,
        counted: &["AGENTS.md"],
        never: &["~/.config/amp/"],
    },
];

// These names remain excluded even within a broadly counted skills or memory directory.
const NEVER_NAMES: &[&str] = &["auth.json", ".credentials.json", ".env", "*.jsonl"];
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

fn environment_path(environment: &Environment, name: &str) -> Option<PathBuf> {
    environment
        .get(std::ffi::OsStr::new(name))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub fn obsidian_config_path(
    home: &Path,
    environment: &Environment,
    platform: Platform,
) -> Option<PathBuf> {
    let directory =
        match platform {
            Platform::Linux => environment_path(environment, "XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config")),
            Platform::MacOs => home.join("Library/Application Support"),
            Platform::Windows => environment_path(environment, "APPDATA")
                .unwrap_or_else(|| home.join("AppData/Roaming")),
            Platform::Other => return None,
        };
    Some(directory.join("obsidian/obsidian.json"))
}

/// Resolves only the supplied user's roots. Rejects relative overrides rather than scanning the process directory.
pub fn resolve_roots(
    assistant: &Assistant,
    home: &Path,
    environment: &Environment,
    platform: Platform,
) -> io::Result<Vec<PathBuf>> {
    if assistant.macos_linux_only && !matches!(platform, Platform::Linux | Platform::MacOs) {
        return Ok(Vec::new());
    }
    if let Some(value) = assistant
        .override_variable
        .and_then(|name| environment_path(environment, name))
    {
        let path = if assistant.id == "pi" {
            crate::pi_settings::pi_agent_directory(home, Some(value.as_os_str()))?
        } else if value == Path::new("~") {
            home.to_owned()
        } else if let Ok(suffix) = value.strip_prefix("~") {
            home.join(suffix)
        } else {
            value
        };
        return absolute_roots(vec![path]);
    }
    let roots = match assistant.roots {
        Roots::Home(paths) => paths.iter().map(|path| home.join(path)).collect(),
        Roots::HomeFile(path) => vec![home.join(path)],
        Roots::HomeWithWindowsLocal {
            home: path,
            windows,
        } => vec![if platform == Platform::Windows {
            environment_path(environment, "LOCALAPPDATA")
                .unwrap_or_else(|| home.join("AppData/Local"))
                .join(windows)
        } else {
            home.join(path)
        }],
        Roots::ObsidianVaults => {
            let Some(config) = obsidian_config_path(home, environment, platform) else {
                return Ok(Vec::new());
            };
            return obsidian_vaults(&config);
        }
    };
    absolute_roots(roots)
}

fn absolute_roots(roots: Vec<PathBuf>) -> io::Result<Vec<PathBuf>> {
    if roots.iter().any(|path| !path.is_absolute()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The assistant root must use an absolute path.",
        ));
    }
    Ok(roots)
}

fn obsidian_vaults(config: &Path) -> io::Result<Vec<PathBuf>> {
    absolute_roots(vec![config.to_owned()])?;
    let directory =
        match Dir::open_ambient_dir(config.parent().expect("config parent"), ambient_authority()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
    let name = config.file_name().expect("config name");
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The Obsidian vault registry is not a bounded regular file.",
        ));
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut bytes = Vec::new();
    directory
        .open_with(name, &options)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The Obsidian vault registry exceeds the size cap.",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let vaults = value
        .get("vaults")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "The Obsidian vault registry has no vault map.",
            )
        })?;
    let mut roots = Vec::new();
    for vault in vaults.values() {
        let path = vault
            .get("path")
            .and_then(serde_json::Value::as_str)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "The Obsidian vault path is invalid.",
                )
            })?;
        roots.push(PathBuf::from(path));
    }
    roots.sort();
    roots.dedup();
    absolute_roots(roots)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanWarning {
    DepthCap,
    TimeCap,
    FileCap,
    Unreadable,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub assistant_id: &'static str,
    pub display_name: &'static str,
    pub root: PathBuf,
    pub file_count: u64,
    pub byte_total: u64,
    pub capped: bool,
    pub warnings: Vec<ScanWarning>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionError {
    pub assistant_id: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<ResolutionError>,
}

#[derive(Clone, Copy)]
struct Limits {
    depth: usize,
    entries: usize,
    time: Duration,
}

const LIMITS: Limits = Limits {
    depth: 6,
    entries: 20_000,
    time: Duration::from_secs(2),
};

/// Returns one finding per existing root, including empty roots. A failed root does not hide other findings.
pub fn scan(home: &Path, environment: &Environment, platform: Platform) -> ScanReport {
    let mut report = ScanReport {
        findings: Vec::new(),
        errors: Vec::new(),
    };
    for assistant in REGISTRY {
        match resolve_roots(assistant, home, environment, platform) {
            Ok(roots) => {
                for root in roots {
                    let start = Instant::now();
                    if let Some(finding) = scan_root(assistant, &root, LIMITS, &mut || {
                        start.elapsed() >= LIMITS.time
                    }) {
                        report.findings.push(finding);
                    }
                }
            }
            Err(error) => report.errors.push(ResolutionError {
                assistant_id: assistant.id,
                message: error.to_string(),
            }),
        }
    }
    report
}

struct Walker<'a> {
    assistant: &'a Assistant,
    finding: Finding,
    limits: Limits,
    visited: usize,
    expired: &'a mut dyn FnMut() -> bool,
}

impl Walker<'_> {
    fn warn(&mut self, warning: ScanWarning) {
        if warning != ScanWarning::Unreadable {
            self.finding.capped = true;
        }
        if !self.finding.warnings.contains(&warning) {
            self.finding.warnings.push(warning);
        }
    }

    fn timed_out(&mut self) -> bool {
        let expired = (self.expired)();
        if expired {
            self.warn(ScanWarning::TimeCap);
        }
        expired
    }

    fn stopped(&mut self) -> bool {
        if self.timed_out() {
            return true;
        }
        if self.visited >= self.limits.entries {
            self.warn(ScanWarning::FileCap);
            return true;
        }
        false
    }

    fn repository_ancestor(&mut self, root: &Path) -> bool {
        for parent in root.parent().into_iter().flat_map(Path::ancestors) {
            if self.timed_out() {
                return true;
            }
            match std::fs::symlink_metadata(parent.join(".git")) {
                Ok(_) => return true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    self.warn(ScanWarning::Unreadable);
                    return true;
                }
            }
        }
        false
    }

    fn file(&mut self, relative: &str, bytes: u64) {
        if self
            .assistant
            .counted
            .iter()
            .any(|pattern| glob(pattern, relative))
        {
            self.finding.file_count += 1;
            self.finding.byte_total = self.finding.byte_total.saturating_add(bytes);
        }
    }

    fn walk(&mut self, directory: &Dir, relative: &str, depth: usize) {
        if self.stopped() {
            return;
        }
        // A .git file also marks a worktree. Never enter repositories, even inside vaults or skills.
        match directory.symlink_metadata(".git") {
            Ok(_) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                self.warn(ScanWarning::Unreadable);
                return;
            }
        }
        let entries = match directory.entries() {
            Ok(entries) => entries,
            Err(_) => {
                self.warn(ScanWarning::Unreadable);
                return;
            }
        };
        let mut entries = entries;
        loop {
            if self.stopped() {
                return;
            }
            let Some(entry) = entries.next() else {
                return;
            };
            // Directory entries also consume the file budget, so empty trees cannot evade it.
            self.visited += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    self.warn(ScanWarning::Unreadable);
                    continue;
                }
            };
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let path = if relative.is_empty() {
                name_str.to_owned()
            } else {
                format!("{relative}/{name_str}")
            };
            if excluded(self.assistant, &path) {
                continue;
            }
            let metadata = match directory.symlink_metadata(&name) {
                Ok(metadata) => metadata,
                Err(_) => {
                    self.warn(ScanWarning::Unreadable);
                    continue;
                }
            };
            if self.timed_out() {
                return;
            }
            if metadata.is_dir() {
                // Root children have depth one. Files at depth six count, but deeper entries do not.
                if depth + 1 >= self.limits.depth {
                    self.warn(ScanWarning::DepthCap);
                    continue;
                }
                match directory.open_dir_nofollow(&name) {
                    Ok(child) => self.walk(&child, &path, depth + 1),
                    Err(_) => self.warn(ScanWarning::Unreadable),
                }
            } else if metadata.is_file() {
                self.file(&path, metadata.len());
            }
        }
    }
}

fn scan_root(
    assistant: &Assistant,
    root: &Path,
    limits: Limits,
    expired: &mut dyn FnMut() -> bool,
) -> Option<Finding> {
    let mut walker = Walker {
        assistant,
        finding: Finding {
            assistant_id: assistant.id,
            display_name: assistant.display_name,
            root: root.to_owned(),
            file_count: 0,
            byte_total: 0,
            capped: false,
            warnings: Vec::new(),
        },
        limits,
        visited: 0,
        expired,
    };
    if walker.stopped() {
        return Some(walker.finding);
    }
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => {
            walker.warn(ScanWarning::Unreadable);
            return Some(walker.finding);
        }
    };
    let file_root = matches!(assistant.roots, Roots::HomeFile(_));
    if (file_root && !metadata.is_file()) || (!file_root && !metadata.is_dir()) {
        return None;
    }
    if walker.repository_ancestor(root) {
        return Some(walker.finding);
    }
    if metadata.is_dir() {
        // Open through the parent without following a replaced root symlink.
        let directory = root.parent().zip(root.file_name()).map(|(parent, name)| {
            Dir::open_ambient_dir(parent, ambient_authority())
                .and_then(|parent| parent.open_dir_nofollow(name))
        });
        match directory {
            Some(Ok(directory)) => walker.walk(&directory, "", 0),
            _ => walker.warn(ScanWarning::Unreadable),
        }
    } else if !walker.stopped() {
        if let Some(name) = root.file_name().and_then(|name| name.to_str()) {
            if !excluded(assistant, name) {
                walker.file(name, metadata.len());
            }
        }
    }
    Some(walker.finding)
}

fn excluded(assistant: &Assistant, path: &str) -> bool {
    // Reject secret names regardless of filesystem case rules.
    let path = path.to_ascii_lowercase();
    NEVER_NAMES
        .iter()
        .chain(assistant.never.iter())
        .any(|pattern| {
            if pattern.starts_with("~/") {
                return false;
            }
            let pattern = pattern.trim_end_matches('/');
            // Never patterns also apply to nested names and prune directories before traversal.
            path.split('/').any(|part| glob(pattern, part)) || glob(pattern, &path)
        })
}

// The registry uses only *, ** and directory suffixes. A single * never crosses a separator.
fn glob(pattern: &str, path: &str) -> bool {
    if let Some(directory) = pattern.strip_suffix('/') {
        return path
            .match_indices('/')
            .any(|(index, _)| glob(directory, &path[..index]));
    }
    let patterns: Vec<_> = pattern.split('/').collect();
    let parts: Vec<_> = path.split('/').collect();
    fn segments(patterns: &[&str], parts: &[&str]) -> bool {
        match patterns.split_first() {
            None => parts.is_empty(),
            Some((&"**", rest)) => (0..=parts.len()).any(|skip| segments(rest, &parts[skip..])),
            Some((pattern, rest)) => parts
                .split_first()
                .is_some_and(|(part, tail)| wildcard(pattern, part) && segments(rest, tail)),
        }
    }
    segments(&patterns, &parts)
}

fn wildcard(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.ends_with(suffix)),
        None => pattern == name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Home(PathBuf);

    impl Home {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("harness-scan-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn plant(root: &Path, name: &str) {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"memory").unwrap();
    }

    fn assistant(id: &str) -> &'static Assistant {
        REGISTRY.iter().find(|row| row.id == id).unwrap()
    }

    fn finding(id: &str, root: &Path) -> Finding {
        scan_root(assistant(id), root, LIMITS, &mut || false).unwrap()
    }

    fn vault_config(home: &Path, vaults: serde_json::Value) {
        let config = obsidian_config_path(home, &Environment::new(), Platform::Linux).unwrap();
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(
            config,
            serde_json::to_vec(&serde_json::json!({"vaults": vaults})).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn registry_covers_every_spec_table_row() {
        let spec = include_str!("../../../SPEC.md");
        let table = spec
            .split("| Assistant | Root and override | Counted | Never |")
            .nth(1)
            .unwrap();
        let names: Vec<_> = table
            .lines()
            .skip(2)
            .take_while(|line| line.starts_with('|'))
            .map(|line| line.split('|').nth(1).unwrap().trim())
            .collect();
        assert_eq!(REGISTRY.len(), names.len());
        assert_eq!(
            REGISTRY
                .iter()
                .map(|row| row.display_name)
                .collect::<Vec<_>>(),
            names
        );
        let ids: std::collections::BTreeSet<_> = REGISTRY.iter().map(|row| row.id).collect();
        assert_eq!(ids.len(), REGISTRY.len());
        for row in REGISTRY {
            assert!(!row.counted.is_empty());
            assert!(!row.never.is_empty());
        }
    }

    #[test]
    fn roots_use_only_the_supplied_home_environment_and_platform() {
        let home = Home::new();
        let empty = Environment::new();
        let defaults = [
            ("claude-code", ".claude"),
            ("codex", ".codex"),
            ("grok-build", ".grok"),
            ("hermes", ".hermes"),
            ("pi", ".pi/agent"),
            ("gemini", ".gemini"),
            ("copilot", ".copilot"),
            ("opencode", ".config/opencode"),
            ("goose", ".config/goose"),
            ("continue", ".continue"),
            ("windsurf", ".codeium/windsurf/memories"),
            ("amp", ".config/AGENTS.md"),
        ];
        for (id, relative) in defaults {
            for platform in [
                Platform::Linux,
                Platform::MacOs,
                Platform::Windows,
                Platform::Other,
            ] {
                let row = assistant(id);
                let roots = resolve_roots(row, &home.0, &empty, platform).unwrap();
                if row.macos_linux_only && !matches!(platform, Platform::MacOs | Platform::Linux) {
                    assert!(roots.is_empty());
                } else {
                    let relative = if id == "hermes" && platform == Platform::Windows {
                        "AppData/Local/hermes"
                    } else {
                        relative
                    };
                    assert_eq!(roots, vec![home.0.join(relative)], "{id} {platform:?}");
                }
                if let Some(variable) = row.override_variable {
                    let override_root = home.0.join("override");
                    let env = Environment::from([(
                        variable.into(),
                        override_root.as_os_str().to_owned(),
                    )]);
                    assert_eq!(
                        resolve_roots(row, &home.0, &env, platform).unwrap(),
                        vec![override_root]
                    );
                    let env = Environment::from([(variable.into(), "".into())]);
                    assert_eq!(resolve_roots(row, &home.0, &env, platform).unwrap(), roots);
                    let env = Environment::from([(variable.into(), "~/custom".into())]);
                    assert_eq!(
                        resolve_roots(row, &home.0, &env, platform).unwrap(),
                        vec![home.0.join("custom")]
                    );
                    let env = Environment::from([(variable.into(), "relative".into())]);
                    assert!(resolve_roots(row, &home.0, &env, platform).is_err());
                }
            }
        }
        assert_eq!(
            resolve_roots(assistant("cline"), &home.0, &empty, Platform::Linux).unwrap(),
            [
                "Documents/Cline/Rules",
                "Documents/Cline/Workflows",
                ".cline/skills"
            ]
            .map(|path| home.0.join(path))
        );
        let local = home.0.join("local");
        let env = Environment::from([("LOCALAPPDATA".into(), local.as_os_str().to_owned())]);
        assert_eq!(
            resolve_roots(assistant("hermes"), &home.0, &env, Platform::Windows).unwrap(),
            vec![local.join("hermes")]
        );
        assert_eq!(
            resolve_roots(assistant("hermes"), &home.0, &env, Platform::Linux).unwrap(),
            vec![home.0.join(".hermes")]
        );
    }

    #[test]
    fn every_fixture_root_rejects_each_secret_and_counts_only_registered_names() {
        let home = Home::new();
        let vault = home.0.join("vault");
        vault_config(&home.0, serde_json::json!({"one": {"path": vault}}));
        let cases = [
            (
                "claude-code",
                vec![
                    "CLAUDE.md",
                    "rules/team.md",
                    "projects/key/memory/topic.md",
                    "agent-memory/a/deep/topic.md",
                ],
                vec![
                    "AGENTS.md",
                    "rules/nested/no.md",
                    "projects/key/transcript.md",
                    "agent-memory/settings.local.json",
                ],
            ),
            (
                "codex",
                vec![
                    "AGENTS.md",
                    "AGENTS.override.md",
                    "memories/topic.md",
                    "memories/a/topic.md",
                ],
                vec!["config.toml", "sessions/no.md"],
            ),
            (
                "grok-build",
                vec!["skills/tool/SKILL.md", "skills/tool/script.py"],
                vec!["skills/tool/config.toml", "skills/tool/sessions/no.md"],
            ),
            (
                "hermes",
                vec![
                    "SOUL.md",
                    "memories/topic.md",
                    "skills/tool/SKILL.md",
                    "skills/tool/deep/reference.md",
                ],
                vec![
                    "memories/deep/no.md",
                    "skills/root.md",
                    "skills/tool/state.db",
                ],
            ),
            (
                "pi",
                vec![
                    "AGENTS.md",
                    "SYSTEM.md",
                    "APPEND_SYSTEM.md",
                    "prompts/prompt.md",
                    "skills/tool/SKILL.md",
                ],
                vec!["skills/settings.json", "skills/sessions/no.md"],
            ),
            (
                "gemini",
                vec!["GEMINI.md"],
                vec!["tmp/GEMINI.md", "oauth_creds.json"],
            ),
            (
                "copilot",
                vec!["copilot-instructions.md", "instructions/rule.md"],
                vec![
                    "instructions/nested/no.md",
                    "mcp-secrets/no.md",
                    "session-state/no.md",
                ],
            ),
            (
                "obsidian",
                vec!["note.md", "folder/note.md"],
                vec![
                    ".obsidian/no.md",
                    ".trash/no.md",
                    "folder/.obsidian/no.md",
                    "image.png",
                ],
            ),
            (
                "opencode",
                vec![
                    "AGENTS.md",
                    "agents/agent.md",
                    "commands/command.md",
                    "skills/tool/SKILL.md",
                ],
                vec!["skills/opencode.db", "other/no.md"],
            ),
            (
                "goose",
                vec![".goosehints", "memory/topic.md"],
                vec![
                    "memory/secrets.yaml",
                    "memory/sessions.db",
                    "memory/deep/no.md",
                ],
            ),
            (
                "continue",
                vec!["rules/rule.md", "prompts/prompt.txt"],
                vec![
                    "prompts/config.yaml",
                    "sessions/no.md",
                    "prompts/deep/no.md",
                ],
            ),
            ("cline", vec!["rule.md", "tool/SKILL.md"], vec!["data.json"]),
            (
                "windsurf",
                vec!["global_rules.md", "memory.txt", "folder/topic.md"],
                vec![],
            ),
            ("amp", vec!["AGENTS.md"], vec!["amp/no.md"]),
        ];
        for (id, counted, never) in cases {
            let roots = resolve_roots(assistant(id), &home.0, &Environment::new(), Platform::Linux)
                .unwrap();
            for root in roots {
                let directory = if id == "amp" {
                    root.parent().unwrap()
                } else {
                    &root
                };
                for name in &counted {
                    plant(directory, name);
                }
                for name in &never {
                    plant(directory, name);
                }
                assert_eq!(finding(id, &root).file_count, counted.len() as u64, "{id}");
                for secret in [
                    "auth.json",
                    ".credentials.json",
                    ".env",
                    "session.jsonl",
                    "AUTH.JSON",
                    ".CREDENTIALS.JSON",
                    ".ENV",
                    "SESSION.JSONL",
                ] {
                    // Test each secret alone in both the root and every counted file's directory.
                    plant(directory, secret);
                    for name in &counted {
                        plant(directory.join(name).parent().unwrap(), secret);
                    }
                    let result = finding(id, &root);
                    assert_eq!(result.file_count, counted.len() as u64, "{id}: {secret}");
                    assert_eq!(
                        result.byte_total,
                        counted.len() as u64 * 6,
                        "{id}: {secret}"
                    );
                    assert!(!result.capped);
                    assert!(result.warnings.is_empty());
                }
            }
        }
        plant(&home.0, ".cline/data/no.md");
        plant(&home.0, ".codeium/other/no.md");
        let report = scan(&home.0, &Environment::new(), Platform::Linux);
        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), REGISTRY.len() + 2);
    }

    #[test]
    fn obsidian_config_uses_platform_directories_and_deduplicates_vaults() {
        let home = Home::new();
        let custom = home.0.join("custom");
        let env = Environment::from([
            ("XDG_CONFIG_HOME".into(), custom.as_os_str().to_owned()),
            ("APPDATA".into(), custom.as_os_str().to_owned()),
        ]);
        for platform in [Platform::Linux, Platform::Windows] {
            assert_eq!(
                obsidian_config_path(&home.0, &env, platform),
                Some(custom.join("obsidian/obsidian.json"))
            );
        }
        assert_eq!(
            obsidian_config_path(&home.0, &env, Platform::MacOs),
            Some(
                home.0
                    .join("Library/Application Support/obsidian/obsidian.json")
            )
        );
        assert_eq!(obsidian_config_path(&home.0, &env, Platform::Other), None);
        assert_eq!(
            obsidian_config_path(&home.0, &Environment::new(), Platform::Windows),
            Some(home.0.join("AppData/Roaming/obsidian/obsidian.json"))
        );
        let a = home.0.join("vault-a");
        let b = home.0.join("vault-b");
        vault_config(
            &home.0,
            serde_json::json!({"a": {"path": a}, "duplicate": {"path": a}, "b": {"path": b}}),
        );
        plant(&a, "a.md");
        plant(&b, "b.md");
        let report = scan(&home.0, &Environment::new(), Platform::Linux);
        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 2);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|row| &row.root)
                .collect::<Vec<_>>(),
            vec![&a, &b]
        );
        assert!(report.findings.iter().all(|row| row.file_count == 1));
    }

    #[test]
    fn invalid_config_does_not_hide_other_assistants() {
        let home = Home::new();
        plant(&home.0, ".pi/agent/AGENTS.md");
        let config = obsidian_config_path(&home.0, &Environment::new(), Platform::Linux).unwrap();
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        for invalid in [
            "{",
            "{}",
            "{\"vaults\":{\"a\":{\"path\":\"\"}}}",
            "{\"vaults\":{\"a\":{\"path\":\"relative\"}}}",
        ] {
            fs::write(&config, invalid).unwrap();
            let report = scan(&home.0, &Environment::new(), Platform::Linux);
            assert_eq!(report.errors.len(), 1);
            assert_eq!(report.errors[0].assistant_id, "obsidian");
            assert_eq!(report.findings.len(), 1);
            assert_eq!(report.findings[0].assistant_id, "pi");
        }
        fs::File::create(&config)
            .unwrap()
            .set_len(MAX_CONFIG_BYTES + 1)
            .unwrap();
        assert!(obsidian_vaults(&config).is_err());
        vault_config(&home.0, serde_json::json!({}));
        assert!(obsidian_vaults(&config).unwrap().is_empty());
    }

    #[test]
    fn empty_missing_and_repository_roots_do_not_create_counts() {
        let home = Home::new();
        assert!(scan(&home.0, &Environment::new(), Platform::Linux)
            .findings
            .is_empty());
        let root = home.0.join(".pi/agent");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(finding("pi", &root).file_count, 0);
        plant(&root, "skills/repo/.git");
        plant(&root, "skills/repo/SKILL.md");
        plant(&root, "AGENTS.md");
        assert_eq!(finding("pi", &root).file_count, 1);
        fs::create_dir(root.join(".git")).unwrap();
        assert_eq!(finding("pi", &root).file_count, 0);
        plant(&root, "docs/nested/note.md");
        assert_eq!(finding("obsidian", &root.join("docs/nested")).file_count, 0);
    }

    #[test]
    fn root_types_and_file_root_repositories_do_not_expand_the_scan() {
        let home = Home::new();
        let amp = home.0.join(".config/AGENTS.md");
        fs::create_dir_all(&amp).unwrap();
        plant(&amp, "AGENTS.md");
        assert!(scan_root(assistant("amp"), &amp, LIMITS, &mut || false).is_none());
        let file = home.0.join("vault.md");
        fs::write(&file, b"note").unwrap();
        assert!(scan_root(assistant("obsidian"), &file, LIMITS, &mut || false).is_none());
        fs::remove_dir_all(&amp).unwrap();
        plant(&home.0, ".config/AGENTS.md");
        plant(&home.0, ".config/.git");
        assert_eq!(finding("amp", &amp).file_count, 0);
        fs::remove_file(home.0.join(".config/.git")).unwrap();
        let mut calls = 0;
        let result = scan_root(assistant("amp"), &amp, LIMITS, &mut || {
            calls += 1;
            calls >= 2
        })
        .unwrap();
        assert!(result.capped);
        assert_eq!(result.file_count, 0);
    }

    #[test]
    fn budgets_reset_for_each_root_and_zero_budget_counts_nothing() {
        let home = Home::new();
        plant(&home.0, "one.md");
        plant(&home.0, "two.md");
        for _ in 0..2 {
            let result = scan_root(
                assistant("obsidian"),
                &home.0,
                Limits {
                    entries: 1,
                    ..LIMITS
                },
                &mut || false,
            )
            .unwrap();
            assert_eq!(result.file_count, 1);
            assert_eq!(result.warnings, vec![ScanWarning::FileCap]);
        }
        let result = scan_root(
            assistant("obsidian"),
            &home.0,
            Limits {
                entries: 0,
                ..LIMITS
            },
            &mut || false,
        )
        .unwrap();
        assert_eq!(result.file_count, 0);
        assert!(result.capped);
    }

    #[test]
    fn depth_cap_counts_depth_six_but_not_seven() {
        let home = Home::new();
        plant(&home.0, "a/b/c/d/e/six.md");
        plant(&home.0, "a/b/c/d/e/f/seven.md");
        let result = finding("obsidian", &home.0);
        assert_eq!(result.file_count, 1);
        assert_eq!(result.byte_total, 6);
        assert!(result.capped);
        assert_eq!(result.warnings, vec![ScanWarning::DepthCap]);
    }

    #[test]
    fn file_cap_bounds_wide_trees_including_uncounted_entries() {
        let home = Home::new();
        for i in 0..=LIMITS.entries {
            plant(&home.0, &format!("{i}.md"));
        }
        let result = finding("obsidian", &home.0);
        assert_eq!(result.file_count, LIMITS.entries as u64);
        assert_eq!(result.byte_total, LIMITS.entries as u64 * 6);
        assert_eq!(result.warnings, vec![ScanWarning::FileCap]);
        assert!(result.capped);
        let result = scan_root(assistant("pi"), &home.0, LIMITS, &mut || false).unwrap();
        assert_eq!(result.file_count, 0);
        assert!(result.capped);
    }

    #[test]
    fn time_cap_stops_before_and_during_a_walk() {
        let home = Home::new();
        plant(&home.0, "one.md");
        plant(&home.0, "two.md");
        let result = scan_root(assistant("obsidian"), &home.0, LIMITS, &mut || true).unwrap();
        assert_eq!(result.file_count, 0);
        assert_eq!(result.warnings, vec![ScanWarning::TimeCap]);
        assert!(result.capped);
        let mut calls = 0;
        let result = scan_root(assistant("obsidian"), &home.0, LIMITS, &mut || {
            calls += 1;
            calls >= 5 + home.0.parent().unwrap().ancestors().count()
        })
        .unwrap();
        assert_eq!(result.file_count, 1);
        assert_eq!(result.warnings, vec![ScanWarning::TimeCap]);
        assert_eq!(LIMITS.time, Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn scan_skips_symlinks_and_counts_unreadable_bodies_from_metadata() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = Home::new();
        let root = home.0.join("root");
        let outside = home.0.join("outside");
        plant(&root, "note.md");
        fs::set_permissions(root.join("note.md"), fs::Permissions::from_mode(0o0)).unwrap();
        plant(&outside, "secret.md");
        symlink(&outside, root.join("linked-dir")).unwrap();
        symlink(outside.join("secret.md"), root.join("linked.md")).unwrap();
        symlink(&root, root.join("loop")).unwrap();
        let result = finding("obsidian", &root);
        assert_eq!(result.file_count, 1);
        assert_eq!(result.byte_total, 6);
        assert!(!result.capped);
        assert!(scan_root(
            assistant("obsidian"),
            &root.join("linked-dir"),
            LIMITS,
            &mut || false
        )
        .is_none());
        let config = home.0.join("obsidian.json");
        symlink(outside.join("secret.md"), &config).unwrap();
        assert!(obsidian_vaults(&config).is_err());
    }

    #[test]
    fn globs_keep_directory_and_recursive_scopes_distinct() {
        for (pattern, yes, no) in [
            ("rules/*.md", "rules/a.md", "rules/a/b.md"),
            ("agent-memory/**/*.md", "agent-memory/a.md", "other/a.md"),
            ("skills/*/", "skills/tool/deep/file.txt", "skills/root.md"),
            (
                "prompts/",
                "prompts/deep/file.txt",
                "other/prompts/file.txt",
            ),
            ("**/*.md", "root.md", "root.json"),
        ] {
            assert!(glob(pattern, yes), "{pattern}: {yes}");
            assert!(!glob(pattern, no), "{pattern}: {no}");
        }
    }
}
