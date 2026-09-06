//! The candidate acquires packages through the verified Pi executable's embedded Bun runtime.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde_json::Value;

pub const PI_PACKAGES: [(&str, &str); 4] = [
    ("pi-web-access", "0.28.0"),
    ("pi-subagents", "0.65.1"),
    ("pi-background-tasks", "2.5.0"),
    ("pi-mcp-adapter", "2.32.1"),
];

fn installed(directory: &Path) -> bool {
    PI_PACKAGES.iter().all(|(name, version)| {
        fs::read(
            directory
                .join("node_modules")
                .join(name)
                .join("package.json"),
        )
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|manifest| manifest["version"] == *version)
    })
}

fn install_command(executable: &Path, directory: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        // Bun's documented BUN_BE_BUN switch exposes the embedded package manager.
        // Scope it to acquisition. The RPC process must run Pi's entrypoint.
        .env("BUN_BE_BUN", "1")
        .arg("install")
        .args(
            PI_PACKAGES
                .iter()
                .map(|(name, version)| format!("{name}@{version}")),
        )
        .args(["--omit=peer", "--ignore-scripts", "--exact", "--cwd"])
        .arg(directory)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn run_install(command: &mut Command, timeout: Duration) -> io::Result<()> {
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(io::Error::other("Pi package acquisition failed.")),
            Err(error) => break Err(error),
            Ok(None) if Instant::now() >= deadline => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Pi package acquisition timed out.",
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// Acquire packages before RPC starts. The caller supplies the verified candidate executable.
pub fn prepare_pi_packages(agent_directory: &Path, executable: &Path) -> io::Result<()> {
    let directory = agent_directory.join("npm");
    fs::create_dir_all(&directory)?;
    // An OS lock releases on process death. Never hold Pi's settings lock during network access.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(".muniment-install.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => break,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
    let marker = directory.join(".muniment-packages.json");
    let identity = serde_json::to_vec(&PI_PACKAGES)?;
    if fs::read(&marker).is_ok_and(|bytes| bytes == identity) && installed(&directory) {
        return Ok(());
    }
    // A failed or interrupted install must retry, even if it wrote the top-level manifests.
    match fs::remove_file(&marker) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join("package.json"))
    {
        Ok(mut file) => file.write_all(b"{\"private\":true}")?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    // Resolve relative overrides before --cwd changes Bun's working directory.
    let directory = fs::canonicalize(directory)?;
    run_install(
        &mut install_command(executable, &directory),
        Duration::from_secs(120),
    )?;
    if !installed(&directory) {
        return Err(io::Error::other(
            "Pi package acquisition did not install the pinned versions.",
        ));
    }
    let mut file = fs::File::create(marker)?;
    file.write_all(&identity)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquisition_uses_embedded_bun_without_system_node_or_scripts() {
        let command = install_command(Path::new("/verified/pi"), Path::new("/agent/npm"));
        assert_eq!(command.get_program(), "/verified/pi");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "install",
                "pi-web-access@0.28.0",
                "pi-subagents@0.65.1",
                "pi-background-tasks@2.5.0",
                "pi-mcp-adapter@2.32.1",
                "--omit=peer",
                "--ignore-scripts",
                "--exact",
                "--cwd",
                "/agent/npm"
            ]
        );
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "BUN_BE_BUN" && value == Some("1".as_ref())));
    }

    #[test]
    fn partial_acquisition_retries_and_releases_the_lock() {
        let root = std::env::temp_dir().join(format!("muniment-packages-{}", uuid::Uuid::new_v4()));
        let npm = root.join("npm");
        for (name, version) in PI_PACKAGES {
            let directory = npm.join("node_modules").join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("package.json"),
                format!("{{\"version\":\"{version}\"}}"),
            )
            .unwrap();
        }
        let missing = root.join("missing-executable");
        assert!(prepare_pi_packages(&root, &missing).is_err());
        assert!(prepare_pi_packages(&root, &missing).is_err());
        let marker = npm.join(".muniment-packages.json");
        assert!(!marker.exists());
        fs::write(&marker, serde_json::to_vec(&PI_PACKAGES).unwrap()).unwrap();
        prepare_pi_packages(&root, &missing).unwrap();
        fs::write(npm.join("node_modules/pi-web-access/package.json"), "{}").unwrap();
        assert!(prepare_pi_packages(&root, &missing).is_err());
        assert!(!marker.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
