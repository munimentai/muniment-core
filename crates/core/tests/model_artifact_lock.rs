use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::model_install::{InstallLock, InstallLockState};
use muniment_core::model_install_native::NativeInstallLock;

const CHILD_ROOT: &str = "MUNIMENT_MODEL_LOCK_CHILD_ROOT";

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child process timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn lock_holder_process() {
    let Some(root) = std::env::var_os(CHILD_ROOT).map(PathBuf::from) else {
        return;
    };
    let mut lock = NativeInstallLock::new(root.join("install.lock"));
    let _guard = match lock.try_lock_exclusive().unwrap() {
        InstallLockState::Acquired(guard) => guard,
        InstallLockState::Contended => panic!("child process could not acquire the install lock"),
    };
    fs::create_dir(root.join("staging-holder")).unwrap();
    fs::write(root.join("ready"), b"ready").unwrap();
    wait_for(&root.join("release"));
}

#[test]
fn install_lock_prevents_two_processes_from_staging_the_same_artifact() {
    let root = std::env::temp_dir().join(format!(
        "muniment-model-process-lock-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("lock_holder_process")
        .arg("--nocapture")
        .env(CHILD_ROOT, &root)
        .spawn()
        .unwrap();
    wait_for(&root.join("ready"));

    let mut contender = NativeInstallLock::new(root.join("install.lock"));
    assert!(matches!(
        contender.try_lock_exclusive().unwrap(),
        InstallLockState::Contended
    ));
    assert!(!root.join("staging-contender").exists());

    fs::write(root.join("release"), b"release").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(matches!(
        contender.try_lock_exclusive().unwrap(),
        InstallLockState::Acquired(_)
    ));
    fs::remove_dir_all(root).unwrap();
}
