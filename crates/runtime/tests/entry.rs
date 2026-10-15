#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::linux::AttachFilesystem;
use muniment_runtime_core::{
    run_runtime, AttachListenerError, RunRuntimeError, RuntimeDirectories, RuntimeHost,
};

mod common;
use common::TemporaryProfile;

#[test]
fn serves_the_endpoint_until_stop_and_refuses_a_second_runtime() {
    let profile = TemporaryProfile::new("entry", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let directories = RuntimeDirectories {
        profile: profile.profile.clone(),
        config: profile.config.clone(),
        endpoint: profile.root.clone(),
    };
    let endpoint = AttachFilesystem::from_runtime_directory(&profile.root)
        .unwrap()
        .endpoint_path()
        .to_owned();
    let (stop_tx, stop_rx) = mpsc::channel();

    thread::scope(|scope| {
        let runtime =
            scope.spawn(|| run_runtime(RuntimeHost::default(), &directories, None, stop_rx));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !endpoint.exists() {
            assert!(Instant::now() < deadline, "the runtime binds its endpoint");
            thread::sleep(Duration::from_millis(10));
        }

        let (_second_stop, second_stop_rx) = mpsc::channel();
        assert_eq!(
            run_runtime(RuntimeHost::default(), &directories, None, second_stop_rx),
            Err(RunRuntimeError::Listener(AttachListenerError::InstanceLock))
        );

        stop_tx.send(()).unwrap();
        assert_eq!(runtime.join().unwrap(), Ok(()));
    });
}
