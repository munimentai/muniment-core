#![cfg(target_os = "windows")]

use std::fs::OpenOptions;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::{
    windows_attach_pipe_path, WindowsAttachAcceptError, WindowsAttachListener,
};
use muniment_core::windows_sid::current_process_user_sid;

static LISTENER_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn binds_the_current_user_pipe_and_rejects_a_second_listener() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let listener = WindowsAttachListener::bind().unwrap();
    let expected_path =
        windows_attach_pipe_path(current_process_user_sid().unwrap().as_str()).unwrap();

    assert_eq!(listener.path(), expected_path);
    assert!(WindowsAttachListener::bind().is_err());
}

#[test]
fn accepts_one_connected_client() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = WindowsAttachListener::bind().unwrap();
    let path = listener.path().to_owned();
    let client = thread::spawn(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    });

    let stream = listener
        .accept(Instant::now() + Duration::from_secs(1))
        .unwrap();

    drop(stream);
    drop(client.join().unwrap());
}

#[test]
fn expires_the_deadline_and_keeps_the_listener_bound() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = WindowsAttachListener::bind().unwrap();

    let error = match listener.accept(Instant::now() + Duration::from_millis(20)) {
        Ok(_) => panic!("the accept deadline did not expire"),
        Err(error) => error,
    };
    assert_eq!(error, WindowsAttachAcceptError::DeadlineExpired);

    let path = listener.path().to_owned();
    let client = thread::spawn(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    });
    let stream = listener
        .accept(Instant::now() + Duration::from_secs(1))
        .unwrap();

    drop(stream);
    drop(client.join().unwrap());
}
