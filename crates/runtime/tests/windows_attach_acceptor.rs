#![cfg(target_os = "windows")]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use muniment_core::attach::{decode_frame, load_windows_attach_pipe_path, Welcome};
use muniment_core::windows_sid::current_process_user_sid;
use muniment_runtime_core::{
    RuntimeHost, WindowsAttachAcceptBoundary, WindowsAttachAcceptOutcome, WindowsAttachAcceptor,
    WindowsAttachStopSignal,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn state_directory() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "muniment-runtime-windows-attach-acceptor-{}-{timestamp}",
        std::process::id()
    ))
}

fn hello_frame() -> Vec<u8> {
    let body = br#"{"protocol":"muniment.attach/1","client":{"kind":"editor-extension","version":"0.0.1"},"supported":{"min":1,"max":1},"client_nonce":"nonce","authorized_client_id":"018f0000-0000-7000-8000-000000000099"}"#;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn read_welcome(client: &mut File) -> Welcome {
    client.write_all(&hello_frame()).unwrap();
    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; 4 + length];
    response[..4].copy_from_slice(&prefix);
    client.read_exact(&mut response[4..]).unwrap();
    decode_frame::<Welcome>(&response).unwrap().unwrap().0
}

fn remove_state_directory(path: PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::remove_dir_all(&path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) if error.raw_os_error() == Some(32) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("could not remove {}: {error}", path.display()),
        }
    }
}

#[test]
fn binds_and_serves_with_the_host_runtime_version() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    let state_directory = state_directory();
    let host = RuntimeHost {
        runtime_version: "9.8.7",
        ..RuntimeHost::default()
    };
    let mut acceptor = WindowsAttachAcceptor::bind(host, &state_directory, Duration::ZERO).unwrap();

    let path = load_windows_attach_pipe_path(current_process_user_sid().unwrap().as_str()).unwrap();
    let client = thread::spawn(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    });
    assert_eq!(acceptor.serve_next(), WindowsAttachAcceptOutcome::Served);

    let welcome = read_welcome(&mut client.join().unwrap());
    assert_eq!(welcome.desktop_version, "9.8.7");

    drop(acceptor);
    remove_state_directory(state_directory);
}

#[test]
fn a_stop_signal_wakes_the_bound_acceptor() {
    let _test_guard = TEST_LOCK.lock().unwrap();
    let state_directory = state_directory();
    let mut acceptor =
        WindowsAttachAcceptor::bind(RuntimeHost::default(), &state_directory, Duration::ZERO)
            .unwrap();
    let stop = acceptor.stop_signal();
    let signaler = thread::spawn(move || stop.signal());

    assert_eq!(acceptor.serve_next(), WindowsAttachAcceptOutcome::Stopped);
    signaler.join().unwrap();

    drop(acceptor);
    fs::remove_dir_all(state_directory).unwrap();
}
