#![cfg(target_os = "windows")]

use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::thread_service::ThreadListService;
use muniment_core::attach::{
    decode_frame, fail_next_windows_attach_pipe_instance_for_tests, serve_next_windows_attach,
    serve_next_windows_attach_until, windows_attach_pipe_path, Welcome, WindowsAttachAcceptError,
    WindowsAttachAcceptOutcome, WindowsAttachBindError, WindowsAttachInstanceLockError,
    WindowsAttachListener, WindowsAttachServeOutcome, WindowsAttachStopEvent,
};
use muniment_core::windows_sid::current_process_user_sid;

struct EmptyService;

impl ThreadListService for EmptyService {}

fn service_factory() -> Result<EmptyService, Infallible> {
    Ok(EmptyService)
}

static LISTENER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn state_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-windows-listener-test-{}",
        std::process::id()
    ))
}

fn bind_listener() -> WindowsAttachListener {
    WindowsAttachListener::bind(state_directory(), Duration::ZERO).unwrap()
}

fn hello_frame() -> Vec<u8> {
    let body = br#"{"protocol":"muniment.attach/1","client":{"kind":"editor-extension","version":"0.0.1"},"supported":{"min":1,"max":1},"client_nonce":"nonce","authorized_client_id":"018f0000-0000-7000-8000-000000000099"}"#;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn connect_and_serve(listener: &mut WindowsAttachListener, path: String) -> File {
    let client = thread::spawn(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    });
    serve_next_windows_attach(
        listener,
        "1.2.3",
        Instant::now() + Duration::from_secs(1),
        Arc::new(service_factory),
    )
    .unwrap();
    client.join().unwrap()
}

fn open_client_with_retry(path: String) -> File {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(client) => return client,
            Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("could not open the recovered pipe: {error}"),
        }
    }
}

fn exchange_hello(client: &mut File) -> Welcome {
    client.write_all(&hello_frame()).unwrap();
    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; 4 + length];
    response[..4].copy_from_slice(&prefix);
    client.read_exact(&mut response[4..]).unwrap();
    let (welcome, consumed) = decode_frame::<Welcome>(&response).unwrap().unwrap();
    assert_eq!(consumed, response.len());
    welcome
}

#[test]
fn binds_the_current_user_pipe_and_rejects_a_second_listener() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let listener = bind_listener();
    let expected_path =
        windows_attach_pipe_path(current_process_user_sid().unwrap().as_str()).unwrap();

    assert_eq!(listener.path(), expected_path);
    assert!(matches!(
        WindowsAttachListener::bind(state_directory(), Duration::ZERO),
        Err(WindowsAttachBindError::InstanceLock(
            WindowsAttachInstanceLockError::Contended
        ))
    ));
    assert!(matches!(
        WindowsAttachListener::bind(
            state_directory().with_extension("other-profile"),
            Duration::ZERO
        ),
        Err(WindowsAttachBindError::Pipe(_))
    ));

    drop(listener);
    assert!(WindowsAttachListener::bind(state_directory(), Duration::ZERO).is_ok());
}

#[test]
fn serve_next_until_reports_an_already_signaled_stop() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let stop = Arc::new(WindowsAttachStopEvent::new().unwrap());
    stop.signal().unwrap();

    assert_eq!(
        serve_next_windows_attach_until(&mut listener, "1.2.3", &stop, Arc::new(service_factory),)
            .unwrap(),
        WindowsAttachServeOutcome::Stopped
    );
}

#[test]
fn serve_next_until_stop_closes_the_worker_connection() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let stop = Arc::new(WindowsAttachStopEvent::new().unwrap());
    let path = listener.path().to_owned();
    let client = thread::spawn(move || open_client_with_retry(path));

    assert_eq!(
        serve_next_windows_attach_until(&mut listener, "1.2.3", &stop, Arc::new(service_factory),)
            .unwrap(),
        WindowsAttachServeOutcome::Served
    );
    let mut client = client.join().unwrap();
    let signaler = thread::spawn(move || stop.signal().unwrap());
    let (read_sender, read_receiver) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        let mut byte = [0];
        read_sender.send(client.read(&mut byte)).unwrap();
    });

    assert_eq!(
        read_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("the worker connection did not close after stop")
            .unwrap(),
        0
    );
    signaler.join().unwrap();
    reader.join().unwrap();
}

#[test]
fn accept_until_stops_when_already_signaled_and_accepts_afterward() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let stop = WindowsAttachStopEvent::new().unwrap();
    stop.signal().unwrap();

    assert!(matches!(
        listener.accept_until(&stop).unwrap(),
        WindowsAttachAcceptOutcome::Stopped
    ));

    let next_stop = WindowsAttachStopEvent::new().unwrap();
    let path = listener.path().to_owned();
    let client = thread::spawn(move || open_client_with_retry(path));
    let stream = match listener.accept_until(&next_stop).unwrap() {
        WindowsAttachAcceptOutcome::Connected(stream) => stream,
        WindowsAttachAcceptOutcome::Stopped => panic!("the accept stopped unexpectedly"),
    };
    drop((stream, client.join().unwrap()));
}

#[test]
fn accept_until_stops_when_signaled_during_the_wait() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let stop = Arc::new(WindowsAttachStopEvent::new().unwrap());
    let signaler = thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            thread::sleep(Duration::from_millis(20));
            stop.signal().unwrap();
        }
    });

    assert!(matches!(
        listener.accept_until(&stop).unwrap(),
        WindowsAttachAcceptOutcome::Stopped
    ));
    signaler.join().unwrap();

    let next_stop = WindowsAttachStopEvent::new().unwrap();
    let path = listener.path().to_owned();
    let client = thread::spawn(move || open_client_with_retry(path));
    let stream = match listener.accept_until(&next_stop).unwrap() {
        WindowsAttachAcceptOutcome::Connected(stream) => stream,
        WindowsAttachAcceptOutcome::Stopped => panic!("the accept stopped unexpectedly"),
    };
    drop((stream, client.join().unwrap()));
}

#[test]
fn accept_until_accepts_two_clients() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let stop = WindowsAttachStopEvent::new().unwrap();
    let path = listener.path().to_owned();

    let first_client = thread::spawn({
        let path = path.clone();
        move || open_client_with_retry(path)
    });
    let first_stream = match listener.accept_until(&stop).unwrap() {
        WindowsAttachAcceptOutcome::Connected(stream) => stream,
        WindowsAttachAcceptOutcome::Stopped => panic!("the first accept stopped unexpectedly"),
    };
    let first_client = first_client.join().unwrap();

    let second_client = thread::spawn(move || open_client_with_retry(path));
    let second_stream = match listener.accept_until(&stop).unwrap() {
        WindowsAttachAcceptOutcome::Connected(stream) => stream,
        WindowsAttachAcceptOutcome::Stopped => panic!("the second accept stopped unexpectedly"),
    };
    let second_client = second_client.join().unwrap();

    drop((first_stream, first_client, second_stream, second_client));
}

#[test]
fn accepts_two_clients_while_both_connections_stay_open() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let path = listener.path().to_owned();
    let first_client = thread::spawn({
        let path = path.clone();
        move || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap()
        }
    });
    let first_stream = listener
        .accept(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let first_client = first_client.join().unwrap();

    assert_eq!(listener.path(), path);
    let _unconnected_handle = listener.handle();
    let second_client = thread::spawn(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    });
    let second_stream = listener
        .accept(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let second_client = second_client.join().unwrap();

    drop((first_stream, first_client, second_stream, second_client));
}

#[test]
fn recovers_after_replacement_creation_fails() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let path = listener.path().to_owned();
    let first_client = thread::spawn({
        let path = path.clone();
        move || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap()
        }
    });

    fail_next_windows_attach_pipe_instance_for_tests();
    serve_next_windows_attach(
        &mut listener,
        "1.2.3",
        Instant::now() + Duration::from_secs(1),
        Arc::new(service_factory),
    )
    .unwrap();
    let mut first_client = first_client.join().unwrap();
    assert_eq!(exchange_hello(&mut first_client).desktop_version, "1.2.3");

    let second_client = thread::spawn(move || open_client_with_retry(path));
    serve_next_windows_attach(
        &mut listener,
        "1.2.3",
        Instant::now() + Duration::from_secs(1),
        Arc::new(service_factory),
    )
    .unwrap();
    let mut second_client = second_client.join().unwrap();
    assert_eq!(exchange_hello(&mut second_client).desktop_version, "1.2.3");
}

#[test]
fn serves_two_sequential_clients_on_independent_threads() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();
    let path = listener.path().to_owned();

    let mut first_client = connect_and_serve(&mut listener, path.clone());
    let mut second_client = connect_and_serve(&mut listener, path);

    let second_welcome = exchange_hello(&mut second_client);
    let first_welcome = exchange_hello(&mut first_client);
    assert_eq!(first_welcome.desktop_version, "1.2.3");
    assert_eq!(second_welcome.desktop_version, "1.2.3");
}

#[test]
fn serve_next_returns_the_accept_error() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();

    assert_eq!(
        serve_next_windows_attach(
            &mut listener,
            "1.2.3",
            Instant::now(),
            Arc::new(service_factory),
        ),
        Err(WindowsAttachAcceptError::DeadlineExpired)
    );
}

#[test]
fn expires_the_deadline_and_keeps_the_listener_bound() {
    let _guard = LISTENER_TEST_LOCK.lock().unwrap();
    let mut listener = bind_listener();

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
