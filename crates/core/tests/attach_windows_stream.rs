#![cfg(target_os = "windows")]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::{
    encode_frame, read_exact_before, write_all_before, ApprovalPresenterStopHandle,
    WindowsAttachListener, WindowsAttachStopEvent,
};
use serde_json::json;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_PIPE_CONNECTED};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::IO::OVERLAPPED;

static WINDOWS_ATTACH_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn moves_frames_times_out_cleanly_and_reports_peer_close() {
    let _test_lock = WINDOWS_ATTACH_TEST_LOCK.lock().unwrap();
    let state_directory = std::env::temp_dir().join(format!(
        "muniment-windows-stream-test-{}",
        std::process::id()
    ));
    let listener = WindowsAttachListener::bind(state_directory, Duration::ZERO).unwrap();
    let request = encode_frame(&json!({ "message": "hello" })).unwrap();
    let response = encode_frame(&json!({ "message": "welcome" })).unwrap();
    let expected_request = request.clone();
    let expected_response = response.clone();
    let path = listener.path().to_owned();
    let (connected_sender, connected_receiver) = mpsc::channel();
    let (timed_out_sender, timed_out_receiver) = mpsc::channel();

    let client = thread::spawn(move || {
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        connected_sender.send(()).unwrap();
        pipe.write_all(&request).unwrap();
        let mut received = vec![0; response.len()];
        pipe.read_exact(&mut received).unwrap();
        assert_eq!(received, response);
        timed_out_receiver.recv().unwrap();
        pipe.write_all(b"next").unwrap();
    });

    connected_receiver.recv().unwrap();
    let mut overlapped = OVERLAPPED::default();
    let connected = unsafe { ConnectNamedPipe(listener.handle().as_raw_handle(), &mut overlapped) };
    assert!(connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);
    let mut stream = listener.into_stream();

    let mut received = vec![0; expected_request.len()];
    read_exact_before(
        &mut stream,
        &mut received,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(received, expected_request);
    write_all_before(
        &mut stream,
        &expected_response,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();

    let mut later = [0; 4];
    let error = read_exact_before(
        &mut stream,
        &mut later,
        Instant::now() + Duration::from_millis(20),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    timed_out_sender.send(()).unwrap();
    read_exact_before(
        &mut stream,
        &mut later,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(&later, b"next");

    client.join().unwrap();
    let mut byte = [0];
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
}

#[test]
fn approval_presenter_stop_exits_the_admitted_idle_supervisor() {
    let _test_lock = WINDOWS_ATTACH_TEST_LOCK.lock().unwrap();
    let state_directory = std::env::temp_dir().join(format!(
        "muniment-windows-presenter-stop-test-{}",
        std::process::id()
    ));
    let listener = WindowsAttachListener::bind(state_directory, Duration::ZERO).unwrap();
    let path = listener.path().to_owned();
    let (connected_sender, connected_receiver) = mpsc::channel();
    let (close_sender, close_receiver) = mpsc::channel();
    let peer = thread::spawn(move || {
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        connected_sender.send(()).unwrap();
        let mut prefix = [0; 4];
        pipe.read_exact(&mut prefix).unwrap();
        let mut hello = vec![0; u32::from_be_bytes(prefix) as usize];
        pipe.read_exact(&mut hello).unwrap();
        pipe.write_all(
            &encode_frame(&muniment_attach::reconnect_welcome(
                1,
                "runtime-1",
                "11".repeat(16),
                "",
            ))
            .unwrap(),
        )
        .unwrap();
        pipe.write_all(
            &encode_frame(&muniment_attach::PeerAuthorizedGrant {
                capability: "33".repeat(32),
                expires_at: 60,
                idle_timeout_seconds: 30,
            })
            .unwrap(),
        )
        .unwrap();
        close_receiver.recv().unwrap();
    });

    connected_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let mut overlapped = OVERLAPPED::default();
    let connected = unsafe { ConnectNamedPipe(listener.handle().as_raw_handle(), &mut overlapped) };
    assert!(connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);
    let stop_event = Arc::new(WindowsAttachStopEvent::new().unwrap());
    let stop = ApprovalPresenterStopHandle::new();
    assert!(stop.register_shutdown({
        let stop_event = Arc::clone(&stop_event);
        move || stop_event.signal().unwrap()
    }));
    let mut stream = listener.into_stream();
    stream.set_stop_event(stop_event);
    let (pending_sender, pending_receiver) = mpsc::channel();
    stream.set_operation_pending_sender_for_tests(pending_sender);
    let mut presenter = Some(
        muniment_attach::handshake_approval_presenter(
            Box::new(stream),
            "1.2.3",
            Duration::from_secs(5),
        )
        .unwrap(),
    );
    // Discard handshake notifications so the next notification proves the idle read has started.
    for _ in pending_receiver.try_iter() {}
    let (exit_sender, exit_receiver) = mpsc::channel();
    let supervisor_stop = stop.clone();
    let supervisor = thread::spawn(move || {
        let mut observed = Vec::new();
        muniment_attach::serve_approval_presenter_with(
            || {
                Some(
                    presenter
                        .take()
                        .expect("the supervisor must not reconnect after stop"),
                )
            },
            supervisor_stop,
            Duration::from_secs(5),
            |connected| observed.push(connected),
            |_| panic!("the idle presenter must not receive an approval request"),
        );
        exit_sender.send(observed).unwrap();
    });
    pending_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let started = Instant::now();
    stop.stop();
    assert_eq!(
        exit_receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
        [true, false]
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    supervisor.join().unwrap();
    // Keep the peer open until the supervisor exits so only the stop event closes the session.
    close_sender.send(()).unwrap();
    peer.join().unwrap();
}

#[test]
fn approval_presenter_stop_interrupts_blocked_and_later_reads() {
    let _test_lock = WINDOWS_ATTACH_TEST_LOCK.lock().unwrap();
    let state_directory = std::env::temp_dir().join(format!(
        "muniment-windows-stream-stop-test-{}",
        std::process::id()
    ));
    let listener = WindowsAttachListener::bind(state_directory, Duration::ZERO).unwrap();
    let path = listener.path().to_owned();
    let (connected_sender, connected_receiver) = mpsc::channel();
    let (close_sender, close_receiver) = mpsc::channel();

    let client = thread::spawn(move || {
        let _pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        connected_sender.send(()).unwrap();
        close_receiver.recv().unwrap();
    });

    connected_receiver.recv().unwrap();
    let mut overlapped = OVERLAPPED::default();
    let connected = unsafe { ConnectNamedPipe(listener.handle().as_raw_handle(), &mut overlapped) };
    assert!(connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);

    let stop_event = Arc::new(WindowsAttachStopEvent::new().unwrap());
    let stop = ApprovalPresenterStopHandle::new();
    let signal_event = Arc::clone(&stop_event);
    assert!(stop.register_shutdown(move || {
        signal_event.signal().unwrap();
    }));
    let mut stream = listener.into_stream();
    stream.set_stop_event(Arc::clone(&stop_event));
    let (operation_pending_sender, operation_pending_receiver) = mpsc::channel();
    stream.set_operation_pending_sender_for_tests(operation_pending_sender);
    let reader = thread::spawn(move || {
        let started = Instant::now();
        let first_error =
            read_exact_before(&mut stream, &mut [0], started + Duration::from_secs(5)).unwrap_err();
        let first_elapsed = started.elapsed();

        let started = Instant::now();
        let second_error =
            read_exact_before(&mut stream, &mut [0], started + Duration::from_secs(5)).unwrap_err();
        let second_elapsed = started.elapsed();
        let started = Instant::now();
        let write_error =
            write_all_before(&mut stream, &[0], started + Duration::from_secs(5)).unwrap_err();
        assert_eq!(write_error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(started.elapsed() < Duration::from_secs(1));
        (
            first_error.kind(),
            first_elapsed,
            second_error.kind(),
            second_elapsed,
        )
    });

    operation_pending_receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let signaler = thread::spawn(move || stop.stop());

    let (first_kind, first_elapsed, second_kind, second_elapsed) = reader.join().unwrap();
    signaler.join().unwrap();
    assert_eq!(first_kind, std::io::ErrorKind::ConnectionAborted);
    assert!(first_elapsed < Duration::from_secs(1));
    assert_eq!(second_kind, std::io::ErrorKind::ConnectionAborted);
    assert!(second_elapsed < Duration::from_secs(1));

    close_sender.send(()).unwrap();
    client.join().unwrap();
}
