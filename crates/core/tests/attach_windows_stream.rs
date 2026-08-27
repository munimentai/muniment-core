#![cfg(target_os = "windows")]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::attach::{
    encode_frame, read_exact_before, write_all_before, WindowsAttachListener,
};
use serde_json::json;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_PIPE_CONNECTED};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::IO::OVERLAPPED;

#[test]
fn moves_frames_times_out_cleanly_and_reports_peer_close() {
    let listener = WindowsAttachListener::bind().unwrap();
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
