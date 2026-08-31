#![cfg(target_os = "windows")]

use std::fs::OpenOptions;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use muniment_core::attach::{
    NativeWindowsAttachRouteReader, WindowsAttachListener, WindowsAttachRouteReader,
};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

#[test]
fn reads_the_connected_peer_process() {
    let state_directory = std::env::temp_dir().join(format!(
        "muniment-windows-route-test-{}",
        std::process::id()
    ));
    let listener = WindowsAttachListener::bind(state_directory, Duration::ZERO).unwrap();
    let path = listener.path().to_owned();
    let (release_sender, release_receiver) = mpsc::channel();
    let client = thread::spawn(move || {
        let _pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        release_receiver.recv().unwrap();
    });

    let connect_event = unsafe { CreateEventW(null(), 1, 0, null()) };
    assert!(!connect_event.is_null());
    let connect_event = unsafe { OwnedHandle::from_raw_handle(connect_event) };
    let mut connect_overlapped = OVERLAPPED {
        hEvent: connect_event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    let connected =
        unsafe { ConnectNamedPipe(listener.handle().as_raw_handle(), &mut connect_overlapped) };
    if connected == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_IO_PENDING {
            assert_eq!(
                unsafe { WaitForSingleObject(connect_event.as_raw_handle(), INFINITE) },
                WAIT_OBJECT_0
            );
            let mut transferred = 0;
            assert_ne!(
                unsafe {
                    GetOverlappedResult(
                        listener.handle().as_raw_handle(),
                        &connect_overlapped,
                        &mut transferred,
                        0,
                    )
                },
                0
            );
        } else {
            assert_eq!(error, ERROR_PIPE_CONNECTED);
        }
    }

    let reader = NativeWindowsAttachRouteReader::new(listener.handle());
    assert_eq!(
        reader.peer_process().unwrap(),
        (std::process::id(), std::env::current_exe().unwrap())
    );

    release_sender.send(()).unwrap();
    client.join().unwrap();
}
