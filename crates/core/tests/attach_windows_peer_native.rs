#![cfg(target_os = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::thread;

use muniment_core::attach::{verify_windows_attach_peer, WindowsAttachListener};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

#[test]
fn admits_a_connected_peer_from_the_same_user() {
    let listener = WindowsAttachListener::bind().unwrap();
    let path = listener.path().to_owned();
    let (release_sender, release_receiver) = mpsc::channel();
    let client = thread::spawn(move || {
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        pipe.write_all(&[0x5a]).unwrap();
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

    let read_event = unsafe { CreateEventW(null(), 1, 0, null()) };
    assert!(!read_event.is_null());
    let read_event = unsafe { OwnedHandle::from_raw_handle(read_event) };
    let mut read_overlapped = OVERLAPPED {
        hEvent: read_event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    let mut byte: u8 = 0;
    let read = unsafe {
        ReadFile(
            listener.handle().as_raw_handle(),
            &mut byte,
            1,
            null_mut(),
            &mut read_overlapped,
        )
    };
    if read == 0 {
        assert_eq!(unsafe { GetLastError() }, ERROR_IO_PENDING);
        assert_eq!(
            unsafe { WaitForSingleObject(read_event.as_raw_handle(), INFINITE) },
            WAIT_OBJECT_0
        );
    }
    let mut bytes_read = 0;
    assert_ne!(
        unsafe {
            GetOverlappedResult(
                listener.handle().as_raw_handle(),
                &read_overlapped,
                &mut bytes_read,
                0,
            )
        },
        0
    );
    assert_eq!(bytes_read, 1);
    assert_eq!(byte, 0x5a);
    assert_eq!(verify_windows_attach_peer(listener.handle()), Ok(()));

    release_sender.send(()).unwrap();
    client.join().unwrap();
}
