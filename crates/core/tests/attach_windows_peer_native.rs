#![cfg(target_os = "windows")]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::sync::mpsc;
use std::thread;

use muniment_core::attach::{verify_windows_attach_peer, WindowsAttachListener};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_PIPE_CONNECTED};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;

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

    let connected = unsafe { ConnectNamedPipe(listener.handle().as_raw_handle(), null_mut()) };
    assert!(connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED);

    let mut byte: u8 = 0;
    let mut bytes_read = 0;
    assert_ne!(
        unsafe {
            ReadFile(
                listener.handle().as_raw_handle(),
                &mut byte,
                1,
                &mut bytes_read,
                null_mut(),
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
