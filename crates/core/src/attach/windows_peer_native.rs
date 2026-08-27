use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use super::{
    verify_windows_attach_peer_with_reader, WindowsAttachPeerReader, WindowsPeerError,
    WindowsPeerReadError,
};
use crate::windows_sid::{copy_sid_bytes, current_process_user_sid};

/// Reads Windows attach peer identity from a connected named pipe.
pub struct NativeWindowsAttachPeerReader<'pipe> {
    pipe: BorrowedHandle<'pipe>,
}

impl<'pipe> NativeWindowsAttachPeerReader<'pipe> {
    /// Creates a peer reader for the borrowed server pipe handle.
    pub fn new(pipe: BorrowedHandle<'pipe>) -> Self {
        Self { pipe }
    }

    fn read_connected_peer_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
        if unsafe { ImpersonateNamedPipeClient(self.pipe.as_raw_handle()) } == 0 {
            return Err(WindowsPeerReadError);
        }

        let sid = read_thread_token_user_sid();
        let reverted = unsafe { RevertToSelf() };
        if reverted == 0 {
            return Err(WindowsPeerReadError);
        }
        sid
    }
}

/// Verifies the connected peer on a borrowed server pipe handle.
pub fn verify_windows_attach_peer(pipe: BorrowedHandle<'_>) -> Result<(), WindowsPeerError> {
    verify_windows_attach_peer_with_reader(&NativeWindowsAttachPeerReader::new(pipe))
}

impl WindowsAttachPeerReader for NativeWindowsAttachPeerReader<'_> {
    fn connected_peer_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
        self.read_connected_peer_sid()
    }

    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPeerReadError> {
        current_process_user_sid()
            .map(|sid| sid.as_bytes().to_vec())
            .map_err(|_| WindowsPeerReadError)
    }
}

fn read_thread_token_user_sid() -> Result<Vec<u8>, WindowsPeerReadError> {
    let mut token = null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0 {
        return Err(WindowsPeerReadError);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };

    let mut length = 0;
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length) };
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || length < size_of::<TOKEN_USER>() as u32
    {
        return Err(WindowsPeerReadError);
    }

    let mut token_user = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_user.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
        || length < size_of::<TOKEN_USER>() as u32
    {
        return Err(WindowsPeerReadError);
    }

    let sid = unsafe { (*(token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    copy_sid_bytes(sid).ok_or(WindowsPeerReadError)
}
