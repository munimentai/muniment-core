use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{WindowsAttachRouteReader, WindowsPeerReadError};

/// Reads the connected peer process from a borrowed server pipe handle.
pub struct NativeWindowsAttachRouteReader<'pipe> {
    pipe: BorrowedHandle<'pipe>,
}

impl<'pipe> NativeWindowsAttachRouteReader<'pipe> {
    /// Creates a route reader for the borrowed server pipe handle.
    pub fn new(pipe: BorrowedHandle<'pipe>) -> Self {
        Self { pipe }
    }
}

impl WindowsAttachRouteReader for NativeWindowsAttachRouteReader<'_> {
    fn peer_process(&self) -> Result<(u32, PathBuf), WindowsPeerReadError> {
        let mut process_id = 0;
        if unsafe { GetNamedPipeClientProcessId(self.pipe.as_raw_handle(), &mut process_id) } == 0 {
            return Err(WindowsPeerReadError);
        }

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return Err(WindowsPeerReadError);
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process) };

        let mut buffer = vec![0u16; MAX_PATH as usize];
        loop {
            let mut length = u32::try_from(buffer.len()).map_err(|_| WindowsPeerReadError)?;
            if unsafe {
                QueryFullProcessImageNameW(
                    process.as_raw_handle(),
                    0,
                    buffer.as_mut_ptr(),
                    &mut length,
                )
            } != 0
            {
                buffer.truncate(length as usize);
                return Ok((process_id, OsString::from_wide(&buffer).into()));
            }
            if buffer.len() >= 32_768 {
                return Err(WindowsPeerReadError);
            }
            buffer.resize((buffer.len() * 2).min(32_768), 0);
        }
    }
}
