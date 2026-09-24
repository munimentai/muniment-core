use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_PIPE_BUSY,
    ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

use super::{
    load_windows_attach_pipe_path, verify_windows_endpoint_owner_with_reader,
    WindowsAttachConnectError, WindowsAttachStream, WindowsPipeAccessControlEntry,
    WindowsPipeSecurityError, WindowsPipeSecurityReadError, WindowsPipeSecurityReader,
};
use crate::windows_sid::{copy_sid_bytes, current_process_user_sid};

const ATTACH_ENDPOINT_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Waits for and connects to the current user's Windows attach endpoint.
pub fn wait_for_windows_attach_endpoint(
    deadline: Instant,
) -> Result<WindowsAttachStream, WindowsAttachConnectError> {
    wait_for_windows_attach_endpoint_with(
        deadline,
        ATTACH_ENDPOINT_RETRY_INTERVAL,
        Instant::now,
        thread::sleep,
        connect_windows_attach_endpoint,
    )
}

#[doc(hidden)]
pub fn wait_for_windows_attach_endpoint_with<T, N, S, C>(
    deadline: Instant,
    retry_interval: Duration,
    mut now: N,
    mut sleep: S,
    mut connect: C,
) -> Result<T, WindowsAttachConnectError>
where
    N: FnMut() -> Instant,
    S: FnMut(Duration),
    C: FnMut(Instant) -> Result<T, WindowsAttachConnectError>,
{
    loop {
        if now() >= deadline {
            return Err(WindowsAttachConnectError::DeadlineExpired);
        }

        match connect(deadline) {
            Ok(stream) => return Ok(stream),
            Err(WindowsAttachConnectError::EndpointAbsent) => {
                let remaining = deadline.saturating_duration_since(now());
                if remaining.is_zero() {
                    return Err(WindowsAttachConnectError::DeadlineExpired);
                }
                sleep(retry_interval.min(remaining));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Opens and verifies the current user's Windows attach endpoint before protocol I/O.
pub fn connect_windows_attach_endpoint(
    deadline: Instant,
) -> Result<WindowsAttachStream, WindowsAttachConnectError> {
    if Instant::now() >= deadline {
        return Err(WindowsAttachConnectError::DeadlineExpired);
    }

    let local_sid =
        current_process_user_sid().map_err(|_| WindowsAttachConnectError::IdentityUnavailable)?;
    // The runtime stores the pipe path when it binds, so a missing file means no endpoint.
    let path = load_windows_attach_pipe_path(local_sid.as_str()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WindowsAttachConnectError::EndpointAbsent
        } else {
            WindowsAttachConnectError::InvalidPipePath
        }
    })?;
    let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();

    let handle = loop {
        if Instant::now() >= deadline {
            return Err(WindowsAttachConnectError::DeadlineExpired);
        }
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            break unsafe { OwnedHandle::from_raw_handle(handle) };
        }

        let error = unsafe { GetLastError() };
        match error {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {
                return Err(WindowsAttachConnectError::EndpointAbsent)
            }
            ERROR_PIPE_BUSY => wait_for_pipe(&wide, deadline)?,
            _ => return Err(WindowsAttachConnectError::Open(error)),
        }
    };

    let reader =
        NativeWindowsEndpointOwnerReader::read(handle.as_raw_handle(), local_sid.as_bytes())
            .map_err(|_| {
                WindowsAttachConnectError::EndpointSecurity(
                    WindowsPipeSecurityError::IdentityUnavailable,
                )
            })?;
    verify_windows_endpoint_owner_with_reader(&reader)
        .map_err(WindowsAttachConnectError::EndpointSecurity)?;

    Ok(WindowsAttachStream::new(handle))
}

fn wait_for_pipe(wide: &[u16], deadline: Instant) -> Result<(), WindowsAttachConnectError> {
    wait_for_windows_attach_pipe_with(deadline, Instant::now, |milliseconds| {
        if unsafe { WaitNamedPipeW(wide.as_ptr(), milliseconds) } != 0 {
            Ok(())
        } else {
            Err(unsafe { GetLastError() })
        }
    })
}

#[doc(hidden)]
pub fn wait_for_windows_attach_pipe_with<N, W>(
    deadline: Instant,
    mut now: N,
    mut wait: W,
) -> Result<(), WindowsAttachConnectError>
where
    N: FnMut() -> Instant,
    W: FnMut(u32) -> Result<(), u32>,
{
    loop {
        let remaining = deadline.saturating_duration_since(now());
        if remaining.is_zero() {
            return Err(WindowsAttachConnectError::DeadlineExpired);
        }
        let milliseconds = (remaining.as_millis()
            + u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
        .min(u128::from(u32::MAX - 1)) as u32;

        match wait(milliseconds) {
            Ok(()) => return Ok(()),
            Err(ERROR_SEM_TIMEOUT) => continue,
            Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => {
                return Err(WindowsAttachConnectError::EndpointAbsent)
            }
            Err(error) => return Err(WindowsAttachConnectError::Wait(error)),
        }
    }
}

struct NativeWindowsEndpointOwnerReader {
    owner_sid: Vec<u8>,
    local_sid: Vec<u8>,
}

impl NativeWindowsEndpointOwnerReader {
    fn read(handle: HANDLE, local_sid: &[u8]) -> Result<Self, WindowsPipeSecurityReadError> {
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 || descriptor.is_null() {
            if !descriptor.is_null() {
                unsafe { LocalFree(descriptor) };
            }
            return Err(WindowsPipeSecurityReadError);
        }

        let owner_sid = copy_sid_bytes(owner);
        unsafe { LocalFree(descriptor) };
        Ok(Self {
            owner_sid: owner_sid.ok_or(WindowsPipeSecurityReadError)?,
            local_sid: local_sid.to_vec(),
        })
    }
}

impl WindowsPipeSecurityReader for NativeWindowsEndpointOwnerReader {
    fn endpoint_owner_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        Ok(self.owner_sid.clone())
    }

    fn dacl_is_protected(&self) -> Result<bool, WindowsPipeSecurityReadError> {
        Err(WindowsPipeSecurityReadError)
    }

    fn access_control_entries(
        &self,
    ) -> Result<Vec<WindowsPipeAccessControlEntry>, WindowsPipeSecurityReadError> {
        Err(WindowsPipeSecurityReadError)
    }

    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        Ok(self.local_sid.clone())
    }
}
