use std::ffi::{c_void, OsStr};
use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::time::Instant;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::{
    verify_windows_pipe_security_with_reader, WindowsAttachStream, WindowsPipeAccessControlEntry,
    WindowsPipeSecurityReadError, WindowsPipeSecurityReader,
};
use crate::attach::windows_attach_pipe_path;
use crate::windows_security::OwnerSecurity;
use crate::windows_sid::{copy_sid_bytes, current_process_user_sid};

const PIPE_ACCESS_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// A failure while accepting a Windows attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachAcceptError {
    DeadlineExpired,
    CreateEvent(u32),
    CreateInstance(u32),
    VerifyInstanceSecurity,
    Connect(u32),
    Wait(u32),
    Cancel(u32),
}

impl fmt::Display for WindowsAttachAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExpired => formatter.write_str("the attach accept deadline expired"),
            Self::CreateEvent(code) => {
                write!(formatter, "could not create an accept event ({code})")
            }
            Self::CreateInstance(code) => {
                write!(
                    formatter,
                    "could not create the next attach pipe instance ({code})"
                )
            }
            Self::VerifyInstanceSecurity => {
                formatter.write_str("could not verify the next attach pipe instance security")
            }
            Self::Connect(code) => write!(
                formatter,
                "could not accept the Windows attach pipe ({code})"
            ),
            Self::Wait(code) => write!(
                formatter,
                "could not wait for a Windows attach client ({code})"
            ),
            Self::Cancel(code) => write!(
                formatter,
                "could not cancel the Windows attach wait ({code})"
            ),
        }
    }
}

impl std::error::Error for WindowsAttachAcceptError {}

/// A bound Windows attach pipe listener.
pub struct WindowsAttachListener {
    path: String,
    handle: Option<OwnedHandle>,
}

impl WindowsAttachListener {
    /// Creates and verifies the current user's Windows attach pipe.
    pub fn bind() -> io::Result<Self> {
        let sid = current_process_user_sid().map_err(io::Error::other)?;
        let path = windows_attach_pipe_path(sid.as_str())
            .map_err(|_| io::Error::other("could not derive the Windows attach pipe path"))?;
        let handle = create_pipe_instance(&path, true)?;

        Ok(Self {
            path,
            handle: Some(handle),
        })
    }

    /// Returns the bound pipe path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the bound server pipe handle.
    pub fn handle(&self) -> BorrowedHandle<'_> {
        self.handle
            .as_ref()
            .expect("the listener has no server pipe handle")
            .as_handle()
    }

    /// Waits until one client connects or the deadline expires.
    pub fn accept(
        &mut self,
        deadline: Instant,
    ) -> Result<WindowsAttachStream, WindowsAttachAcceptError> {
        if Instant::now() >= deadline {
            return Err(WindowsAttachAcceptError::DeadlineExpired);
        }

        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(WindowsAttachAcceptError::CreateEvent(unsafe {
                GetLastError()
            }));
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        let handle = self.handle().as_raw_handle();

        if unsafe { ConnectNamedPipe(handle, &mut overlapped) } == 0 {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => {}
                ERROR_IO_PENDING => self.wait_for_connection(deadline, &overlapped)?,
                error => return Err(WindowsAttachAcceptError::Connect(error)),
            }
        }

        self.take_stream_and_replace()
    }

    fn wait_for_connection(
        &self,
        deadline: Instant,
        overlapped: &OVERLAPPED,
    ) -> Result<(), WindowsAttachAcceptError> {
        let handle = self.handle().as_raw_handle();
        let wait = unsafe {
            WaitForSingleObject(
                overlapped.hEvent,
                deadline_millis(deadline.saturating_duration_since(Instant::now())),
            )
        };
        if wait == WAIT_TIMEOUT {
            let cancelled = unsafe { CancelIoEx(handle, overlapped) } != 0;
            let cancel_error = if cancelled {
                None
            } else {
                Some(unsafe { GetLastError() })
            };
            let mut transferred = 0;
            if unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 1) } != 0 {
                return Ok(());
            }
            let completion_error = unsafe { GetLastError() };
            if cancelled && completion_error == ERROR_OPERATION_ABORTED {
                return Err(WindowsAttachAcceptError::DeadlineExpired);
            }
            if cancel_error == Some(ERROR_NOT_FOUND) {
                return Err(WindowsAttachAcceptError::Connect(completion_error));
            }
            return Err(WindowsAttachAcceptError::Cancel(
                cancel_error.unwrap_or(completion_error),
            ));
        }
        if wait == WAIT_FAILED {
            let error = unsafe { GetLastError() };
            cancel_connect_and_wait(handle, overlapped);
            return Err(WindowsAttachAcceptError::Wait(error));
        }
        if wait != WAIT_OBJECT_0 {
            cancel_connect_and_wait(handle, overlapped);
            return Err(WindowsAttachAcceptError::Wait(wait));
        }

        let mut transferred = 0;
        if unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 0) } == 0 {
            return Err(WindowsAttachAcceptError::Connect(unsafe { GetLastError() }));
        }
        Ok(())
    }

    fn take_stream_and_replace(&mut self) -> Result<WindowsAttachStream, WindowsAttachAcceptError> {
        let next = create_pipe_instance(&self.path, false).map_err(|error| {
            error
                .raw_os_error()
                .map(|code| WindowsAttachAcceptError::CreateInstance(code as u32))
                .unwrap_or(WindowsAttachAcceptError::VerifyInstanceSecurity)
        })?;
        let connected = self
            .handle
            .replace(next)
            .expect("the listener has no server pipe handle");
        Ok(WindowsAttachStream::new(connected))
    }

    fn take_stream(&mut self) -> WindowsAttachStream {
        WindowsAttachStream::new(
            self.handle
                .take()
                .expect("the listener has no server pipe handle"),
        )
    }

    /// Converts a connected listener into an attach stream.
    pub fn into_stream(mut self) -> WindowsAttachStream {
        self.take_stream()
    }
}

fn create_pipe_instance(path: &str, first: bool) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let mut security = OwnerSecurity::new(PIPE_ACCESS_MASK)?;
    let attributes = security.attributes();
    let first_instance = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | first_instance | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            0,
            0,
            0,
            &attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let reader = NativeWindowsPipeSecurityReader::read(handle.as_raw_handle())
        .map_err(|_| io::Error::other("could not read the Windows attach pipe security"))?;
    verify_windows_pipe_security_with_reader(&reader).map_err(io::Error::other)?;
    Ok(handle)
}

fn deadline_millis(remaining: std::time::Duration) -> u32 {
    if remaining.is_zero() {
        return 0;
    }
    remaining
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u128::from(u32::MAX - 1)) as u32
}

fn cancel_connect_and_wait(handle: HANDLE, overlapped: &OVERLAPPED) {
    unsafe {
        CancelIoEx(handle, overlapped);
        let mut transferred = 0;
        GetOverlappedResult(handle, overlapped, &mut transferred, 1);
    }
}

/// A native snapshot of a Windows pipe owner and DACL.
pub struct NativeWindowsPipeSecurityReader {
    owner_sid: Vec<u8>,
    protected: bool,
    entries: Vec<WindowsPipeAccessControlEntry>,
    local_sid: Vec<u8>,
}

impl NativeWindowsPipeSecurityReader {
    fn read(handle: HANDLE) -> Result<Self, WindowsPipeSecurityReadError> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let result = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 || descriptor.is_null() {
            return Err(WindowsPipeSecurityReadError);
        }

        let snapshot = read_security_snapshot(owner, dacl, descriptor);
        unsafe { LocalFree(descriptor) };
        let (owner_sid, protected, entries) = snapshot?;
        let local_sid = current_process_user_sid()
            .map_err(|_| WindowsPipeSecurityReadError)?
            .as_bytes()
            .to_vec();
        Ok(Self {
            owner_sid,
            protected,
            entries,
            local_sid,
        })
    }
}

impl WindowsPipeSecurityReader for NativeWindowsPipeSecurityReader {
    fn endpoint_owner_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        Ok(self.owner_sid.clone())
    }

    fn dacl_is_protected(&self) -> Result<bool, WindowsPipeSecurityReadError> {
        Ok(self.protected)
    }

    fn access_control_entries(
        &self,
    ) -> Result<Vec<WindowsPipeAccessControlEntry>, WindowsPipeSecurityReadError> {
        Ok(self.entries.clone())
    }

    fn local_process_user_sid(&self) -> Result<Vec<u8>, WindowsPipeSecurityReadError> {
        Ok(self.local_sid.clone())
    }
}

fn read_security_snapshot(
    owner: PSID,
    dacl: *mut ACL,
    descriptor: *mut c_void,
) -> Result<(Vec<u8>, bool, Vec<WindowsPipeAccessControlEntry>), WindowsPipeSecurityReadError> {
    let owner_sid = copy_sid_bytes(owner).ok_or(WindowsPipeSecurityReadError)?;
    if dacl.is_null() {
        return Err(WindowsPipeSecurityReadError);
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(WindowsPipeSecurityReadError);
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(WindowsPipeSecurityReadError);
    }

    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(WindowsPipeSecurityReadError);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let (access_mask, sid, allows) = match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE => {
                let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                (
                    ace.Mask,
                    (&ace.SidStart as *const u32).cast_mut().cast(),
                    true,
                )
            }
            ACCESS_DENIED_ACE_TYPE => {
                let ace = unsafe { &*ace.cast::<ACCESS_DENIED_ACE>() };
                (
                    ace.Mask,
                    (&ace.SidStart as *const u32).cast_mut().cast(),
                    false,
                )
            }
            _ => return Err(WindowsPipeSecurityReadError),
        };
        entries.push(WindowsPipeAccessControlEntry {
            sid: copy_sid_bytes(sid).ok_or(WindowsPipeSecurityReadError)?,
            access_mask,
            allows,
            inherited: u32::from(header.AceFlags) & INHERITED_ACE != 0,
        });
    }

    Ok((owner_sid, control & SE_DACL_PROTECTED != 0, entries))
}
