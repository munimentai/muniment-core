use std::ffi::{c_void, OsStr};
use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{
    AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle,
};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_NO_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
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
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::{
    verify_windows_pipe_security_with_reader, WindowsAttachAcceptError, WindowsAttachStream,
    WindowsPipeAccessControlEntry, WindowsPipeSecurityReadError, WindowsPipeSecurityReader,
};
use crate::attach::thread_service::ThreadListService;
use crate::attach::{
    acquire_windows_attach_instance_lock, serve_windows_attach_session_with_factory,
    WindowsAttachInstanceLock, WindowsAttachInstanceLockError,
};
use crate::windows_security::OwnerSecurity;
use crate::windows_sid::{copy_sid_bytes, current_process_user_sid};

const PIPE_ACCESS_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
const WINDOWS_ATTACH_SESSION_TIMEOUT: Duration = Duration::from_secs(5);
static FAIL_NEXT_PIPE_INSTANCE: AtomicBool = AtomicBool::new(false);

#[doc(hidden)]
pub fn fail_next_windows_attach_pipe_instance_for_tests() {
    FAIL_NEXT_PIPE_INSTANCE.store(true, Ordering::SeqCst);
}

/// A failure while binding the Windows attach listener.
#[derive(Debug)]
pub enum WindowsAttachBindError {
    InstanceLock(WindowsAttachInstanceLockError),
    Pipe(io::Error),
}

impl fmt::Display for WindowsAttachBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstanceLock(error) => write!(
                formatter,
                "could not acquire the attach instance lock: {error}"
            ),
            Self::Pipe(error) => write!(
                formatter,
                "could not create or verify the attach pipe: {error}"
            ),
        }
    }
}

impl std::error::Error for WindowsAttachBindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InstanceLock(error) => Some(error),
            Self::Pipe(error) => Some(error),
        }
    }
}

/// The result of waiting for a Windows attach connection or a stop signal.
pub enum WindowsAttachAcceptOutcome {
    Connected(WindowsAttachStream),
    Stopped,
}

/// The result of serving one Windows attach connection or receiving a stop signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachServeOutcome {
    Served,
    Stopped,
}

/// A manual-reset event that stops a Windows attach wait.
pub struct WindowsAttachStopEvent {
    handle: OwnedHandle,
}

impl WindowsAttachStopEvent {
    /// Creates an unsignaled stop event.
    pub fn new() -> Result<Self, WindowsAttachAcceptError> {
        Ok(Self {
            handle: create_accept_event()?,
        })
    }

    /// Signals the stop event.
    pub fn signal(&self) -> io::Result<()> {
        if unsafe { SetEvent(self.handle.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsRawHandle for WindowsAttachStopEvent {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

/// A bound Windows attach pipe listener.
pub struct WindowsAttachListener {
    path: String,
    handle: Option<OwnedHandle>,
    _instance_lock: WindowsAttachInstanceLock,
}

/// Accepts and serves one Windows attach stream on a worker thread.
pub fn serve_next_windows_attach<S, F, E>(
    listener: &mut WindowsAttachListener,
    desktop_version: &str,
    accept_deadline: Instant,
    service_factory: Arc<F>,
) -> Result<(), WindowsAttachAcceptError>
where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    let stream = listener.accept(accept_deadline)?;
    serve_windows_attach_on_worker(stream, desktop_version, service_factory);
    Ok(())
}

/// Accepts until stopped and serves one Windows attach stream on a worker thread.
pub fn serve_next_windows_attach_until<S, F, E>(
    listener: &mut WindowsAttachListener,
    desktop_version: &str,
    stop: &Arc<WindowsAttachStopEvent>,
    service_factory: Arc<F>,
) -> Result<WindowsAttachServeOutcome, WindowsAttachAcceptError>
where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    match listener.accept_until(stop)? {
        WindowsAttachAcceptOutcome::Connected(mut stream) => {
            stream.set_stop_event(Arc::clone(stop));
            serve_windows_attach_on_worker(stream, desktop_version, service_factory);
            Ok(WindowsAttachServeOutcome::Served)
        }
        WindowsAttachAcceptOutcome::Stopped => Ok(WindowsAttachServeOutcome::Stopped),
    }
}

fn serve_windows_attach_on_worker<S, F, E>(
    stream: WindowsAttachStream,
    desktop_version: &str,
    service_factory: Arc<F>,
) where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    let desktop_version = desktop_version.to_owned();
    let session_deadline = Instant::now() + WINDOWS_ATTACH_SESSION_TIMEOUT;
    std::thread::spawn(move || {
        let _ = serve_windows_attach_session_with_factory(
            stream,
            &desktop_version,
            session_deadline,
            move || service_factory(),
        );
    });
}

impl WindowsAttachListener {
    /// Creates and verifies the current user's Windows attach pipe.
    pub fn bind(
        state_directory: impl AsRef<Path>,
        bounded_wait: Duration,
    ) -> Result<Self, WindowsAttachBindError> {
        let instance_lock = acquire_windows_attach_instance_lock(state_directory, bounded_wait)
            .map_err(WindowsAttachBindError::InstanceLock)?;
        let sid = current_process_user_sid()
            .map_err(io::Error::other)
            .map_err(WindowsAttachBindError::Pipe)?;
        let path = super::load_or_create_windows_attach_pipe_path(sid.as_str())
            .map_err(WindowsAttachBindError::Pipe)?;
        let handle = create_pipe_instance(&path, true)
            .map_err(io::Error::other)
            .map_err(WindowsAttachBindError::Pipe)?;

        Ok(Self {
            path,
            handle: Some(handle),
            _instance_lock: instance_lock,
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
        loop {
            match self.accept_once(deadline) {
                Err(WindowsAttachAcceptError::Connect(ERROR_NO_DATA)) => self.disconnect_probe()?,
                result => return result,
            }
        }
    }

    fn accept_once(
        &mut self,
        deadline: Instant,
    ) -> Result<WindowsAttachStream, WindowsAttachAcceptError> {
        if Instant::now() >= deadline {
            return Err(WindowsAttachAcceptError::DeadlineExpired);
        }
        if self.handle.is_none() {
            self.handle = Some(self.create_listening_instance()?);
        }

        let event = create_accept_event()?;
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

    /// Waits until one client connects or the stop event is signaled.
    pub fn accept_until(
        &mut self,
        stop: &WindowsAttachStopEvent,
    ) -> Result<WindowsAttachAcceptOutcome, WindowsAttachAcceptError> {
        loop {
            match unsafe { WaitForSingleObject(stop.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => return Ok(WindowsAttachAcceptOutcome::Stopped),
                WAIT_TIMEOUT => {}
                WAIT_FAILED => {
                    return Err(WindowsAttachAcceptError::Wait(unsafe { GetLastError() }));
                }
                wait => return Err(WindowsAttachAcceptError::Wait(wait)),
            }
            match self.accept_until_once(stop) {
                Err(WindowsAttachAcceptError::Connect(ERROR_NO_DATA)) => self.disconnect_probe()?,
                result => return result,
            }
        }
    }

    fn disconnect_probe(&self) -> Result<(), WindowsAttachAcceptError> {
        // A probe can close before ConnectNamedPipe. Reset the same owner-only instance.
        if unsafe { DisconnectNamedPipe(self.handle().as_raw_handle()) } == 0 {
            return Err(WindowsAttachAcceptError::Disconnect(unsafe {
                GetLastError()
            }));
        }
        Ok(())
    }

    fn accept_until_once(
        &mut self,
        stop: &WindowsAttachStopEvent,
    ) -> Result<WindowsAttachAcceptOutcome, WindowsAttachAcceptError> {
        if self.handle.is_none() {
            self.handle = Some(self.create_listening_instance()?);
        }

        let event = create_accept_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        let handle = self.handle().as_raw_handle();

        if unsafe { ConnectNamedPipe(handle, &mut overlapped) } == 0 {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => {}
                ERROR_IO_PENDING => {
                    let events = [overlapped.hEvent, stop.handle.as_raw_handle()];
                    let wait = unsafe {
                        WaitForMultipleObjects(events.len() as u32, events.as_ptr(), 0, INFINITE)
                    };
                    if wait == WAIT_OBJECT_0 + 1 {
                        let cancelled = unsafe { CancelIoEx(handle, &overlapped) } != 0;
                        let cancel_error = if cancelled {
                            None
                        } else {
                            Some(unsafe { GetLastError() })
                        };
                        let mut transferred = 0;
                        if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 1) }
                            != 0
                        {
                            return self
                                .take_stream_and_replace()
                                .map(WindowsAttachAcceptOutcome::Connected);
                        }
                        let completion_error = unsafe { GetLastError() };
                        if cancelled && completion_error == ERROR_OPERATION_ABORTED {
                            return Ok(WindowsAttachAcceptOutcome::Stopped);
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
                        cancel_connect_and_wait(handle, &overlapped);
                        return Err(WindowsAttachAcceptError::Wait(error));
                    }
                    if wait != WAIT_OBJECT_0 {
                        cancel_connect_and_wait(handle, &overlapped);
                        return Err(WindowsAttachAcceptError::Wait(wait));
                    }
                    let mut transferred = 0;
                    if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } == 0
                    {
                        return Err(WindowsAttachAcceptError::Connect(unsafe { GetLastError() }));
                    }
                }
                error => return Err(WindowsAttachAcceptError::Connect(error)),
            }
        }

        self.take_stream_and_replace()
            .map(WindowsAttachAcceptOutcome::Connected)
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
        let connected = self
            .handle
            .take()
            .expect("the listener has no server pipe handle");
        // Keep the connected client. The next accept retries a failed replacement.
        self.handle = self.create_listening_instance().ok();
        Ok(WindowsAttachStream::new(connected))
    }

    fn create_listening_instance(&self) -> Result<OwnedHandle, WindowsAttachAcceptError> {
        create_pipe_instance(&self.path, false)
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

fn create_accept_event() -> Result<OwnedHandle, WindowsAttachAcceptError> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(WindowsAttachAcceptError::CreateEvent(unsafe {
            GetLastError()
        }));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(event) })
}

fn create_pipe_instance(path: &str, first: bool) -> Result<OwnedHandle, WindowsAttachAcceptError> {
    if FAIL_NEXT_PIPE_INSTANCE.swap(false, Ordering::SeqCst) {
        return Err(WindowsAttachAcceptError::VerifyInstanceSecurity(None));
    }
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let mut security = OwnerSecurity::new(PIPE_ACCESS_MASK).map_err(instance_security_error)?;
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
        return Err(WindowsAttachAcceptError::CreateInstance(unsafe {
            GetLastError()
        }));
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let reader = NativeWindowsPipeSecurityReader::read(handle.as_raw_handle())
        .map_err(instance_security_error)?;
    verify_windows_pipe_security_with_reader(&reader)
        .map_err(|_| WindowsAttachAcceptError::VerifyInstanceSecurity(None))?;
    Ok(handle)
}

fn instance_security_error(error: io::Error) -> WindowsAttachAcceptError {
    WindowsAttachAcceptError::VerifyInstanceSecurity(error.raw_os_error().map(|code| code as u32))
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
    fn read(handle: HANDLE) -> io::Result<Self> {
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
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        if descriptor.is_null() {
            return Err(io::Error::other("the pipe security descriptor is null"));
        }

        let snapshot = read_security_snapshot(owner, dacl, descriptor);
        unsafe { LocalFree(descriptor) };
        let (owner_sid, protected, entries) = snapshot?;
        let local_sid = current_process_user_sid()
            .map_err(io::Error::other)?
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
) -> io::Result<(Vec<u8>, bool, Vec<WindowsPipeAccessControlEntry>)> {
    let owner_sid =
        copy_sid_bytes(owner).ok_or_else(|| io::Error::other("the pipe owner SID is invalid"))?;
    if dacl.is_null() {
        return Err(io::Error::other("the pipe DACL is null"));
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
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
        return Err(io::Error::last_os_error());
    }

    let mut entries = Vec::with_capacity(information.AceCount as usize);
    for index in 0..information.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if ace.is_null() {
            return Err(io::Error::other("the pipe ACE is null"));
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
            _ => return Err(io::Error::other("the pipe ACE type is unexpected")),
        };
        entries.push(WindowsPipeAccessControlEntry {
            sid: copy_sid_bytes(sid)
                .ok_or_else(|| io::Error::other("the pipe ACE SID is invalid"))?,
            access_mask,
            allows,
            inherited: u32::from(header.AceFlags) & INHERITED_ACE != 0,
        });
    }

    Ok((owner_sid, control & SE_DACL_PROTECTED != 0, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;

    #[test]
    fn a_security_read_failure_keeps_its_win32_code() {
        let error = match NativeWindowsPipeSecurityReader::read(null_mut()) {
            Err(error) => error,
            Ok(_) => panic!("the security reader accepted a null handle"),
        };
        assert_eq!(
            instance_security_error(error),
            WindowsAttachAcceptError::VerifyInstanceSecurity(Some(ERROR_INVALID_HANDLE))
        );
    }
}
