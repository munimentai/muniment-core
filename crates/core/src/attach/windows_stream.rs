use std::cell::Cell;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF,
    ERROR_NOT_FOUND, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_NOT_CONNECTED, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::{DisconnectNamedPipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use muniment_attach::ClientStream;

use super::deadline_io::{DeadlineStream, ReadableWait};
use super::WindowsAttachStopEvent;

/// A connected Windows attach pipe that uses bounded overlapped I/O.
pub struct WindowsAttachStream {
    handle: OwnedHandle,
    read_timeout: Cell<Option<Duration>>,
    write_timeout: Cell<Option<Duration>>,
    stop_event: Option<Arc<WindowsAttachStopEvent>>,
    operation_pending_sender: Option<mpsc::Sender<()>>,
}

impl WindowsAttachStream {
    /// Wraps a connected pipe handle created with `FILE_FLAG_OVERLAPPED`.
    pub fn new(handle: OwnedHandle) -> Self {
        Self {
            handle,
            read_timeout: Cell::new(None),
            write_timeout: Cell::new(None),
            stop_event: None,
            operation_pending_sender: None,
        }
    }

    /// Registers the shared stop event that interrupts blocked operations.
    pub fn set_stop_event(&mut self, stop_event: Arc<WindowsAttachStopEvent>) {
        self.stop_event = Some(stop_event);
    }

    #[doc(hidden)]
    pub fn set_operation_pending_sender_for_tests(&mut self, sender: mpsc::Sender<()>) {
        self.operation_pending_sender = Some(sender);
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        let process = unsafe { GetCurrentProcess() };
        let mut duplicated = null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                self.handle.as_raw_handle(),
                process,
                &mut duplicated,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(duplicated) };
        Ok(Self {
            handle,
            read_timeout: Cell::new(self.read_timeout.get()),
            write_timeout: Cell::new(self.write_timeout.get()),
            stop_event: self.stop_event.clone(),
            operation_pending_sender: None,
        })
    }

    pub(crate) fn wait_until_closed(&self) {
        loop {
            if self.stop_event.as_ref().is_some_and(|stop_event| unsafe {
                WaitForSingleObject(stop_event.as_raw_handle(), 0) == WAIT_OBJECT_0
            }) {
                return;
            }
            if unsafe {
                PeekNamedPipe(
                    self.handle.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            } == 0
            {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn disconnect(&self) {
        unsafe {
            DisconnectNamedPipe(self.handle.as_raw_handle());
        }
    }

    fn operate(
        &self,
        timeout: Option<Duration>,
        issue: impl FnOnce(*mut OVERLAPPED) -> i32,
    ) -> io::Result<usize> {
        if let Some(stop_event) = &self.stop_event {
            match unsafe { WaitForSingleObject(stop_event.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => return Err(io::Error::from(io::ErrorKind::Interrupted)),
                WAIT_TIMEOUT => {}
                WAIT_FAILED => return Err(io::Error::last_os_error()),
                _ => return Err(io::Error::other("unexpected stop event wait result")),
            }
        }

        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        let handle = self.handle.as_raw_handle();

        if issue(&mut overlapped) == 0 {
            let error = unsafe { GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_IO_PENDING {
                return operation_error(error);
            }
            if let Some(sender) = &self.operation_pending_sender {
                let _ = sender.send(());
            }
        }

        let wait = if let Some(stop_event) = &self.stop_event {
            let events = [event.as_raw_handle(), stop_event.as_raw_handle()];
            unsafe {
                WaitForMultipleObjects(
                    events.len() as u32,
                    events.as_ptr(),
                    0,
                    timeout_millis(timeout),
                )
            }
        } else {
            unsafe { WaitForSingleObject(event.as_raw_handle(), timeout_millis(timeout)) }
        };
        if wait == WAIT_TIMEOUT {
            let cancelled = unsafe { CancelIoEx(handle, &overlapped) } != 0;
            let cancel_error = if cancelled {
                None
            } else {
                Some(unsafe { GetLastError() })
            };
            let mut transferred = 0;
            let completed =
                unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 1) };
            if completed != 0 {
                return Ok(transferred as usize);
            }
            let completion_error = unsafe { GetLastError() };
            if cancelled && completion_error == ERROR_OPERATION_ABORTED {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            if cancelled || cancel_error == Some(ERROR_NOT_FOUND) {
                return operation_error(completion_error);
            }
            return Err(io::Error::from_raw_os_error(
                cancel_error.unwrap_or(completion_error) as i32,
            ));
        }
        if wait == WAIT_FAILED {
            let error = io::Error::last_os_error();
            cancel_and_wait(handle, &overlapped);
            return Err(error);
        }
        if self.stop_event.is_some() && wait == WAIT_OBJECT_0 + 1 {
            cancel_and_wait(handle, &overlapped);
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if wait != WAIT_OBJECT_0 {
            cancel_and_wait(handle, &overlapped);
            return Err(io::Error::other("unexpected overlapped I/O wait result"));
        }

        let mut transferred = 0;
        if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 0) } == 0 {
            return operation_error(unsafe { GetLastError() });
        }
        Ok(transferred as usize)
    }
}

impl AsRawHandle for WindowsAttachStream {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

impl Read for WindowsAttachStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let length = bytes.len().min(u32::MAX as usize) as u32;
        let handle = self.handle.as_raw_handle();
        self.operate(self.read_timeout.get(), |overlapped| unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr().cast(),
                length,
                null_mut(),
                overlapped,
            )
        })
    }
}

impl Write for WindowsAttachStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let length = bytes.len().min(u32::MAX as usize) as u32;
        let handle = self.handle.as_raw_handle();
        self.operate(self.write_timeout.get(), |overlapped| unsafe {
            WriteFile(
                handle,
                bytes.as_ptr().cast(),
                length,
                null_mut(),
                overlapped,
            )
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for WindowsAttachStream {
    fn wait_until_readable(&self, deadline: Instant) -> ReadableWait {
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return ReadableWait::Timeout;
            };
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.handle.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            } == 0
            {
                return ReadableWait::Closed;
            }
            if available > 0 {
                return ReadableWait::Ready;
            }
            thread::sleep(remaining.min(Duration::from_millis(50)));
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout.set(timeout);
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout.set(timeout);
        Ok(())
    }
}

impl ClientStream for WindowsAttachStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        DeadlineStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        DeadlineStream::set_write_timeout(self, timeout)
    }
}

fn cancel_and_wait(handle: windows_sys::Win32::Foundation::HANDLE, overlapped: &OVERLAPPED) {
    unsafe {
        CancelIoEx(handle, overlapped);
        let mut transferred = 0;
        GetOverlappedResult(handle, overlapped, &mut transferred, 1);
    }
}

fn timeout_millis(timeout: Option<Duration>) -> u32 {
    timeout.map_or(INFINITE, |timeout| {
        timeout
            .as_nanos()
            .div_ceil(1_000_000)
            .max(1)
            .min(u128::from(INFINITE - 1)) as u32
    })
}

fn operation_error(code: u32) -> io::Result<usize> {
    if matches!(
        code,
        ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
    ) {
        Ok(0)
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
