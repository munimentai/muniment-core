use std::fmt;
#[cfg(target_os = "windows")]
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use muniment_attach::{
    ApprovalDecision, ApprovalPresentRequest, ApprovalPresenterStopHandle, ChatEventSupervisorStop,
    DesktopClientStopHandle,
};
use muniment_attach::{
    ClientError, ClientStream, DesktopClient, DesktopClientHolder, DesktopClientSupervisorStop,
};

use super::WindowsPipeSecurityError;

/// A failure while connecting to the current user's Windows attach endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachConnectError {
    DeadlineExpired,
    EndpointAbsent,
    IdentityUnavailable,
    InvalidPipePath,
    Open(u32),
    Wait(u32),
    EndpointSecurity(WindowsPipeSecurityError),
}

impl fmt::Display for WindowsAttachConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExpired => formatter.write_str("the attach connection deadline expired"),
            Self::EndpointAbsent => formatter.write_str("the Windows attach endpoint is absent"),
            Self::IdentityUnavailable => {
                formatter.write_str("the current process identity is unavailable")
            }
            Self::InvalidPipePath => formatter.write_str("the Windows attach pipe path is invalid"),
            Self::Open(code) => {
                write!(formatter, "could not open the Windows attach pipe ({code})")
            }
            Self::Wait(code) => write!(
                formatter,
                "could not wait for the Windows attach pipe ({code})"
            ),
            Self::EndpointSecurity(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for WindowsAttachConnectError {}

/// Waits for the current user's endpoint and opens a desktop client.
#[cfg(target_os = "windows")]
pub fn connect_windows_desktop_client(
    client_version: &str,
    io_timeout: Duration,
    connect_deadline: Instant,
) -> Result<DesktopClient, ClientError> {
    connect_windows_desktop_client_with(
        client_version,
        io_timeout,
        connect_deadline,
        super::wait_for_windows_attach_endpoint,
        muniment_attach::handshake_desktop_client,
    )
}

/// Stops a Windows chat-event supervisor and its active pipe operation.
#[cfg(target_os = "windows")]
#[derive(Clone)]
pub struct WindowsChatEventStopHandle {
    inner: Arc<(Mutex<bool>, Condvar)>,
    event: Arc<super::WindowsAttachStopEvent>,
}

#[cfg(target_os = "windows")]
impl WindowsChatEventStopHandle {
    pub fn new() -> Result<Self, super::WindowsAttachAcceptError> {
        Ok(Self {
            inner: Arc::new((Mutex::new(false), Condvar::new())),
            event: Arc::new(super::WindowsAttachStopEvent::new()?),
        })
    }

    pub fn stop(&self) {
        let (stopped, wake) = &*self.inner;
        *stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        let _ = self.event.signal();
        wake.notify_all();
    }
}

#[cfg(target_os = "windows")]
impl ChatEventSupervisorStop for WindowsChatEventStopHandle {
    fn stopped(&self) -> bool {
        *self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wait_for_retry(&self, retry_interval: Duration) -> bool {
        let (stopped, wake) = &*self.inner;
        let stopped = stopped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (stopped, _) = wake
            .wait_timeout_while(stopped, retry_interval, |stopped| !*stopped)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !*stopped
    }
}

/// Serves a reconnecting chat-event subscription over the current user's Windows attach endpoint.
#[cfg(target_os = "windows")]
pub fn serve_windows_chat_events(
    client_version: &str,
    io_timeout: Duration,
    retry_interval: Duration,
    stop: WindowsChatEventStopHandle,
    observe: impl FnMut(bool),
    deliver: impl FnMut(serde_json::Value),
) {
    let connection_stop = stop.clone();
    muniment_attach::serve_chat_events_with(
        || {
            let now = Instant::now();
            let connect_deadline = now.checked_add(retry_interval).unwrap_or(now);
            let mut stream = super::wait_for_windows_attach_endpoint(connect_deadline).ok()?;
            stream.set_stop_event(Arc::clone(&connection_stop.event));
            muniment_attach::handshake_desktop_client(Box::new(stream), client_version, io_timeout)
                .ok()
        },
        stop,
        retry_interval,
        observe,
        deliver,
    );
}

/// Serves approval requests over the current user's Windows attach endpoint.
#[cfg(target_os = "windows")]
pub fn serve_windows_approval_presenter(
    client_version: &str,
    io_timeout: Duration,
    retry_interval: Duration,
    stop: ApprovalPresenterStopHandle,
    observe: impl FnMut(bool),
    choose: impl FnMut(&ApprovalPresentRequest) -> ApprovalDecision,
) {
    let Ok(event) = super::WindowsAttachStopEvent::new() else {
        return;
    };
    let event = Arc::new(event);
    let connection_stop = stop.clone();
    let connection_event = Arc::clone(&event);
    muniment_attach::serve_approval_presenter_with(
        || {
            let shutdown_event = Arc::clone(&connection_event);
            if !connection_stop.register_shutdown(move || {
                let _ = shutdown_event.signal();
            }) {
                return None;
            }
            let now = Instant::now();
            let connect_deadline = now.checked_add(retry_interval).unwrap_or(now);
            let mut stream = super::wait_for_windows_attach_endpoint(connect_deadline).ok()?;
            stream.set_stop_event(Arc::clone(&connection_event));
            muniment_attach::handshake_approval_presenter(
                Box::new(stream),
                client_version,
                io_timeout,
            )
            .ok()
        },
        stop,
        retry_interval,
        observe,
        choose,
    );
}

/// Serves a reconnecting desktop client over the current user's Windows attach endpoint.
#[cfg(target_os = "windows")]
pub fn serve_windows_desktop_client(
    client_version: &str,
    io_timeout: Duration,
    retry_interval: Duration,
    stop: DesktopClientStopHandle,
    holder: DesktopClientHolder,
    observe: impl FnMut(bool),
) {
    serve_windows_desktop_client_with(
        client_version,
        io_timeout,
        retry_interval,
        stop,
        holder,
        observe,
        (
            super::wait_for_windows_attach_endpoint,
            muniment_attach::handshake_desktop_client,
        ),
    );
}

#[doc(hidden)]
pub fn serve_windows_desktop_client_with<S, C, H, Stop>(
    client_version: &str,
    io_timeout: Duration,
    retry_interval: Duration,
    stop: Stop,
    holder: DesktopClientHolder,
    observe: impl FnMut(bool),
    operations: (C, H),
) where
    S: ClientStream + Send + 'static,
    C: FnMut(Instant) -> Result<S, WindowsAttachConnectError>,
    H: FnMut(Box<dyn ClientStream + Send>, &str, Duration) -> Result<DesktopClient, ClientError>,
    Stop: DesktopClientSupervisorStop,
{
    let (mut connect, mut handshake) = operations;
    muniment_attach::serve_desktop_client_with(
        || {
            let now = Instant::now();
            let connect_deadline = now.checked_add(retry_interval).unwrap_or(now);
            connect_windows_desktop_client_with(
                client_version,
                io_timeout,
                connect_deadline,
                &mut connect,
                &mut handshake,
            )
            .ok()
        },
        stop,
        holder,
        retry_interval,
        observe,
    );
}

#[doc(hidden)]
pub fn connect_windows_desktop_client_with<S, T, C, H>(
    client_version: &str,
    io_timeout: Duration,
    connect_deadline: Instant,
    connect: C,
    handshake: H,
) -> Result<T, ClientError>
where
    S: ClientStream + Send + 'static,
    C: FnOnce(Instant) -> Result<S, WindowsAttachConnectError>,
    H: FnOnce(Box<dyn ClientStream + Send>, &str, Duration) -> Result<T, ClientError>,
{
    let stream = connect(connect_deadline).map_err(map_connect_error)?;
    handshake(Box::new(stream), client_version, io_timeout)
}

fn map_connect_error(error: WindowsAttachConnectError) -> ClientError {
    match error {
        WindowsAttachConnectError::DeadlineExpired => ClientError::Timeout,
        WindowsAttachConnectError::EndpointAbsent
        | WindowsAttachConnectError::IdentityUnavailable
        | WindowsAttachConnectError::InvalidPipePath
        | WindowsAttachConnectError::Open(_)
        | WindowsAttachConnectError::Wait(_)
        | WindowsAttachConnectError::EndpointSecurity(_) => ClientError::DesktopUnavailable,
    }
}
