use std::io;
use std::time::{Duration, Instant};

use muniment_attach::{
    decode_frame, encode_frame, Envelope, Id, Operation, Protocol, Request, MAX_FRAME_LENGTH,
};
use serde::Deserialize;
use serde_json::json;

use super::deadline_io::{read_exact_before, write_all_before, DeadlineStream};
use super::ApprovalRequest;

/// A stream that supports an approval presenter session.
pub trait ApprovalPresenterStream: DeadlineStream + Send + Sized + 'static {
    fn try_clone_presenter_stream(&self) -> io::Result<Self>;
    fn wait_until_closed(&self);
    fn close_presenter_stream(&self);
}

#[cfg(unix)]
impl ApprovalPresenterStream for std::os::unix::net::UnixStream {
    fn try_clone_presenter_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }

    #[cfg(target_os = "macos")]
    fn wait_until_closed(&self) {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        // macOS poll can lose a hangup after readable data. Watch EOF without consuming replies.
        let descriptor = unsafe { libc::kqueue() };
        if descriptor < 0 {
            crate::runtime_eprintln!(
                "muniment-runtime: approval presenter watch failed step=kqueue reason={}",
                io::Error::last_os_error()
            );
            return;
        }
        // SAFETY: kqueue returned a new descriptor that this guard owns.
        let queue = unsafe { OwnedFd::from_raw_fd(descriptor) };
        // SAFETY: The queue owns a live descriptor. F_SETFD accepts FD_CLOEXEC.
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            crate::runtime_eprintln!(
                "muniment-runtime: approval presenter watch failed step=close_on_exec reason={}",
                io::Error::last_os_error()
            );
            return;
        }
        let change = libc::kevent {
            ident: self.as_raw_fd() as libc::uintptr_t,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: The change references a live socket. No output buffer is requested.
        if unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            crate::runtime_eprintln!(
                "muniment-runtime: approval presenter watch failed step=register reason={}",
                io::Error::last_os_error()
            );
            return;
        }
        loop {
            let mut event = change;
            // SAFETY: The queue and output buffer remain valid throughout the wait.
            let result = unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    std::ptr::null(),
                )
            };
            if result > 0 && event.flags & (libc::EV_EOF | libc::EV_ERROR) != 0 {
                return;
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                crate::runtime_eprintln!(
                    "muniment-runtime: approval presenter watch failed step=wait reason={}",
                    io::Error::last_os_error()
                );
                return;
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn wait_until_closed(&self) {
        use std::os::fd::AsRawFd;

        let mut descriptor = libc::pollfd {
            fd: self.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
            if result > 0
                && descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            {
                return;
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }

    fn close_presenter_stream(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(target_os = "windows")]
impl ApprovalPresenterStream for super::WindowsAttachStream {
    fn try_clone_presenter_stream(&self) -> io::Result<Self> {
        super::WindowsAttachStream::try_clone(self)
    }

    fn wait_until_closed(&self) {
        super::WindowsAttachStream::wait_until_closed(self);
    }

    fn close_presenter_stream(&self) {
        super::WindowsAttachStream::disconnect(self);
    }
}

/// A claimed presenter connection used to show approval challenges.
pub struct ApprovalPresenterConnection<S: ApprovalPresenterStream> {
    stream: S,
    capability: String,
}

impl<S: ApprovalPresenterStream> ApprovalPresenterConnection<S> {
    pub fn new(stream: S, capability: impl Into<String>) -> Self {
        Self {
            stream,
            capability: capability.into(),
        }
    }

    pub(crate) fn try_clone_stream(&self) -> io::Result<S> {
        self.stream.try_clone_presenter_stream()
    }

    pub fn present(&mut self, request: &ApprovalRequest, remaining: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(remaining) else {
            return false;
        };
        let request_id = Id::new(uuid::Uuid::new_v4().to_string())
            .expect("generated approval request ID is valid");
        let envelope = Request {
            protocol: Protocol,
            request_id: request_id.clone(),
            operation: Operation::ApprovalPresent,
            capability: self.capability.clone(),
            idempotency_key: None,
            body: json!({
                "challenge": request.challenge,
                "claimed_kind": request.claimed_kind,
                "claimed_version": request.claimed_version,
                "workspace": request.workspace,
                "scopes": request.scopes,
                "deadline_ms": u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
            }),
        };
        let Ok(frame) = encode_frame(&envelope) else {
            return false;
        };
        if write_all_before(&mut self.stream, &frame, deadline).is_err() {
            return false;
        }
        let Ok(response) = read_envelope_before(&mut self.stream, deadline) else {
            return false;
        };
        let Envelope::Response(response) = response else {
            return false;
        };
        if response.request_id != request_id {
            return false;
        }
        let Ok(body) = serde_json::from_value::<ApprovalDecision>(response.body) else {
            return false;
        };
        body.challenge == request.challenge && body.decision == "approve"
    }
}

#[derive(Deserialize)]
struct ApprovalDecision {
    challenge: String,
    decision: String,
}

fn read_envelope_before<S: DeadlineStream>(
    stream: &mut S,
    deadline: Instant,
) -> io::Result<Envelope> {
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut frame = vec![0_u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)?;
    decode_frame(&frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid frame"))?
        .map(|(envelope, _)| envelope)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete frame"))
}
