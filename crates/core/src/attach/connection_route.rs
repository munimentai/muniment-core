//! Linux attach connection routing.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use muniment_attach::{decode_frame, Hello};

use super::linux::PeerCredentials;
use super::verify_approval_presenter_peer_with_reader;
use crate::browser_control::LinuxProcReader;

const ROUTE_PEEK_CAP: usize = 4 * 1024;

/// The handler for a new attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachConnectionRoute {
    ApprovalPresenter,
    DesktopClient,
    Companion,
}

/// Names the route without consuming the connection's first frame.
pub fn name_attach_connection_route(
    stream: &UnixStream,
    peer_credentials: PeerCredentials,
    expected_desktop_executable: &Path,
    process_reader: &dyn LinuxProcReader,
    timeout: Duration,
) -> AttachConnectionRoute {
    let peer_authorized = u32::try_from(peer_credentials.pid).is_ok_and(|peer_pid| {
        verify_approval_presenter_peer_with_reader(
            peer_pid,
            expected_desktop_executable,
            process_reader,
        )
        .is_ok()
    });
    if !peer_authorized || timeout.is_zero() {
        return AttachConnectionRoute::Companion;
    }

    let Ok(previous_timeout) = stream.read_timeout() else {
        return AttachConnectionRoute::Companion;
    };
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return AttachConnectionRoute::Companion;
    };

    let route =
        peek_hello(stream, deadline).map_or(AttachConnectionRoute::Companion, |hello| match hello
            .client
            .kind
            .as_str()
        {
            "desktop" => AttachConnectionRoute::ApprovalPresenter,
            "desktop-client" => AttachConnectionRoute::DesktopClient,
            _ => AttachConnectionRoute::Companion,
        });
    let _ = stream.set_read_timeout(previous_timeout);
    route
}

fn peek_hello(stream: &UnixStream, deadline: Instant) -> Option<Hello> {
    let mut prefix = [0_u8; 4];
    peek_exact(stream, &mut prefix, deadline).ok()?;
    let frame_length = (u32::from_be_bytes(prefix) as usize).checked_add(prefix.len())?;
    if frame_length > ROUTE_PEEK_CAP {
        return None;
    }

    let mut frame = vec![0_u8; frame_length];
    peek_exact(stream, &mut frame, deadline).ok()?;
    match decode_frame::<Hello>(&frame) {
        Ok(Some((hello, consumed))) if consumed == frame.len() => Some(hello),
        _ => None,
    }
}

fn peek_exact(stream: &UnixStream, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(remaining))?;
        let read = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_PEEK | libc::MSG_WAITALL,
            )
        };
        if read == buffer.len() as isize {
            return Ok(());
        }
        if read == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(if read == -1 {
            io::Error::last_os_error()
        } else {
            io::Error::from(io::ErrorKind::UnexpectedEof)
        });
    }
}
