use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum ReadableWait {
    Ready,
    Timeout,
    Closed,
}

#[doc(hidden)]
pub trait DeadlineStream: Read + Write {
    fn wait_until_readable(&self, deadline: Instant) -> ReadableWait;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

#[cfg(unix)]
impl DeadlineStream for UnixStream {
    fn wait_until_readable(&self, deadline: Instant) -> ReadableWait {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return ReadableWait::Timeout;
        };
        let millis = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result == 0 {
            return ReadableWait::Timeout;
        }
        if result < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                ReadableWait::Timeout
            } else {
                ReadableWait::Closed
            };
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return ReadableWait::Closed;
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            if descriptor.revents & libc::POLLIN == 0 {
                return ReadableWait::Closed;
            }
            let mut byte = 0u8;
            let peeked = unsafe {
                libc::recv(
                    self.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_DONTWAIT | libc::MSG_PEEK,
                )
            };
            if peeked <= 0 {
                return ReadableWait::Closed;
            }
        }
        ReadableWait::Ready
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

#[doc(hidden)]
pub fn read_exact_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn write_all_before<S: DeadlineStream + ?Sized>(
    stream: &mut S,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

pub(super) fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
