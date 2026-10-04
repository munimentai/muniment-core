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
        unless_disconnected(stream.set_read_timeout(Some(remaining(deadline)?)))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
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
        unless_disconnected(stream.set_write_timeout(Some(remaining(deadline)?)))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

// macOS answers EINVAL from setsockopt on a socket disconnected in both
// directions. A read then drains the buffered reply and ends at EOF, and a
// write answers EPIPE, so neither call blocks without the timeout.
fn unless_disconnected(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
        result => result,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct AbortedStream(usize);

    impl Read for AbortedStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            assert_eq!(self.0, 1, "the runtime must not retry a permanent stop");
            Err(io::ErrorKind::ConnectionAborted.into())
        }
    }

    impl Write for AbortedStream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.read(&mut [])
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DeadlineStream for AbortedStream {
        fn wait_until_readable(&self, _: Instant) -> ReadableWait {
            ReadableWait::Closed
        }
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn permanent_stop_closes_io_without_retry() {
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            read_exact_before(&mut AbortedStream(0), &mut [0], deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            write_all_before(&mut AbortedStream(0), &[0], deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    struct InterruptedStream {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        interrupt: bool,
        stall_until: Option<Instant>,
    }

    impl InterruptedStream {
        fn step(&mut self) -> io::Result<()> {
            if let Some(until) = self.stall_until {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.interrupt = !self.interrupt;
            if self.interrupt {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        }
    }

    impl Read for InterruptedStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.step()?;
            self.input.read(&mut bytes[..1])
        }
    }

    impl Write for InterruptedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.step()?;
            self.output.push(bytes[0]);
            Ok(1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DeadlineStream for InterruptedStream {
        fn wait_until_readable(&self, _: Instant) -> ReadableWait {
            ReadableWait::Ready
        }
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn interrupted_partial_io_preserves_bytes_and_eof() {
        let mut stream = InterruptedStream {
            input: io::Cursor::new(b"hello".to_vec()),
            output: Vec::new(),
            interrupt: false,
            stall_until: None,
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut bytes = [0; 5];
        read_exact_before(&mut stream, &mut bytes, deadline).unwrap();
        assert_eq!(&bytes, b"hello");
        write_all_before(&mut stream, &bytes, deadline).unwrap();
        assert_eq!(stream.output, b"hello");
        assert_eq!(
            read_exact_before(&mut stream, &mut [0], deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn interruptions_do_not_reset_the_admission_deadline() {
        for read in [true, false] {
            let deadline = Instant::now() + Duration::from_millis(5);
            let mut stream = InterruptedStream {
                input: io::Cursor::new(Vec::new()),
                output: Vec::new(),
                interrupt: false,
                stall_until: Some(deadline),
            };
            let result = if read {
                read_exact_before(&mut stream, &mut [0], deadline)
            } else {
                write_all_before(&mut stream, &[0], deadline)
            };
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert!(stream.output.is_empty());
        }
    }
}
