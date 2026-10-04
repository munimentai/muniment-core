use crate::{decode_frame, ClientError, FrameError, MAX_FRAME_LENGTH};
use serde_json::Value;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub trait ClientStream: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

#[cfg(unix)]
impl ClientStream for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

pub(crate) fn read_exact_before<S: ClientStream + ?Sized>(
    stream: &mut S,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), ClientError> {
    while !bytes.is_empty() {
        unless_disconnected(stream.set_read_timeout(Some(remaining(deadline)?)))
            .map_err(|_| ClientError::DesktopUnavailable)?;
        match stream.read(bytes) {
            Ok(0) => return Err(ClientError::ConnectionClosed),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io_error(error)),
        }
    }
    Ok(())
}

pub(crate) fn write_all_before<S: ClientStream + ?Sized>(
    stream: &mut S,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), ClientError> {
    while !bytes.is_empty() {
        unless_disconnected(stream.set_write_timeout(Some(remaining(deadline)?)))
            .map_err(|_| ClientError::DesktopUnavailable)?;
        match stream.write(bytes) {
            Ok(0) => return Err(ClientError::ConnectionClosed),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io_error(error)),
        }
    }
    Ok(())
}

// macOS answers EINVAL from setsockopt on a socket the runtime has closed in
// both directions. A read then drains the buffered reply and ends at EOF, and
// a write answers EPIPE, so neither call blocks without the timeout.
fn unless_disconnected(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
        result => result,
    }
}

pub(crate) fn read_value<S: ClientStream + ?Sized>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Value, ClientError> {
    let mut prefix = [0u8; 4];
    read_exact_before(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(ClientError::PayloadTooLarge);
    }
    let mut frame = vec![0u8; length + 4];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline)?;
    decode_frame(&frame)
        .map_err(map_frame_error)?
        .map(|(value, _)| value)
        .ok_or(ClientError::MalformedFrame)
}

pub(crate) fn read_approval_value<S: ClientStream + ?Sized>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Value, ClientError> {
    let mut prefix = [0u8; 4];
    read_exact_before(stream, &mut prefix, deadline)?;
    read_approval_value_with_prefix(stream, prefix, deadline)
}

pub(crate) fn read_approval_value_with_prefix<S: ClientStream + ?Sized>(
    stream: &mut S,
    prefix: [u8; 4],
    deadline: Instant,
) -> Result<Value, ClientError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(ClientError::PayloadTooLarge);
    }
    let mut frame = vec![0u8; length];
    read_exact_before(stream, &mut frame, deadline)?;
    serde_json::from_slice(&frame).map_err(|_| ClientError::MalformedFrame)
}

fn remaining(deadline: Instant) -> Result<Duration, ClientError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ClientError::Timeout)
}

pub(crate) fn map_io_error(error: io::Error) -> ClientError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ClientError::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => ClientError::ConnectionClosed,
        _ => ClientError::DesktopUnavailable,
    }
}

fn map_frame_error(error: FrameError) -> ClientError {
    match error {
        FrameError::PayloadTooLarge => ClientError::PayloadTooLarge,
        _ => ClientError::MalformedFrame,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;

    pub(crate) struct AbortedStream(pub usize);

    impl Read for AbortedStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.0 += 1;
            assert_eq!(self.0, 1, "the client must not retry a permanent stop");
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

    impl ClientStream for AbortedStream {
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
            read_exact_before(&mut AbortedStream(0), &mut [0], deadline),
            Err(ClientError::ConnectionClosed)
        );
        assert_eq!(
            write_all_before(&mut AbortedStream(0), &[0], deadline),
            Err(ClientError::ConnectionClosed)
        );
    }

    struct InterruptedStream {
        input: VecDeque<u8>,
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
            let Some(byte) = self.input.pop_front() else {
                return Ok(0);
            };
            bytes[0] = byte;
            Ok(1)
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

    impl ClientStream for InterruptedStream {
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
            input: VecDeque::from(*b"hello"),
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
            read_exact_before(&mut stream, &mut [0], deadline),
            Err(ClientError::ConnectionClosed)
        );
    }

    #[test]
    fn desktop_and_presenter_handshakes_survive_interrupted_frames() {
        for presenter in [false, true] {
            let welcome = crate::reconnect_welcome(1, "1.2.3", "aa".repeat(16), "");
            let mut input = crate::encode_frame(&welcome).unwrap();
            let capability = "bb".repeat(32);
            let grant = if presenter {
                crate::encode_frame(&crate::PeerAuthorizedGrant {
                    capability: capability.clone(),
                    expires_at: 60,
                    idle_timeout_seconds: 30,
                })
                .unwrap()
            } else {
                crate::encode_frame(&crate::DesktopClientAuthorizedGrant {
                    capability: capability.clone(),
                    expires_at: 60,
                    idle_timeout_seconds: 30,
                    profile_id: "desktop-owner".into(),
                    workspace_scopes: Default::default(),
                })
                .unwrap()
            };
            input.extend(grant);
            let stream = Box::new(InterruptedStream {
                input: input.into(),
                output: Vec::new(),
                interrupt: false,
                stall_until: None,
            });
            let admitted = if presenter {
                crate::presenter_client::handshake_approval_presenter(
                    stream,
                    "1.2.3",
                    Duration::from_secs(1),
                )
                .map(|client| client.capability().to_owned())
            } else {
                crate::desktop_client::handshake_desktop_client(
                    stream,
                    "1.2.3",
                    Duration::from_secs(1),
                )
                .map(|client| client.capability().to_owned())
            };
            assert_eq!(admitted, Ok(capability));
        }
    }

    #[test]
    fn interruptions_do_not_reset_the_io_deadline() {
        for read in [true, false] {
            let deadline = Instant::now() + Duration::from_millis(5);
            let mut stream = InterruptedStream {
                input: VecDeque::new(),
                output: Vec::new(),
                interrupt: false,
                stall_until: Some(deadline),
            };
            let result = if read {
                read_exact_before(&mut stream, &mut [0], deadline)
            } else {
                write_all_before(&mut stream, &[0], deadline)
            };
            assert_eq!(result, Err(ClientError::Timeout));
            assert!(stream.output.is_empty());
        }
    }
}
