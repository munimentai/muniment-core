use crate::{decode_frame, ClientError, FrameError, MAX_FRAME_LENGTH};
use serde_json::Value;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(crate) trait ClientStream: Read + Write {
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
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| ClientError::DesktopUnavailable)?;
        match stream.read(bytes).map_err(map_io_error)? {
            0 => return Err(ClientError::ConnectionClosed),
            read => bytes = &mut bytes[read..],
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
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| ClientError::DesktopUnavailable)?;
        match stream.write(bytes).map_err(map_io_error)? {
            0 => return Err(ClientError::ConnectionClosed),
            written => bytes = &bytes[written..],
        }
    }
    Ok(())
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

fn map_io_error(error: io::Error) -> ClientError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ClientError::Timeout,
        io::ErrorKind::UnexpectedEof
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
