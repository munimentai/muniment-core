#![cfg(target_os = "linux")]

#[path = "../src/attach/deadline_io.rs"]
mod deadline_io;

use deadline_io::{is_timeout, read_exact_before, write_all_before, DeadlineStream, ReadableWait};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

struct FakeStream {
    input: Vec<u8>,
    read_offset: usize,
    max_read: usize,
    output: Vec<u8>,
    max_write: usize,
    zero_write: bool,
    read_calls: usize,
    write_calls: usize,
    read_timeout_calls: Cell<usize>,
    write_timeout_calls: Cell<usize>,
}

impl FakeStream {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            read_offset: 0,
            max_read: usize::MAX,
            output: Vec::new(),
            max_write: usize::MAX,
            zero_write: false,
            read_calls: 0,
            write_calls: 0,
            read_timeout_calls: Cell::new(0),
            write_timeout_calls: Cell::new(0),
        }
    }
}

impl Read for FakeStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_calls += 1;
        let available = self.input.len() - self.read_offset;
        let count = available.min(bytes.len()).min(self.max_read);
        bytes[..count].copy_from_slice(&self.input[self.read_offset..self.read_offset + count]);
        self.read_offset += count;
        Ok(count)
    }
}

impl Write for FakeStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_calls += 1;
        if self.zero_write {
            return Ok(0);
        }
        let count = bytes.len().min(self.max_write);
        self.output.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for FakeStream {
    fn wait_until_readable(&self, _deadline: Instant) -> ReadableWait {
        ReadableWait::Ready
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        assert!(timeout.is_some_and(|timeout| !timeout.is_zero()));
        self.read_timeout_calls
            .set(self.read_timeout_calls.get() + 1);
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        assert!(timeout.is_some_and(|timeout| !timeout.is_zero()));
        self.write_timeout_calls
            .set(self.write_timeout_calls.get() + 1);
        Ok(())
    }
}

fn future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

#[test]
fn unix_stream_reports_readable_data_without_consuming_it() {
    let (mut sender, mut stream) = UnixStream::pair().unwrap();
    sender.write_all(b"x").unwrap();
    drop(sender);

    assert_eq!(
        stream.wait_until_readable(future_deadline()),
        ReadableWait::Ready
    );
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"x");
}

#[test]
fn unix_stream_reports_a_readable_wait_timeout() {
    let (_sender, stream) = UnixStream::pair().unwrap();

    assert_eq!(
        stream.wait_until_readable(Instant::now() + Duration::from_millis(10)),
        ReadableWait::Timeout
    );
}

#[test]
fn unix_stream_reports_a_closed_peer() {
    let (sender, stream) = UnixStream::pair().unwrap();
    drop(sender);

    assert_eq!(
        stream.wait_until_readable(future_deadline()),
        ReadableWait::Closed
    );
}

#[test]
fn reads_until_the_buffer_is_full() {
    let mut stream = FakeStream::new(b"frame");
    stream.max_read = 2;
    let mut bytes = [0; 5];

    read_exact_before(&mut stream, &mut bytes, future_deadline()).unwrap();

    assert_eq!(&bytes, b"frame");
    assert_eq!(stream.read_calls, 3);
    assert_eq!(stream.read_timeout_calls.get(), 3);
}

#[test]
fn reports_an_early_end_of_stream() {
    let mut stream = FakeStream::new(b"short");
    let mut bytes = [0; 6];

    let error = read_exact_before(&mut stream, &mut bytes, future_deadline()).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(stream.read_calls, 2);
}

#[test]
fn writes_until_all_bytes_are_sent() {
    let mut stream = FakeStream::new(&[]);
    stream.max_write = 2;

    write_all_before(&mut stream, b"frame", future_deadline()).unwrap();

    assert_eq!(stream.output, b"frame");
    assert_eq!(stream.write_calls, 3);
    assert_eq!(stream.write_timeout_calls.get(), 3);
}

#[test]
fn reports_a_zero_length_write() {
    let mut stream = FakeStream::new(&[]);
    stream.zero_write = true;

    let error = write_all_before(&mut stream, b"frame", future_deadline()).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert_eq!(stream.write_calls, 1);
}

#[test]
fn rejects_an_elapsed_deadline_before_io() {
    let mut stream = FakeStream::new(b"frame");
    let mut bytes = [0; 5];

    let error = read_exact_before(&mut stream, &mut bytes, Instant::now()).unwrap_err();

    assert!(is_timeout(&error));
    assert_eq!(stream.read_calls, 0);
    assert_eq!(stream.read_timeout_calls.get(), 0);
}
