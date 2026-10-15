//! A blocking TLS stream over TCP for the remote attach route.
//!
//! Each call reads or writes through the socket's own timeouts, so the
//! callers' deadline loops bound TLS work the same way they bound a local
//! socket. A write returns only after its records reach the socket, so a
//! timed-out write surfaces as an error instead of bytes left in a buffer.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::client_stream::ClientStream;

/// What a wait for readable plaintext found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsReadable {
    Ready,
    Timeout,
    Closed,
}

/// A TLS connection, client or server, and the TCP socket it runs on.
pub struct TlsStream {
    connection: rustls::Connection,
    socket: TcpStream,
}

impl std::fmt::Debug for TlsStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TlsStream { .. }")
    }
}

impl TlsStream {
    pub fn new(connection: impl Into<rustls::Connection>, socket: TcpStream) -> Self {
        Self {
            connection: connection.into(),
            socket,
        }
    }

    pub fn socket(&self) -> &TcpStream {
        &self.socket
    }

    /// Runs the handshake to completion before `deadline`. A failure sends
    /// the TLS alert when it can and reports the cause as `InvalidData` with
    /// the rustls error inside.
    pub fn handshake_before(&mut self, deadline: Instant) -> io::Result<()> {
        while self.connection.is_handshaking() || self.connection.wants_write() {
            if self.connection.wants_write() {
                self.socket.set_write_timeout(Some(remaining(deadline)?))?;
                match self.connection.write_tls(&mut self.socket) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
            self.socket.set_read_timeout(Some(remaining(deadline)?))?;
            match self.connection.read_tls(&mut self.socket) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => self.process()?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Waits until plaintext is ready to read, the peer closes, or `deadline`
    /// passes. Plaintext that rustls already decrypted counts as ready even
    /// when the socket holds no more bytes.
    pub fn wait_until_readable(&mut self, deadline: Instant) -> TlsReadable {
        loop {
            match self.connection.process_new_packets() {
                Ok(state) if state.plaintext_bytes_to_read() > 0 => return TlsReadable::Ready,
                Ok(state) if state.peer_has_closed() => return TlsReadable::Closed,
                Ok(_) => {}
                Err(_) => return TlsReadable::Closed,
            }
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
            else {
                return TlsReadable::Timeout;
            };
            if self.socket.set_read_timeout(Some(remaining)).is_err() {
                return TlsReadable::Closed;
            }
            match self.socket.peek(&mut [0_u8; 1]) {
                Ok(0) => return TlsReadable::Closed,
                Ok(_) => {}
                Err(error) if is_timeout(&error) => return TlsReadable::Timeout,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return TlsReadable::Closed,
            }
            // The socket holds bytes, so this read returns without blocking.
            match self.connection.read_tls(&mut self.socket) {
                Ok(0) => return TlsReadable::Closed,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return TlsReadable::Closed,
            }
        }
    }

    /// Sends a close alert and shuts the socket, ignoring failures.
    pub fn close(&mut self) {
        self.connection.send_close_notify();
        let _ = self
            .socket
            .set_write_timeout(Some(Duration::from_millis(100)));
        let _ = self.flush_tls();
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }

    fn process(&mut self) -> io::Result<()> {
        match self.connection.process_new_packets() {
            Ok(_) => Ok(()),
            Err(error) => {
                let _ = self.connection.write_tls(&mut self.socket);
                Err(io::Error::new(io::ErrorKind::InvalidData, error))
            }
        }
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl Read for TlsStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.flush_tls()?;
            match self.connection.reader().read(bytes) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            // A zero-byte read marks EOF inside rustls, and the next reader
            // call reports it as a clean close or an unexpected EOF.
            self.connection.read_tls(&mut self.socket)?;
            self.process()?;
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.connection.writer().write(bytes)?;
        self.flush_tls()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_tls()?;
        self.socket.flush()
    }
}

impl ClientStream for TlsStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
