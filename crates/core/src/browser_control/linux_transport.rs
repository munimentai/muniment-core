//! Fail-closed Linux transport for browser-control connections.

use super::{authorize_browser_process, AuthorizationError};
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};

/// A browser-control listener bound to a numeric loopback address.
pub struct BrowserControlListener {
    listener: TcpListener,
    expected_executable: PathBuf,
}

impl BrowserControlListener {
    /// Binds an OS-assigned port. Hostnames and explicit ports are not accepted.
    pub fn bind(
        bind_address: &str,
        expected_executable: impl Into<PathBuf>,
    ) -> Result<Self, BrowserControlBindError> {
        let address: SocketAddr = bind_address
            .parse()
            .map_err(|_| BrowserControlBindError::InvalidConfiguration)?;
        if !address.ip().is_loopback() || address.port() != 0 {
            return Err(BrowserControlBindError::InvalidConfiguration);
        }

        let listener = TcpListener::bind(address).map_err(|_| BrowserControlBindError::Bind)?;
        let bound = listener
            .local_addr()
            .map_err(|_| BrowserControlBindError::Bind)?;
        if !bound.ip().is_loopback() || bound.port() == 0 {
            return Err(BrowserControlBindError::Bind);
        }
        Ok(Self {
            listener,
            expected_executable: expected_executable.into(),
        })
    }

    /// Returns the numeric loopback endpoint selected by the operating system.
    pub fn local_addr(&self) -> Result<SocketAddr, BrowserControlBindError> {
        self.listener
            .local_addr()
            .map_err(|_| BrowserControlBindError::Bind)
    }

    /// Accepts one stream and releases it only after browser-process authorization.
    pub fn accept(&self) -> Result<TcpStream, BrowserControlAcceptError> {
        self.accept_with(&self.listener, &LinuxBrowserProcessAuthorizer)
    }

    /// Accepts through injected boundaries for deterministic contract tests.
    #[doc(hidden)]
    pub fn accept_with(
        &self,
        listener: &impl BrowserControlStreamListener,
        authorizer: &impl BrowserControlProcessAuthorizer,
    ) -> Result<TcpStream, BrowserControlAcceptError> {
        let stream = listener
            .accept_stream()
            .map_err(|_| BrowserControlAcceptError::Accept)?;
        let local = stream
            .local_addr()
            .map_err(|_| BrowserControlAcceptError::EndpointUnavailable)?;
        let peer = stream
            .peer_addr()
            .map_err(|_| BrowserControlAcceptError::EndpointUnavailable)?;
        authorizer
            .authorize(local, peer, &self.expected_executable)
            .map_err(|_| BrowserControlAcceptError::Unauthorized)?;
        Ok(stream)
    }
}

/// Injected accepted-stream boundary.
pub trait BrowserControlStreamListener {
    fn accept_stream(&self) -> io::Result<TcpStream>;
}

impl BrowserControlStreamListener for TcpListener {
    fn accept_stream(&self) -> io::Result<TcpStream> {
        self.accept().map(|(stream, _)| stream)
    }
}

/// Injected opaque process-authorization boundary.
pub trait BrowserControlProcessAuthorizer {
    fn authorize(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        expected_executable: &Path,
    ) -> Result<(), AuthorizationError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxBrowserProcessAuthorizer;

impl BrowserControlProcessAuthorizer for LinuxBrowserProcessAuthorizer {
    fn authorize(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        expected_executable: &Path,
    ) -> Result<(), AuthorizationError> {
        authorize_browser_process(local, peer, expected_executable).map(|_| ())
    }
}

/// A bounded, redacted listener-creation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserControlBindError {
    InvalidConfiguration,
    Bind,
}

impl fmt::Display for BrowserControlBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "browser-control bind configuration is invalid",
            Self::Bind => "browser-control listener could not be opened",
        })
    }
}

impl std::error::Error for BrowserControlBindError {}

/// A bounded, redacted accepted-stream failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserControlAcceptError {
    Accept,
    EndpointUnavailable,
    Unauthorized,
}

impl fmt::Display for BrowserControlAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Accept => "browser-control connection could not be accepted",
            Self::EndpointUnavailable => "browser-control connection could not be inspected",
            Self::Unauthorized => "browser-control connection was not authorized",
        })
    }
}

impl std::error::Error for BrowserControlAcceptError {}
