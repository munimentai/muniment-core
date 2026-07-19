// Fail-closed native transport for browser-control connections.

use super::{authorize_browser_process, AuthorizationError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha1::{Digest, Sha1};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PAIRING_PROTOCOL: &str = "muniment-pairing";

/// Exact policy and resource bounds for a WebSocket opening handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketHandshakeConfig {
    target: String,
    origin: String,
    max_header_bytes: usize,
    max_header_count: usize,
    read_deadline: Duration,
}

impl WebSocketHandshakeConfig {
    pub fn new(
        target: impl Into<String>,
        origin: impl Into<String>,
        max_header_bytes: usize,
        max_header_count: usize,
        read_deadline: Duration,
    ) -> Result<Self, WebSocketHandshakeError> {
        let target = target.into();
        let origin = origin.into();
        if target.is_empty()
            || !target.starts_with('/')
            || target.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
            || origin.is_empty()
            || origin.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
            || max_header_bytes == 0
            || max_header_count == 0
            || read_deadline.is_zero()
        {
            return Err(WebSocketHandshakeError::InvalidConfiguration);
        }
        Ok(Self {
            target,
            origin,
            max_header_bytes,
            max_header_count,
            read_deadline,
        })
    }
}

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
        self.accept_with(&self.listener, &NATIVE_BROWSER_PROCESS_AUTHORIZER)
    }

    /// Authorizes one peer, completes its bounded WebSocket handshake, then releases it.
    pub fn accept_websocket(
        &self,
        config: &WebSocketHandshakeConfig,
        pairing_authorizer: &impl BrowserControlPairingAuthorizer,
    ) -> Result<TcpStream, WebSocketHandshakeError> {
        self.accept_websocket_with(
            &self.listener,
            &NATIVE_BROWSER_PROCESS_AUTHORIZER,
            pairing_authorizer,
            config,
        )
    }

    /// Injected variant used to verify authorization and handshake ordering.
    #[doc(hidden)]
    pub fn accept_websocket_with(
        &self,
        listener: &impl BrowserControlStreamListener,
        authorizer: &impl BrowserControlProcessAuthorizer,
        pairing_authorizer: &impl BrowserControlPairingAuthorizer,
        config: &WebSocketHandshakeConfig,
    ) -> Result<TcpStream, WebSocketHandshakeError> {
        self.accept_websocket_with_endpoint_inspector(
            listener,
            &NATIVE_ENDPOINT_INSPECTOR,
            authorizer,
            pairing_authorizer,
            config,
        )
    }

    /// Injected endpoint-inspection variant used by fail-closed contract tests.
    #[doc(hidden)]
    pub fn accept_websocket_with_endpoint_inspector(
        &self,
        listener: &impl BrowserControlStreamListener,
        endpoint_inspector: &impl BrowserControlEndpointInspector,
        authorizer: &impl BrowserControlProcessAuthorizer,
        pairing_authorizer: &impl BrowserControlPairingAuthorizer,
        config: &WebSocketHandshakeConfig,
    ) -> Result<TcpStream, WebSocketHandshakeError> {
        let mut stream =
            self.accept_with_endpoint_inspector(listener, endpoint_inspector, authorizer)?;
        perform_websocket_handshake(&mut stream, config, pairing_authorizer)?;
        Ok(stream)
    }

    /// Accepts through injected boundaries for deterministic contract tests.
    #[doc(hidden)]
    pub fn accept_with(
        &self,
        listener: &impl BrowserControlStreamListener,
        authorizer: &impl BrowserControlProcessAuthorizer,
    ) -> Result<TcpStream, BrowserControlAcceptError> {
        self.accept_with_endpoint_inspector(listener, &NATIVE_ENDPOINT_INSPECTOR, authorizer)
    }

    /// Injected endpoint-inspection variant used by fail-closed contract tests.
    #[doc(hidden)]
    pub fn accept_with_endpoint_inspector(
        &self,
        listener: &impl BrowserControlStreamListener,
        endpoint_inspector: &impl BrowserControlEndpointInspector,
        authorizer: &impl BrowserControlProcessAuthorizer,
    ) -> Result<TcpStream, BrowserControlAcceptError> {
        let stream = listener
            .accept_stream()
            .map_err(|_| BrowserControlAcceptError::Accept)?;
        let local = endpoint_inspector
            .local_addr(&stream)
            .map_err(|_| BrowserControlAcceptError::EndpointUnavailable)?;
        let peer = endpoint_inspector
            .peer_addr(&stream)
            .map_err(|_| BrowserControlAcceptError::EndpointUnavailable)?;
        authorizer
            .authorize(local, peer, &self.expected_executable)
            .map_err(|_| BrowserControlAcceptError::Unauthorized)?;
        Ok(stream)
    }
}

/// Injected accepted-stream endpoint-inspection boundary.
pub trait BrowserControlEndpointInspector {
    fn local_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr>;
    fn peer_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr>;
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeEndpointInspector;

impl BrowserControlEndpointInspector for NativeEndpointInspector {
    fn local_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        stream.local_addr()
    }

    fn peer_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        stream.peer_addr()
    }
}

const NATIVE_ENDPOINT_INSPECTOR: NativeEndpointInspector = NativeEndpointInspector;

/// Injected single-use pairing-token boundary. Implementations own expiry and revocation state.
pub trait BrowserControlPairingAuthorizer {
    fn authorize(&self, token: Option<&str>) -> Result<(), PairingAuthorizationError>;
}

/// Opaque pairing rejection; token material is never retained in transport errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingAuthorizationError;

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

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxBrowserProcessAuthorizer;

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsBrowserProcessAuthorizer;

#[cfg(target_os = "macos")]
impl BrowserControlProcessAuthorizer for MacOsBrowserProcessAuthorizer {
    fn authorize(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        expected_executable: &Path,
    ) -> Result<(), AuthorizationError> {
        authorize_browser_process(local, peer, expected_executable).map(|_| ())
    }
}

#[cfg(target_os = "linux")]
const NATIVE_BROWSER_PROCESS_AUTHORIZER: LinuxBrowserProcessAuthorizer =
    LinuxBrowserProcessAuthorizer;
#[cfg(target_os = "macos")]
const NATIVE_BROWSER_PROCESS_AUTHORIZER: MacOsBrowserProcessAuthorizer =
    MacOsBrowserProcessAuthorizer;

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

/// A bounded, redacted opening-handshake failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketHandshakeError {
    InvalidConfiguration,
    Accept(BrowserControlAcceptError),
    Timeout,
    Incomplete,
    HeaderBytesExceeded,
    HeaderCountExceeded,
    Malformed,
    PolicyRejected,
    PairingRejected,
    Io,
}

impl From<BrowserControlAcceptError> for WebSocketHandshakeError {
    fn from(error: BrowserControlAcceptError) -> Self {
        Self::Accept(error)
    }
}

impl fmt::Display for WebSocketHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "browser-control handshake configuration is invalid",
            Self::Accept(_) => "browser-control connection was not accepted",
            Self::Timeout => "browser-control handshake timed out",
            Self::Incomplete => "browser-control handshake was incomplete",
            Self::HeaderBytesExceeded => "browser-control handshake was too large",
            Self::HeaderCountExceeded => "browser-control handshake had too many headers",
            Self::Malformed => "browser-control handshake was malformed",
            Self::PolicyRejected => "browser-control handshake was rejected",
            Self::PairingRejected => "browser-control pairing was rejected",
            Self::Io => "browser-control handshake I/O failed",
        })
    }
}

impl std::error::Error for WebSocketHandshakeError {}

fn perform_websocket_handshake(
    stream: &mut TcpStream,
    config: &WebSocketHandshakeConfig,
    pairing_authorizer: &impl BrowserControlPairingAuthorizer,
) -> Result<(), WebSocketHandshakeError> {
    let deadline = Instant::now()
        .checked_add(config.read_deadline)
        .ok_or(WebSocketHandshakeError::InvalidConfiguration)?;
    let mut request = Vec::with_capacity(config.max_header_bytes.min(4096));
    let mut byte = [0u8; 1];
    loop {
        if request.len() == config.max_header_bytes {
            return Err(WebSocketHandshakeError::HeaderBytesExceeded);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(WebSocketHandshakeError::Timeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| WebSocketHandshakeError::Io)?;
        match stream.read(&mut byte) {
            Ok(0) => return Err(WebSocketHandshakeError::Incomplete),
            Ok(_) => request.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(WebSocketHandshakeError::Timeout)
            }
            Err(_) => return Err(WebSocketHandshakeError::Io),
        }
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let (accept, token) = validate_handshake(&request, config)?;
    pairing_authorizer
        .authorize(token)
        .map_err(|_| WebSocketHandshakeError::PairingRejected)?;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {PAIRING_PROTOCOL}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|_| WebSocketHandshakeError::Io)?;
    stream
        .set_read_timeout(None)
        .map_err(|_| WebSocketHandshakeError::Io)
}

fn validate_handshake<'a>(
    request: &'a [u8],
    config: &WebSocketHandshakeConfig,
) -> Result<(String, Option<&'a str>), WebSocketHandshakeError> {
    let text = std::str::from_utf8(request).map_err(|_| WebSocketHandshakeError::Malformed)?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or(WebSocketHandshakeError::Malformed)?
        .split("\r\n");
    let mut start = lines
        .next()
        .ok_or(WebSocketHandshakeError::Malformed)?
        .split(' ');
    if start.next() != Some("GET")
        || start.next() != Some(config.target.as_str())
        || start.next() != Some("HTTP/1.1")
        || start.next().is_some()
    {
        return Err(WebSocketHandshakeError::PolicyRejected);
    }

    let mut headers: Vec<(String, &str)> = Vec::new();
    for line in lines {
        if headers.len() == config.max_header_count {
            return Err(WebSocketHandshakeError::HeaderCountExceeded);
        }
        if line.starts_with([' ', '\t']) {
            return Err(WebSocketHandshakeError::Malformed);
        }
        let (name, raw_value) = line
            .split_once(':')
            .ok_or(WebSocketHandshakeError::Malformed)?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(WebSocketHandshakeError::Malformed);
        }
        let value = raw_value.trim_matches([' ', '\t']);
        if value.is_empty() || value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) {
            return Err(WebSocketHandshakeError::Malformed);
        }
        headers.push((name.to_ascii_lowercase(), value));
    }

    let singleton = |name: &str| -> Result<&str, WebSocketHandshakeError> {
        let mut values = headers
            .iter()
            .filter(|(header, _)| header == name)
            .map(|(_, value)| *value);
        let value = values
            .next()
            .ok_or(WebSocketHandshakeError::PolicyRejected)?;
        if values.next().is_some() {
            return Err(WebSocketHandshakeError::Malformed);
        }
        Ok(value)
    };
    let host = singleton("host")?;
    if !valid_host(host) {
        return Err(WebSocketHandshakeError::Malformed);
    }
    if !has_token(singleton("upgrade")?, "websocket")
        || !has_token(singleton("connection")?, "upgrade")
        || singleton("sec-websocket-version")? != "13"
        || singleton("origin")? != config.origin
    {
        return Err(WebSocketHandshakeError::PolicyRejected);
    }
    let key = singleton("sec-websocket-key")?;
    let decoded = STANDARD
        .decode(key)
        .map_err(|_| WebSocketHandshakeError::PolicyRejected)?;
    if decoded.len() != 16 {
        return Err(WebSocketHandshakeError::PolicyRejected);
    }
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID);
    let token = pairing_token(&headers)?;
    Ok((STANDARD.encode(digest.finalize()), token))
}

fn pairing_token<'a>(
    headers: &[(String, &'a str)],
) -> Result<Option<&'a str>, WebSocketHandshakeError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name == "sec-websocket-protocol")
        .map(|(_, value)| *value);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(WebSocketHandshakeError::Malformed);
    }
    let mut protocols = value.split(',').map(str::trim);
    if protocols.next() != Some(PAIRING_PROTOCOL) {
        return Err(WebSocketHandshakeError::PolicyRejected);
    }
    let token = protocols.next();
    if protocols.next().is_some() {
        return Err(WebSocketHandshakeError::PolicyRejected);
    }
    Ok(token)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn has_token(value: &str, expected: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|token| token.eq_ignore_ascii_case(expected))
        && value
            .split(',')
            .all(|token| !token.trim().is_empty() && token.trim().bytes().all(is_token_byte))
}

fn valid_host(host: &str) -> bool {
    if host.contains(',')
        || host
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || matches!(byte, b'/' | b'\\' | b'@'))
    {
        return false;
    }

    let (host_part, port) = if host.starts_with('[') {
        let Some(close) = host.find(']') else {
            return false;
        };
        let literal = &host[1..close];
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let remainder = &host[close + 1..];
        if remainder.is_empty() {
            return true;
        }
        let Some(port) = remainder.strip_prefix(':') else {
            return false;
        };
        (literal, Some(port))
    } else {
        let mut parts = host.split(':');
        let host_part = parts.next().unwrap_or_default();
        let port = parts.next();
        if parts.next().is_some()
            || host_part.is_empty()
            || matches!(url::Host::parse(host_part), Err(_) | Ok(url::Host::Ipv6(_)))
        {
            return false;
        }
        (host_part, port)
    };

    !host_part.is_empty() && port.is_none_or(|port| !port.is_empty() && port.parse::<u16>().is_ok())
}
