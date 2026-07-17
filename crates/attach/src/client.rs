use std::fmt;

/// Closed, redacted outcomes from the companion pairing handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    UnsupportedPlatform,
    AuthorizationExpired,
    RequestRejected,
    DesktopFailed,
    RuntimeDirectoryMissing,
    RuntimeDirectoryRelative,
    DesktopUnavailable,
    Timeout,
    ConnectionClosed,
    MalformedFrame,
    PayloadTooLarge,
    UnexpectedMessage,
    ProtocolIncompatible,
    RandomnessUnavailable,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedPlatform => "desktop attach is unsupported on this platform",
            Self::AuthorizationExpired => "desktop authorization is no longer valid",
            Self::RequestRejected => "the desktop rejected the thread list request",
            Self::DesktopFailed => "the desktop could not list threads",
            Self::RuntimeDirectoryMissing => "XDG_RUNTIME_DIR is not set",
            Self::RuntimeDirectoryRelative => "XDG_RUNTIME_DIR must be an absolute path",
            Self::DesktopUnavailable => "the Muniment desktop attach service is unavailable",
            Self::Timeout => "the desktop did not complete pairing in time",
            Self::ConnectionClosed => "the desktop closed the pairing connection",
            Self::MalformedFrame => "the desktop sent a malformed attach message",
            Self::PayloadTooLarge => "the desktop sent an oversized attach message",
            Self::UnexpectedMessage => "the desktop sent an unexpected pairing message",
            Self::ProtocolIncompatible => "the desktop and CLI attach protocols are incompatible",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
        })
    }
}

impl std::error::Error for ClientError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSummary {
    pub expires_in_seconds: u64,
    pub idle_timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedThreadSummary {
    pub thread_id: String,
    pub title: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadListPage {
    pub threads: Vec<RedactedThreadSummary>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{AuthorizationSummary, ClientError, ThreadListPage};
    use crate::{
        decode_frame, encode_frame, Authorized, Client, Envelope, ErrorCode, ErrorEnvelope,
        FrameError, Hello, Id, Operation, Protocol, Request, VersionRange, Welcome,
        MAX_FRAME_LENGTH, MAX_TEXT_LENGTH, PROTOCOL,
    };
    use serde::de::DeserializeOwned;
    use serde_json::Value;
    use std::env;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
    const THREAD_LIST_LIMIT: u8 = 100;

    /// An authorization bound to the connection on which pairing completed.
    pub struct AuthorizedClient {
        stream: UnixStream,
        capability: String,
        summary: AuthorizationSummary,
        io_timeout: Duration,
    }

    impl std::fmt::Debug for AuthorizedClient {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("AuthorizedClient { .. }")
        }
    }

    impl AuthorizedClient {
        pub fn authorization_summary(&self) -> AuthorizationSummary {
            self.summary.clone()
        }

        pub fn list_threads(&mut self) -> Result<ThreadListPage, ClientError> {
            let request_id = fresh_request_id()?;
            let request = Request {
                protocol: Protocol,
                request_id: request_id.clone(),
                operation: Operation::ThreadList,
                capability: self.capability.clone(),
                idempotency_key: None,
                body: serde_json::json!({ "limit": THREAD_LIST_LIMIT }),
            };
            let deadline = deadline(self.io_timeout);
            let bytes = encode_frame(&request).map_err(map_frame_error)?;
            write_all_before(&mut self.stream, &bytes, deadline)?;
            let value = read_value(&mut self.stream, deadline)?;
            if value
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol != PROTOCOL)
            {
                return Err(ClientError::ProtocolIncompatible);
            }
            let response =
                match serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)? {
                    Envelope::Response(response) if response.request_id == request_id => response,
                    Envelope::Error(error) if error.request_id.as_ref() == Some(&request_id) => {
                        return Err(map_protocol_error(error.error.code()));
                    }
                    _ => return Err(ClientError::UnexpectedMessage),
                };
            let page: ThreadListPage = serde_json::from_value(response.body)
                .map_err(|_| ClientError::UnexpectedMessage)?;
            if page.threads.len() > usize::from(THREAD_LIST_LIMIT)
                || page.threads.iter().any(|thread| {
                    thread.thread_id.is_empty()
                        || thread.thread_id.len() > MAX_TEXT_LENGTH
                        || thread.title.len() > MAX_TEXT_LENGTH
                        || thread.updated_at.is_empty()
                        || thread.updated_at.len() > MAX_TEXT_LENGTH
                })
                || page
                    .next_cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.is_empty() || cursor.len() > MAX_TEXT_LENGTH)
            {
                return Err(ClientError::UnexpectedMessage);
            }
            Ok(page)
        }
    }

    pub fn handshake(
        client_version: &str,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        let endpoint = endpoint_from_environment()?;
        let stream = UnixStream::connect(endpoint).map_err(|_| ClientError::DesktopUnavailable)?;
        handshake_stream(
            stream,
            client_version,
            IO_TIMEOUT,
            APPROVAL_TIMEOUT,
            pairing_pending,
        )
    }

    fn endpoint_from_environment() -> Result<PathBuf, ClientError> {
        let runtime = env::var_os("XDG_RUNTIME_DIR")
            .ok_or(ClientError::RuntimeDirectoryMissing)
            .map(PathBuf::from)?;
        if !runtime.is_absolute() {
            return Err(ClientError::RuntimeDirectoryRelative);
        }
        Ok(runtime.join("muniment").join("attach-v1.sock"))
    }

    #[doc(hidden)]
    pub fn handshake_stream(
        mut stream: UnixStream,
        client_version: &str,
        io_timeout: Duration,
        approval_timeout: Duration,
        pairing_pending: impl FnOnce(),
    ) -> Result<AuthorizedClient, ClientError> {
        let hello = Hello {
            protocol: Protocol,
            client: Client {
                kind: "cli".into(),
                version: client_version.into(),
            },
            supported: VersionRange { min: 1, max: 1 },
            client_nonce: fresh_nonce()?,
        };
        let bytes = encode_frame(&hello).map_err(map_frame_error)?;
        write_all_before(&mut stream, &bytes, deadline(io_timeout))?;

        let welcome_value = read_value(&mut stream, deadline(io_timeout))?;
        reject_protocol_error(&welcome_value)?;
        let welcome: Welcome = parse_message(welcome_value)?;
        if welcome.selected != 1 {
            return Err(ClientError::ProtocolIncompatible);
        }
        if !is_hex_secret(&welcome.server_nonce, 32)
            || !is_hex_secret(&welcome.approval_challenge, 32)
        {
            return Err(ClientError::UnexpectedMessage);
        }
        pairing_pending();

        let authorized_value = read_value(&mut stream, deadline(approval_timeout))?;
        reject_protocol_error(&authorized_value)?;
        let authorized: Authorized = parse_message(authorized_value)?;
        if !is_hex_secret(&authorized.capability, 64)
            || authorized.expires_at == 0
            || authorized.expires_at > 8 * 60 * 60
            || authorized.idle_timeout_seconds == 0
            || authorized.idle_timeout_seconds > 15 * 60
        {
            return Err(ClientError::UnexpectedMessage);
        }
        Ok(AuthorizedClient {
            stream,
            capability: authorized.capability,
            summary: AuthorizationSummary {
                expires_in_seconds: authorized.expires_at,
                idle_timeout_seconds: authorized.idle_timeout_seconds,
            },
            io_timeout,
        })
    }

    fn fresh_request_id() -> Result<Id, ClientError> {
        let nonce = fresh_nonce()?;
        Id::new(format!(
            "{}-{}-{}-{}-{}",
            &nonce[0..8],
            &nonce[8..12],
            &nonce[12..16],
            &nonce[16..20],
            &nonce[20..32]
        ))
        .map_err(|_| ClientError::RandomnessUnavailable)
    }

    fn map_protocol_error(code: ErrorCode) -> ClientError {
        match code {
            ErrorCode::ProtocolIncompatible => ClientError::ProtocolIncompatible,
            ErrorCode::Unauthorized => ClientError::AuthorizationExpired,
            ErrorCode::PersistenceFailed => ClientError::DesktopFailed,
            _ => ClientError::RequestRejected,
        }
    }

    fn fresh_nonce() -> Result<String, ClientError> {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|_| ClientError::RandomnessUnavailable)?;
        let mut nonce = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut nonce, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(nonce)
    }

    fn is_hex_secret(value: &str, length: usize) -> bool {
        value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn deadline(timeout: Duration) -> Instant {
        Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now)
    }

    fn remaining(deadline: Instant) -> Result<Duration, ClientError> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ClientError::Timeout)
    }

    fn read_exact_before(
        stream: &mut UnixStream,
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

    fn write_all_before(
        stream: &mut UnixStream,
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

    fn read_value(stream: &mut UnixStream, deadline: Instant) -> Result<Value, ClientError> {
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

    fn reject_protocol_error(value: &Value) -> Result<(), ClientError> {
        if value
            .get("protocol")
            .and_then(Value::as_str)
            .is_some_and(|p| p != PROTOCOL)
        {
            return Err(ClientError::ProtocolIncompatible);
        }
        if value.get("ok") == Some(&Value::Bool(false)) {
            let error: ErrorEnvelope =
                serde_json::from_value(value.clone()).map_err(|_| ClientError::MalformedFrame)?;
            return Err(if error.error.code() == ErrorCode::ProtocolIncompatible {
                ClientError::ProtocolIncompatible
            } else {
                ClientError::UnexpectedMessage
            });
        }
        Ok(())
    }

    fn parse_message<T: DeserializeOwned>(value: Value) -> Result<T, ClientError> {
        serde_json::from_value(value).map_err(|_| ClientError::UnexpectedMessage)
    }

    fn map_frame_error(error: FrameError) -> ClientError {
        match error {
            FrameError::PayloadTooLarge => ClientError::PayloadTooLarge,
            _ => ClientError::MalformedFrame,
        }
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
}

#[cfg(target_os = "linux")]
pub use linux::{handshake_stream, AuthorizedClient};

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct AuthorizedClient;

#[cfg(not(target_os = "linux"))]
impl AuthorizedClient {
    pub fn list_threads(&mut self) -> Result<ThreadListPage, ClientError> {
        Err(ClientError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
pub fn handshake(
    client_version: &str,
    pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    linux::handshake(client_version, pairing_pending)
}

#[cfg(not(target_os = "linux"))]
pub fn handshake(
    _client_version: &str,
    _pairing_pending: impl FnOnce(),
) -> Result<AuthorizedClient, ClientError> {
    Err(ClientError::UnsupportedPlatform)
}
