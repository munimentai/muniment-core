//! How a session sends one GET.
//!
//! Each engine session owns one transport, and the transport owns that
//! engine's cookie jar. The default is `ureq` with rustls and the OS
//! certificate verifier. With the `curl` feature Brave goes over the system
//! libcurl, whose TLS handshake Brave lets through when it flags rustls.

use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::engines::EngineId;

/// How long one request may take.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// How many redirects one request follows.
pub const REDIRECTS: u32 = 10;

/// The user agent and request headers of a desktop Chrome navigation.
pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
pub const ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
pub const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

/// A finished response: its status, the URL after redirects, and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub final_url: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The peer reset or aborted the connection. The session retries once.
    ConnectionReset(String),
    Other(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::ConnectionReset(message) => write!(f, "connection reset: {message}"),
            TransportError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TransportError {}

/// Sends GET requests for one engine and keeps its cookies between them.
pub trait Transport: Send {
    /// Fetches `url`, sending `referer` when the session has a same-origin one.
    /// Any HTTP status is a response, not an error.
    fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError>;
}

/// Builds the transport a fresh engine session uses.
pub type TransportFactory = Arc<dyn Fn(EngineId) -> Box<dyn Transport> + Send + Sync>;

/// The default transport for `engine`.
pub fn default_transport(engine: EngineId) -> Box<dyn Transport> {
    #[cfg(feature = "curl")]
    if engine == EngineId::Brave {
        return Box::new(CurlTransport::new());
    }
    let _ = engine;
    Box::new(UreqTransport::new())
}

/// The default transport factory.
pub fn default_factory() -> TransportFactory {
    Arc::new(default_transport)
}

/// `ureq` over rustls with its own cookie store.
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .tls_config(tls_config())
            .try_proxy_from_env(true)
            .timeout(TIMEOUT)
            .redirects(REDIRECTS)
            .user_agent(USER_AGENT)
            .build();
        UreqTransport { agent }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UreqTransport {
    fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError> {
        let mut request = self
            .agent
            .get(url)
            .set("accept", ACCEPT)
            .set("accept-language", ACCEPT_LANGUAGE);
        if let Some(referer) = referer {
            request = request.set("referer", referer);
        }
        let response = match request.call() {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => return Err(ureq_error(error)),
        };
        let status = response.status();
        let final_url = response.get_url().to_owned();
        let body = response.into_string().map_err(|error| io_error(&error))?;
        Ok(Response {
            status,
            final_url,
            body,
        })
    }
}

fn ureq_error(error: ureq::Transport) -> TransportError {
    use std::error::Error as _;
    let reset = error
        .source()
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .map(io_error);
    match reset {
        Some(TransportError::ConnectionReset(_)) => {
            TransportError::ConnectionReset(error.to_string())
        }
        _ => TransportError::Other(error.to_string()),
    }
}

fn io_error(error: &std::io::Error) -> TransportError {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
            TransportError::ConnectionReset(error.to_string())
        }
        _ => TransportError::Other(error.to_string()),
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    use rustls_platform_verifier::BuilderVerifierExt;

    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // Select ring explicitly even when another dependency enables a second crypto provider.
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("The TLS protocol versions are invalid.")
            .with_platform_verifier()
            .expect("The OS certificate verifier could not start.")
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// The system libcurl with an in-memory cookie jar.
#[cfg(feature = "curl")]
pub struct CurlTransport {
    easy: Option<curl::easy::Easy>,
}

#[cfg(feature = "curl")]
impl CurlTransport {
    pub fn new() -> Self {
        CurlTransport { easy: None }
    }

    fn handle(&mut self) -> Result<&mut curl::easy::Easy, curl::Error> {
        if self.easy.is_none() {
            let mut easy = curl::easy::Easy::new();
            // An empty file name turns on the in-memory cookie engine.
            easy.cookie_file("")?;
            // An empty value offers every encoding libcurl decodes.
            easy.accept_encoding("")?;
            easy.http_version(curl::easy::HttpVersion::V2TLS)?;
            easy.follow_location(true)?;
            easy.max_redirections(REDIRECTS)?;
            easy.timeout(TIMEOUT)?;
            easy.useragent(USER_AGENT)?;
            self.easy = Some(easy);
        }
        Ok(self.easy.as_mut().expect("the handle was just set"))
    }
}

#[cfg(feature = "curl")]
impl Default for CurlTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "curl")]
impl Transport for CurlTransport {
    fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError> {
        let fetched = (|| {
            let easy = self.handle()?;
            easy.url(url)?;
            let mut headers = curl::easy::List::new();
            headers.append(&format!("accept: {ACCEPT}"))?;
            headers.append(&format!("accept-language: {ACCEPT_LANGUAGE}"))?;
            if let Some(referer) = referer {
                headers.append(&format!("referer: {referer}"))?;
            }
            easy.http_headers(headers)?;
            let mut body = Vec::new();
            {
                let mut transfer = easy.transfer();
                transfer.write_function(|data| {
                    body.extend_from_slice(data);
                    Ok(data.len())
                })?;
                transfer.perform()?;
            }
            let final_url = easy.effective_url()?.unwrap_or(url).to_owned();
            let status = easy.response_code()? as u16;
            Ok::<_, curl::Error>(Response {
                status,
                final_url,
                body: String::from_utf8_lossy(&body).into_owned(),
            })
        })();
        fetched.map_err(|error| {
            if error.is_recv_error() || error.is_send_error() {
                TransportError::ConnectionReset(error.to_string())
            } else {
                TransportError::Other(error.to_string())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn ureq_keeps_cookies_and_reports_error_statuses_as_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for answer in [
                "HTTP/1.1 200 OK\r\nSet-Cookie: id=7; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let read = socket.read(&mut request).unwrap();
                seen.push(String::from_utf8_lossy(&request[..read]).to_lowercase());
                socket.write_all(answer.as_bytes()).unwrap();
            }
            seen
        });
        let mut transport = UreqTransport::new();
        let first = transport.get(&format!("http://{address}/"), None).unwrap();
        assert_eq!((first.status, first.body.as_str()), (200, "ok"));
        let second = transport
            .get(&format!("http://{address}/search"), Some(&first.final_url))
            .unwrap();
        assert_eq!((second.status, second.body.as_str()), (429, "slow"));
        let seen = server.join().unwrap();
        assert!(seen[0].contains("user-agent: mozilla/5.0"));
        assert!(seen[0].contains("accept-language: en-us"));
        assert!(seen[1].contains("cookie: id=7"));
        assert!(seen[1].contains(&format!("referer: http://{address}/")));
    }
}
