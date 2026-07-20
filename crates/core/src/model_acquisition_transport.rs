//! Shared native HTTPS transport for pinned model acquisition.

use std::io::Read;
use std::time::{Duration, Instant};

use crate::asr::acquisition::{
    AsrDownloadRequest, AsrDownloadResponse, AsrDownloadTransport, AsrTransportError,
};
use crate::llama::acquisition::{
    GemmaDownloadRequest, GemmaDownloadResponse, GemmaDownloadTransport, GemmaTransportError,
};
use crate::llama::runtime::{
    RuntimeArchiveError, RuntimeDownloadRequest, RuntimeDownloadResponse, RuntimeDownloadTransport,
};
use crate::sidecar::pi_install::{
    PiDownloadRequest, PiDownloadResponse, PiDownloadTransport, PiTransportError,
};

const MAX_REDIRECTS: usize = 5;
const ALLOWED_HOSTS: &[&str] = &[
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "cdn-lfs-us-1.huggingface.co",
    "cdn-lfs-eu-1.huggingface.co",
    "cas-bridge.xethub.hf.co",
    "cas-server.xethub.hf.co",
    "github.com",
    "release-assets.githubusercontent.com",
];

pub type ModelResponseBody = Box<dyn Read + Send + Sync + 'static>;

/// Production transport shared by the Gemma and Parakeet state machines.
pub struct NativeModelAcquisitionTransport {
    backend: Box<dyn HttpBackend>,
}

impl std::fmt::Debug for NativeModelAcquisitionTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeModelAcquisitionTransport")
            .finish_non_exhaustive()
    }
}

impl Default for NativeModelAcquisitionTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportFailure {
    Transient,
    Unavailable,
    Rejected,
}

struct Response {
    status: u16,
    content_range: Option<(u64, u64, u64)>,
    body: ModelResponseBody,
}

impl NativeModelAcquisitionTransport {
    pub fn new() -> Self {
        Self {
            backend: Box::new(UreqBackend),
        }
    }

    #[cfg(test)]
    fn with_backend(backend: impl HttpBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }

    fn request(
        &mut self,
        url: &str,
        offset: u64,
        connect_timeout: Duration,
        read_timeout: Duration,
        deadline: Duration,
    ) -> Result<Response, TransportFailure> {
        request_with(
            url,
            offset,
            connect_timeout,
            read_timeout,
            deadline,
            |request| self.backend.execute(request),
        )
    }
}

impl GemmaDownloadTransport for NativeModelAcquisitionTransport {
    type Body = ModelResponseBody;

    fn download(
        &mut self,
        request: &GemmaDownloadRequest,
    ) -> Result<GemmaDownloadResponse<Self::Body>, GemmaTransportError> {
        self.request(
            request.url(),
            request.offset,
            request.limits.connect_timeout,
            request.limits.read_timeout,
            request.limits.deadline,
        )
        .map(|response| GemmaDownloadResponse {
            status: response.status,
            content_range: response.content_range,
            body: response.body,
        })
        .map_err(|error| match error {
            TransportFailure::Transient => GemmaTransportError::Transient,
            TransportFailure::Unavailable => GemmaTransportError::Unavailable,
            TransportFailure::Rejected => GemmaTransportError::Rejected,
        })
    }
}

impl AsrDownloadTransport for NativeModelAcquisitionTransport {
    type Body = ModelResponseBody;

    fn download(
        &mut self,
        request: &AsrDownloadRequest,
    ) -> Result<AsrDownloadResponse<Self::Body>, AsrTransportError> {
        self.request(
            request.url(),
            request.offset,
            request.limits.connect_timeout,
            request.limits.read_timeout,
            request.limits.deadline,
        )
        .map(|response| AsrDownloadResponse {
            status: response.status,
            content_range: response.content_range,
            body: response.body,
        })
        .map_err(|error| match error {
            TransportFailure::Transient => AsrTransportError::Transient,
            TransportFailure::Unavailable => AsrTransportError::Unavailable,
            TransportFailure::Rejected => AsrTransportError::Rejected,
        })
    }
}

impl RuntimeDownloadTransport for NativeModelAcquisitionTransport {
    type Body = ModelResponseBody;

    fn download(
        &mut self,
        request: &RuntimeDownloadRequest,
    ) -> Result<RuntimeDownloadResponse<Self::Body>, RuntimeArchiveError> {
        self.request(
            request.url(),
            request.offset,
            request.connect_timeout,
            request.read_timeout,
            request.deadline,
        )
        .map(|response| RuntimeDownloadResponse {
            status: response.status,
            content_range: response.content_range,
            body: response.body,
        })
        .map_err(|_| RuntimeArchiveError::Download)
    }
}

impl PiDownloadTransport for NativeModelAcquisitionTransport {
    type Body = ModelResponseBody;

    fn download(
        &mut self,
        request: &PiDownloadRequest,
    ) -> Result<PiDownloadResponse<Self::Body>, PiTransportError> {
        self.request(
            request.url(),
            0,
            request.connect_timeout,
            request.read_timeout,
            request.deadline,
        )
        .map(|response| PiDownloadResponse {
            status: response.status,
            body: response.body,
        })
        .map_err(|error| match error {
            TransportFailure::Transient => PiTransportError::Transient,
            TransportFailure::Unavailable => PiTransportError::Unavailable,
            TransportFailure::Rejected => PiTransportError::Rejected,
        })
    }
}

struct BackendRequest {
    url: url::Url,
    offset: u64,
    connect_timeout: Duration,
    read_timeout: Duration,
    deadline: Duration,
}

struct BackendResponse {
    status: u16,
    location: Option<String>,
    content_range: Option<String>,
    body: ModelResponseBody,
}

trait HttpBackend: Send + Sync {
    fn execute(&mut self, request: &BackendRequest) -> Result<BackendResponse, TransportFailure>;
}

struct UreqBackend;

impl HttpBackend for UreqBackend {
    fn execute(&mut self, request: &BackendRequest) -> Result<BackendResponse, TransportFailure> {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .https_only(true)
            .try_proxy_from_env(true)
            .timeout_connect(request.connect_timeout)
            .timeout_read(request.read_timeout)
            .timeout(request.deadline)
            .build();
        let mut call = agent.get(request.url.as_str());
        if request.offset != 0 {
            call = call.set("Range", &format!("bytes={}-", request.offset));
        }
        match call.call() {
            Ok(response) | Err(ureq::Error::Status(_, response)) => Ok(BackendResponse {
                status: response.status(),
                location: response.header("Location").map(str::to_owned),
                content_range: response.header("Content-Range").map(str::to_owned),
                body: response.into_reader(),
            }),
            Err(ureq::Error::Transport(error)) => Err(match error.kind() {
                ureq::ErrorKind::InvalidUrl
                | ureq::ErrorKind::UnknownScheme
                | ureq::ErrorKind::InsecureRequestHttpsOnly
                | ureq::ErrorKind::TooManyRedirects
                | ureq::ErrorKind::BadStatus
                | ureq::ErrorKind::BadHeader
                | ureq::ErrorKind::InvalidProxyUrl
                | ureq::ErrorKind::ProxyUnauthorized => TransportFailure::Rejected,
                ureq::ErrorKind::ConnectionFailed
                    if error.message() == Some("tls connection init failed") =>
                {
                    TransportFailure::Rejected
                }
                _ => TransportFailure::Transient,
            }),
        }
    }
}

fn request_with<F>(
    initial_url: &str,
    offset: u64,
    connect_timeout: Duration,
    read_timeout: Duration,
    deadline: Duration,
    mut execute: F,
) -> Result<Response, TransportFailure>
where
    F: FnMut(&BackendRequest) -> Result<BackendResponse, TransportFailure>,
{
    let mut url = checked_url(initial_url)?;
    let started_at = Instant::now();
    for hop in 0..=MAX_REDIRECTS {
        let remaining = deadline
            .checked_sub(started_at.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TransportFailure::Transient)?;
        let response = execute(&BackendRequest {
            url: url.clone(),
            offset,
            connect_timeout: connect_timeout.min(remaining),
            read_timeout: read_timeout.min(remaining),
            deadline: remaining,
        })?;
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            if hop == MAX_REDIRECTS {
                return Err(TransportFailure::Rejected);
            }
            let location = response.location.ok_or(TransportFailure::Rejected)?;
            url = checked_url(
                url.join(&location)
                    .map_err(|_| TransportFailure::Rejected)?
                    .as_str(),
            )?;
            continue;
        }
        if matches!(response.status, 404 | 410) {
            return Err(TransportFailure::Unavailable);
        }
        if response.status >= 500 {
            return Err(TransportFailure::Transient);
        }
        let content_range = response
            .content_range
            .as_deref()
            .map(parse_content_range)
            .transpose()?
            .flatten();
        return Ok(Response {
            status: response.status,
            content_range,
            body: response.body,
        });
    }
    Err(TransportFailure::Rejected)
}

fn checked_url(value: &str) -> Result<url::Url, TransportFailure> {
    let parsed = url::Url::parse(value).map_err(|_| TransportFailure::Rejected)?;
    if parsed.scheme() != "https"
        || parsed.port_or_known_default() != Some(443)
        || !ALLOWED_HOSTS.contains(&parsed.host_str().unwrap_or_default())
    {
        return Err(TransportFailure::Rejected);
    }
    Ok(parsed)
}

fn parse_content_range(value: &str) -> Result<Option<(u64, u64, u64)>, TransportFailure> {
    let value = value
        .strip_prefix("bytes ")
        .ok_or(TransportFailure::Rejected)?;
    let (range, total) = value.split_once('/').ok_or(TransportFailure::Rejected)?;
    if range == "*" {
        return Ok(None);
    }
    let (first, last) = range.split_once('-').ok_or(TransportFailure::Rejected)?;
    Ok(Some((
        first.parse().map_err(|_| TransportFailure::Rejected)?,
        last.parse().map_err(|_| TransportFailure::Rejected)?,
        total.parse().map_err(|_| TransportFailure::Rejected)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asr::acquisition::AsrAcquisitionLimits;
    use crate::llama::acquisition::GemmaAcquisitionLimits;
    use std::collections::VecDeque;
    use std::io::Cursor;

    struct FixtureBackend {
        replies: VecDeque<Result<BackendResponse, TransportFailure>>,
    }

    impl HttpBackend for FixtureBackend {
        fn execute(
            &mut self,
            request: &BackendRequest,
        ) -> Result<BackendResponse, TransportFailure> {
            assert_eq!(request.offset, 7);
            assert!(request.connect_timeout <= Duration::from_secs(5));
            assert!(request.read_timeout <= Duration::from_secs(5));
            assert!(request.deadline <= Duration::from_secs(5));
            self.replies.pop_front().unwrap()
        }
    }

    fn reply(
        status: u16,
        location: Option<&str>,
        range: Option<&str>,
        body: &[u8],
    ) -> BackendResponse {
        BackendResponse {
            status,
            location: location.map(str::to_owned),
            content_range: range.map(str::to_owned),
            body: Box::new(Cursor::new(body.to_vec())),
        }
    }

    fn transport(
        replies: Vec<Result<BackendResponse, TransportFailure>>,
    ) -> NativeModelAcquisitionTransport {
        NativeModelAcquisitionTransport::with_backend(FixtureBackend {
            replies: VecDeque::from(replies),
        })
    }

    fn gemma_request() -> GemmaDownloadRequest {
        GemmaDownloadRequest::for_transport_test(
            "https://huggingface.co/repo/resolve/revision/model?secret=value".into(),
            7,
            GemmaAcquisitionLimits {
                connect_timeout: Duration::from_secs(10),
                read_timeout: Duration::from_secs(30),
                deadline: Duration::from_secs(5),
                max_attempts: 1,
            },
        )
    }

    fn asr_request() -> AsrDownloadRequest {
        AsrDownloadRequest::for_transport_test(
            "https://huggingface.co/repo/resolve/revision/model?secret=value".into(),
            7,
            AsrAcquisitionLimits {
                connect_timeout: Duration::from_secs(10),
                read_timeout: Duration::from_secs(30),
                deadline: Duration::from_secs(5),
                max_attempts: 1,
            },
        )
    }

    #[test]
    fn gemma_adapter_streams_200() {
        let mut transport = transport(vec![Ok(reply(200, None, None, b"streamed"))]);
        let mut response =
            GemmaDownloadTransport::download(&mut transport, &gemma_request()).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.content_range, None);
        let mut bytes = Vec::new();
        response.body.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"streamed");
    }

    #[test]
    fn asr_adapter_streams_206_and_parses_range() {
        let mut transport = transport(vec![Ok(reply(206, None, Some("bytes 7-9/10"), b"abc"))]);
        let mut response = AsrDownloadTransport::download(&mut transport, &asr_request()).unwrap();
        assert_eq!(response.status, 206);
        assert_eq!(response.content_range, Some((7, 9, 10)));
        let mut bytes = Vec::new();
        response.body.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn both_adapters_map_status_and_transport_failures() {
        let mut gemma = transport(vec![Ok(reply(503, None, None, b"private body"))]);
        assert!(matches!(
            GemmaDownloadTransport::download(&mut gemma, &gemma_request()),
            Err(GemmaTransportError::Transient)
        ));
        let mut asr = transport(vec![Err(TransportFailure::Transient)]);
        assert!(matches!(
            AsrDownloadTransport::download(&mut asr, &asr_request()),
            Err(AsrTransportError::Transient)
        ));
        for status in [404, 410] {
            let mut gemma = transport(vec![Ok(reply(status, None, None, b"secret body"))]);
            assert!(matches!(
                GemmaDownloadTransport::download(&mut gemma, &gemma_request()),
                Err(GemmaTransportError::Unavailable)
            ));
            let mut asr = transport(vec![Ok(reply(status, None, None, b"secret body"))]);
            assert!(matches!(
                AsrDownloadTransport::download(&mut asr, &asr_request()),
                Err(AsrTransportError::Unavailable)
            ));
        }
    }

    #[test]
    fn rejects_downgrade_and_unrelated_redirects() {
        let mut gemma = transport(vec![Ok(reply(
            302,
            Some("http://huggingface.co/file"),
            None,
            b"",
        ))]);
        assert!(matches!(
            GemmaDownloadTransport::download(&mut gemma, &gemma_request()),
            Err(GemmaTransportError::Rejected)
        ));
        let mut asr = transport(vec![Ok(reply(
            302,
            Some("https://example.com/file"),
            None,
            b"",
        ))]);
        assert!(matches!(
            AsrDownloadTransport::download(&mut asr, &asr_request()),
            Err(AsrTransportError::Rejected)
        ));
    }

    #[test]
    fn accepts_expected_content_host_without_exposing_sensitive_values() {
        let mut allowed_transport = transport(vec![
            Ok(reply(
                302,
                Some("https://cdn-lfs.huggingface.co/file?token=credential"),
                None,
                b"",
            )),
            Ok(reply(200, None, None, b"streamed")),
        ]);
        let result = GemmaDownloadTransport::download(&mut allowed_transport, &gemma_request());
        assert!(result.is_ok());
        let mut transport = transport(vec![Ok(reply(
            302,
            Some("https://evil.invalid/path?token=credential"),
            None,
            b"",
        ))]);
        let error = match AsrDownloadTransport::download(&mut transport, &asr_request()) {
            Err(error) => format!("{error:?}"),
            Ok(_) => panic!("unrelated redirect was accepted"),
        };
        assert_eq!(error, "Rejected");
        assert!(!error.contains("token"));
        assert!(!error.contains("credential"));
    }
}
