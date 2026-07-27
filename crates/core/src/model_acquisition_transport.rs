//! Shared native HTTPS transport for pinned model acquisition.

use std::io::Read;
use std::time::{Duration, Instant};

use crate::asr::acquisition::{
    AsrDownloadRequest, AsrDownloadResponse, AsrDownloadTransport, AsrTransportError,
};
use crate::kokoro::acquisition::{
    KokoroDownloadRequest, KokoroDownloadResponse, KokoroDownloadTransport, KokoroTransportError,
};
use crate::llama::acquisition::{
    ResidentModelDownloadRequest, ResidentModelDownloadResponse, ResidentModelDownloadTransport,
    ResidentModelTransportError,
};
use crate::llama::runtime::{
    RuntimeArchiveError, RuntimeDownloadRequest, RuntimeDownloadResponse, RuntimeDownloadTransport,
};
use crate::sidecar::pi_install::{
    PiDownloadRequest, PiDownloadResponse, PiDownloadTransport, PiTransportError,
};

const MAX_REDIRECTS: usize = 5;

#[derive(Clone, Copy)]
enum HostPolicy {
    HuggingFace,
    GitHub,
}

pub type ModelResponseBody = Box<dyn Read + Send + Sync + 'static>;

/// Production transport shared by the resident model and Parakeet state machines.
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
        host_policy: HostPolicy,
        offset: u64,
        connect_timeout: Duration,
        read_timeout: Duration,
        deadline: Duration,
    ) -> Result<Response, TransportFailure> {
        request_with(
            url,
            host_policy,
            offset,
            connect_timeout,
            read_timeout,
            deadline,
            |request| self.backend.execute(request),
        )
    }
}

impl ResidentModelDownloadTransport for NativeModelAcquisitionTransport {
    type Body = ModelResponseBody;

    fn download(
        &mut self,
        request: &ResidentModelDownloadRequest,
    ) -> Result<ResidentModelDownloadResponse<Self::Body>, ResidentModelTransportError> {
        self.request(
            request.url(),
            HostPolicy::HuggingFace,
            request.offset,
            request.limits.connect_timeout,
            request.limits.read_timeout,
            request.limits.deadline,
        )
        .map(|response| ResidentModelDownloadResponse {
            status: response.status,
            content_range: response.content_range,
            body: response.body,
        })
        .map_err(|error| match error {
            TransportFailure::Transient => ResidentModelTransportError::Transient,
            TransportFailure::Unavailable => ResidentModelTransportError::Unavailable,
            TransportFailure::Rejected => ResidentModelTransportError::Rejected,
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
            HostPolicy::HuggingFace,
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

impl KokoroDownloadTransport for NativeModelAcquisitionTransport {
    type Body = ModelResponseBody;

    fn download(
        &mut self,
        request: &KokoroDownloadRequest,
    ) -> Result<KokoroDownloadResponse<Self::Body>, KokoroTransportError> {
        self.request(
            request.url(),
            HostPolicy::GitHub,
            request.offset,
            request.limits.connect_timeout,
            request.limits.read_timeout,
            request.limits.deadline,
        )
        .map(|response| KokoroDownloadResponse {
            status: response.status,
            content_range: response.content_range,
            body: response.body,
        })
        .map_err(|error| match error {
            TransportFailure::Transient => KokoroTransportError::Transient,
            TransportFailure::Unavailable => KokoroTransportError::Unavailable,
            TransportFailure::Rejected => KokoroTransportError::Rejected,
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
            HostPolicy::GitHub,
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
            HostPolicy::GitHub,
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
    host_policy: HostPolicy,
    offset: u64,
    connect_timeout: Duration,
    read_timeout: Duration,
    deadline: Duration,
    mut execute: F,
) -> Result<Response, TransportFailure>
where
    F: FnMut(&BackendRequest) -> Result<BackendResponse, TransportFailure>,
{
    let mut url = checked_initial_url(initial_url, host_policy)?;
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
            url = checked_redirect_url(
                url.join(&location)
                    .map_err(|_| TransportFailure::Rejected)?
                    .as_str(),
                host_policy,
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

fn checked_initial_url(value: &str, host_policy: HostPolicy) -> Result<url::Url, TransportFailure> {
    let parsed = url::Url::parse(value).map_err(|_| TransportFailure::Rejected)?;
    let expected_host = match host_policy {
        HostPolicy::HuggingFace => "huggingface.co",
        HostPolicy::GitHub => "github.com",
    };
    if !has_secure_origin(&parsed) || parsed.host_str() != Some(expected_host) {
        return Err(TransportFailure::Rejected);
    }
    Ok(parsed)
}

fn checked_redirect_url(
    value: &str,
    host_policy: HostPolicy,
) -> Result<url::Url, TransportFailure> {
    let parsed = url::Url::parse(value).map_err(|_| TransportFailure::Rejected)?;
    let host = parsed.host_str().unwrap_or_default();
    let allowed_host = match host_policy {
        HostPolicy::HuggingFace => {
            host_equals_or_has_dot_suffix(host, "hf.co")
                || host_equals_or_has_dot_suffix(host, "huggingface.co")
        }
        HostPolicy::GitHub => {
            host == "github.com" || host == "release-assets.githubusercontent.com"
        }
    };
    if !has_secure_origin(&parsed) || !allowed_host {
        return Err(TransportFailure::Rejected);
    }
    Ok(parsed)
}

fn has_secure_origin(url: &url::Url) -> bool {
    url.scheme() == "https" && url.port_or_known_default() == Some(443)
}

fn host_equals_or_has_dot_suffix(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
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
    use crate::llama::acquisition::ResidentModelAcquisitionLimits;
    #[cfg(feature = "network-tests")]
    use crate::llama::RESIDENT_MODEL;
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

    fn resident_model_request() -> ResidentModelDownloadRequest {
        ResidentModelDownloadRequest::for_transport_test(
            "https://huggingface.co/repo/resolve/revision/model?secret=value".into(),
            7,
            ResidentModelAcquisitionLimits {
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

    fn kokoro_request() -> KokoroDownloadRequest {
        KokoroDownloadRequest::for_transport_test(
            "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/model"
                .into(),
            7,
            crate::kokoro::acquisition::KokoroAcquisitionLimits {
                connect_timeout: Duration::from_secs(10),
                read_timeout: Duration::from_secs(30),
                deadline: Duration::from_secs(5),
                max_attempts: 1,
            },
        )
    }

    #[test]
    fn resident_model_adapter_streams_200() {
        let mut transport = transport(vec![Ok(reply(200, None, None, b"streamed"))]);
        let mut response =
            ResidentModelDownloadTransport::download(&mut transport, &resident_model_request())
                .unwrap();
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
    fn kokoro_adapter_forwards_range_and_maps_response() {
        let mut transport = transport(vec![Ok(reply(206, None, Some("bytes 7-9/10"), b"abc"))]);
        let mut response =
            KokoroDownloadTransport::download(&mut transport, &kokoro_request()).unwrap();
        assert_eq!(response.status, 206);
        assert_eq!(response.content_range, Some((7, 9, 10)));
        let mut bytes = Vec::new();
        response.body.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
    }

    #[test]
    fn kokoro_adapter_maps_failures_and_enforces_redirect_policy() {
        for (reply, expected) in [
            (
                Err(TransportFailure::Transient),
                KokoroTransportError::Transient,
            ),
            (
                Err(TransportFailure::Unavailable),
                KokoroTransportError::Unavailable,
            ),
            (
                Err(TransportFailure::Rejected),
                KokoroTransportError::Rejected,
            ),
            (
                Ok(reply(302, Some("http://github.com/file"), None, b"")),
                KokoroTransportError::Rejected,
            ),
            (
                Ok(reply(302, Some("https://example.com/file"), None, b"")),
                KokoroTransportError::Rejected,
            ),
        ] {
            let mut transport = transport(vec![reply]);
            assert!(matches!(
                KokoroDownloadTransport::download(&mut transport, &kokoro_request()),
                Err(error) if error == expected
            ));
        }

        let mut allowed = transport(vec![
            Ok(reply(
                302,
                Some("https://release-assets.githubusercontent.com/file"),
                None,
                b"",
            )),
            Ok(reply(200, None, None, b"ok")),
        ]);
        assert!(KokoroDownloadTransport::download(&mut allowed, &kokoro_request()).is_ok());

        for (status, expected) in [
            (503, KokoroTransportError::Transient),
            (404, KokoroTransportError::Unavailable),
        ] {
            let mut transport = transport(vec![Ok(reply(status, None, None, b"private"))]);
            assert!(matches!(
                KokoroDownloadTransport::download(&mut transport, &kokoro_request()),
                Err(error) if error == expected
            ));
        }
    }

    #[test]
    fn both_adapters_map_status_and_transport_failures() {
        let mut resident_model = transport(vec![Ok(reply(503, None, None, b"private body"))]);
        assert!(matches!(
            ResidentModelDownloadTransport::download(
                &mut resident_model,
                &resident_model_request()
            ),
            Err(ResidentModelTransportError::Transient)
        ));
        let mut asr = transport(vec![Err(TransportFailure::Transient)]);
        assert!(matches!(
            AsrDownloadTransport::download(&mut asr, &asr_request()),
            Err(AsrTransportError::Transient)
        ));
        for status in [404, 410] {
            let mut resident_model = transport(vec![Ok(reply(status, None, None, b"secret body"))]);
            assert!(matches!(
                ResidentModelDownloadTransport::download(
                    &mut resident_model,
                    &resident_model_request()
                ),
                Err(ResidentModelTransportError::Unavailable)
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
        let mut resident_model = transport(vec![Ok(reply(
            302,
            Some("http://huggingface.co/file"),
            None,
            b"",
        ))]);
        assert!(matches!(
            ResidentModelDownloadTransport::download(
                &mut resident_model,
                &resident_model_request()
            ),
            Err(ResidentModelTransportError::Rejected)
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
        let result = ResidentModelDownloadTransport::download(
            &mut allowed_transport,
            &resident_model_request(),
        );
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

    #[test]
    fn redirect_policy_rejects_insecure_ports_and_unrelated_hosts() {
        for url in [
            "http://us.aws.cdn.hf.co/file",
            "https://us.aws.cdn.hf.co:444/file",
            "https://evilhf.co/file",
            "https://hf.co.attacker.com/file",
            "https://nothuggingface.co/file",
            "https://attacker.com/file",
        ] {
            assert_eq!(
                checked_redirect_url(url, HostPolicy::HuggingFace),
                Err(TransportFailure::Rejected),
                "{url}"
            );
        }
    }

    #[test]
    fn redirect_policy_accepts_hugging_face_owned_hosts() {
        for url in [
            "https://us.aws.cdn.hf.co/file",
            "https://eu.aws.cdn.hf.co/file",
            "https://cas-bridge.xethub.hf.co/file",
            "https://cdn-lfs-us-1.huggingface.co/file",
        ] {
            assert!(
                checked_redirect_url(url, HostPolicy::HuggingFace).is_ok(),
                "{url}"
            );
        }
    }

    #[test]
    fn initial_url_policy_rejects_hugging_face_cdn_hosts() {
        assert_eq!(
            checked_initial_url("https://us.aws.cdn.hf.co/file", HostPolicy::HuggingFace),
            Err(TransportFailure::Rejected)
        );
    }

    #[cfg(feature = "network-tests")]
    #[test]
    fn resident_model_redirect_matches_redirect_policy() {
        let initial_url =
            checked_initial_url(RESIDENT_MODEL.source_url, HostPolicy::HuggingFace).unwrap();
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .https_only(true)
            .try_proxy_from_env(true)
            .build();
        let response = match agent.head(initial_url.as_str()).call() {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("resident model HEAD failed: {error}"),
        };
        assert!(
            matches!(response.status(), 301 | 302 | 303 | 307 | 308),
            "resident model HEAD returned {}",
            response.status()
        );
        let location = response
            .header("Location")
            .expect("resident model redirect lacks a Location header");
        let redirect_url = initial_url
            .join(location)
            .expect("resident model Location header is invalid");
        assert_eq!(
            checked_redirect_url(redirect_url.as_str(), HostPolicy::HuggingFace),
            Ok(redirect_url)
        );
    }
}
