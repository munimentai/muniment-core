//! Managed, loopback-only `llama-server` process and health boundary.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sidecar::{ProbeOutcome, SidecarConfig, SidecarError, SidecarSupervisor};

const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HEALTH_BODY_BYTES: u64 = 64 * 1024;
const MAX_CHAT_BODY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::System,
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::User,
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[non_exhaustive]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub max_tokens: u32,
    pub temperature: f32,
}

impl ChatCompletionRequest {
    pub fn new(
        model: impl Into<String>,
        messages: Vec<ChatMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Self {
        Self {
            model: model.into(),
            messages,
            max_tokens,
            temperature,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ChatTokenUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatCompletionResponse {
    pub text: String,
    pub usage: Option<ChatTokenUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlamaChatError {
    InvalidBaseUrl(String),
    InvalidTimeout,
    Transport(String),
    HttpStatus(u16),
    BodyTooLarge { limit: u64 },
    MalformedJson,
    InvalidResponse(&'static str),
}

impl std::fmt::Display for LlamaChatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBaseUrl(message) => write!(f, "invalid llama chat base URL: {message}"),
            Self::InvalidTimeout => write!(f, "llama chat timeout must be greater than zero"),
            Self::Transport(error) => write!(f, "llama chat request failed: {error}"),
            Self::HttpStatus(status) => write!(f, "llama chat endpoint returned HTTP {status}"),
            Self::BodyTooLarge { limit } => write!(f, "llama chat response exceeds {limit} bytes"),
            Self::MalformedJson => write!(f, "invalid JSON in llama chat response"),
            Self::InvalidResponse(reason) => write!(f, "invalid llama chat response: {reason}"),
        }
    }
}

impl std::error::Error for LlamaChatError {}

#[derive(Debug, Clone)]
pub struct LlamaChatClient {
    base_url: String,
    timeout: Duration,
    max_response_bytes: u64,
}

impl LlamaChatClient {
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Result<Self, LlamaChatError> {
        let base_url = base_url.into();
        validate_loopback_base_url(&base_url).map_err(LlamaChatError::InvalidBaseUrl)?;
        if timeout.is_zero() {
            return Err(LlamaChatError::InvalidTimeout);
        }
        Ok(Self {
            base_url,
            timeout,
            max_response_bytes: MAX_CHAT_BODY_BYTES,
        })
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn complete(
        &self,
        request: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, LlamaChatError> {
        #[derive(Serialize)]
        struct WireRequest<'a> {
            #[serde(flatten)]
            request: &'a ChatCompletionRequest,
            stream: bool,
        }
        let url = format!("{}/v1/chat/completions", self.base_url);
        let response = match ureq::post(&url)
            .timeout(self.timeout)
            .send_json(WireRequest {
                request,
                stream: false,
            }) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, _)) => return Err(LlamaChatError::HttpStatus(status)),
            Err(ureq::Error::Transport(error)) => {
                return Err(LlamaChatError::Transport(error.to_string()))
            }
        };
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(self.max_response_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| LlamaChatError::Transport(error.to_string()))?;
        if bytes.len() as u64 > self.max_response_bytes {
            return Err(LlamaChatError::BodyTooLarge {
                limit: self.max_response_bytes,
            });
        }
        let wire: WireChatResponse =
            serde_json::from_slice(&bytes).map_err(|_| LlamaChatError::MalformedJson)?;
        if wire.choices.len() != 1 {
            return Err(LlamaChatError::InvalidResponse(
                "expected exactly one choice",
            ));
        }
        let message = wire.choices.into_iter().next().unwrap().message;
        if message.role != ChatRole::Assistant {
            return Err(LlamaChatError::InvalidResponse(
                "choice role is not assistant",
            ));
        }
        if message.content.trim().is_empty() {
            return Err(LlamaChatError::InvalidResponse(
                "assistant content is empty",
            ));
        }
        Ok(ChatCompletionResponse {
            text: message.content,
            usage: wire.usage,
        })
    }
}

#[derive(Deserialize)]
struct WireChatResponse {
    choices: Vec<WireChoice>,
    usage: Option<ChatTokenUsage>,
}
#[derive(Deserialize)]
struct WireChoice {
    message: ChatMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackHost {
    Ipv4,
    Ipv6,
}

impl LoopbackHost {
    fn argument(self) -> &'static str {
        match self {
            Self::Ipv4 => "127.0.0.1",
            Self::Ipv6 => "::1",
        }
    }

    fn base_url(self, port: u16) -> String {
        match self {
            Self::Ipv4 => format!("http://127.0.0.1:{port}"),
            Self::Ipv6 => format!("http://[::1]:{port}"),
        }
    }
}

/// The complete set of inputs needed to launch one local llama server.
#[derive(Debug, Clone)]
pub struct LlamaServerConfig {
    executable: PathBuf,
    model: PathBuf,
    port: u16,
    host: LoopbackHost,
}

impl LlamaServerConfig {
    pub fn new(executable: impl Into<PathBuf>, model: impl Into<PathBuf>, port: u16) -> Self {
        Self {
            executable: executable.into(),
            model: model.into(),
            port,
            host: LoopbackHost::Ipv4,
        }
    }

    pub fn with_host(mut self, host: LoopbackHost) -> Self {
        self.host = host;
        self
    }

    pub fn base_url(&self) -> String {
        self.host.base_url(self.port)
    }

    pub fn sidecar_config(&self) -> SidecarConfig {
        let mut config = SidecarConfig::new(self.executable.to_string_lossy().into_owned());
        config.args = vec![
            "--model".into(),
            self.model.to_string_lossy().into_owned(),
            "--host".into(),
            self.host.argument().into(),
            "--port".into(),
            self.port.to_string(),
        ];
        config
    }
}

#[derive(Debug, Clone)]
pub struct LlamaHealthClient {
    base_url: String,
    timeout: Duration,
}

impl LlamaHealthClient {
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Result<Self, String> {
        let base_url = base_url.into();
        validate_loopback_base_url(&base_url)?;
        if timeout.is_zero() {
            return Err("llama health timeout must be greater than zero".into());
        }
        Ok(Self { base_url, timeout })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn probe(&self) -> Result<ProbeOutcome, String> {
        let url = format!("{}/health", self.base_url);
        match ureq::get(&url).timeout(self.timeout).call() {
            Ok(response) => parse_ready(response),
            Err(ureq::Error::Status(503, response)) => parse_loading(response),
            Err(ureq::Error::Status(status, _)) => {
                Err(format!("llama health endpoint returned HTTP {status}"))
            }
            Err(ureq::Error::Transport(error)) => {
                Err(format!("llama health request failed: {error}"))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReadyResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct LoadingResponse {
    error: LoadingError,
}

#[derive(Debug, Deserialize)]
struct LoadingError {
    code: u16,
    message: String,
}

fn parse_ready(response: ureq::Response) -> Result<ProbeOutcome, String> {
    let body: ReadyResponse = parse_body(response, 200)?;
    if body.status == "ok" {
        Ok(ProbeOutcome::Ready)
    } else {
        Err("unexpected llama health response for HTTP 200".into())
    }
}

fn parse_loading(response: ureq::Response) -> Result<ProbeOutcome, String> {
    let body: LoadingResponse = parse_body(response, 503)?;
    if body.error.code == 503 && body.error.message == "Loading model" {
        Ok(ProbeOutcome::Loading)
    } else {
        Err("unexpected llama health response for HTTP 503".into())
    }
}

fn parse_body<T: for<'de> Deserialize<'de>>(
    response: ureq::Response,
    status: u16,
) -> Result<T, String> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_HEALTH_BODY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!("failed reading llama health response for HTTP {status}: {error}")
        })?;
    if bytes.len() as u64 > MAX_HEALTH_BODY_BYTES {
        return Err(format!(
            "llama health response for HTTP {status} exceeds {MAX_HEALTH_BODY_BYTES} bytes"
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid llama health response for HTTP {status}: {error}"))
}

fn validate_loopback_base_url(base_url: &str) -> Result<(), String> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or_else(|| "llama base URL must use http on loopback".to_string())?;
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || !authority_has_loopback_host(authority)
    {
        return Err("llama base URL must contain only a loopback host and port".into());
    }
    Ok(())
}

fn authority_has_loopback_host(authority: &str) -> bool {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return false;
        };
        (host, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        (host, port)
    };
    port.parse::<u16>().is_ok()
        && host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip == Ipv4Addr::LOCALHOST || ip == Ipv6Addr::LOCALHOST)
}

/// Owns the supervisor and exposes only the local HTTP boundary needed by later roles.
pub struct LlamaServer {
    base_url: String,
    health: LlamaHealthClient,
    supervisor: SidecarSupervisor,
}

impl LlamaServer {
    pub fn spawn(config: LlamaServerConfig) -> Result<Self, SidecarError> {
        let base_url = config.base_url();
        let health = LlamaHealthClient::new(base_url.clone(), DEFAULT_HEALTH_TIMEOUT)
            .expect("typed llama configuration always produces a loopback URL");
        let probe = health.clone();
        let supervisor = SidecarSupervisor::spawn(config.sidecar_config(), move |_| probe.probe())?;
        Ok(Self {
            base_url,
            health,
            supervisor,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn health(&self) -> Result<ProbeOutcome, String> {
        self.health.probe()
    }

    pub fn supervisor(&self) -> &SidecarSupervisor {
        &self.supervisor
    }

    pub fn shutdown(&mut self) -> Result<(), SidecarError> {
        self.supervisor.shutdown()
    }
}
