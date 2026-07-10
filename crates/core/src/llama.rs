//! Managed, loopback-only `llama-server` process and health boundary.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::sidecar::{ProbeOutcome, SidecarConfig, SidecarError, SidecarSupervisor};

const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HEALTH_BODY_BYTES: u64 = 64 * 1024;

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
