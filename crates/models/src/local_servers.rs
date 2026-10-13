//! The first-run scan for model servers on this computer and for coding tools
//! that already hold a provider sign-in. Probes reach the loopback address only
//! and carry no credential. Hint checks read file metadata, never file contents.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

/// The environment a scan reads, by variable name.
pub type Environment = BTreeMap<OsString, OsString>;

/// The operating system whose install paths a scan reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }
}

/// Each connect and each read waits this long.
const PROBE_TIMEOUT: Duration = Duration::from_millis(400);
/// One request, from its connect to its last body byte.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(800);
/// The whole scan answers within this budget.
pub const SCAN_BUDGET: Duration = Duration::from_millis(1800);
const BODY_LIMIT: u64 = 256 * 1024;
const FILE_LIMIT: u64 = 1024 * 1024;
pub const LOOPBACK_ERROR: &str = "Use a server address on this computer.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerState {
    Ready,
    NeedsKey,
    NotRunning,
}

/// One model server the scan found or found installed.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    id: &'static str,
    name: &'static str,
    base_url: String,
    state: ServerState,
    model_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_model: Option<String>,
    /// The display path of a settings file that holds the server's key.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_file: Option<String>,
    #[serde(skip)]
    port: u16,
}

/// A provider the user already reaches through a tool on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hint {
    provider: &'static str,
    evidence: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ProviderScan {
    servers: Vec<Server>,
    hints: Vec<Hint>,
}

/// One kind of local server: the ports it listens on by default, where its
/// OpenAI-compatible API sits, and the paths beside it that tell it apart.
#[derive(Debug, Serialize)]
pub struct Kind {
    pub id: &'static str,
    pub name: &'static str,
    pub ports: &'static [u16],
    pub api: &'static str,
    pub paths: &'static [&'static str],
}

pub const KINDS: &[Kind] = &[
    Kind {
        id: "ollama",
        name: "Ollama",
        ports: &[11434],
        api: "/v1",
        paths: &["/"],
    },
    Kind {
        id: "lmstudio",
        name: "LM Studio",
        ports: &[1234],
        api: "/v1",
        paths: &["/lmstudio-greeting"],
    },
    Kind {
        id: "llamacpp",
        name: "llama.cpp",
        ports: &[9931, 8080],
        api: "/v1",
        paths: &["/health"],
    },
    Kind {
        id: "mlx-lm",
        name: "MLX LM",
        ports: &[8080],
        api: "/v1",
        paths: &["/health"],
    },
    Kind {
        id: "omlx",
        name: "oMLX",
        ports: &[8000],
        api: "/v1",
        paths: &["/health"],
    },
    Kind {
        id: "vllm",
        name: "vLLM",
        ports: &[8000],
        api: "/v1",
        paths: &["/version"],
    },
    Kind {
        id: "jan",
        name: "Jan",
        ports: &[1337],
        api: "/v1",
        paths: &[],
    },
    Kind {
        id: "osaurus",
        name: "Osaurus",
        ports: &[1337],
        api: "/v1",
        paths: &["/"],
    },
    Kind {
        id: "localai",
        name: "LocalAI",
        ports: &[8080],
        api: "/v1",
        paths: &["/.well-known/localai.json"],
    },
    Kind {
        id: "lemonade",
        name: "Lemonade",
        ports: &[13305],
        api: "/v1",
        paths: &["/live"],
    },
    Kind {
        id: "koboldcpp",
        name: "KoboldCpp",
        ports: &[5001],
        api: "/v1",
        paths: &[],
    },
    Kind {
        id: "docker-model-runner",
        name: "Docker Model Runner",
        ports: &[12434],
        api: "/engines/v1",
        paths: &["/"],
    },
    Kind {
        id: "textgen",
        name: "Text Generation WebUI",
        ports: &[5000],
        api: "/v1",
        paths: &["/v1/internal/health"],
    },
    Kind {
        id: "exo",
        name: "exo",
        ports: &[52415],
        api: "/v1",
        paths: &[],
    },
];

/// The servers that leave install evidence, so the scan reports them when they do not answer.
pub const INSTALLABLE: &[&str] = &["ollama", "lmstudio", "omlx", "jan"];

pub fn kind(id: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|kind| kind.id == id)
}

fn rank(id: &str) -> usize {
    KINDS
        .iter()
        .position(|kind| kind.id == id)
        .unwrap_or(KINDS.len())
}

/// Where the scan looks: the user's home, their environment, the platform, and
/// the root that absolute install paths sit under.
pub struct Context<'a> {
    pub home: &'a Path,
    pub environment: &'a Environment,
    pub platform: Platform,
    pub root: &'a Path,
}

impl Context<'_> {
    fn var(&self, name: &str) -> Option<&OsStr> {
        self.environment
            .get(OsStr::new(name))
            .map(|value| value.as_os_str())
            .filter(|value| !value.is_empty())
    }

    fn dir_var(&self, name: &str) -> Option<PathBuf> {
        self.var(name).map(PathBuf::from)
    }

    fn port_var(&self, name: &str) -> Option<u16> {
        self.var(name)?.to_str().and_then(parse_port)
    }

    fn home_path(&self, parts: &[&str]) -> PathBuf {
        join(self.home, parts)
    }

    fn system_path(&self, parts: &[&str]) -> PathBuf {
        join(self.root, parts)
    }
}

fn join(base: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

fn parse_port(text: &str) -> Option<u16> {
    text.trim().parse().ok().filter(|port| *port != 0)
}

fn port_value(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .or_else(|| value.as_str().and_then(parse_port))
}

fn read_text(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(FILE_LIMIT)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&read_text(path)?).ok()
}

fn json_port(path: &Path, pointer: &str) -> Option<u16> {
    port_value(read_json(path)?.pointer(pointer)?)
}

fn expand_home(home: &Path, text: &str) -> PathBuf {
    match text.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(text),
    }
}

fn display_path(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => Path::new("~").join(rest).display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

fn loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

/// The port `OLLAMA_HOST` names when it names this computer, read as Ollama reads it.
fn ollama_host_port(value: &str) -> Option<u16> {
    let value = value.trim();
    let (default, rest) = match value.split_once("://") {
        Some(("http", rest)) => (80, rest),
        Some(("https", rest)) => (443, rest),
        Some((_, rest)) => (11434, rest),
        None => (11434, value),
    };
    let address = rest.split('/').next().unwrap_or_default();
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') || host.ends_with(']') => (host, Some(port)),
        _ => (address, None),
    };
    if !loopback_host(host) {
        return None;
    }
    port.map_or(Some(default), parse_port)
}

/// LM Studio's home: the folder its pointer file names, else its cache folder, else `~/.lmstudio`.
fn lmstudio_home(context: &Context) -> Option<PathBuf> {
    read_text(&context.home_path(&[".lmstudio-home-pointer"]))
        .map(|text| PathBuf::from(text.trim()))
        .filter(|path| path.is_absolute() && path.is_dir())
        .or_else(|| {
            [
                context.home_path(&[".cache", "lm-studio"]),
                context.home_path(&[".lmstudio"]),
            ]
            .into_iter()
            .find(|path| path.is_dir())
        })
}

fn omlx_base(context: &Context) -> PathBuf {
    if let Some(base) = context.var("OMLX_BASE_PATH") {
        return expand_home(context.home, &base.to_string_lossy());
    }
    if context.platform == Platform::MacOs {
        let pointer = context.home_path(&["Library", "Application Support", "oMLX", "base-path"]);
        if let Some(text) = read_text(&pointer).filter(|text| !text.trim().is_empty()) {
            return expand_home(context.home, text.trim());
        }
    }
    context.home_path(&[".omlx"])
}

fn omlx_settings(context: &Context) -> PathBuf {
    omlx_base(context).join("settings.json")
}

/// The key in oMLX's settings file. Only a connect reads it, and it goes straight to storage.
pub fn omlx_key(context: &Context) -> Option<String> {
    read_json(&omlx_settings(context))?
        .pointer("/auth/api_key")?
        .as_str()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
}

fn llamacpp_config_port(context: &Context) -> Option<u16> {
    let directory = if context.platform == Platform::Windows {
        context.dir_var("APPDATA")?
    } else {
        context
            .dir_var("XDG_CONFIG_HOME")
            .unwrap_or_else(|| context.home_path(&[".config"]))
    };
    read_text(&directory.join("llama.cpp").join("config.ini"))?
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "port")
                .then(|| parse_port(value.trim().trim_matches('"')))
                .flatten()
        })
}

/// The ports a kind listens on here: its configured port, else its defaults.
fn ports(kind: &Kind, context: &Context) -> Vec<u16> {
    let configured = match kind.id {
        "ollama" => context
            .var("OLLAMA_HOST")
            .and_then(|value| ollama_host_port(&value.to_string_lossy())),
        "lmstudio" => lmstudio_home(context).and_then(|home| {
            json_port(
                &home.join(".internal").join("http-server-config.json"),
                "/port",
            )
        }),
        "omlx" => context
            .port_var("OMLX_PORT")
            .or_else(|| json_port(&omlx_settings(context), "/server/port")),
        "osaurus" => json_port(
            &context.home_path(&[".osaurus", "config", "server.json"]),
            "/port",
        ),
        "lemonade" => context.port_var("LEMONADE_PORT"),
        "llamacpp" => {
            let mut ports = kind.ports.to_vec();
            ports.extend(llamacpp_config_port(context).filter(|port| !ports.contains(port)));
            return ports;
        }
        _ => None,
    };
    configured.map_or_else(|| kind.ports.to_vec(), |port| vec![port])
}

/// Each port to probe and the kinds that may answer there.
fn port_plan(context: &Context) -> BTreeMap<u16, Vec<&'static Kind>> {
    let mut plan: BTreeMap<u16, Vec<&'static Kind>> = BTreeMap::new();
    for kind in KINDS {
        for port in ports(kind, context) {
            let kinds = plan.entry(port).or_default();
            if !kinds.iter().any(|known| known.id == kind.id) {
                kinds.push(kind);
            }
        }
    }
    plan
}

fn probe_paths(kinds: &[&Kind]) -> Vec<String> {
    kinds
        .iter()
        .flat_map(|kind| {
            std::iter::once(format!("{}/models", kind.api))
                .chain(kind.paths.iter().map(|path| (*path).to_owned()))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn installed(id: &str, context: &Context) -> bool {
    let programs = |name: &str| {
        context
            .dir_var("LOCALAPPDATA")
            .is_some_and(|local| local.join("Programs").join(name).exists())
    };
    let mac_app = |name: &str| {
        context.platform == Platform::MacOs && context.system_path(&["Applications", name]).exists()
    };
    match id {
        "ollama" => match context.platform {
            Platform::Windows => programs("Ollama"),
            _ => {
                mac_app("Ollama.app")
                    || [
                        &["usr", "local", "bin"][..],
                        &["usr", "bin"],
                        &["opt", "homebrew", "bin"],
                    ]
                    .iter()
                    .any(|directory| context.system_path(directory).join("ollama").is_file())
            }
        },
        "lmstudio" => {
            lmstudio_home(context).is_some()
                || mac_app("LM Studio.app")
                || (context.platform == Platform::Windows && programs("LM Studio"))
        }
        "omlx" => omlx_settings(context).is_file() || mac_app("oMLX.app"),
        "jan" => match context.platform {
            Platform::MacOs => context
                .home_path(&["Library", "Application Support", "Jan"])
                .is_dir(),
            Platform::Windows => context
                .dir_var("APPDATA")
                .is_some_and(|roaming| roaming.join("Jan").is_dir()),
            _ => context.home_path(&[".local", "share", "Jan"]).is_dir(),
        },
        _ => false,
    }
}

/// What one path answered.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    status: u16,
    server: String,
    body: String,
}

pub type Replies = BTreeMap<String, Reply>;

fn json(reply: &Reply) -> Option<Value> {
    serde_json::from_str(&reply.body).ok()
}

/// Loopback probes never go through a proxy, never follow a redirect, and send no credential.
fn probe_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout_connect(PROBE_TIMEOUT)
        .timeout_read(PROBE_TIMEOUT)
        .timeout_write(PROBE_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
}

fn fetch(agent: &ureq::Agent, port: u16, path: &str) -> Option<Reply> {
    let response = match agent.get(&format!("http://127.0.0.1:{port}{path}")).call() {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(_) => return None,
    };
    let status = response.status();
    let server = response.header("server").unwrap_or_default().to_owned();
    let mut body = Vec::new();
    let _ = response
        .into_reader()
        .take(BODY_LIMIT)
        .read_to_end(&mut body);
    Some(Reply {
        status,
        server,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// One connect tells whether the port listens. A listening port gets its paths in parallel.
fn probe_port(port: u16, paths: &[String], deadline: Instant) -> Option<Replies> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&address, PROBE_TIMEOUT).ok()?;
    let agent = probe_agent();
    let (sender, receiver) = mpsc::channel();
    for path in paths {
        let (agent, sender, path) = (agent.clone(), sender.clone(), path.clone());
        std::thread::spawn(move || {
            let reply = fetch(&agent, port, &path);
            let _ = sender.send((path, reply));
        });
    }
    drop(sender);
    let mut replies = Replies::new();
    while let Ok((path, reply)) =
        receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        if let Some(reply) = reply {
            replies.insert(path, reply);
        }
    }
    Some(replies)
}

fn owner_kind(owner: &str) -> Option<&'static str> {
    Some(match owner {
        "omlx" => "omlx",
        "vllm" => "vllm",
        "llamacpp" => "llamacpp",
        "osaurus" => "osaurus",
        "lemonade" => "lemonade",
        "koboldcpp" => "koboldcpp",
        "docker" => "docker-model-runner",
        "exo" => "exo",
        "user" => "textgen",
        "llama.cpp" | "mlx" | "remote" => "jan",
        _ => return None,
    })
}

/// The kind the replies fingerprint, strongest evidence first.
fn identify(replies: &Replies) -> Option<&'static Kind> {
    let ok = |path: &str| replies.get(path).filter(|reply| reply.status == 200);
    let text = |path: &str| ok(path).map(|reply| reply.body.trim_start());
    let json_at = |path: &str| ok(path).and_then(json);
    let server = |prefix: &str| {
        replies.values().any(|reply| {
            reply
                .server
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
        })
    };
    let owner = ["/v1/models", "/engines/v1/models"]
        .iter()
        .filter_map(|path| json_at(path))
        .find_map(|list| {
            list.get("data")?
                .as_array()?
                .iter()
                .find_map(|model| model.get("owned_by")?.as_str().map(str::to_owned))
        });
    let refused = replies
        .get("/v1/models")
        .filter(|reply| matches!(reply.status, 401 | 403));
    let refusal = refused.and_then(json);
    let refusal_message = refusal.as_ref().and_then(|body| match body.get("error")? {
        Value::String(message) => Some(message.clone()),
        error => error.get("message")?.as_str().map(str::to_owned),
    });
    let status_ok = |path: &str| {
        json_at(path).is_some_and(|body| body.get("status").and_then(Value::as_str) == Some("ok"))
    };

    let id = if text("/").is_some_and(|body| body.starts_with("Ollama is running")) {
        "ollama"
    } else if text("/").is_some_and(|body| body.starts_with("Docker Model Runner is running")) {
        "docker-model-runner"
    } else if text("/").is_some_and(|body| body.starts_with("Osaurus Server is running")) {
        "osaurus"
    } else if json_at("/lmstudio-greeting")
        .is_some_and(|body| body.get("lmstudio") == Some(&Value::Bool(true)))
    {
        "lmstudio"
    } else if replies
        .get("/health")
        .and_then(json)
        .is_some_and(|body| body.get("engine_pool").is_some())
    {
        "omlx"
    } else if json_at("/.well-known/localai.json").is_some() {
        "localai"
    } else if let Some(id) = owner.as_deref().and_then(owner_kind) {
        id
    } else if server("KoboldCpp") {
        "koboldcpp"
    } else if server("llama.cpp") {
        "llamacpp"
    } else if refused.is_some_and(|reply| {
        reply
            .body
            .contains("Invalid or missing authorization token")
    }) {
        "jan"
    } else if let Some(id) = refusal_message
        .as_deref()
        .and_then(|message| match message {
            "API key required" => Some("omlx"),
            "Invalid or missing API key" => Some("lemonade"),
            "Invalid API Key" => Some("llamacpp"),
            "Unauthorized" if json_at("/version").is_some() => Some("vllm"),
            _ => None,
        })
    {
        id
    } else if status_ok("/live") {
        "lemonade"
    } else if json_at("/version").is_some_and(|body| body.get("version").is_some())
        && replies.contains_key("/v1/models")
    {
        "vllm"
    } else if status_ok("/health") && server("BaseHTTP") {
        "mlx-lm"
    } else if ok("/v1/internal/health").is_some() {
        "textgen"
    } else {
        return None;
    };
    kind(id)
}

/// Names the server behind a port from what its paths answered. The model
/// list decides the state: a refusal needs a key, and a list is ready.
pub fn classify(port: u16, replies: &Replies) -> Option<Server> {
    let kind = identify(replies)?;
    let models = replies.get(&format!("{}/models", kind.api));
    let state = match models.map(|reply| reply.status) {
        Some(401 | 403) => ServerState::NeedsKey,
        _ => ServerState::Ready,
    };
    let listed = models
        .filter(|reply| reply.status == 200)
        .and_then(json)
        .and_then(|body| body.get("data")?.as_array().cloned())
        .unwrap_or_default();
    let mut model_count = listed.len();
    let mut default_model = listed
        .first()
        .and_then(|model| model.get("id")?.as_str())
        .map(str::to_owned);
    // oMLX names its pool and its default without a key, so the card shows them behind a refusal.
    if kind.id == "omlx" {
        if let Some(health) = replies.get("/health").and_then(json) {
            if let Some(count) = health
                .pointer("/engine_pool/model_count")
                .and_then(Value::as_u64)
            {
                model_count = usize::try_from(count).unwrap_or(usize::MAX);
            }
            if let Some(model) = health
                .get("default_model")
                .and_then(Value::as_str)
                .filter(|model| !model.is_empty())
            {
                default_model = Some(model.to_owned());
            }
        }
    }
    Some(Server {
        id: kind.id,
        name: kind.name,
        base_url: format!("http://127.0.0.1:{port}{}", kind.api),
        state,
        model_count,
        default_model,
        key_file: None,
        port,
    })
}

/// Probes every planned port in parallel and names what answers.
fn scan_ports(plan: &BTreeMap<u16, Vec<&'static Kind>>, deadline: Instant) -> Vec<Server> {
    let (sender, receiver) = mpsc::channel();
    for (&port, kinds) in plan {
        let (sender, paths) = (sender.clone(), probe_paths(kinds));
        std::thread::spawn(move || {
            let _ = sender.send((port, probe_port(port, &paths, deadline)));
        });
    }
    drop(sender);
    let mut found = Vec::new();
    while let Ok((port, replies)) =
        receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        found.extend(replies.and_then(|replies| classify(port, &replies)));
    }
    found
}

/// Keeps one server per id, adds installed servers that did not answer, marks
/// the oMLX key file, and sorts ready, then needs-key, then not-running.
fn finish(context: &Context, mut found: Vec<Server>) -> Vec<Server> {
    found.sort_by_key(|server| (server.state, rank(server.id), server.port));
    let mut servers: Vec<Server> = Vec::new();
    for server in found {
        if !servers.iter().any(|known| known.id == server.id) {
            servers.push(server);
        }
    }
    for kind in KINDS.iter().filter(|kind| INSTALLABLE.contains(&kind.id)) {
        if servers.iter().any(|known| known.id == kind.id) || !installed(kind.id, context) {
            continue;
        }
        let port = ports(kind, context)[0];
        if servers.iter().any(|known| known.port == port) {
            continue;
        }
        servers.push(Server {
            id: kind.id,
            name: kind.name,
            base_url: format!("http://127.0.0.1:{port}{}", kind.api),
            state: ServerState::NotRunning,
            model_count: 0,
            default_model: None,
            key_file: None,
            port,
        });
    }
    if servers.iter().any(|server| server.id == "omlx") && omlx_key(context).is_some() {
        let key_file = display_path(context.home, &omlx_settings(context));
        for server in servers.iter_mut().filter(|server| server.id == "omlx") {
            server.key_file = Some(key_file.clone());
        }
    }
    servers.sort_by_key(|server| (server.state, rank(server.id)));
    servers
}

fn scan_servers(context: &Context, deadline: Instant) -> Vec<Server> {
    finish(context, scan_ports(&port_plan(context), deadline))
}

/// Finds model servers on this computer and the tools that hold a provider
/// sign-in. `claude_code` answers the Claude Code check once the ports answer.
pub fn scan(
    context: &Context,
    deadline: Instant,
    claude_code: impl FnOnce() -> ClaudeCode,
) -> ProviderScan {
    let servers = scan_servers(context, deadline);
    let hints = hints(context, claude_code());
    ProviderScan { servers, hints }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeCode {
    Absent,
    Installed,
    SignedIn,
}

/// The tools that hold a provider sign-in, in the order the first run lists them.
pub fn hints(context: &Context, claude_code: ClaudeCode) -> Vec<Hint> {
    let mut hints = Vec::new();
    let mut add = |provider, evidence| hints.push(Hint { provider, evidence });
    let tool_dir = |variable: &str, folder: &str| {
        context
            .dir_var(variable)
            .unwrap_or_else(|| context.home_path(&[folder]))
    };
    match claude_code {
        ClaudeCode::SignedIn => add("anthropic", "Claude Code is signed in"),
        ClaudeCode::Installed => add("anthropic", "Claude Code is installed"),
        ClaudeCode::Absent => {}
    }
    let codex = tool_dir("CODEX_HOME", ".codex");
    if codex.join("auth.json").exists() {
        add("openai", "Codex CLI is signed in");
    } else if codex.is_dir() {
        add("openai", "Codex CLI is installed");
    }
    if tool_dir("GROK_HOME", ".grok").join("auth.json").exists() {
        add("xai", "Grok Build is signed in");
    }
    let gemini = match context.dir_var("GEMINI_CLI_HOME") {
        Some(home) => vec![home.join(".gemini"), home],
        None => vec![context.home_path(&[".gemini"])],
    };
    let gemini_files = [
        "gemini-credentials.json",
        "oauth_creds.json",
        "google_accounts.json",
    ];
    if gemini.iter().any(|directory| {
        gemini_files
            .iter()
            .any(|file| directory.join(file).exists())
    }) {
        add("google", "Gemini CLI is signed in");
    }
    if tool_dir("COPILOT_HOME", ".copilot").is_dir() {
        add("github-copilot", "Copilot CLI is installed");
    }
    if context.home_path(&[".kimi", "credentials"]).exists() {
        add("kimi", "Kimi CLI is signed in");
    } else if context.home_path(&[".kimi"]).is_dir() {
        add("kimi", "Kimi CLI is installed");
    }
    let devin_data = if context.platform == Platform::Windows {
        context.dir_var("APPDATA")
    } else {
        Some(
            context
                .dir_var("XDG_DATA_HOME")
                .unwrap_or_else(|| context.home_path(&[".local", "share"])),
        )
    };
    if devin_data.is_some_and(|data| data.join("devin").join("credentials.toml").exists()) {
        add("devin", "Devin CLI is signed in");
    } else if context.home_path(&[".config", "devin"]).is_dir() {
        add("devin", "Devin CLI is installed");
    }
    if context.home_path(&[".config", "muse"]).is_dir() {
        add("meta", "Muse Code is installed");
    }
    if context.home_path(&[".ori"]).is_dir() {
        add("openrouter", "Ori CLI is installed");
    }
    hints
}

/// Accepts a plain http address on this computer, with no credentials in it.
pub fn loopback_url(base_url: &str) -> Result<(), String> {
    let url = url::Url::parse(base_url).map_err(|_| LOOPBACK_ERROR.to_owned())?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.scheme() != "http"
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LOOPBACK_ERROR.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn temporary_directory() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("muniment-provider-scan-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn environment(pairs: &[(&str, &Path)]) -> Environment {
        pairs
            .iter()
            .map(|(name, value)| (OsString::from(name), value.as_os_str().to_owned()))
            .collect()
    }

    fn context<'a>(
        home: &'a Path,
        environment: &'a Environment,
        platform: Platform,
    ) -> Context<'a> {
        Context {
            home,
            environment,
            platform,
            root: home,
        }
    }

    fn reply(status: u16, server: &str, body: &str) -> Reply {
        Reply {
            status,
            server: server.to_owned(),
            body: body.to_owned(),
        }
    }

    fn replies(entries: &[(&str, Reply)]) -> Replies {
        entries
            .iter()
            .map(|(path, reply)| ((*path).to_owned(), reply.clone()))
            .collect()
    }

    fn models(owner: Option<&str>, ids: &[&str]) -> String {
        let data: Vec<Value> = ids
            .iter()
            .map(|id| match owner {
                Some(owner) => {
                    serde_json::json!({ "id": id, "object": "model", "owned_by": owner })
                }
                None => serde_json::json!({ "id": id, "object": "model" }),
            })
            .collect();
        serde_json::json!({ "object": "list", "data": data }).to_string()
    }

    type Found = (&'static str, ServerState, usize);

    fn found(port: u16, entries: &[(&str, Reply)]) -> Found {
        let server = classify(port, &replies(entries)).expect("a fingerprint");
        (server.id, server.state, server.model_count)
    }

    #[test]
    fn each_server_is_told_apart_by_its_own_fingerprint() {
        use ServerState::{NeedsKey, Ready};
        let not_found = reply(404, "", "Not Found");
        let cases: Vec<(Found, Vec<(&str, Reply)>)> = vec![
            (
                ("ollama", Ready, 2),
                vec![
                    ("/", reply(200, "", "Ollama is running")),
                    (
                        "/v1/models",
                        reply(200, "", &models(Some("library"), &["qwen3:8b", "llama3.2"])),
                    ),
                ],
            ),
            (
                ("lmstudio", NeedsKey, 0),
                vec![
                    ("/lmstudio-greeting", reply(200, "", r#"{"lmstudio":true}"#)),
                    ("/v1/models", reply(401, "", r#"{"error":"Unauthorized"}"#)),
                ],
            ),
            (
                ("llamacpp", Ready, 1),
                vec![
                    ("/health", reply(200, "llama.cpp", r#"{"status":"ok"}"#)),
                    (
                        "/v1/models",
                        reply(200, "llama.cpp", &models(Some("llamacpp"), &["gemma"])),
                    ),
                ],
            ),
            (
                ("llamacpp", NeedsKey, 0),
                vec![
                    (
                        "/health",
                        reply(503, "", r#"{"error":{"message":"Loading model"}}"#),
                    ),
                    (
                        "/v1/models",
                        reply(
                            401,
                            "",
                            r#"{"error":{"message":"Invalid API Key","type":"authentication_error"}}"#,
                        ),
                    ),
                ],
            ),
            (
                ("mlx-lm", Ready, 1),
                vec![
                    (
                        "/health",
                        reply(200, "BaseHTTP/0.6 Python/3.12.4", r#"{"status": "ok"}"#),
                    ),
                    (
                        "/v1/models",
                        reply(
                            200,
                            "BaseHTTP/0.6 Python/3.12.4",
                            &models(None, &["mlx-community/Qwen3"]),
                        ),
                    ),
                    ("/.well-known/localai.json", not_found.clone()),
                ],
            ),
            (
                ("vllm", Ready, 1),
                vec![
                    ("/version", reply(200, "uvicorn", r#"{"version":"0.11.0"}"#)),
                    (
                        "/v1/models",
                        reply(200, "uvicorn", &models(Some("vllm"), &["Qwen/Qwen3-8B"])),
                    ),
                ],
            ),
            (
                ("vllm", NeedsKey, 0),
                vec![
                    ("/health", reply(200, "uvicorn", "")),
                    ("/version", reply(200, "uvicorn", r#"{"version":"0.11.0"}"#)),
                    (
                        "/v1/models",
                        reply(401, "uvicorn", r#"{"error":"Unauthorized"}"#),
                    ),
                ],
            ),
            (
                ("jan", Ready, 1),
                vec![(
                    "/v1/models",
                    reply(200, "", &models(Some("llama.cpp"), &["jan-nano"])),
                )],
            ),
            (
                ("jan", NeedsKey, 0),
                vec![(
                    "/v1/models",
                    reply(401, "", "Invalid or missing authorization token"),
                )],
            ),
            (
                ("osaurus", Ready, 1),
                vec![
                    ("/", reply(200, "", "Osaurus Server is running! 🦕")),
                    (
                        "/v1/models",
                        reply(200, "", &models(Some("osaurus"), &["foundation"])),
                    ),
                ],
            ),
            (
                ("localai", NeedsKey, 0),
                vec![
                    (
                        "/.well-known/localai.json",
                        reply(200, "", r#"{"version":"v3"}"#),
                    ),
                    ("/health", reply(200, "", "OK")),
                    (
                        "/v1/models",
                        reply(401, "", r#"{"error":{"message":"An API key is required"}}"#),
                    ),
                ],
            ),
            (
                ("lemonade", Ready, 1),
                vec![
                    ("/live", reply(200, "", r#"{"status":"ok"}"#)),
                    (
                        "/v1/models",
                        reply(200, "", &models(Some("lemonade"), &["Qwen3-0.6B-GGUF"])),
                    ),
                ],
            ),
            (
                ("lemonade", NeedsKey, 0),
                vec![(
                    "/v1/models",
                    reply(401, "", r#"{"error":"Invalid or missing API key"}"#),
                )],
            ),
            (
                ("koboldcpp", Ready, 1),
                vec![(
                    "/v1/models",
                    reply(
                        200,
                        "KoboldCppServer/1.0",
                        &models(None, &["koboldcpp/model"]),
                    ),
                )],
            ),
            (
                ("docker-model-runner", Ready, 1),
                vec![
                    ("/", reply(200, "", "Docker Model Runner is running")),
                    (
                        "/engines/v1/models",
                        reply(200, "", &models(Some("docker"), &["ai/smollm2"])),
                    ),
                ],
            ),
            (
                ("textgen", Ready, 1),
                vec![
                    ("/v1/internal/health", reply(200, "", r#"{"status":"ok"}"#)),
                    (
                        "/v1/models",
                        reply(200, "", &models(Some("user"), &["model"])),
                    ),
                ],
            ),
            (
                ("exo", Ready, 1),
                vec![(
                    "/v1/models",
                    reply(200, "", &models(Some("exo"), &["llama-3.2-1b"])),
                )],
            ),
        ];
        for (expected, entries) in cases {
            assert_eq!(found(8080, &entries), expected, "{entries:?}");
        }
    }

    #[test]
    fn an_ollama_emulation_on_api_tags_is_not_ollama() {
        let server = classify(
            5001,
            &replies(&[
                (
                    "/",
                    reply(200, "KoboldCppServer", "<html>KoboldAI Lite</html>"),
                ),
                (
                    "/api/tags",
                    reply(
                        200,
                        "KoboldCppServer",
                        r#"{"models":[{"name":"koboldcpp"}]}"#,
                    ),
                ),
                (
                    "/v1/models",
                    reply(
                        200,
                        "KoboldCppServer",
                        &models(Some("koboldcpp"), &["koboldcpp/x"]),
                    ),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(server.id, "koboldcpp");
    }

    #[test]
    fn an_unknown_answer_names_no_server() {
        assert_eq!(classify(8080, &Replies::new()), None);
        assert_eq!(
            classify(
                8080,
                &replies(&[
                    ("/health", reply(200, "nginx", r#"{"status":"ok"}"#)),
                    ("/v1/models", reply(404, "nginx", "Not Found")),
                ])
            ),
            None
        );
    }

    #[test]
    fn omlx_shows_its_pool_and_default_behind_a_key() {
        let server = classify(
            8080,
            &replies(&[
                ("/health", reply(200, "uvicorn", r#"{"status":"healthy","default_model":"Qwen3-Coder","engine_pool":{"model_count":8,"loaded":1}}"#)),
                ("/v1/models", reply(401, "uvicorn", r#"{"error":{"message":"API key required","type":"authentication_error"}}"#)),
            ]),
        )
        .unwrap();
        assert_eq!(server.id, "omlx");
        assert_eq!(server.state, ServerState::NeedsKey);
        assert_eq!(server.model_count, 8);
        assert_eq!(server.default_model.as_deref(), Some("Qwen3-Coder"));
        assert_eq!(server.base_url, "http://127.0.0.1:8080/v1");
        let loading = classify(
            8000,
            &replies(&[
                ("/health", reply(503, "uvicorn", r#"{"status":"loading"}"#)),
                (
                    "/v1/models",
                    reply(
                        401,
                        "uvicorn",
                        r#"{"error":{"message":"API key required"}}"#,
                    ),
                ),
            ]),
        )
        .unwrap();
        assert_eq!((loading.id, loading.state), ("omlx", ServerState::NeedsKey));
    }

    #[test]
    fn the_scan_serializes_in_the_shape_the_first_run_reads() {
        let server = classify(
            12434,
            &replies(&[
                ("/", reply(200, "", "Docker Model Runner is running")),
                (
                    "/engines/v1/models",
                    reply(200, "", &models(Some("docker"), &["ai/smollm2"])),
                ),
            ]),
        )
        .unwrap();
        let scan = ProviderScan {
            servers: vec![server],
            hints: vec![Hint {
                provider: "anthropic",
                evidence: "Claude Code is signed in",
            }],
        };
        assert_eq!(
            serde_json::to_value(&scan).unwrap(),
            serde_json::json!({
                "servers": [{
                    "id": "docker-model-runner",
                    "name": "Docker Model Runner",
                    "baseUrl": "http://127.0.0.1:12434/engines/v1",
                    "state": "ready",
                    "modelCount": 1,
                    "defaultModel": "ai/smollm2"
                }],
                "hints": [{ "provider": "anthropic", "evidence": "Claude Code is signed in" }]
            })
        );
        assert_eq!(
            serde_json::to_value(ServerState::NeedsKey).unwrap(),
            "needs-key"
        );
        assert_eq!(
            serde_json::to_value(ServerState::NotRunning).unwrap(),
            "not-running"
        );
    }

    /// Serves canned answers by path and records every request it reads.
    fn serve(answers: Vec<(&'static str, String)>) -> (u16, Arc<Mutex<Vec<String>>>) {
        let answers = Arc::new(answers);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (seen, answers) = (seen.clone(), answers.clone());
                std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                        match stream.read(&mut buffer) {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request).into_owned();
                    let path = request.split(' ').nth(1).unwrap_or_default().to_owned();
                    seen.lock().unwrap().push(request);
                    let response = match answers.iter().find(|(known, _)| *known == path) {
                        Some((_, response)) => response.clone(),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
                    };
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        (port, requests)
    }

    #[test]
    fn the_probe_reads_a_live_server_and_sends_no_credential() {
        const HEALTH: &str =
            "{\"status\":\"healthy\",\"default_model\":\"m\",\"engine_pool\":{\"model_count\":3}}";
        const REFUSAL: &str = "{\"error\":{\"message\":\"API key required\"}}";
        let answer = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\nServer: uvicorn\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let answers = vec![
            ("/health", answer("200 OK", HEALTH)),
            ("/v1/models", answer("401 Unauthorized", REFUSAL)),
        ];
        let (port, requests) = serve(answers);
        let plan = BTreeMap::from([(port, vec![kind("omlx").unwrap(), kind("vllm").unwrap()])]);
        let started = Instant::now();
        let servers = scan_ports(&plan, Instant::now() + SCAN_BUDGET);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "omlx");
        assert_eq!(servers[0].state, ServerState::NeedsKey);
        assert_eq!(servers[0].model_count, 3);
        let requests = requests.lock().unwrap();
        let paths: BTreeSet<&str> = requests
            .iter()
            .filter_map(|request| request.split(' ').nth(1))
            .collect();
        assert_eq!(paths, BTreeSet::from(["/health", "/v1/models", "/version"]));
        for request in requests.iter() {
            assert!(request.starts_with("GET "));
            assert!(!request.to_ascii_lowercase().contains("authorization"));
            assert!(request.contains("Host: 127.0.0.1"));
        }
    }

    #[test]
    fn a_silent_server_ends_within_the_budget_and_a_closed_port_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let silent = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });
        let started = Instant::now();
        let replies = probe_port(
            silent,
            &["/v1/models".into(), "/health".into()],
            Instant::now() + SCAN_BUDGET,
        )
        .unwrap();
        assert!(replies.is_empty());
        assert!(started.elapsed() < Duration::from_millis(1500));

        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let started = Instant::now();
        assert!(probe_port(closed, &["/v1/models".into()], Instant::now() + SCAN_BUDGET).is_none());
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn configured_ports_replace_the_defaults() {
        let home = temporary_directory();
        let omlx_base = home.join("omlx-base");
        write(
            &omlx_base.join("settings.json"),
            r#"{"server":{"port":8123}}"#,
        );
        write(
            &home.join(".lmstudio/.internal/http-server-config.json"),
            r#"{"port":4321}"#,
        );
        write(
            &home.join(".osaurus/config/server.json"),
            r#"{"port":"1400"}"#,
        );
        write(
            &home.join(".config/llama.cpp/config.ini"),
            "[server]\nport = 9999\n",
        );
        let mut environment = environment(&[("OMLX_BASE_PATH", &omlx_base)]);
        environment.insert("OLLAMA_HOST".into(), "127.0.0.1:11500".into());
        environment.insert("LEMONADE_PORT".into(), "8020".into());
        let context = context(&home, &environment, Platform::MacOs);
        let plan = port_plan(&context);
        let ids = |port: u16| -> Vec<&str> {
            plan.get(&port)
                .map(|kinds| kinds.iter().map(|kind| kind.id).collect())
                .unwrap_or_default()
        };
        assert_eq!(ids(11500), ["ollama"]);
        assert_eq!(ids(4321), ["lmstudio"]);
        assert_eq!(ids(8123), ["omlx"]);
        assert_eq!(ids(1400), ["osaurus"]);
        assert_eq!(ids(8020), ["lemonade"]);
        assert_eq!(ids(9999), ["llamacpp"]);
        assert_eq!(ids(8080), ["llamacpp", "mlx-lm", "localai"]);
        assert_eq!(ids(8000), ["vllm"]);
        assert_eq!(ids(1337), ["jan"]);
        assert!(!plan.contains_key(&11434));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn ollama_host_counts_only_when_it_names_this_computer() {
        assert_eq!(ollama_host_port("127.0.0.1:11500"), Some(11500));
        assert_eq!(ollama_host_port("http://localhost:8001"), Some(8001));
        assert_eq!(ollama_host_port("0.0.0.0"), Some(11434));
        assert_eq!(ollama_host_port("[::1]:11600"), Some(11600));
        assert_eq!(ollama_host_port("http://127.0.0.1"), Some(80));
        assert_eq!(ollama_host_port("example.com:11434"), None);
        assert_eq!(ollama_host_port("192.0.2.4:11434"), None);
    }

    #[test]
    fn the_omlx_key_file_shows_only_when_it_holds_a_key() {
        let home = temporary_directory();
        let environment = Environment::new();
        let context = context(&home, &environment, Platform::MacOs);
        let settings = home.join(".omlx").join("settings.json");
        let secret = uuid::Uuid::now_v7().to_string();
        let running = || {
            vec![Server {
                id: "omlx",
                name: "oMLX",
                base_url: "http://127.0.0.1:8000/v1".into(),
                state: ServerState::NeedsKey,
                model_count: 2,
                default_model: None,
                key_file: None,
                port: 8000,
            }]
        };

        write(
            &settings,
            &format!(r#"{{"server":{{"port":8000}},"auth":{{"api_key":"{secret}"}}}}"#),
        );
        let servers = finish(&context, running());
        assert_eq!(
            servers[0].key_file.as_deref(),
            Some("~/.omlx/settings.json")
        );
        assert!(omlx_key(&context).is_some());
        let serialized = serde_json::to_string(&ProviderScan {
            servers,
            hints: hints(&context, ClaudeCode::Absent),
        })
        .unwrap();
        assert!(!serialized.contains(&secret));

        for without in [
            r#"{"auth":{"api_key":""}}"#,
            r#"{"auth":{}}"#,
            "{}",
            "not json",
        ] {
            write(&settings, without);
            assert_eq!(finish(&context, running())[0].key_file, None);
            assert!(omlx_key(&context).is_none());
        }
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn installed_servers_that_do_not_answer_sort_last() {
        let home = temporary_directory();
        write(
            &home.join(".omlx/settings.json"),
            r#"{"server":{"port":8123},"auth":{"api_key":"set"}}"#,
        );
        write(&home.join("usr/local/bin/ollama"), "");
        std::fs::create_dir_all(home.join("Library/Application Support/Jan")).unwrap();
        std::fs::create_dir_all(home.join(".lmstudio")).unwrap();
        let environment = Environment::new();
        let context = context(&home, &environment, Platform::MacOs);
        let llama = classify(
            8080,
            &replies(&[(
                "/v1/models",
                reply(200, "llama.cpp", &models(Some("llamacpp"), &["m"])),
            )]),
        )
        .unwrap();
        let jan_port_taken = classify(
            1337,
            &replies(&[(
                "/v1/models",
                reply(401, "", r#"{"error":"Invalid or missing API key"}"#),
            )]),
        )
        .unwrap();
        let servers = finish(&context, vec![jan_port_taken, llama.clone(), llama]);
        let summary: Vec<(&str, ServerState, &str)> = servers
            .iter()
            .map(|server| (server.id, server.state, server.base_url.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                ("llamacpp", ServerState::Ready, "http://127.0.0.1:8080/v1"),
                (
                    "lemonade",
                    ServerState::NeedsKey,
                    "http://127.0.0.1:1337/v1"
                ),
                (
                    "ollama",
                    ServerState::NotRunning,
                    "http://127.0.0.1:11434/v1"
                ),
                (
                    "lmstudio",
                    ServerState::NotRunning,
                    "http://127.0.0.1:1234/v1"
                ),
                ("omlx", ServerState::NotRunning, "http://127.0.0.1:8123/v1"),
            ]
        );
        assert_eq!(
            servers[4].key_file.as_deref(),
            Some("~/.omlx/settings.json")
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn windows_install_evidence_reads_the_local_and_roaming_folders() {
        let home = temporary_directory();
        let local = home.join("AppData").join("Local");
        let roaming = home.join("AppData").join("Roaming");
        std::fs::create_dir_all(local.join("Programs").join("Ollama")).unwrap();
        std::fs::create_dir_all(local.join("Programs").join("LM Studio")).unwrap();
        std::fs::create_dir_all(roaming.join("Jan")).unwrap();
        let environment = environment(&[("LOCALAPPDATA", &local), ("APPDATA", &roaming)]);
        let context = context(&home, &environment, Platform::Windows);
        for id in ["ollama", "lmstudio", "jan"] {
            assert!(installed(id, &context), "{id}");
        }
        assert!(!installed("omlx", &context));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn hints_follow_the_list_order_from_metadata_alone() {
        let home = temporary_directory();
        write(&home.join(".codex/auth.json"), "{}");
        write(&home.join(".grok/auth.json"), "{}");
        write(&home.join(".gemini/oauth_creds.json"), "{}");
        std::fs::create_dir_all(home.join(".copilot")).unwrap();
        std::fs::create_dir_all(home.join(".kimi")).unwrap();
        write(&home.join(".local/share/devin/credentials.toml"), "");
        std::fs::create_dir_all(home.join(".config/muse")).unwrap();
        std::fs::create_dir_all(home.join(".ori")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = std::fs::Permissions::from_mode(0o000);
            std::fs::set_permissions(home.join(".codex/auth.json"), unreadable).unwrap();
        }
        let environment = Environment::new();
        let context = context(&home, &environment, Platform::MacOs);
        let evidence: Vec<(&str, &str)> = hints(&context, ClaudeCode::SignedIn)
            .iter()
            .map(|hint| (hint.provider, hint.evidence))
            .collect();
        assert_eq!(
            evidence,
            [
                ("anthropic", "Claude Code is signed in"),
                ("openai", "Codex CLI is signed in"),
                ("xai", "Grok Build is signed in"),
                ("google", "Gemini CLI is signed in"),
                ("github-copilot", "Copilot CLI is installed"),
                ("kimi", "Kimi CLI is installed"),
                ("devin", "Devin CLI is signed in"),
                ("meta", "Muse Code is installed"),
                ("openrouter", "Ori CLI is installed"),
            ]
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn hint_folders_follow_their_environment_overrides() {
        let home = temporary_directory();
        let codex = home.join("elsewhere-codex");
        let gemini = home.join("elsewhere-gemini");
        let roaming = home.join("roaming");
        std::fs::create_dir_all(&codex).unwrap();
        write(&gemini.join(".gemini/google_accounts.json"), "{}");
        write(&roaming.join("devin/credentials.toml"), "");
        std::fs::create_dir_all(home.join(".config/devin")).unwrap();
        let environment = environment(&[
            ("CODEX_HOME", &codex),
            ("GEMINI_CLI_HOME", &gemini),
            ("APPDATA", &roaming),
        ]);
        let windows = context(&home, &environment, Platform::Windows);
        let evidence: Vec<&str> = hints(&windows, ClaudeCode::Installed)
            .iter()
            .map(|hint| hint.evidence)
            .collect();
        assert_eq!(
            evidence,
            [
                "Claude Code is installed",
                "Codex CLI is installed",
                "Gemini CLI is signed in",
                "Devin CLI is signed in",
            ]
        );
        let empty = Environment::new();
        assert!(hints(
            &context(&home.join("missing"), &empty, Platform::Linux),
            ClaudeCode::Absent
        )
        .is_empty());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_connect_takes_only_a_plain_address_on_this_computer() {
        for good in [
            "http://127.0.0.1:8080/v1",
            "http://localhost:1234/v1",
            "http://[::1]:8000/v1",
            "http://127.0.0.1:12434/engines/v1",
        ] {
            assert!(loopback_url(good).is_ok(), "{good}");
        }
        for bad in [
            "https://127.0.0.1:8080/v1",
            "http://192.0.2.5:8080/v1",
            "http://example.com/v1",
            "http://user:secret@127.0.0.1:8080/v1",
            "http://127.0.0.1:8080/v1?key=secret",
            "file:///tmp/v1",
            "",
        ] {
            assert_eq!(loopback_url(bad), Err(LOOPBACK_ERROR.to_owned()), "{bad}");
        }
    }
}
