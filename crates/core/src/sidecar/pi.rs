use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::time::Duration;

use serde_json::{json, Value};

use super::{ProbeOutcome, RestartPolicy, SidecarConfig, SidecarIo};

pub const PI_NPM_PACKAGE: &str = "@mariozechner/pi-coding-agent";
pub const PI_VERSION: &str = "0.73.1";

type PendingCalls = Arc<Mutex<HashMap<String, Option<mpsc::Sender<Result<Value, String>>>>>>;
type CurrentTransport = Arc<Mutex<Option<(u64, Arc<PiRpcTransport>)>>>;
/// Builds the production Pi RPC launch contract for a verified, platform-native
/// Pi executable. The executable contains its Node-compatible runtime; a system
/// `node` installation is deliberately not part of this contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiSessionLocator(String);

impl PiSessionLocator {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn canonical_session_root(session_root: &Path) -> Result<PathBuf, String> {
    let root = session_root
        .canonicalize()
        .map_err(|_| "Pi session directory is unavailable".to_string())?;
    if !root
        .metadata()
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return Err("Pi session directory is unavailable".into());
    }
    Ok(root)
}

/// Validate a Pi-owned session file without allowing a journal locator to
/// escape Muniment's session directory. Errors deliberately omit paths.
pub fn validate_pi_session(
    session_root: &Path,
    locator: &str,
) -> Result<(PiSessionLocator, PathBuf), String> {
    if locator.is_empty()
        || locator.contains('/')
        || locator.contains('\\')
        || !locator.ends_with(".jsonl")
    {
        return Err("Pi session locator is invalid".into());
    }
    let root = canonical_session_root(session_root)?;
    let path = root.join(locator);
    let canonical = path
        .canonicalize()
        .map_err(|_| "Pi session file is unavailable".to_string())?;
    if !canonical.starts_with(&root)
        || !canonical
            .metadata()
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    {
        return Err("Pi session file is unavailable".into());
    }
    Ok((PiSessionLocator(locator.to_owned()), canonical))
}

/// Builds either a new persistent Pi session or an explicit reopen. The
/// session directory must already exist so ownership is established by the
/// application before launch.
pub fn pi_sidecar_config(
    program: impl Into<String>,
    session_root: &Path,
    reopen: Option<&PiSessionLocator>,
) -> Result<SidecarConfig, String> {
    let root = canonical_session_root(session_root)?;
    let mut config = SidecarConfig::new(program);
    config.args = vec![
        "--mode".into(),
        "rpc".into(),
        "--session-dir".into(),
        root.to_string_lossy().into_owned(),
    ];
    if let Some(locator) = reopen {
        let (_, path) = validate_pi_session(&root, locator.as_str())?;
        config
            .args
            .extend(["--session".into(), path.to_string_lossy().into_owned()]);
    }
    config.restart = RestartPolicy::default();
    config.health_interval = Duration::from_secs(15);
    config.startup_timeout = Duration::from_secs(30);
    config.shutdown_timeout = Duration::from_secs(2);
    Ok(config)
}

impl PiRpcTransport {
    /// Reads the pinned 0.73.1 state contract and turns its session file into a
    /// root-relative, non-secret locator suitable for the journal.
    pub fn session_locator(
        &self,
        session_root: &Path,
        timeout: Duration,
    ) -> Result<PiSessionLocator, String> {
        let response = self.call(json!({"type": "get_state"}), timeout)?;
        if response.get("type").and_then(Value::as_str) != Some("response")
            || response.get("command").and_then(Value::as_str) != Some("get_state")
            || response.get("success").and_then(Value::as_bool) != Some(true)
        {
            return Err("Pi session state is invalid".into());
        }
        let file = response
            .pointer("/data/sessionFile")
            .and_then(Value::as_str)
            .ok_or_else(|| "Pi session state is invalid".to_string())?;
        let name = Path::new(file)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "Pi session state is invalid".to_string())?;
        let (locator, canonical) = validate_pi_session(session_root, name)?;
        let reported = Path::new(file)
            .canonicalize()
            .map_err(|_| "Pi session file is unavailable".to_string())?;
        if reported != canonical {
            return Err("Pi session file is unavailable".into());
        }
        Ok(locator)
    }
}

/// The sole stdout consumer for Pi's multiplexed JSONL protocol.
///
/// Calls are serialized so responses cannot race each other or the supervisor's
/// health probe. Frames that do not match the active call are delivered to all
/// subscribers in order instead of being consumed as probe responses.
pub struct PiRpcTransport {
    io: SidecarIo,
    generation: u64,
    next_id: AtomicU64,
    call_lock: Mutex<()>,
    pending: PendingCalls,
    subscribers: Arc<Mutex<Vec<mpsc::Sender<Value>>>>,
}

/// Shared wiring for the supervisor health probe and all application RPC.
/// Keeping this handle alongside the supervisor guarantees there is only one
/// stdout consumer for a child generation.
#[derive(Clone, Default)]
pub struct PiRpcWiring {
    transport: CurrentTransport,
}

impl PiRpcWiring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn transport(&self) -> Option<Arc<PiRpcTransport>> {
        self.transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(_, transport)| Arc::clone(transport))
    }

    pub fn readiness_probe(
        &self,
        timeout: Duration,
    ) -> impl Fn(&SidecarIo) -> Result<ProbeOutcome, String> + Send + Sync + 'static {
        let shared = Arc::clone(&self.transport);
        move |io| {
            let generation = io.stdin.generation();
            let transport = {
                let mut current = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match current.as_ref() {
                    Some((seen, transport)) if *seen == generation => Arc::clone(transport),
                    _ => {
                        let transport =
                            Arc::new(PiRpcTransport::new_for_generation(io.clone(), generation));
                        *current = Some((generation, Arc::clone(&transport)));
                        transport
                    }
                }
            };
            transport.health_probe(timeout)(io)
        }
    }
}

impl PiRpcTransport {
    pub fn new(io: SidecarIo) -> Self {
        let generation = io.stdin.generation();
        Self::new_for_generation(io, generation)
    }

    fn new_for_generation(io: SidecarIo, generation: u64) -> Self {
        let pending = Arc::new(Mutex::new(HashMap::<
            String,
            Option<mpsc::Sender<Result<Value, String>>>,
        >::new()));
        let subscribers = Arc::new(Mutex::new(Vec::<mpsc::Sender<Value>>::new()));
        let reader = io.stdout.clone();
        let reader_pending = Arc::clone(&pending);
        let reader_subscribers = Arc::clone(&subscribers);
        std::thread::Builder::new()
            .name("pi-rpc-dispatcher".into())
            .spawn(move || loop {
                let frame = match reader.read_line_for_generation(generation) {
                    Ok(line) => match serde_json::from_str::<Value>(&line) {
                        Ok(frame) => frame,
                        Err(error) => {
                            let message = format!("invalid Pi RPC JSON: {error}");
                            for waiter in reader_pending
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .drain()
                                .filter_map(|(_, waiter)| waiter)
                            {
                                let _ = waiter.send(Err(message.clone()));
                            }
                            continue;
                        }
                    },
                    Err(error) => {
                        let message = error.to_string();
                        for waiter in reader_pending
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .drain()
                            .filter_map(|(_, waiter)| waiter)
                        {
                            let _ = waiter.send(Err(message.clone()));
                        }
                        break;
                    }
                };
                let waiter = frame.get("id").and_then(Value::as_str).and_then(|id| {
                    reader_pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(id)
                });
                if let Some(Some(waiter)) = waiter {
                    let _ = waiter.send(Ok(frame));
                } else if waiter.is_none() {
                    reader_subscribers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .retain(|subscriber| subscriber.send(frame.clone()).is_ok());
                }
            })
            .expect("spawn Pi RPC dispatcher");
        Self {
            io,
            generation,
            next_id: AtomicU64::new(1),
            call_lock: Mutex::new(()),
            pending,
            subscribers,
        }
    }

    /// Receives interleaved events and responses not correlated to this
    /// transport's currently active call.
    pub fn subscribe(&self) -> mpsc::Receiver<Value> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sender);
        receiver
    }

    /// Sends a Pi command and waits for its correlated response. The command
    /// must be a JSON object with a `type`; the transport supplies its own ID.
    pub fn call(&self, mut command: Value, timeout: Duration) -> Result<Value, String> {
        let guard = self
            .call_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = format!(
            "muniment-pi-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let object = command
            .as_object_mut()
            .ok_or_else(|| "Pi RPC command must be a JSON object".to_string())?;
        if object.get("type").and_then(Value::as_str).is_none() {
            return Err("Pi RPC command must contain a string `type`".into());
        }
        object.insert("id".into(), Value::String(id.clone()));
        self.call_locked(command, &id, timeout, guard)
    }

    /// Sends one pre-correlated Pi frame without waiting for a response.
    pub fn send(&self, frame: Value) -> Result<(), String> {
        if self.io.stdin.generation() != self.generation {
            return Err("Pi RPC transport belongs to a replaced child generation".into());
        }
        self.io
            .stdin
            .write_line(&frame.to_string())
            .map_err(|error| error.to_string())
    }

    /// Builds a health probe on the same dispatcher used by application calls.
    /// If a call is active, its bounded timeout owns health detection and the
    /// periodic probe does not compete for stdout.
    pub fn health_probe(
        self: &Arc<Self>,
        timeout: Duration,
    ) -> impl Fn(&SidecarIo) -> Result<ProbeOutcome, String> + Send + Sync + 'static {
        let transport = Arc::clone(self);
        move |_| {
            let guard = match transport.call_lock.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(error)) => error.into_inner(),
                Err(TryLockError::WouldBlock) => return Ok(ProbeOutcome::Ready),
            };
            let id = format!(
                "muniment-ready-{}",
                transport.next_id.fetch_add(1, Ordering::Relaxed)
            );
            let response = transport.call_locked(
                json!({"id": id, "type": "get_state"}),
                &id,
                timeout,
                guard,
            )?;
            if response.get("type").and_then(Value::as_str) != Some("response")
                || response.get("command").and_then(Value::as_str) != Some("get_state")
                || response.get("success").and_then(Value::as_bool) != Some(true)
            {
                return Err(format!("unexpected Pi readiness response: {response}"));
            }
            Ok(ProbeOutcome::Ready)
        }
    }

    fn call_locked(
        &self,
        command: Value,
        id: &str,
        timeout: Duration,
        _guard: std::sync::MutexGuard<'_, ()>,
    ) -> Result<Value, String> {
        if self.io.stdin.generation() != self.generation {
            return Err("Pi RPC transport belongs to a replaced child generation".into());
        }
        let (sender, receiver) = mpsc::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_owned(), Some(sender));
        if let Err(error) = self.io.stdin.write_line(&command.to_string()) {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(id);
            return Err(error.to_string());
        }
        match receiver.recv_timeout(timeout) {
            Ok(response) => response,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Keep a tombstone until the response arrives (or the
                // generation ends), so a late correlated response cannot be
                // mistaken for an unsolicited stream frame.
                if let Some(waiter) = self
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_mut(id)
                {
                    *waiter = None;
                }
                Err(format!("timed out waiting for Pi RPC response `{id}`"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!(
                "Pi RPC dispatcher stopped while waiting for `{id}`"
            )),
        }
    }
}

/// Pi RPC is JSONL, not JSON-RPC 2.0. `get_state` is local, side-effect free,
/// and does not contact a model provider, so it is a suitable readiness probe.
/// The lazily-created transport remains the sole stdout consumer across every
/// periodic probe.
pub fn pi_readiness_probe(
    timeout: Duration,
) -> impl Fn(&SidecarIo) -> Result<ProbeOutcome, String> + Send + Sync + 'static {
    PiRpcWiring::new().readiness_probe(timeout)
}
