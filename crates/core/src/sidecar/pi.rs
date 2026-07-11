use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::time::Duration;

use serde_json::{json, Value};

use super::{ProbeOutcome, RestartPolicy, SidecarConfig, SidecarIo};

pub const PI_NPM_PACKAGE: &str = "@mariozechner/pi-coding-agent";
pub const PI_VERSION: &str = "0.73.1";

type PendingCalls = Arc<Mutex<HashMap<String, mpsc::Sender<Result<Value, String>>>>>;
type CurrentTransport = Arc<Mutex<Option<(u64, Arc<PiRpcTransport>)>>>;
/// Builds the production Pi RPC launch contract for a verified, platform-native
/// Pi executable. The executable contains its Node-compatible runtime; a system
/// `node` installation is deliberately not part of this contract.
pub fn pi_sidecar_config(program: impl Into<String>) -> SidecarConfig {
    let mut config = SidecarConfig::new(program);
    config.args = vec!["--mode".into(), "rpc".into(), "--no-session".into()];
    config.restart = RestartPolicy::default();
    config.health_interval = Duration::from_secs(15);
    config.startup_timeout = Duration::from_secs(30);
    config.shutdown_timeout = Duration::from_secs(2);
    config
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
            mpsc::Sender<Result<Value, String>>,
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
                            for (_, waiter) in reader_pending
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .drain()
                            {
                                let _ = waiter.send(Err(message.clone()));
                            }
                            continue;
                        }
                    },
                    Err(error) => {
                        let message = error.to_string();
                        for (_, waiter) in reader_pending
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .drain()
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
                if let Some(waiter) = waiter {
                    let _ = waiter.send(Ok(frame));
                } else {
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
            .insert(id.to_owned(), sender);
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
                self.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(id);
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
