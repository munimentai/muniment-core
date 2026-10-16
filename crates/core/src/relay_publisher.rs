//! The desktop side of the session relay `muniment.session-relay/1`.
//!
//! While a phone pair holds relay keys and an account is signed in, the
//! publisher keeps one WebSocket open to the cloud's `/v1/events`. It
//! registers each live run as a relay session, publishes the run's events
//! sealed for the paired phone under `muniment.relay-encryption/1`, and opens
//! the phone's sealed commands and applies them through the runtime's own
//! stop, steer, follow-up and permission answer operations. The cloud reads
//! only the plaintext headers.
//!
//! The host supplies the account through [`RelayAccount`] and the runtime
//! through [`RelayRuntime`], so a host without a cloud starts no publisher.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocket;
use tungstenite::Message;

use crate::active_run::ChatDelivery;
use crate::chat_view::{ChatPendingPermission, ChatToolActivity};
use crate::journal::reducer::PermissionRequest;
use crate::permission_gate::ChatPermissionAnswer;
use crate::relay_encryption::{
    self, canonical_json, open_command, seal_event, AnswerDecision, CommandContent,
    CommandEnvelope, EventContent, EventHeader, GateDecision, GateWindow, Phase, RelayCryptoError,
    RelayKeys, ReplayWindow, SendCounter,
};
use crate::run_events::{ChatEvent, ChatEventSubscription};

/// The relay protocol every envelope names.
pub const RELAY_PROTOCOL: &str = "muniment.session-relay/1";

/// The file under the profile that keeps the pair's counters and replay window.
pub const RELAY_STATE_FILE_NAME: &str = "remote-control-relay.json";

/// The path the cloud serves the relay on.
pub const EVENTS_PATH: &str = "/v1/events";

/// How long a permission gate stays open without a timeout of its own.
const DEFAULT_GATE_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// The longest a permission gate stays open.
const MAX_GATE_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The most text one assistant delta carries, in bytes, so a sealed event
/// stays well under its 64 KiB limit after base64.
const MAX_DELTA_BYTES: usize = 16 * 1024;

/// How many applied receipts the publisher keeps to answer a repeated command.
const RECENT_RECEIPTS: usize = 64;

/// A cloud connection the account answers: the API base and a fresh bearer.
#[derive(Clone)]
pub struct RelayConnection {
    pub api_base: String,
    pub access_token: String,
}

impl fmt::Debug for RelayConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayConnection")
            .field("api_base", &self.api_base)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// The account side of the relay.
pub trait RelayAccount: Send + Sync {
    /// The relay keys of the phone pair this host keeps, read locally.
    fn keys(&self) -> Option<RelayKeys>;

    /// The cloud API base and a fresh access token, once the cloud still
    /// holds the pair `pair_id`. None when no account is signed in, the host
    /// has no cloud, or the pair is gone.
    fn connection(&self, pair_id: &str) -> Option<RelayConnection>;
}

/// The runtime operations the relay drives.
pub trait RelayRuntime: Send + Sync {
    /// Subscribes to the runtime's live run events. The first events are the
    /// whole state of each live run.
    fn subscribe(&self) -> Option<ChatEventSubscription>;

    /// Stops a run.
    fn stop(&self, run_id: &str) -> Result<(), String>;

    /// Queues a steering or follow-up message for a run.
    fn queue(&self, run_id: &str, delivery: ChatDelivery, text: &str) -> Result<(), String>;

    /// Answers a run's pending permission gate.
    fn answer(
        &self,
        run_id: &str,
        gate_id: &str,
        answer: ChatPermissionAnswer,
    ) -> Result<(), String>;

    /// How a gate the desktop answered locally closed, when the runtime knows.
    fn gate_decision(&self, run_id: &str, gate_id: &str) -> Option<GateDecision> {
        let _ = (run_id, gate_id);
        None
    }
}

/// How often the publisher polls and how long it waits.
#[derive(Clone, Copy, Debug)]
pub struct RelayTiming {
    /// How often an idle publisher looks for keys and a session.
    pub idle_poll: Duration,
    /// The first and the longest wait before a reconnect.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// How long one socket read waits before the publisher sends events.
    pub read_tick: Duration,
    /// How long a connection may stay silent before the publisher reconnects.
    pub silence_limit: Duration,
    /// How often a connected publisher checks that its pair still holds.
    pub pair_check: Duration,
}

impl Default for RelayTiming {
    fn default() -> Self {
        Self {
            idle_poll: Duration::from_secs(5),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            read_tick: Duration::from_millis(50),
            silence_limit: Duration::from_secs(75),
            pair_check: Duration::from_secs(5),
        }
    }
}

/// The pair's relay counters and command replay window, kept with the pair.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayState {
    pair_id: String,
    /// The reserved high-water mark of the desktop-to-phone counter.
    send_reserved: u64,
    commands: ReplayWindow,
    /// A command failed to authenticate, so the owner pairs again.
    key_mismatch: bool,
}

/// The path of the relay state under a profile.
pub fn relay_state_path(profile_directory: &Path) -> PathBuf {
    profile_directory.join(RELAY_STATE_FILE_NAME)
}

fn load_state(path: &Path, pair_id: &str) -> RelayState {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RelayState>(&bytes).ok())
        .filter(|state| state.pair_id == pair_id)
        .unwrap_or_else(|| RelayState {
            pair_id: pair_id.to_owned(),
            ..RelayState::default()
        })
}

fn save_state(path: &Path, state: &RelayState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
    crate::model_router::config::write_private(path, &bytes)
        .map_err(|error| format!("the relay state could not be saved: {error}"))
}

/// Erases the relay counters and replay window of the profile's pair.
pub fn forget_relay_state(profile_directory: &Path) -> io::Result<()> {
    match std::fs::remove_file(relay_state_path(profile_directory)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Whether a command for the pair `pair_id` failed to authenticate, so the
/// owner pairs again.
pub fn relay_key_mismatch(profile_directory: &Path, pair_id: &str) -> bool {
    load_state(&relay_state_path(profile_directory), pair_id).key_mismatch
}

/// A running publisher. Dropping it leaves the thread running; `stop` ends it.
pub struct RelayPublisher {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RelayPublisher {
    /// Starts the publisher thread. `state_path` names the relay state file.
    pub fn start(
        account: Arc<dyn RelayAccount>,
        runtime: Arc<dyn RelayRuntime>,
        state_path: PathBuf,
    ) -> Self {
        Self::start_with_timing(account, runtime, state_path, RelayTiming::default())
    }

    pub fn start_with_timing(
        account: Arc<dyn RelayAccount>,
        runtime: Arc<dyn RelayRuntime>,
        state_path: PathBuf,
        timing: RelayTiming,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let mut publisher = Publisher {
            account,
            runtime,
            state_path,
            timing,
            stop: Arc::clone(&stop),
            runs: BTreeMap::new(),
            receipts: VecDeque::new(),
        };
        let thread = std::thread::Builder::new()
            .name("muniment-relay".into())
            .spawn(move || publisher.run())
            .ok();
        Self { stop, thread }
    }

    /// Ends the publisher and waits for its thread. The socket closes.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Why one connection ended.
enum Ended {
    Stopped,
    Closed,
    PairChanged,
}

/// The identity the cloud bound this connection to.
#[derive(Clone, Debug)]
struct Identity {
    connection_id: String,
    user_id: String,
    device_id: String,
}

/// A permission gate a run holds open.
#[derive(Clone, Debug)]
struct OpenGate {
    local_id: String,
    relay_id: String,
    digest: String,
    request: PermissionRequest,
    window: GateWindow,
    expires: DateTime<Utc>,
}

/// What the relay knows of one run: its session and what it published.
#[derive(Debug)]
struct RunRelay {
    session_id: String,
    run_id: String,
    thread_id: Option<String>,
    sequence: u64,
    registered: bool,
    text: String,
    tools: BTreeMap<String, String>,
    gate: Option<OpenGate>,
    phase: Phase,
    answered: BTreeMap<String, AnswerDecision>,
}

struct Publisher {
    account: Arc<dyn RelayAccount>,
    runtime: Arc<dyn RelayRuntime>,
    state_path: PathBuf,
    timing: RelayTiming,
    stop: Arc<AtomicBool>,
    /// Live runs by local run id.
    runs: BTreeMap<String, RunRelay>,
    /// The latest applied receipts by command id.
    receipts: VecDeque<(String, Value)>,
}

/// The open connection and the pair's sealing state.
struct Link {
    socket: WebSocket<Stream>,
    identity: Identity,
    keys: RelayKeys,
    state: RelayState,
    counter: SendCounter,
    state_path: PathBuf,
}

impl Publisher {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Waits `duration` in short slices, returning early on stop.
    fn pause(&self, duration: Duration) {
        let deadline = Instant::now() + duration;
        while !self.stopped() && Instant::now() < deadline {
            std::thread::sleep(
                Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn run(&mut self) {
        let mut backoff = self.timing.backoff_min;
        while !self.stopped() {
            let Some(keys) = self.account.keys() else {
                self.runs.clear();
                self.pause(self.timing.idle_poll);
                continue;
            };
            let Some(connection) = self.account.connection(&keys.pair_id) else {
                // The account is signed out, the cloud is unreachable or the
                // pair is gone; each later look waits longer.
                self.pause(backoff.max(self.timing.idle_poll));
                backoff = (backoff * 2).min(self.timing.backoff_max);
                continue;
            };
            let started = Instant::now();
            let served = self.serve(keys, &connection);
            // A connection that held a while starts the backoff over, so one
            // the relay keeps refusing waits longer each time.
            if started.elapsed() >= self.timing.backoff_max {
                backoff = self.timing.backoff_min;
            }
            match served {
                Ok(Ended::Stopped) => return,
                Ok(Ended::PairChanged) => {
                    self.runs.clear();
                    backoff = self.timing.backoff_min;
                    continue;
                }
                Ok(Ended::Closed) => {}
                Err(error) => {
                    crate::runtime_eprintln!("muniment-runtime: relay connection ended: {error}");
                }
            }
            self.pause(backoff);
            backoff = (backoff * 2).min(self.timing.backoff_max);
        }
    }

    fn serve(&mut self, keys: RelayKeys, connection: &RelayConnection) -> Result<Ended, String> {
        let mut socket = connect(connection)?;
        let identity = wait_ready(&mut socket, Duration::from_secs(10))?;
        socket
            .get_mut()
            .set_read_timeout(Some(self.timing.read_tick))
            .map_err(|error| error.to_string())?;
        let state = load_state(&self.state_path, &keys.pair_id);
        let mut link = Link {
            socket,
            identity,
            counter: SendCounter::resume(state.send_reserved),
            keys,
            state,
            state_path: self.state_path.clone(),
        };
        for run in self.runs.values_mut() {
            run.registered = false;
        }
        let mut subscription = self
            .runtime
            .subscribe()
            .ok_or("the runtime has no event stream")?;
        let mut heard = Instant::now();
        let mut checked = Instant::now();
        loop {
            if self.stopped() {
                let _ = link.socket.close(None);
                let _ = link.socket.flush();
                return Ok(Ended::Stopped);
            }
            match link.socket.read() {
                Ok(Message::Text(text)) => {
                    heard = Instant::now();
                    self.inbound(&mut link, text.as_str())?;
                }
                Ok(Message::Close(_)) => return Ok(Ended::Closed),
                Ok(_) => heard = Instant::now(),
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    return Ok(Ended::Closed)
                }
                Err(error) => return Err(error.to_string()),
            }
            loop {
                match subscription.try_recv() {
                    Ok(event) => self.publish(&mut link, event)?,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        subscription = self
                            .runtime
                            .subscribe()
                            .ok_or("the runtime has no event stream")?;
                        break;
                    }
                }
            }
            match link.socket.flush() {
                Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                }
                Err(error) => return Err(error.to_string()),
                Ok(()) => {}
            }
            if heard.elapsed() > self.timing.silence_limit {
                return Err("the relay went silent".into());
            }
            if checked.elapsed() > self.timing.pair_check {
                checked = Instant::now();
                match self.account.keys() {
                    Some(keys) if keys.pair_id == link.keys.pair_id => {}
                    _ => {
                        let _ = link.socket.close(None);
                        let _ = link.socket.flush();
                        return Ok(Ended::PairChanged);
                    }
                }
            }
        }
    }

    fn inbound(&mut self, link: &mut Link, text: &str) -> Result<(), String> {
        let Ok(message) = serde_json::from_str::<Value>(text) else {
            return Ok(());
        };
        if message["protocol"] != RELAY_PROTOCOL {
            // The cloud's own `heartbeat` and `entitlement.refresh` events.
            return Ok(());
        }
        match message["type"].as_str().unwrap_or_default() {
            "control.heartbeat" if message["payload"]["kind"] == "ping" => {
                let nonce = message["payload"]["nonce"].clone();
                link.send(
                    "control.heartbeat",
                    None,
                    json!({"kind": "pong", "nonce": nonce}),
                )
            }
            "command.interrupt" | "command.steer" | "command.follow_up" | "permission.answer" => {
                self.command(link, &message)
            }
            "protocol.error" => {
                let code = message["payload"]["code"].as_str().unwrap_or("unknown");
                crate::runtime_eprintln!("muniment-runtime: relay refused a message: {code}");
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn command(&mut self, link: &mut Link, message: &Value) -> Result<(), String> {
        let envelope_type = message["type"].as_str().unwrap_or_default();
        let message_id = message["message_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let session_id = message["session_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let header_run = message["payload"]["header"]["run_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let fail = |link: &mut Link, status: &str, code: &str| {
            link.failure(&session_id, &message_id, &header_run, status, code)
        };
        let Ok(sealed) =
            serde_json::from_value::<relay_encryption::SealedCommand>(message["payload"].clone())
        else {
            return fail(link, "rejected", "invalid_command");
        };
        let opened = match open_command(
            &link.keys.phone_to_desktop,
            &sealed,
            CommandEnvelope {
                envelope_type,
                session_id: &session_id,
                message_id: &message_id,
            },
        ) {
            Ok(opened) => opened,
            Err(error) => {
                if error == RelayCryptoError::AuthenticationFailed {
                    link.state.key_mismatch = true;
                    let _ = save_state(&link.state_path, &link.state);
                }
                return fail(link, "rejected", "invalid_command");
            }
        };
        let header = &sealed.header;
        if !link.state.commands.admits(opened.counter) {
            // A repeat of an applied command gets its receipt again; any
            // other repeat is a replay and is dropped.
            if let Some((_, receipt)) = self
                .receipts
                .iter()
                .find(|(command_id, _)| *command_id == header.command_id)
            {
                let receipt = receipt.clone();
                return link.send("command.receipt", Some(&session_id), receipt);
            }
            return Ok(());
        }
        link.state.commands.accept(opened.counter);
        save_state(&link.state_path, &link.state)?;
        let expired = DateTime::parse_from_rfc3339(&header.expires_at)
            .map_or(true, |expires_at| expires_at <= Utc::now());
        if expired {
            return fail(link, "expired", "command_expired");
        }
        let Some((local_run, run)) = self
            .runs
            .iter_mut()
            .find(|(_, run)| run.session_id == header.session_id)
        else {
            return fail(link, "rejected", "invalid_command");
        };
        if run.run_id != header.run_id {
            return fail(link, "rejected", "invalid_command");
        }
        let local_run = local_run.clone();
        let applied = match &opened.content {
            CommandContent::Stop { .. } => self
                .runtime
                .stop(&local_run)
                .map(|()| (json!("interrupted"), None)),
            CommandContent::Steer { text } => self
                .runtime
                .queue(&local_run, ChatDelivery::Steer, text)
                .map(|()| (json!("steered"), None)),
            CommandContent::FollowUp { text } => self
                .runtime
                .queue(&local_run, ChatDelivery::FollowUp, text)
                .map(|()| (json!("queued"), None)),
            CommandContent::PermissionAnswer {
                gate_id,
                decision,
                request_digest,
            } => {
                let answer = run.gate.as_ref().and_then(|gate| {
                    let current = gate.relay_id == *gate_id
                        && gate.digest == *request_digest
                        && Utc::now() < gate.expires;
                    current
                        .then(|| local_answer(gate, *decision))
                        .flatten()
                        .map(|answer| (gate.local_id.clone(), answer))
                });
                match answer {
                    Some((local_gate, answer)) => self
                        .runtime
                        .answer(&local_run, &local_gate, answer)
                        .map(|()| {
                            run.answered.insert(gate_id.clone(), *decision);
                            (Value::Null, Some(gate_id.clone()))
                        }),
                    None => Err("the gate is not open".into()),
                }
            }
        };
        let (result, gate_id) = match applied {
            Ok(applied) => applied,
            Err(_) => return fail(link, "rejected", "invalid_command"),
        };
        let mut payload = json!({
            "command_id": header.command_id,
            "run_id": header.run_id,
            "idempotency_key": header.command_id,
            "stage": "applied",
            "result": result,
            "applied_at": relay_encryption::timestamp(Utc::now()),
        });
        if let Some(gate_id) = gate_id {
            payload["gate_id"] = json!(gate_id);
        }
        self.receipts
            .push_back((header.command_id.clone(), payload.clone()));
        while self.receipts.len() > RECENT_RECEIPTS {
            self.receipts.pop_front();
        }
        link.send("command.receipt", Some(&session_id), payload)
    }

    /// Publishes what one runtime event changed.
    fn publish(&mut self, link: &mut Link, event: ChatEvent) -> Result<(), String> {
        let now = Utc::now();
        let runtime = Arc::clone(&self.runtime);
        let Some(phase) = phase_of(&event) else {
            return Ok(());
        };
        if !self.runs.contains_key(&event.run_id) {
            // A run the relay never saw that already ended has nothing to show.
            if event.delta.is_some() || phase.terminal() {
                return Ok(());
            }
            self.runs.insert(
                event.run_id.clone(),
                RunRelay {
                    session_id: format!("ses_{}", uuid::Uuid::new_v4().simple()),
                    run_id: relay_id("run", &event.run_id),
                    thread_id: event.thread_id.clone(),
                    sequence: 0,
                    registered: false,
                    text: String::new(),
                    tools: BTreeMap::new(),
                    gate: None,
                    phase: Phase::Running,
                    answered: BTreeMap::new(),
                },
            );
        }
        let run = self
            .runs
            .get_mut(&event.run_id)
            .expect("the run was just recorded");
        if !run.registered {
            link.register(run)?;
            run.registered = true;
            link.event(run, None, EventContent::RunStatus { detail: None })?;
        }
        let mut contents = Vec::new();
        if let Some(delta) = &event.delta {
            match utf16_byte_offset(&run.text, delta.text_start) {
                Some(end) if end == run.text.len() => {
                    run.text.push_str(&event.text);
                    contents.extend(deltas(&event.text));
                }
                Some(end) => {
                    run.text.truncate(end);
                    run.text.push_str(&event.text);
                }
                None => {}
            }
            for content in contents {
                link.event(run, None, content)?;
            }
            return Ok(());
        }
        if let Some(appended) = event.text.strip_prefix(run.text.as_str()) {
            contents.extend(deltas(appended));
        }
        run.text.clone_from(&event.text);
        for tool in &event.tool_activity {
            if run.tools.get(&tool.effect_id) != Some(&tool.status) {
                run.tools
                    .insert(tool.effect_id.clone(), tool.status.clone());
                contents.push(EventContent::ToolActivity {
                    summary: tool_summary(tool),
                });
            }
        }
        for content in contents {
            link.event(run, None, content)?;
        }
        let current_gate = event
            .pending_permission
            .as_ref()
            .filter(|_| !phase.terminal());
        let gate_changed =
            run.gate.as_ref().map(|gate| &gate.local_id) != current_gate.map(|gate| &gate.gate_id);
        if gate_changed {
            if let Some(gate) = run.gate.take() {
                let decision = run
                    .answered
                    .get(&gate.relay_id)
                    .map(|decision| match decision {
                        AnswerDecision::Allow => GateDecision::Allow,
                        AnswerDecision::Deny => GateDecision::Deny,
                    })
                    .or_else(|| runtime.gate_decision(&event.run_id, &gate.local_id))
                    .unwrap_or(if phase.terminal() {
                        GateDecision::Cancelled
                    } else if now >= gate.expires {
                        GateDecision::Expired
                    } else {
                        GateDecision::Allow
                    });
                run.phase = phase;
                link.event(
                    run,
                    Some(phase),
                    EventContent::PermissionResolved {
                        gate_id: gate.relay_id,
                        decision,
                    },
                )?;
            }
            if let Some(pending) = current_gate {
                let gate = open_gate(pending, now);
                let ask = EventContent::PermissionAsk {
                    gate_id: gate.relay_id.clone(),
                    kind: gate_kind(&gate.request).to_owned(),
                    summary: gate_summary(&gate.request),
                    request_digest: gate.digest.clone(),
                };
                run.gate = Some(gate);
                run.phase = Phase::WaitingForPermission;
                link.event(run, Some(Phase::WaitingForPermission), ask)?;
            }
        }
        if phase.terminal() {
            let detail = event
                .failure_reason
                .as_deref()
                .filter(|_| phase == Phase::Failed)
                .map(|reason| bounded(&redact(reason), 280))
                .filter(|detail| !detail.is_empty());
            run.phase = phase;
            link.event(run, Some(phase), EventContent::RunStatus { detail })?;
            self.runs.remove(&event.run_id);
        } else if run.gate.is_none() {
            run.phase = Phase::Running;
        }
        Ok(())
    }
}

impl Link {
    fn envelope(&self, kind: &str, session_id: Option<&str>, payload: Value) -> Value {
        let prefix = match kind {
            "session.register" => "reg",
            "session.event" => "evt",
            "command.receipt" => "rcpt",
            "command.failure" => "fail",
            _ => "msg",
        };
        json!({
            "protocol": RELAY_PROTOCOL,
            "type": kind,
            "message_id": format!("{prefix}_{}", uuid::Uuid::new_v4().simple()),
            "session_id": session_id,
            "connection_id": self.identity.connection_id,
            "device_id": self.identity.device_id,
            "actor": {
                "user_id": self.identity.user_id,
                "device_id": self.identity.device_id,
                "role": "desktop",
            },
            "sequence": 0,
            "timestamp": relay_encryption::timestamp(Utc::now()),
            "payload": payload,
        })
    }

    fn send(&mut self, kind: &str, session_id: Option<&str>, payload: Value) -> Result<(), String> {
        let envelope = self.envelope(kind, session_id, payload);
        self.socket
            .send(Message::text(envelope.to_string()))
            .map_err(|error| error.to_string())
    }

    fn register(&mut self, run: &RunRelay) -> Result<(), String> {
        let mut payload = json!({
            "run_id": run.run_id,
            "state": if run.gate.is_some() { "waiting" } else { "running" },
            "client_protocols": [RELAY_PROTOCOL],
        });
        if let Some(thread_id) = run.thread_id.as_deref().filter(|id| id.len() <= 256) {
            payload["thread_id"] = json!(thread_id);
        }
        self.send("session.register", Some(&run.session_id), payload)
    }

    /// Seals one event for the run. `phase` overrides the run's phase.
    fn event(
        &mut self,
        run: &mut RunRelay,
        phase: Option<Phase>,
        content: EventContent,
    ) -> Result<(), String> {
        let phase = phase.unwrap_or(if run.gate.is_some() {
            Phase::WaitingForPermission
        } else {
            run.phase
        });
        let permission = run
            .gate
            .as_ref()
            .filter(|_| phase == Phase::WaitingForPermission)
            .map(|gate| gate.window.clone());
        let phase = if phase == Phase::WaitingForPermission && permission.is_none() {
            Phase::Running
        } else {
            phase
        };
        run.sequence += 1;
        let header = EventHeader::new(
            &run.session_id,
            &run.run_id,
            run.sequence,
            phase,
            permission,
            &relay_encryption::timestamp(Utc::now()),
        );
        let path = self.state_path.clone();
        let state = &mut self.state;
        let counter = self.counter.next(|reserved| {
            state.send_reserved = reserved;
            save_state(&path, state).map_err(PublishError::State)
        });
        let counter = counter.map_err(|error| error.to_string())?;
        let sealed = seal_event(&self.keys.desktop_to_phone, &header, counter, &content)
            .map_err(|error| error.to_string())?;
        let payload = serde_json::to_value(&sealed).map_err(|error| error.to_string())?;
        let session_id = run.session_id.clone();
        self.send("session.event", Some(&session_id), payload)
    }

    fn failure(
        &mut self,
        session_id: &str,
        command_id: &str,
        run_id: &str,
        status: &str,
        code: &str,
    ) -> Result<(), String> {
        if session_id.is_empty() || command_id.is_empty() {
            return Ok(());
        }
        let payload = json!({
            "command_id": command_id,
            "correlation_id": command_id,
            "idempotency_key": command_id,
            "run_id": run_id,
            "terminal_status": status,
            "code": code,
            "failed_at": relay_encryption::timestamp(Utc::now()),
            "retryable": false,
        });
        self.send("command.failure", Some(session_id), payload)
    }
}

#[derive(Debug)]
enum PublishError {
    State(String),
    Crypto(RelayCryptoError),
}

impl From<RelayCryptoError> for PublishError {
    fn from(error: RelayCryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => formatter.write_str(error),
            Self::Crypto(error) => write!(formatter, "{error}"),
        }
    }
}

/// The header phase of a run event, or none for an event outside a run's
/// projection, such as the sign-in link or a delivery notice.
fn phase_of(event: &ChatEvent) -> Option<Phase> {
    Some(match event.phase.as_str() {
        "acquiring-pi" | "thinking" | "streaming" => Phase::Running,
        "pending-permission" => Phase::WaitingForPermission,
        "complete" => Phase::Completed,
        "failed" | "interrupted" => Phase::Failed,
        "cancelled" => Phase::Cancelled,
        _ => return None,
    })
}

/// A relay identifier for a local one: the local value when it fits the
/// relay pattern, else a prefix and the start of its SHA-256.
fn relay_id(prefix: &str, local: &str) -> String {
    if relay_encryption::valid_id(local) {
        return local.to_owned();
    }
    let digest = Sha256::digest(local.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}_{}", &hex[..32])
}

fn open_gate(pending: &ChatPendingPermission, now: DateTime<Utc>) -> OpenGate {
    let timeout = match &pending.request {
        PermissionRequest::Select { timeout, .. }
        | PermissionRequest::Confirm { timeout, .. }
        | PermissionRequest::Input { timeout, .. }
        | PermissionRequest::Editor { timeout, .. } => *timeout,
        PermissionRequest::CodeDiff { .. } => None,
    };
    let lifetime = timeout
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_GATE_LIFETIME)
        .clamp(Duration::from_secs(1), MAX_GATE_LIFETIME);
    let expires = now + chrono::Duration::from_std(lifetime).unwrap_or_default();
    let request = serde_json::to_value(pending).unwrap_or(Value::Null);
    let digest = Sha256::digest(canonical_json(&request).as_bytes());
    OpenGate {
        local_id: pending.gate_id.clone(),
        relay_id: relay_id("gate", &pending.gate_id),
        digest: format!(
            "sha256:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        request: pending.request.clone(),
        window: GateWindow {
            gate_id: relay_id("gate", &pending.gate_id),
            requested_at: relay_encryption::timestamp(now),
            expires_at: relay_encryption::timestamp(expires),
        },
        expires,
    }
}

fn gate_kind(request: &PermissionRequest) -> &'static str {
    match request {
        PermissionRequest::Select { .. } => "select",
        PermissionRequest::Confirm { .. } => "confirm",
        PermissionRequest::Input { .. } => "input",
        PermissionRequest::Editor { .. } => "editor",
        PermissionRequest::CodeDiff { .. } => "code_diff",
    }
}

fn gate_summary(request: &PermissionRequest) -> String {
    let summary = match request {
        PermissionRequest::Confirm { title, message, .. } if !message.is_empty() => {
            format!("{title}: {message}")
        }
        PermissionRequest::Select { title, .. }
        | PermissionRequest::Confirm { title, .. }
        | PermissionRequest::Input { title, .. }
        | PermissionRequest::Editor { title, .. } => title.clone(),
        PermissionRequest::CodeDiff { .. } => "Apply the proposed file changes".to_owned(),
    };
    let summary = bounded(&redact(&summary), 2048);
    if summary.trim().is_empty() {
        "A run asks for permission".to_owned()
    } else {
        summary
    }
}

/// The answer the phone's decision makes for a gate, or none when the
/// gate's dialog needs a value the phone cannot give. Deny cancels any gate,
/// as the desktop's own Deny does. Allow confirms a yes-or-no gate and
/// applies a proposed file change.
fn local_answer(gate: &OpenGate, decision: AnswerDecision) -> Option<ChatPermissionAnswer> {
    match (decision, &gate.request) {
        (AnswerDecision::Deny, _) => Some(ChatPermissionAnswer::Cancelled),
        (AnswerDecision::Allow, PermissionRequest::Confirm { .. }) => {
            Some(ChatPermissionAnswer::Confirm(true))
        }
        (
            AnswerDecision::Allow,
            PermissionRequest::CodeDiff {
                effect_id,
                code_diff_id,
                diff_sha256,
                write_plan_sha256,
            },
        ) => Some(ChatPermissionAnswer::CodeDiff {
            gate_id: gate.local_id.clone(),
            effect_id: effect_id.clone(),
            code_diff_id: code_diff_id.clone(),
            diff_sha256: diff_sha256.clone(),
            write_plan_sha256: write_plan_sha256.clone(),
        }),
        (AnswerDecision::Allow, _) => None,
    }
}

fn tool_summary(tool: &ChatToolActivity) -> String {
    let name = tool
        .display_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("Tool");
    bounded(&redact(&format!("{name}: {}", tool.status)), 2048)
}

/// Splits appended assistant text into deltas of at most 16 KiB, in order.
fn deltas(text: &str) -> Vec<EventContent> {
    let text = redact(text);
    let mut contents = Vec::new();
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let mut end = rest.len().min(MAX_DELTA_BYTES);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        contents.push(EventContent::AssistantDelta {
            text: rest[..end].to_owned(),
        });
        rest = &rest[end..];
    }
    contents
}

/// Replaces credentials the assistant text scanner finds with `[redacted]`.
fn redact(text: &str) -> String {
    let scan = crate::assistant_text::scan(text, true);
    let mut redacted = text.to_owned();
    if let Some(start) = scan.withhold_from {
        redacted.replace_range(start.., "[redacted]");
    }
    for matched in scan.matches.into_iter().rev() {
        if matched.range.end <= scan.withhold_from.unwrap_or(usize::MAX) {
            redacted.replace_range(matched.range, "[redacted]");
        }
    }
    redacted
}

/// The first `limit` characters of `text`.
fn bounded(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// The byte index in `text` of the UTF-16 offset `units`, or none past its end.
fn utf16_byte_offset(text: &str, units: usize) -> Option<usize> {
    let mut counted = 0;
    for (index, character) in text.char_indices() {
        if counted >= units {
            return (counted == units).then_some(index);
        }
        counted += character.len_utf16();
    }
    (counted == units).then_some(text.len())
}

/// A plain or TLS byte stream under the WebSocket.
enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => stream.get_ref(),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.tcp().set_read_timeout(timeout)
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// The relay URL for an API base: `wss` for `https` and `ws` for `http`.
fn events_url(api_base: &str) -> Result<url::Url, String> {
    let mut url = url::Url::parse(api_base).map_err(|_| "the cloud API base is not a URL")?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err("the cloud API base is neither HTTPS nor HTTP".into()),
    };
    url.set_scheme(scheme)
        .map_err(|()| "the cloud API base has no host")?;
    url.set_path(EVENTS_PATH);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn connect(connection: &RelayConnection) -> Result<WebSocket<Stream>, String> {
    let url = events_url(&connection.api_base)?;
    let host = url.host_str().ok_or("the cloud API base has no host")?;
    let port = url
        .port_or_known_default()
        .ok_or("the cloud API base has no port")?;
    let address = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("the relay host did not resolve: {error}"))?
        .next()
        .ok_or("the relay host did not resolve")?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|error| format!("the relay did not answer: {error}"))?;
    let _ = tcp.set_nodelay(true);
    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|()| tcp.set_write_timeout(Some(Duration::from_secs(10))))
        .map_err(|error| error.to_string())?;
    let stream = if url.scheme() == "wss" {
        Stream::Tls(Box::new(tls_stream(host, tcp)?))
    } else {
        Stream::Plain(tcp)
    };
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| error.to_string())?;
    let bearer =
        tungstenite::http::HeaderValue::from_str(&format!("Bearer {}", connection.access_token))
            .map_err(|_| "the access token is not a header value")?;
    request.headers_mut().insert("Authorization", bearer);
    let (socket, _) =
        tungstenite::client::client(request, stream).map_err(|error| match error {
            tungstenite::HandshakeError::Failure(tungstenite::Error::Http(response)) => {
                format!(
                    "the relay refused the connection with HTTP {}",
                    response.status()
                )
            }
            tungstenite::HandshakeError::Failure(error) => error.to_string(),
            tungstenite::HandshakeError::Interrupted(_) => "the relay handshake timed out".into(),
        })?;
    Ok(socket)
}

#[cfg(feature = "tls")]
fn tls_stream(
    host: &str,
    tcp: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| "the relay host is not a TLS name")?;
    let connection = rustls::ClientConnection::new(crate::http::tls_config(), name)
        .map_err(|error| error.to_string())?;
    Ok(rustls::StreamOwned::new(connection, tcp))
}

#[cfg(not(feature = "tls"))]
fn tls_stream(
    _host: &str,
    _tcp: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    Err("this build has no TLS for the relay".into())
}

/// Waits for `connection.ready` and reads the identity the cloud bound.
fn wait_ready(socket: &mut WebSocket<Stream>, limit: Duration) -> Result<Identity, String> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        let text = match socket.read() {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => return Err("the relay closed before it was ready".into()),
            Ok(_) => continue,
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.to_string()),
        };
        let Ok(message) = serde_json::from_str::<Value>(text.as_str()) else {
            continue;
        };
        if message["type"] != "connection.ready" {
            continue;
        }
        let data = if message["data"].is_object() {
            &message["data"]
        } else {
            &message["payload"]
        };
        let field = |name: &str| data[name].as_str().map(str::to_owned);
        if data["client_role"] != "desktop" {
            return Err("the relay bound this connection to another role".into());
        }
        return match (field("connection_id"), field("user_id"), field("device_id")) {
            (Some(connection_id), Some(user_id), Some(device_id)) => Ok(Identity {
                connection_id,
                user_id,
                device_id,
            }),
            _ => Err("the relay's ready event carries no identity".into()),
        };
    }
    Err("the relay was not ready in time".into())
}

#[cfg(test)]
mod tests;
