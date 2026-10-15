//! Dormant runtime chat event delivery boundaries.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use muniment_core::attach::SignedWorkspaceApproval;
use muniment_core::chat_launch::{ChatGrant, FetchGrantError, FetchReceiptError};
use muniment_core::chat_profile::ChatProfile;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatEventSubscription};
use muniment_core::runtime_eprintln as eprintln;
use muniment_core::sidecar::pi_chat::Receipt;
use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_SELECTED_ARTIFACT};

use crate::host::{ChatGrantService, NoCloud, RuntimeHost};

pub const CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY: usize = 256;

/// The most events a resuming subscriber replays. A longer gap gets the
/// whole state of each run that changed instead.
pub const CHAT_REPLAY_MAX_EVENTS: usize = 128;

/// The most serialized event bytes a resuming subscriber replays.
pub const CHAT_REPLAY_MAX_BYTES: usize = 1024 * 1024;

/// How many runs keep their whole state for a subscriber that attaches or
/// resumes past the replay budget. The least recently changed run goes first.
const CHAT_RUN_STATES: usize = 32;

/// The phases of a run the runtime still drives. A new subscriber gets the
/// whole state of each run in one of them.
const LIVE_PHASES: [&str; 4] = [
    "acquiring-pi",
    "thinking",
    "streaming",
    "pending-permission",
];

/// How long a streaming text event may reuse the last read of the local-mode
/// marker. Every other phase reads the marker, so a run's start, gates and end
/// always see the current mode.
const LOCAL_MODE_STREAMING_REUSE: Duration = Duration::from_secs(1);

/// Fans each chat event out to every live subscriber without blocking a run.
#[derive(Clone, Default)]
pub struct RuntimeChatEventBroadcast {
    shared: Arc<RuntimeChatEventBroadcastShared>,
    approval: SignedWorkspaceApproval,
    config_directory: Option<PathBuf>,
}

#[derive(Default)]
struct RuntimeChatEventBroadcastShared {
    next_id: AtomicU64,
    full_queue_drops: AtomicU64,
    stream: Mutex<ChatEventStream>,
    local_mode: Mutex<Option<(PathBuf, bool, Instant)>>,
    #[cfg(target_os = "linux")]
    delivery_failures: Mutex<std::collections::BTreeMap<(String, String), ChatEvent>>,
}

struct RuntimeChatEventSubscriber {
    id: u64,
    capacity: usize,
    sender: SyncSender<ChatEvent>,
}

/// The subscribers and what a later subscriber needs to catch up: the newest
/// events within the replay budget and the whole state of recent runs. Each
/// entry keeps the workspace whose gate it passed, or none for a device-wide
/// event, so a subscriber reads only what the gate allows when it subscribes.
struct ChatEventStream {
    subscribers: Vec<RuntimeChatEventSubscriber>,
    /// The position of the newest event.
    seq: u64,
    replay: VecDeque<StreamEntry>,
    replay_bytes: usize,
    runs: BTreeMap<String, (ChatEvent, String)>,
}

struct StreamEntry {
    event: ChatEvent,
    workspace: Option<String>,
    bytes: usize,
}

impl Default for ChatEventStream {
    fn default() -> Self {
        Self {
            subscribers: Vec::new(),
            seq: stream_origin(),
            replay: VecDeque::new(),
            replay_bytes: 0,
            runs: BTreeMap::new(),
        }
    }
}

/// Starts a stream's positions at the clock in microseconds, so the cursor
/// of an earlier runtime falls before this stream's first event.
fn stream_origin() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX / 2)
        })
}

impl ChatEventStream {
    fn record(&mut self, event: &ChatEvent, workspace: Option<&str>, keeps_state: bool) {
        let bytes =
            muniment_core::serde_json::to_vec(event).map_or(usize::MAX, |bytes| bytes.len());
        self.replay.push_back(StreamEntry {
            event: event.clone(),
            workspace: workspace.map(str::to_owned),
            bytes,
        });
        self.replay_bytes = self.replay_bytes.saturating_add(bytes);
        while self.replay.len() > CHAT_REPLAY_MAX_EVENTS
            || self.replay_bytes > CHAT_REPLAY_MAX_BYTES
        {
            let Some(evicted) = self.replay.pop_front() else {
                break;
            };
            self.replay_bytes = self.replay_bytes.saturating_sub(evicted.bytes);
        }
        if let (true, Some(workspace)) = (keeps_state, workspace) {
            self.update_run(event, workspace);
        }
    }

    /// Folds one event into its run's whole state. A delta that does not
    /// extend the kept text drops the state, and the run's next whole event
    /// starts it again.
    fn update_run(&mut self, event: &ChatEvent, workspace: &str) {
        match &event.delta {
            None => {
                self.runs
                    .insert(event.run_id.clone(), (event.clone(), workspace.to_owned()));
            }
            Some(delta) => {
                let extended = self.runs.get_mut(&event.run_id).and_then(|(state, _)| {
                    let end = utf16_byte_offset(&state.text, delta.text_start)?;
                    state.text.truncate(end);
                    state.text.push_str(&event.text);
                    state.phase.clone_from(&event.phase);
                    state.routing_stage = None;
                    state.seq = event.seq;
                    Some(())
                });
                if extended.is_none() {
                    self.runs.remove(&event.run_id);
                }
            }
        }
        while self.runs.len() > CHAT_RUN_STATES {
            let Some(oldest) = self
                .runs
                .iter()
                .min_by_key(|(_, (state, _))| state.seq)
                .map(|(run_id, _)| run_id.clone())
            else {
                break;
            };
            self.runs.remove(&oldest);
        }
    }

    /// What a subscriber reads before live events. A cursor this stream still
    /// holds the events after gets those events. A cursor before the replay
    /// budget gets the whole state of each run that changed after it. No
    /// cursor, or one this stream never reached, gets the whole state of each
    /// live run. Each whole state carries the stream's current position.
    fn catch_up(&self, cursor: Option<u64>, allowed: Option<&str>) -> Vec<ChatEvent> {
        let readable =
            |workspace: Option<&str>| workspace.is_none_or(|workspace| allowed == Some(workspace));
        let replayable = |cursor: u64| {
            cursor == self.seq
                || self
                    .replay
                    .front()
                    .is_some_and(|entry| entry.event.seq.is_some_and(|seq| seq <= cursor + 1))
        };
        match cursor.filter(|&cursor| cursor <= self.seq) {
            Some(cursor) if replayable(cursor) => self
                .replay
                .iter()
                .filter(|entry| {
                    entry.event.seq.is_some_and(|seq| seq > cursor)
                        && readable(entry.workspace.as_deref())
                })
                .map(|entry| entry.event.clone())
                .collect(),
            cursor => {
                let mut states: Vec<_> = self
                    .runs
                    .values()
                    .filter(|(state, workspace)| {
                        readable(Some(workspace))
                            && match cursor {
                                Some(cursor) => state.seq.is_some_and(|seq| seq > cursor),
                                None => LIVE_PHASES.contains(&state.phase.as_str()),
                            }
                    })
                    .map(|(state, _)| state.clone())
                    .collect();
                states.sort_by_key(|state| state.seq);
                for state in &mut states {
                    state.seq = Some(self.seq);
                }
                states
            }
        }
    }
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

impl RuntimeChatEventBroadcast {
    pub fn new(approval: SignedWorkspaceApproval) -> Self {
        Self {
            shared: Arc::new(RuntimeChatEventBroadcastShared::default()),
            approval,
            config_directory: None,
        }
    }

    pub fn with_config_directory(mut self, config_directory: PathBuf) -> Self {
        self.config_directory = Some(config_directory);
        self
    }

    #[cfg(target_os = "linux")]
    fn allows_workspace(&self, workspace: &str) -> bool {
        self.allows_workspace_with(workspace, false)
    }

    fn allows_workspace_with(&self, workspace: &str, streaming: bool) -> bool {
        self.allowed_workspace(streaming).as_deref() == Some(workspace)
    }

    /// The one workspace whose run events subscribers may read now.
    fn allowed_workspace(&self, streaming: bool) -> Option<String> {
        if self.local_mode(streaming) {
            return Some("local".into());
        }
        self.approval.approval().map(|approval| approval.workspace)
    }

    /// Reads the local-mode marker. A streaming event reuses a read younger
    /// than one second, so a text stream costs at most one marker read a second.
    fn local_mode(&self, streaming: bool) -> bool {
        let Some(directory) = &self.config_directory else {
            return false;
        };
        let mut cached = self
            .shared
            .local_mode
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((read_directory, local, read_at)) = &*cached {
            if streaming
                && read_directory == directory
                && read_at.elapsed() < LOCAL_MODE_STREAMING_REUSE
            {
                return *local;
            }
        }
        let local = muniment_core::local_mode::is_local_mode(directory);
        *cached = Some((directory.clone(), local, Instant::now()));
        local
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn record_delivery_failure(&self, workspace: String, event: ChatEvent) {
        // Subscription setup and socket writes do not acknowledge receipt by the shell.
        // Keep each run's latest cause for every desktop in its workspace until runtime exit.
        let mut failures = self
            .shared
            .delivery_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        failures.insert((workspace.clone(), event.run_id.clone()), event.clone());
        self.deliver_with(&workspace, event, false);
    }

    /// Subscribes from now. The subscriber first gets the whole state of each
    /// live run.
    pub fn subscribe(&self) -> ChatEventSubscription {
        self.subscribe_after(None)
    }

    /// Subscribes after the stream position `cursor`, the `seq` of the last
    /// event the subscriber applied. It first gets the events it missed while
    /// they fit the replay budget, else the whole state of each run that
    /// changed. Live events follow with no gap, because both happen under the
    /// lock that every delivery takes.
    pub fn subscribe_after(&self, cursor: Option<u64>) -> ChatEventSubscription {
        #[cfg(target_os = "linux")]
        let failures = self
            .shared
            .delivery_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let allowed = self.allowed_workspace(false);
        let mut stream = self
            .shared
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let catch_up = stream.catch_up(cursor, allowed.as_deref());
        #[cfg(target_os = "linux")]
        let capacity = CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY.max(failures.len() + catch_up.len());
        #[cfg(not(target_os = "linux"))]
        let capacity = CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY.max(catch_up.len());
        let (sender, receiver) = mpsc::sync_channel(capacity);
        #[cfg(target_os = "linux")]
        for ((workspace, _), failure) in failures.iter() {
            if self.allows_workspace(workspace) {
                let _ = sender.try_send(failure.clone());
            }
        }
        for event in catch_up {
            let _ = sender.try_send(event);
        }
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        stream.subscribers.push(RuntimeChatEventSubscriber {
            id,
            capacity,
            sender,
        });
        drop(stream);
        let shared = Arc::downgrade(&self.shared);
        ChatEventSubscription::new(receiver, move || remove_subscriber(&shared, id))
    }

    #[doc(hidden)]
    pub fn subscriber_count(&self) -> usize {
        self.shared
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .subscribers
            .len()
    }

    /// Counts the subscribers this broadcast dropped for a full queue.
    #[doc(hidden)]
    pub fn full_queue_drop_count(&self) -> u64 {
        self.shared.full_queue_drops.load(Ordering::Relaxed)
    }

    fn deliver(&self, workspace: &str, event: ChatEvent) {
        self.deliver_with(workspace, event, true);
    }

    /// Delivers one run event. `keeps_state` folds it into the run's whole
    /// state, which a notice outside the run's projection must not replace.
    fn deliver_with(&self, workspace: &str, event: ChatEvent, keeps_state: bool) {
        if !self.allows_workspace_with(workspace, event.phase == "streaming") {
            return;
        }
        self.fan_out(event, Some(workspace), keeps_state);
    }

    /// Sends a device-wide event, such as the sign-in link, to every live
    /// subscriber. The workspace gate guards run events, and this event names
    /// no run.
    pub(crate) fn announce(&self, event: ChatEvent) {
        self.fan_out(event, None, false);
    }

    fn fan_out(&self, mut event: ChatEvent, workspace: Option<&str>, keeps_state: bool) {
        let mut full_queue_drops = Vec::new();
        let mut stream = self
            .shared
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stream.seq += 1;
        event.seq = Some(stream.seq);
        stream.record(&event, workspace, keeps_state);
        stream.subscribers.retain(
            |subscriber| match subscriber.sender.try_send(event.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    full_queue_drops.push((subscriber.id, subscriber.capacity));
                    false
                }
                // A disconnected receiver is the ordinary close of a client connection.
                Err(TrySendError::Disconnected(_)) => false,
            },
        );
        drop(stream);
        self.shared
            .full_queue_drops
            .fetch_add(full_queue_drops.len() as u64, Ordering::Relaxed);
        // Report each drop after the lock releases, so no run waits on stderr.
        for (id, capacity) in full_queue_drops {
            eprintln!(
                "muniment-runtime: dropped chat-event subscriber {id} because its \
                 {capacity}-event queue is full"
            );
        }
    }
}

fn remove_subscriber(shared: &Weak<RuntimeChatEventBroadcastShared>, id: u64) {
    let Some(shared) = shared.upgrade() else {
        return;
    };
    shared
        .stream
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .subscribers
        .retain(|subscriber| subscriber.id != id);
}

/// Names where one run sends its chat events.
pub enum RuntimeChatEventTarget {
    /// Sends to one caller-owned subscriber, or to nobody.
    Subscriber(Option<Sender<ChatEvent>>),
    /// Fans out to every live subscriber of the shared broadcast.
    Broadcast(RuntimeChatEventBroadcast),
}

pub struct RuntimeChatEventSink {
    profile: ChatProfile,
    target: Mutex<RuntimeChatEventTarget>,
    chat_grants: Arc<dyn ChatGrantService>,
    runtime_version: &'static str,
    pi_artifact: PiArtifactDescriptor,
    memory_runtime: Arc<ApplicationMemoryRuntime>,
    thread_id: String,
    workspace: String,
    earlier_models: Vec<String>,
    project_context: String,
}

impl RuntimeChatEventSink {
    pub fn new(
        profile_directory: impl AsRef<Path>,
        broadcast: RuntimeChatEventBroadcast,
        memory_runtime: Arc<ApplicationMemoryRuntime>,
        thread_id: String,
        workspace: String,
    ) -> Self {
        Self::with_target(
            profile_directory,
            RuntimeChatEventTarget::Broadcast(broadcast),
            memory_runtime,
            thread_id,
            workspace,
        )
    }

    pub fn with_subscriber(
        profile_directory: impl AsRef<Path>,
        subscriber: Option<Sender<ChatEvent>>,
        memory_runtime: Arc<ApplicationMemoryRuntime>,
        thread_id: String,
    ) -> Self {
        Self::with_target(
            profile_directory,
            RuntimeChatEventTarget::Subscriber(subscriber),
            memory_runtime,
            thread_id,
            String::new(),
        )
    }

    pub fn with_target(
        profile_directory: impl AsRef<Path>,
        target: RuntimeChatEventTarget,
        memory_runtime: Arc<ApplicationMemoryRuntime>,
        thread_id: String,
        workspace: String,
    ) -> Self {
        Self {
            profile: ChatProfile::new(profile_directory.as_ref()),
            target: Mutex::new(target),
            chat_grants: Arc::new(NoCloud),
            runtime_version: env!("CARGO_PKG_VERSION"),
            pi_artifact: PI_SELECTED_ARTIFACT,
            memory_runtime,
            thread_id,
            workspace,
            earlier_models: Vec::new(),
            project_context: String::new(),
        }
    }

    pub fn with_pi_artifact(mut self, pi_artifact: PiArtifactDescriptor) -> Self {
        self.pi_artifact = pi_artifact;
        self
    }

    /// The host whose chat grants a run renews and fetches receipts with,
    /// and whose runtime version the journal records.
    pub fn with_host(mut self, host: &RuntimeHost) -> Self {
        self.chat_grants = Arc::clone(&host.chat_grants);
        self.runtime_version = host.runtime_version;
        self
    }

    /// The models that answered earlier runs of this thread, for the prompt's facts.
    pub fn with_project_context(mut self, context: String) -> Self {
        self.project_context = context;
        self
    }

    pub fn with_earlier_models(mut self, earlier_models: Vec<String>) -> Self {
        self.earlier_models = earlier_models;
        self
    }
}

impl ChatEventSink for RuntimeChatEventSink {
    fn provenance(&self) -> (&str, &str) {
        ("muniment-runtime", self.runtime_version)
    }

    fn deliver(&self, mut event: ChatEvent) -> Result<(), ()> {
        event.thread_id = Some(self.thread_id.clone());
        let mut target = self.target.lock().map_err(|_| ())?;
        match &mut *target {
            RuntimeChatEventTarget::Subscriber(subscriber) => {
                if subscriber
                    .as_ref()
                    .is_some_and(|subscriber| subscriber.send(event).is_err())
                {
                    *subscriber = None;
                }
                Ok(())
            }
            RuntimeChatEventTarget::Broadcast(broadcast) => {
                broadcast.deliver(&self.workspace, event);
                Ok(())
            }
        }
    }
}

impl PiLaunchBoundaries for RuntimeChatEventSink {
    fn renew_chat_grant(&self, access_token: &str) -> Result<ChatGrant, FetchGrantError> {
        self.chat_grants.fetch_grant(access_token)
    }

    fn inspect_chat_session(&self, access_token: &str) -> Result<String, FetchGrantError> {
        self.chat_grants.inspect_session(access_token)
    }

    fn fetch_receipt(
        &self,
        grant: &ChatGrant,
        access_token: &str,
        run_id: &str,
    ) -> Result<Receipt, FetchReceiptError> {
        self.chat_grants.fetch_receipt(grant, access_token, run_id)
    }

    fn extension_thread_id(&self) -> Option<String> {
        Some(self.thread_id.clone())
    }
    fn pi_artifact(&self) -> PiArtifactDescriptor {
        self.pi_artifact
    }

    fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
        Ok(self.profile.pi_session_root())
    }

    fn memory_agent_extension_path(&self) -> Option<PathBuf> {
        Some(self.memory_runtime.agent_extension_path())
    }

    fn project_context(&self) -> Option<&str> {
        (!self.project_context.is_empty()).then_some(self.project_context.as_str())
    }

    fn agent_instructions(&self) -> Result<Option<String>, PiLaunchError> {
        let sessions = self.profile.pi_session_root();
        let profile = sessions
            .parent()
            .ok_or(PiLaunchError::UnavailableSessionRoot)?;
        let mut instructions = muniment_core::agents::thread_instructions(profile, &self.thread_id)
            .map_err(|e| PiLaunchError::rejected("agent", e))?
            .unwrap_or_default();
        if let Some(plan) = muniment_core::creations::read(profile, &self.thread_id)
            .map_err(|e| PiLaunchError::rejected("creation", e))?
        {
            instructions.push_str(&format!("\nCreation thread: {}\nGoal: {}\nSpecified output: {}\nUse creation-plan to retain user-approved refinements. Continue in this dedicated thread.",plan.kind,plan.goal,plan.output));
        }
        Ok((!instructions.is_empty()).then_some(instructions))
    }

    fn project_directory(&self) -> Result<Option<PathBuf>, PiLaunchError> {
        let sessions = self.profile.pi_session_root();
        let profile = sessions
            .parent()
            .ok_or(PiLaunchError::UnavailableSessionRoot)?;
        muniment_core::projects::workspace_with_config(
            profile,
            self.memory_runtime.config_directory(),
            &self.thread_id,
        )
        .map(Some)
        .map_err(|error| PiLaunchError::rejected("project_folder", error))
    }

    fn earlier_models(&self) -> Vec<String> {
        self.earlier_models.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(phase: &str) -> ChatEvent {
        ChatEvent {
            run_id: "run-1".into(),
            thread_id: None,
            phase: phase.into(),
            text: "hello".into(),
            prompt_accepted: false,
            turn_started: false,
            routing_stage: None,
            prompt_storage_notice: None,
            failure_reason: None,
            receipt: None,
            tool_activity: Vec::new(),
            attachments: Vec::new(),
            recalls: Vec::new(),
            applied_diffs: Vec::new(),
            pending_permission: None,
            delta: None,
            seq: None,
        }
    }

    #[test]
    fn the_journal_records_the_host_runtime_version() {
        let root = std::env::temp_dir().join("muniment-sink-runtime-version");
        let memory = Arc::new(ApplicationMemoryRuntime::new(
            root.clone(),
            root.join("memory"),
        ));
        let sink =
            RuntimeChatEventSink::with_subscriber(&root, None, Arc::clone(&memory), "t".into());
        assert_eq!(
            sink.provenance(),
            ("muniment-runtime", env!("CARGO_PKG_VERSION"))
        );
        let host = RuntimeHost {
            runtime_version: "9.8.7",
            ..RuntimeHost::default()
        };
        let sink =
            RuntimeChatEventSink::with_subscriber(&root, None, memory, "t".into()).with_host(&host);
        assert_eq!(sink.provenance(), ("muniment-runtime", "9.8.7"));
    }

    #[test]
    fn streaming_events_reuse_the_marker_read_and_other_phases_read_it_again() {
        let config = std::env::temp_dir().join(format!(
            "muniment-sink-local-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&config).unwrap();
        let marker = config.join(muniment_core::local_mode::LOCAL_MODE_MARKER);
        let broadcast = RuntimeChatEventBroadcast::new(SignedWorkspaceApproval::default())
            .with_config_directory(config.clone());
        let subscriber = broadcast.subscribe();

        broadcast.deliver("local", event("thinking"));
        assert!(subscriber.try_recv().is_err());
        std::fs::write(&marker, "1").unwrap();
        // The streaming event reuses the read that found no marker.
        broadcast.deliver("local", event("streaming"));
        assert!(subscriber.try_recv().is_err());
        // A phase change reads the marker at once.
        broadcast.deliver("local", event("pending-permission"));
        assert_eq!(subscriber.try_recv().unwrap().phase, "pending-permission");
        broadcast.deliver("local", event("streaming"));
        assert_eq!(subscriber.try_recv().unwrap().phase, "streaming");

        std::fs::remove_file(&marker).unwrap();
        broadcast.deliver("local", event("complete"));
        assert!(subscriber.try_recv().is_err());
        std::fs::remove_dir_all(config).unwrap();
    }
}
