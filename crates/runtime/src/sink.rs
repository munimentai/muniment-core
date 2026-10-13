//! Dormant runtime chat event delivery boundaries.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use muniment_core::attach::SignedWorkspaceApproval;
use muniment_core::chat_launch::{ChatGrant, FetchGrantError, FetchReceiptError};
use muniment_core::chat_profile::ChatProfile;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_launch::{PiLaunchBoundaries, PiLaunchError};
use muniment_core::run_events::{ChatEvent, ChatEventSink, ChatEventSubscription};
use muniment_core::runtime_eprintln as eprintln;
use muniment_core::sidecar::pi_chat::Receipt;
use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_SELECTED_ARTIFACT};

use crate::host::{ChatGrantService, NoCloud};

pub const CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY: usize = 256;

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
    subscribers: Mutex<Vec<RuntimeChatEventSubscriber>>,
    local_mode: Mutex<Option<(PathBuf, bool, Instant)>>,
    #[cfg(target_os = "linux")]
    delivery_failures: Mutex<std::collections::BTreeMap<(String, String), ChatEvent>>,
}

struct RuntimeChatEventSubscriber {
    id: u64,
    capacity: usize,
    sender: SyncSender<ChatEvent>,
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
        if self.local_mode(streaming) {
            return workspace == "local";
        }
        self.approval
            .approval()
            .is_some_and(|approval| approval.workspace == workspace)
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
        self.deliver(&workspace, event);
    }

    pub fn subscribe(&self) -> ChatEventSubscription {
        #[cfg(target_os = "linux")]
        let failures = self
            .shared
            .delivery_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(target_os = "linux")]
        let capacity = CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY.max(failures.len());
        #[cfg(not(target_os = "linux"))]
        let capacity = CHAT_EVENT_SUBSCRIBER_QUEUE_CAPACITY;
        let (sender, receiver) = mpsc::sync_channel(capacity);
        #[cfg(target_os = "linux")]
        for ((workspace, _), failure) in failures.iter() {
            if self.allows_workspace(workspace) {
                let _ = sender.try_send(failure.clone());
            }
        }
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        self.shared
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(RuntimeChatEventSubscriber {
                id,
                capacity,
                sender,
            });
        let shared = Arc::downgrade(&self.shared);
        ChatEventSubscription::new(receiver, move || remove_subscriber(&shared, id))
    }

    #[doc(hidden)]
    pub fn subscriber_count(&self) -> usize {
        self.shared
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Counts the subscribers this broadcast dropped for a full queue.
    #[doc(hidden)]
    pub fn full_queue_drop_count(&self) -> u64 {
        self.shared.full_queue_drops.load(Ordering::Relaxed)
    }

    fn deliver(&self, workspace: &str, event: ChatEvent) {
        if !self.allows_workspace_with(workspace, event.phase == "streaming") {
            return;
        }
        self.fan_out(event);
    }

    /// Sends a device-wide event, such as the sign-in link, to every live
    /// subscriber. The workspace gate guards run events, and this event names
    /// no run.
    pub(crate) fn announce(&self, event: ChatEvent) {
        self.fan_out(event);
    }

    fn fan_out(&self, event: ChatEvent) {
        let mut full_queue_drops = Vec::new();
        self.shared
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(
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
        .subscribers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    /// The cloud chat grants a run renews and fetches receipts with.
    pub fn with_chat_grants(mut self, chat_grants: Arc<dyn ChatGrantService>) -> Self {
        self.chat_grants = chat_grants;
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
        ("muniment-runtime", env!("CARGO_PKG_VERSION"))
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
        }
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
