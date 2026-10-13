//! Shared state for runtime attach connections.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[cfg(any(unix, target_os = "windows"))]
use muniment_core::attach::ApprovalCoordinator;
use muniment_core::attach::{
    CompanionRegistry, DesktopAttachService, DrainState, ProtocolError, RuntimeActivityRegistry,
    SignedWorkspaceApproval,
};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_execution::PiRuntime;
use muniment_core::run_start::ActiveRun;
use muniment_core::session_thread::SessionThread;

use crate::host::RuntimeHost;
use crate::service::{open_companion_registry, open_profile_storage_as};
#[cfg(target_os = "linux")]
use crate::AttachListenerInputs;
use crate::{compose_attach_service, RuntimeAttachBoundaries, RuntimeChatEventBroadcast};

/// Owns the state shared by all runtime attach connections.
pub struct RuntimeAttachState {
    profile_directory: PathBuf,
    config_directory: PathBuf,
    storage: muniment_core::run_events::SharedStorage,
    active: Arc<Mutex<Option<ActiveRun>>>,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    memory_runtime: Arc<ApplicationMemoryRuntime>,
    runtime_activity: RuntimeActivityRegistry,
    drain_state: DrainState,
    host: RuntimeHost,
    approval: SignedWorkspaceApproval,
    session_thread: Arc<SessionThread>,
    companion_registry: CompanionRegistry,
    #[cfg(any(unix, target_os = "windows"))]
    approvals: ApprovalCoordinator,
    sign_in_running: Arc<AtomicBool>,
    chat_events: RuntimeChatEventBroadcast,
}

impl RuntimeAttachState {
    /// Opens the profile storage and companion registry for the runtime of one host.
    pub fn open(
        host: RuntimeHost,
        profile_directory: impl AsRef<Path>,
        config_directory: impl AsRef<Path>,
    ) -> Result<Self, ProtocolError> {
        let profile_directory = profile_directory.as_ref().to_path_buf();
        let config_directory = config_directory.as_ref().to_path_buf();
        let storage = open_profile_storage_as(&profile_directory, host.runtime_version)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let companion_registry = open_companion_registry(&profile_directory)?;
        let drain_state = DrainState::new();
        let runtime_activity = RuntimeActivityRegistry::with_drain_state(&drain_state);
        let approval = SignedWorkspaceApproval::default();

        Ok(Self {
            memory_runtime: Arc::new(ApplicationMemoryRuntime::new(
                config_directory.clone(),
                profile_directory.join("memory"),
            )),
            profile_directory,
            config_directory,
            storage,
            active: Arc::new(Mutex::new(None)),
            runtime: Arc::new(Mutex::new(None)),
            runtime_activity,
            drain_state,
            host,
            approval: approval.clone(),
            session_thread: Arc::new(SessionThread::default()),
            companion_registry,
            #[cfg(any(unix, target_os = "windows"))]
            approvals: ApprovalCoordinator::default(),
            sign_in_running: Arc::new(AtomicBool::new(false)),
            chat_events: RuntimeChatEventBroadcast::new(approval),
        })
    }

    /// Builds boundaries that share the runtime state.
    pub fn boundaries(&self) -> RuntimeAttachBoundaries {
        RuntimeAttachBoundaries::new_with_sign_in(
            Arc::clone(&self.storage),
            Arc::clone(&self.active),
            self.profile_directory.clone(),
            self.config_directory.clone(),
            Arc::clone(&self.runtime),
            Arc::clone(&self.memory_runtime),
            self.runtime_activity.clone(),
            self.host.clone(),
            self.approval.clone(),
            Arc::clone(&self.session_thread),
            self.companion_registry.clone(),
            #[cfg(any(unix, target_os = "windows"))]
            self.approvals.clone(),
            Arc::clone(&self.sign_in_running),
            self.chat_events.clone(),
        )
    }

    /// Composes a service for one companion connection.
    pub fn attach_service(
        &self,
    ) -> Result<DesktopAttachService<RuntimeAttachBoundaries>, ProtocolError> {
        let mut service = compose_attach_service(
            self.boundaries(),
            &self.companion_registry,
            &self.profile_directory,
            &self.config_directory,
        )?;
        service.drain_state = self.drain_state.clone();
        Ok(service)
    }

    /// Builds listener inputs that share the runtime attach state.
    #[cfg(target_os = "linux")]
    pub fn attach_listener_inputs(&self) -> AttachListenerInputs<'_> {
        AttachListenerInputs {
            companion_registry: &self.companion_registry,
            approval: self.approval.clone(),
            approvals: self.approvals.clone(),
            expected_desktop_executable: self.host.expected_desktop_executable.clone(),
            runtime_version: self.host.runtime_version,
        }
    }

    /// Returns the companion registry shared with attach services.
    pub fn companion_registry(&self) -> &CompanionRegistry {
        &self.companion_registry
    }

    /// Returns the workspace approval shared with attach boundaries.
    pub fn signed_workspace_approval(&self) -> SignedWorkspaceApproval {
        self.approval.clone()
    }

    /// Returns the version the runtime announces on attach.
    pub fn runtime_version(&self) -> &'static str {
        self.host.runtime_version
    }

    /// Returns the activity registry an activation reads before a refresh.
    pub fn runtime_activity(&self) -> RuntimeActivityRegistry {
        self.runtime_activity.clone()
    }

    /// Returns the drain state an executable replacement sets.
    pub fn drain_state(&self) -> DrainState {
        self.drain_state.clone()
    }

    pub(crate) fn agent_profile(&self) -> &Path {
        &self.profile_directory
    }
    pub(crate) fn agent_storage(&self) -> muniment_core::run_events::SharedStorage {
        Arc::clone(&self.storage)
    }
    pub(crate) fn agent_events(
        &self,
        run: &str,
    ) -> Result<Vec<muniment_core::journal::EventEnvelope>, String> {
        self.storage
            .lock()
            .map_err(|_| "Agent history is busy.".to_owned())?
            .journal
            .events(run)
            .map_err(|e| e.to_string())
    }

    /// Applies the retention choice currently recorded for this profile.
    pub fn apply_recorded_retention(&self) -> Result<(), String> {
        apply_recorded_retention(&self.config_directory, &self.storage)
    }
}

/// Re-reads the recorded retention choice and applies its age limit.
pub(crate) fn apply_recorded_retention(
    config_directory: &Path,
    storage: &muniment_core::run_events::SharedStorage,
) -> Result<(), String> {
    muniment_core::retention_record::apply_recorded_retention(config_directory, |max_age_seconds| {
        crate::service::apply_retention(Arc::clone(storage), max_age_seconds)
    })
    .map(|_| ())
}
