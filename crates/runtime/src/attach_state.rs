//! Shared state for runtime attach connections.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[cfg(any(unix, target_os = "windows"))]
use muniment_core::attach::ApprovalCoordinator;
use muniment_core::attach::{
    CompanionRegistry, DesktopAttachService, DrainState, ProtocolError, RemoteAccess,
    RemoteAccessOpenError, RemoteAccessOptions, RemoteListener, RemoteListenerError, RemoteRoute,
    RemoteRouteOptions, RemoteServe, RuntimeActivityRegistry, SignedWorkspaceApproval,
};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_execution::PiRuntime;
use muniment_core::run_start::ActiveRun;
use muniment_core::session_thread::SessionThread;

use crate::host::RuntimeHost;
use crate::models::ModelService;
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
    models: Arc<ModelService>,
    remote_access: Mutex<Option<RemoteAccess>>,
    remote_route: Mutex<Option<Arc<RemoteRoute>>>,
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
        // Session folders from older versions take their thread titles here,
        // so the runtime stays the only process that opens the journal.
        if let Err(error) = muniment_core::projects::migrate_session_names(&profile_directory) {
            muniment_core::runtime_eprintln!(
                "muniment-runtime: session_names outcome=failed error={error}"
            );
        }
        let companion_registry = open_companion_registry(&profile_directory)?;
        let drain_state = DrainState::new();
        let runtime_activity = RuntimeActivityRegistry::with_drain_state(&drain_state);
        let approval = SignedWorkspaceApproval::default();
        muniment_core::model_router::native_auth::set_provider_clients(
            host.provider_clients.clone(),
        );
        let models = Arc::new(ModelService::new(
            &profile_directory,
            Arc::clone(&host.sign_in_page),
        ));

        Ok(Self {
            memory_runtime: Arc::new(
                ApplicationMemoryRuntime::new(
                    config_directory.clone(),
                    profile_directory.join("memory"),
                )
                .with_extraction_model(
                    muniment_core::memory_extract::extraction_model(profile_directory.clone()),
                ),
            ),
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
            models,
            remote_access: Mutex::new(None),
            remote_route: Mutex::new(None),
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
            Arc::clone(&self.models),
        )
    }

    /// Returns the model service shared by every attach connection.
    pub fn models(&self) -> &Arc<ModelService> {
        &self.models
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
        service.remote_access = self.remote_access();
        service.remote_route = self.remote_route();
        Ok(service)
    }

    /// Opens remote access under `<state root>/remote` and shares it with
    /// every attach service composed after this call, so the owner's local
    /// desktop route can pair and revoke devices. Later local desktop
    /// welcomes carry the runtime's identity.
    pub fn open_remote_access(
        &self,
        options: RemoteAccessOptions,
    ) -> Result<RemoteAccess, RemoteAccessOpenError> {
        let access = RemoteAccess::open(self.profile_directory.join("remote"), options)?;
        access.announce_on_local_route();
        *self
            .remote_access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(access.clone());
        Ok(access)
    }

    /// Opens remote access and starts the remote listener as the stored
    /// settings and the host's overrides direct. The owner's local desktop
    /// route then reads and saves the settings, and a save starts, stops or
    /// rebinds the listener. The host calls `stop_remote_route` before it
    /// exits.
    pub fn start_remote_route(
        self: &Arc<Self>,
        options: RemoteRouteOptions,
    ) -> Result<Arc<RemoteRoute>, RemoteAccessOpenError> {
        let access = self.open_remote_access(options.access)?;
        let state = Arc::downgrade(self);
        let serve: RemoteServe = Arc::new(move |listener, access, stop| match state.upgrade() {
            Some(state) => state.serve_remote_listener(listener, access, stop),
            None => Ok(()),
        });
        // A route started earlier releases its port before the new one binds.
        self.stop_remote_route();
        let route = Arc::new(RemoteRoute::new(access, options.overrides, serve));
        route.apply();
        *self
            .remote_route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&route));
        Ok(route)
    }

    /// The remote route the host started, if any.
    pub fn remote_route(&self) -> Option<Arc<RemoteRoute>> {
        self.remote_route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Stops the remote listener and forgets the route.
    pub fn stop_remote_route(&self) {
        let route = self
            .remote_route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(route) = route {
            route.stop();
        }
    }

    /// The remote access the host opened, if any.
    pub fn remote_access(&self) -> Option<RemoteAccess> {
        self.remote_access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Serves the remote attach route on `listener` with this state until
    /// `stop` fires. The host opens remote access first and binds the
    /// listener only when its configuration names a listen address.
    pub fn serve_remote_listener(
        self: &Arc<Self>,
        listener: RemoteListener,
        access: RemoteAccess,
        stop: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), RemoteListenerError> {
        let state = Arc::clone(self);
        listener.serve(
            access,
            self.approval.clone(),
            move || state.attach_service(),
            stop,
        )
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
