//! Run service operations.

use muniment_core::account::TokenSet;
use muniment_core::active_run::{
    cancel_active_run, queue_message, queue_permission_answer_with_commit, ChatQueueRequest,
};
use muniment_core::attach::RuntimeActivityRegistry;
use muniment_core::chat_coordinate::{coordinate, coordinate_compaction};
use muniment_core::chat_launch::{
    grant_authorizes_workspace, validate_grant, ChatGrant, FetchGrantError,
};
use muniment_core::chat_profile::ChatProfile;
use muniment_core::chat_resume::{
    clear_active_run, install_active_run, install_resume_run, resumable_context,
    run_resume as drive_resume, ResumeLaunch,
};
use muniment_core::chat_view::{chat_attachments, ChatAttachment};
use muniment_core::engine::CompactionOutcome;
use muniment_core::memory_index::ModelMemoryCapability;
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::permission_gate::ChatPermissionAnswer;
use muniment_core::pi_execution::PiRuntime;
use muniment_core::run_events::SharedStorage;
use muniment_core::run_preparation::{
    prepare_opened_run_with_prompt_storage, record_persistence_failure, OpenSelectedFile,
    SessionThreadStart,
};
use muniment_core::run_start::{accepted_time_now, ActiveRun};
use muniment_core::session_thread::SessionThread;
use muniment_core::sidecar::pi_install::{PiArtifactDescriptor, PI_SELECTED_ARTIFACT};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::runtime_provenance;
use crate::host::{ChatGrantService, RuntimeHost};
use crate::{RuntimeChatEventSink, RuntimeChatEventTarget};

pub struct PromptAcceptance {
    pub run_id: String,
    pub thread_id: String,
    pub attachments: Vec<ChatAttachment>,
    pub committed_seq: u64,
    pub accepted_at: String,
}

pub struct PromptLaunch {
    profile_directory: PathBuf,
    storage: SharedStorage,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    memory_runtime: Arc<ApplicationMemoryRuntime>,
    runtime_activity: RuntimeActivityRegistry,
    active: Arc<Mutex<Option<ActiveRun>>>,
    run_id: String,
    thread_id: String,
    prompt: String,
    /// The thinking level the prompt asks for. None runs the model at its default.
    thinking_level: Option<String>,
    access_token: String,
    subject: Option<String>,
    grant: ChatGrant,
    cancelled: Arc<AtomicBool>,
    transport: Arc<Mutex<Option<Arc<muniment_core::sidecar::PiRpcTransport>>>>,
    adapter: Arc<Mutex<Option<Arc<muniment_core::sidecar::pi_chat::PiRunAdapter>>>>,
    permission_answers:
        Arc<Mutex<VecDeque<muniment_core::permission_gate::PendingPermissionAnswer>>>,
    events: RuntimeChatEventTarget,
    host: RuntimeHost,
    pi_artifact: Option<PiArtifactDescriptor>,
    prepared: (u64, muniment_core::journal::reducer::ChatProjector),
    /// `Some` makes the run a manual compaction with these instructions.
    compaction: Option<Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigureRunError {
    Grant(FetchGrantError),
    Unauthorized,
}
/// Fetches a cloud chat grant and checks the requested workspace.
pub fn configure_run(
    chat_grants: &dyn ChatGrantService,
    access_token: &str,
    requested_workspace: Option<&str>,
) -> Result<ChatGrant, ConfigureRunError> {
    let grant = chat_grants
        .fetch_grant(access_token)
        .map_err(ConfigureRunError::Grant)?;
    validate_grant(&grant).map_err(ConfigureRunError::Grant)?;
    if !grant_authorizes_workspace(&grant, requested_workspace) {
        return Err(ConfigureRunError::Unauthorized);
    }
    Ok(grant)
}

/// Accepts one prompt without driving it to completion.
#[allow(clippy::too_many_arguments)]
pub fn accept_prompt(
    host: &RuntimeHost,
    profile_directory: impl AsRef<Path>,
    storage: SharedStorage,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    runtime_activity: &RuntimeActivityRegistry,
    config_directory: impl AsRef<Path>,
    run_id: String,
    prompt: String,
    thread_id: Option<String>,
    session_thread: &SessionThread,
    continue_existing: bool,
    access_token: String,
    subject: Option<String>,
    files: Vec<OpenSelectedFile>,
    grant: ChatGrant,
    active: Arc<Mutex<Option<ActiveRun>>>,
    events: RuntimeChatEventTarget,
    pi_artifact: Option<PiArtifactDescriptor>,
) -> Result<(PromptAcceptance, PromptLaunch), String> {
    accept_run(
        host,
        profile_directory.as_ref(),
        storage,
        runtime,
        runtime_activity,
        config_directory.as_ref(),
        run_id,
        prompt,
        None,
        thread_id,
        session_thread,
        continue_existing,
        access_token,
        subject,
        files,
        grant,
        active,
        events,
        pi_artifact,
    )
}

/// Accepts one manual compaction of a thread as a run in that thread. The
/// run carries no prompt, so nothing is stored for one.
#[allow(clippy::too_many_arguments)]
pub fn accept_compaction(
    host: &RuntimeHost,
    profile_directory: impl AsRef<Path>,
    storage: SharedStorage,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    runtime_activity: &RuntimeActivityRegistry,
    config_directory: impl AsRef<Path>,
    run_id: String,
    thread_id: String,
    instructions: Option<String>,
    session_thread: &SessionThread,
    access_token: String,
    subject: Option<String>,
    grant: ChatGrant,
    active: Arc<Mutex<Option<ActiveRun>>>,
    events: RuntimeChatEventTarget,
    pi_artifact: Option<PiArtifactDescriptor>,
) -> Result<PromptLaunch, String> {
    accept_run(
        host,
        profile_directory.as_ref(),
        storage,
        runtime,
        runtime_activity,
        config_directory.as_ref(),
        run_id,
        String::new(),
        Some(instructions),
        Some(thread_id),
        session_thread,
        false,
        access_token,
        subject,
        Vec::new(),
        grant,
        active,
        events,
        pi_artifact,
    )
    .map(|(_, launch)| launch)
}

#[allow(clippy::too_many_arguments)]
fn accept_run(
    host: &RuntimeHost,
    profile_directory: &Path,
    storage: SharedStorage,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    runtime_activity: &RuntimeActivityRegistry,
    config_directory: &Path,
    run_id: String,
    prompt: String,
    compaction: Option<Option<String>>,
    thread_id: Option<String>,
    session_thread: &SessionThread,
    continue_existing: bool,
    access_token: String,
    subject: Option<String>,
    files: Vec<OpenSelectedFile>,
    grant: ChatGrant,
    active: Arc<Mutex<Option<ActiveRun>>>,
    events: RuntimeChatEventTarget,
    pi_artifact: Option<PiArtifactDescriptor>,
) -> Result<(PromptAcceptance, PromptLaunch), String> {
    let memory_runtime = Arc::new(ApplicationMemoryRuntime::new(
        config_directory.to_path_buf(),
        profile_directory.join("memory"),
    ));
    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(Mutex::new(None));
    let adapter = Arc::new(Mutex::new(None));
    let permission_answers = Arc::new(Mutex::new(VecDeque::new()));
    install_active_run(
        &active,
        ActiveRun {
            id: run_id.clone(),
            workspace: grant.workspace.clone(),
            cancelled: Arc::clone(&cancelled),
            transport: Arc::clone(&transport),
            adapter: Arc::clone(&adapter),
            permission_answers: Arc::clone(&permission_answers),
            _activity: runtime_activity.mark_active_run(),
        },
    )?;
    let setup = (|| {
        let mut notice = None;
        let mut provenance = runtime_provenance(host.runtime_version);
        if let Some(thread) = thread_id.as_deref() {
            let events = storage
                .lock()
                .map_err(|_| "Conversation history is busy.")?
                .journal
                .thread_events(thread)
                .map_err(|e| e.to_string())?;
            if events
                .first()
                .and_then(|event| event.provenance.extra.get("attach_profile"))
                .and_then(|value| value.as_str())
                == Some("desktop-owner")
            {
                // RunSubmit is the authenticated desktop-owner path. Keep its
                // scope when the desktop creates the thread before its first run.
                provenance
                    .extra
                    .insert("attach_profile".into(), "desktop-owner".into());
            }
        }
        let mut prepared = prepare_opened_run_with_prompt_storage(
            &storage,
            SessionThreadStart {
                tracker: session_thread,
                continue_existing: thread_id.is_none() && continue_existing,
            },
            &run_id,
            &grant.workspace,
            subject.as_deref(),
            files,
            Some(provenance),
            thread_id.as_deref(),
            "muniment-runtime",
            host.runtime_version,
            || {
                if compaction.is_none() {
                    notice = super::prompt_storage::store_prompt_or_notice(
                        &run_id,
                        &prompt,
                        subject.as_deref(),
                    );
                }
                Ok(notice.clone())
            },
        )
        .map_err(|error| match notice {
            Some(notice) => format!("{notice} {error}"),
            None => error,
        })?;
        let thread_id = {
            let mut storage = match storage.lock() {
                Ok(storage) => storage,
                Err(poisoned) => {
                    let reason = format!("Conversation history lock failed: {poisoned}");
                    let mut storage = poisoned.into_inner();
                    record_persistence_failure(
                        &mut storage.journal,
                        &mut prepared.1,
                        &run_id,
                        prepared.0,
                        subject.as_deref(),
                        "muniment-runtime",
                        host.runtime_version,
                    );
                    return Err(reason);
                }
            };
            match storage.journal.run_thread_id(&run_id) {
                Ok(Some(thread_id)) => thread_id,
                result => {
                    record_persistence_failure(
                        &mut storage.journal,
                        &mut prepared.1,
                        &run_id,
                        prepared.0,
                        subject.as_deref(),
                        "muniment-runtime",
                        host.runtime_version,
                    );
                    return Err(match result {
                        Err(error) => error.to_string(),
                        Ok(None) => format!("The journal has no thread for run {run_id}."),
                        Ok(Some(_)) => unreachable!(),
                    });
                }
            }
        };
        if let Err(error) = memory_runtime.open_session(
            &run_id,
            &thread_id,
            ModelMemoryCapability {
                minimum_cacheable_prefix_characters: grant.minimum_cacheable_prefix_characters,
            },
        ) {
            let mut storage = storage
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            record_persistence_failure(
                &mut storage.journal,
                &mut prepared.1,
                &run_id,
                prepared.0,
                subject.as_deref(),
                "muniment-runtime",
                host.runtime_version,
            );
            return Err(format!(
                "Conversation history memory session failed: {error:?}"
            ));
        }
        Ok::<_, String>((prepared, thread_id))
    })();
    let (prepared, thread_id) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            clear_active_run(&active, &run_id);
            memory_runtime.close_session(&run_id);
            return Err(error);
        }
    };
    let projection = match prepared.1.projection() {
        Ok(projection) => projection,
        Err(error) => {
            memory_runtime.close_session(&run_id);
            clear_active_run(&active, &run_id);
            return Err(error.to_string());
        }
    };
    let attachments = chat_attachments(&projection.attachments);
    let acceptance = PromptAcceptance {
        run_id: run_id.clone(),
        thread_id: thread_id.clone(),
        attachments,
        committed_seq: prepared.0,
        accepted_at: accepted_time_now(),
    };
    let launch = PromptLaunch {
        profile_directory: profile_directory.to_path_buf(),
        storage,
        runtime,
        memory_runtime,
        runtime_activity: runtime_activity.clone(),
        active,
        run_id,
        thread_id,
        prompt,
        thinking_level: None,
        access_token,
        subject,
        grant,
        cancelled,
        transport,
        adapter,
        permission_answers,
        events,
        host: host.clone(),
        pi_artifact,
        prepared,
        compaction,
    };
    Ok((acceptance, launch))
}

impl PromptLaunch {
    /// Runs the prompt at a thinking level. None runs the model at its default.
    pub fn with_thinking_level(mut self, thinking_level: Option<String>) -> Self {
        self.thinking_level = thinking_level;
        self
    }
}

/// Drives an accepted prompt to completion.
pub fn drive_prompt(launch: PromptLaunch) {
    coordinate(
        RuntimeChatEventSink::with_target(
            &launch.profile_directory,
            launch.events,
            launch.memory_runtime.clone(),
            launch.thread_id,
            launch.grant.workspace.clone(),
        )
        .with_host(&launch.host)
        .with_pi_artifact(launch.pi_artifact.unwrap_or(PI_SELECTED_ARTIFACT)),
        launch.storage,
        launch.runtime,
        launch.runtime_activity,
        launch.memory_runtime.clone(),
        launch.run_id.clone(),
        launch.prompt,
        launch.thinking_level,
        launch.access_token,
        launch.subject,
        launch.grant,
        launch.cancelled,
        launch.transport,
        launch.adapter,
        launch.permission_answers,
        None,
        None,
        Some(launch.prepared),
    );
    launch.memory_runtime.close_session(&launch.run_id);
    clear_active_run(&launch.active, &launch.run_id);
}

/// Drives an accepted compaction to its end and answers its token counts.
pub fn drive_compaction(launch: PromptLaunch) -> Result<CompactionOutcome, String> {
    let (outcome, result) = std::sync::mpsc::channel();
    coordinate_compaction(
        RuntimeChatEventSink::with_target(
            &launch.profile_directory,
            launch.events,
            launch.memory_runtime.clone(),
            launch.thread_id,
            launch.grant.workspace.clone(),
        )
        .with_host(&launch.host)
        .with_pi_artifact(launch.pi_artifact.unwrap_or(PI_SELECTED_ARTIFACT)),
        launch.storage,
        launch.runtime,
        launch.runtime_activity,
        launch.memory_runtime.clone(),
        launch.run_id.clone(),
        launch.compaction.flatten(),
        launch.access_token,
        launch.subject,
        launch.grant,
        launch.cancelled,
        launch.transport,
        launch.adapter,
        launch.permission_answers,
        Some(launch.prepared),
        outcome,
    );
    launch.memory_runtime.close_session(&launch.run_id);
    clear_active_run(&launch.active, &launch.run_id);
    result
        .recv()
        .unwrap_or_else(|_| Err("Context compaction did not finish. Try again.".into()))
}

/// Runs one prompt to completion through the dormant runtime service boundaries.
#[allow(clippy::too_many_arguments)]
pub fn run_prompt(
    host: &RuntimeHost,
    profile_directory: impl AsRef<Path>,
    storage: SharedStorage,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    runtime_activity: &RuntimeActivityRegistry,
    config_directory: impl AsRef<Path>,
    run_id: String,
    prompt: String,
    thread_id: Option<String>,
    session_thread: &SessionThread,
    continue_existing: bool,
    access_token: String,
    subject: Option<String>,
    files: Vec<OpenSelectedFile>,
    grant: ChatGrant,
    active: Arc<Mutex<Option<ActiveRun>>>,
    events: RuntimeChatEventTarget,
    pi_artifact: Option<PiArtifactDescriptor>,
) -> Result<(), String> {
    let (_, launch) = accept_prompt(
        host,
        profile_directory,
        storage,
        runtime,
        runtime_activity,
        config_directory,
        run_id,
        prompt,
        thread_id,
        session_thread,
        continue_existing,
        access_token,
        subject,
        files,
        grant,
        active,
        events,
        pi_artifact,
    )?;
    drive_prompt(launch);
    Ok(())
}

/// Queues a message for the active run.
pub fn queue_run_message(
    active: Arc<Mutex<Option<ActiveRun>>>,
    request: ChatQueueRequest,
) -> Result<(), String> {
    queue_message(&active, request)
}

/// Cancels the active run in one workspace.
pub fn cancel_run(
    active: Arc<Mutex<Option<ActiveRun>>>,
    workspace: String,
    run_id: String,
) -> Result<(), String> {
    cancel_active_run(&active, &run_id, Some(&workspace))
}

/// Answers one permission gate and returns its committed run sequence.
pub fn answer_permission(
    active: Arc<Mutex<Option<ActiveRun>>>,
    workspace: String,
    run_id: String,
    gate_id: String,
    answer: ChatPermissionAnswer,
    timeout: Duration,
) -> Result<u64, String> {
    let resolved =
        queue_permission_answer_with_commit(&active, Some(&workspace), run_id, gate_id, answer)?;
    resolved
        .recv_timeout(timeout)
        .map_err(|_| "The permission answer did not commit in time.".to_string())?
        .ok_or_else(|| "The permission answer was rejected.".to_string())
}

/// Resumes one interrupted run through the dormant runtime service boundaries.
#[allow(clippy::too_many_arguments)]
pub fn resume_run(
    host: &RuntimeHost,
    profile_directory: impl AsRef<Path>,
    storage: SharedStorage,
    runtime: Arc<Mutex<Option<PiRuntime>>>,
    runtime_activity: &RuntimeActivityRegistry,
    config_directory: impl AsRef<Path>,
    run_id: String,
    access_token: String,
    subject: Option<String>,
    grant: ChatGrant,
    active: Arc<Mutex<Option<ActiveRun>>>,
    events: RuntimeChatEventTarget,
    pi_artifact: Option<PiArtifactDescriptor>,
) -> Result<(), String> {
    let profile_directory = profile_directory.as_ref();
    let profile = ChatProfile::new(profile_directory);
    let (resume, thread_id) = {
        let mut storage = storage
            .lock()
            .map_err(|_| "This reply cannot be resumed.".to_string())?;
        let events = storage
            .journal
            .events(&run_id)
            .map_err(|_| "This reply cannot be resumed.".to_string())?;
        let thread_id = storage
            .journal
            .run_thread_id(&run_id)
            .map_err(|_| "This reply cannot be resumed.".to_string())?
            .ok_or_else(|| "This reply cannot be resumed.".to_string())?;
        let resume = resumable_context(&events, subject.as_deref(), &profile.pi_session_root())
            .map_err(|_| "This reply cannot be resumed.".to_string())?;
        (resume, thread_id)
    };
    let memory_runtime = Arc::new(ApplicationMemoryRuntime::new(
        config_directory.as_ref().to_path_buf(),
        profile_directory.join("memory"),
    ));
    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(Mutex::new(None));
    let adapter = Arc::new(Mutex::new(None));
    let permission_answers = Arc::new(Mutex::new(VecDeque::new()));
    install_resume_run(
        &memory_runtime,
        &active,
        ActiveRun {
            id: run_id.clone(),
            workspace: grant.workspace.clone(),
            cancelled: Arc::clone(&cancelled),
            transport: Arc::clone(&transport),
            adapter: Arc::clone(&adapter),
            permission_answers: Arc::clone(&permission_answers),
            _activity: runtime_activity.mark_active_run(),
        },
        &thread_id,
        grant.minimum_cacheable_prefix_characters,
    )?;
    let (attempt, result) = std::sync::mpsc::channel();
    drive_resume(ResumeLaunch {
        sink: RuntimeChatEventSink::with_target(
            profile_directory,
            events,
            memory_runtime.clone(),
            thread_id,
            grant.workspace.clone(),
        )
        .with_host(host)
        .with_pi_artifact(pi_artifact.unwrap_or(PI_SELECTED_ARTIFACT)),
        storage,
        runtime,
        runtime_activity: runtime_activity.clone(),
        memory_runtime,
        active,
        run_id,
        tokens: TokenSet {
            access_token,
            refresh_token: None,
            expires_at: None,
            subject,
        },
        grant,
        cancelled,
        transport,
        adapter,
        permission_answers,
        resume,
        attempt,
    });
    result
        .recv()
        .map_err(|_| "This reply could not be resumed. Try again.".to_string())?
}
