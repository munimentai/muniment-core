use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::attach::linux::{ThreadListPage, ThreadListRequest, ThreadOpenPage, ThreadOpenRequest};
#[cfg(target_os = "linux")]
use crate::attach::ProtocolError;
use crate::attach::RuntimeActivityGuard;
use crate::auth::TokenSet;
use crate::chat_grant::ChatGrant;
use crate::chat_view::{ChatAttachment, SelectedFile};
use crate::journal::reducer::ChatProjector;
use crate::journal::Provenance;
use crate::permission_gate::{ChatPermissionAnswer, PendingPermissionAnswer};
use crate::sidecar::pi_chat::PiRunAdapter;
use crate::sidecar::PiRpcTransport;

/// Returns the timestamp used when a run is accepted.
pub fn accepted_time_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitResult {
    pub run_id: String,
    pub attachments: Vec<ChatAttachment>,
    #[serde(skip)]
    pub committed_seq: u64,
    #[serde(skip)]
    pub accepted_at: String,
}

pub struct ActiveRun {
    pub id: String,
    pub workspace: String,
    pub cancelled: Arc<AtomicBool>,
    pub transport: Arc<Mutex<Option<Arc<PiRpcTransport>>>>,
    pub adapter: Arc<Mutex<Option<Arc<PiRunAdapter>>>>,
    pub permission_answers: Arc<Mutex<VecDeque<PendingPermissionAnswer>>>,
    pub _activity: RuntimeActivityGuard,
}

pub struct RunStartRequest {
    pub prompt: String,
    pub files: Vec<SelectedFile>,
    pub workspace: Option<String>,
    pub provenance: Option<Provenance>,
    pub thread_id: Option<String>,
}

pub struct RunStartLaunch {
    pub run_id: String,
    pub prompt: String,
    pub tokens: TokenSet,
    pub grant: ChatGrant,
    pub cancelled: Arc<AtomicBool>,
    pub transport: Arc<Mutex<Option<Arc<PiRpcTransport>>>>,
    pub adapter: Arc<Mutex<Option<Arc<PiRunAdapter>>>>,
    pub permission_answers: Arc<Mutex<VecDeque<PendingPermissionAnswer>>>,
    pub prepared: (u64, ChatProjector),
}

pub trait RunAttachBoundaries {
    #[cfg(target_os = "linux")]
    fn session_status(&self) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn entitlement_snapshot(
        &self,
    ) -> Result<crate::attach::linux::EntitlementSnapshotResult, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn sign_in(&self, _provenance: Provenance) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn sign_out(&self, _provenance: Provenance) -> Result<crate::auth::AuthStatus, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn list_devices(&self) -> Result<crate::auth::NativeDeviceList, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn list_companions(&self) -> Result<Vec<crate::attach::CompanionRecord>, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn revoke_companion(&self, _client_identity: &str) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn list_threads(
        &self,
        workspace: &str,
        request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError>;
    #[cfg(target_os = "linux")]
    fn open_thread(
        &self,
        workspace: &str,
        request: ThreadOpenRequest,
    ) -> Result<ThreadOpenPage, ProtocolError>;
    #[cfg(target_os = "linux")]
    fn thread_summaries(
        &self,
        _request: ThreadListRequest,
    ) -> Result<crate::journal::thread_summaries::ThreadSummaryPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(all(target_os = "linux", feature = "keyring"))]
    fn thread_history(
        &self,
        _request: ThreadOpenRequest,
    ) -> Result<crate::thread_history::ChatThreadOpenPage, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn create_thread(
        &self,
        _workspace: &str,
        _provenance: Provenance,
    ) -> Result<String, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn rename_thread(
        &self,
        _thread_id: &str,
        _title: &str,
        _provenance: Provenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn delete_thread(
        &self,
        _thread_id: &str,
        _provenance: Provenance,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn stream_run(
        &self,
        workspace: &str,
        run_id: &str,
        after_run_seq: u64,
    ) -> Result<crate::attach::linux::RunStreamPage, ProtocolError>;
    #[cfg(target_os = "linux")]
    fn subscribe_run_commits(
        &self,
        run_id: &str,
    ) -> Result<crate::journal::CommitSubscription, ProtocolError>;
    #[cfg(target_os = "linux")]
    fn subscribe_chat_events(
        &self,
    ) -> Result<std::sync::mpsc::Receiver<crate::run_events::ChatEvent>, ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    #[cfg(target_os = "linux")]
    fn queue_attach_permission_answer(
        &self,
        workspace: &str,
        run_id: &str,
        gate_id: &str,
        answer: ChatPermissionAnswer,
    ) -> Result<std::sync::mpsc::Receiver<Option<u64>>, RunStartError>;
}

pub trait RunStartBoundaries {
    fn mark_active_run(&self) -> RuntimeActivityGuard;

    fn active_run_exists(&self) -> bool;
    fn fresh_tokens(&self) -> Result<TokenSet, RunStartError>;
    fn configure_run(
        &self,
        run_id: &str,
        prompt: &str,
        tokens: &TokenSet,
        requested_workspace: Option<&str>,
    ) -> Result<ChatGrant, RunStartError>;
    #[cfg(target_os = "linux")]
    fn attach_approval(&self) -> Option<crate::attach::Approval> {
        None
    }
    #[cfg(target_os = "linux")]
    fn control_migration(
        &self,
        _request: crate::attach::linux::MigrationControlRequest,
        _peer_pid: u32,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::unsupported_operation())
    }
    fn install_active_run(&self, run: ActiveRun) -> Result<(), RunStartError>;
    #[allow(clippy::too_many_arguments)]
    fn prepare_run(
        &self,
        run_id: &str,
        prompt: &str,
        grant: &ChatGrant,
        tokens: &TokenSet,
        files: Vec<SelectedFile>,
        provenance: Option<Provenance>,
        thread_id: Option<&str>,
    ) -> Result<(u64, ChatProjector), RunStartError>;
    fn project_attachments(
        &self,
        projector: &ChatProjector,
    ) -> Result<Vec<ChatAttachment>, RunStartError>;
    fn run_thread_id(&self, run_id: &str) -> Result<String, RunStartError>;
    fn open_memory_session(
        &self,
        run_id: &str,
        thread_id: &str,
        minimum_cacheable_prefix_characters: usize,
    ) -> Result<(), RunStartError>;
    fn close_memory_session(&self, run_id: &str);
    fn fail_prepared_run(&self, launch: &RunStartLaunch) -> Result<(), RunStartError>;
    fn cancel_run(&self, workspace: &str, run_id: &str) -> Result<(), RunStartError>;
    fn clear_active_run(&self, run_id: &str);
    fn launch(&self, launch: RunStartLaunch);
}

#[derive(Debug)]
pub enum RunStartError {
    Unauthorized(String),
    InvalidRequest(String),
    ThreadNotFound,
    Persistence(String),
}

impl RunStartError {
    #[cfg(target_os = "linux")]
    pub fn protocol_error(&self) -> ProtocolError {
        match self {
            Self::Unauthorized(_) => ProtocolError::unauthorized(),
            Self::InvalidRequest(_) => ProtocolError::invalid_request(),
            Self::ThreadNotFound => ProtocolError::thread_not_found(),
            Self::Persistence(_) => ProtocolError::persistence_failed(),
        }
    }

    pub fn into_message(self) -> String {
        match self {
            Self::Unauthorized(message)
            | Self::InvalidRequest(message)
            | Self::Persistence(message) => message,
            Self::ThreadNotFound => "The thread was not found.".into(),
        }
    }
}

/// Shared, channel-neutral acceptance path for starting a desktop-owned run.
/// Channel adapters supply boundaries but cannot bypass validation or ownership.
pub fn start_desktop_run(
    boundaries: &impl RunStartBoundaries,
    request: RunStartRequest,
) -> Result<SubmitResult, RunStartError> {
    let (result, launch) = prepare_desktop_run(boundaries, request)?;
    boundaries.launch(launch);
    Ok(result)
}

pub fn prepare_desktop_run(
    boundaries: &impl RunStartBoundaries,
    request: RunStartRequest,
) -> Result<(SubmitResult, RunStartLaunch), RunStartError> {
    let prompt = request.prompt.trim().to_owned();
    if prompt.is_empty() {
        return Err(RunStartError::InvalidRequest(
            "Enter a message before sending.".into(),
        ));
    }
    if boundaries.active_run_exists() {
        return Err(RunStartError::InvalidRequest(
            "A reply is already in progress.".into(),
        ));
    }

    let tokens = boundaries.fresh_tokens()?;
    let run_id = Uuid::now_v7().to_string();
    let grant =
        boundaries.configure_run(&run_id, &prompt, &tokens, request.workspace.as_deref())?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(Mutex::new(None));
    let adapter = Arc::new(Mutex::new(None));
    let permission_answers = Arc::new(Mutex::new(VecDeque::new()));
    if let Err(error) = boundaries.install_active_run(ActiveRun {
        id: run_id.clone(),
        workspace: grant.workspace.clone(),
        cancelled: Arc::clone(&cancelled),
        transport: Arc::clone(&transport),
        adapter: Arc::clone(&adapter),
        permission_answers: Arc::clone(&permission_answers),
        _activity: boundaries.mark_active_run(),
    }) {
        boundaries.clear_active_run(&run_id);
        return Err(error);
    }
    let prepared = match boundaries.prepare_run(
        &run_id,
        &prompt,
        &grant,
        &tokens,
        request.files,
        request.provenance,
        request.thread_id.as_deref(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            boundaries.clear_active_run(&run_id);
            return Err(error);
        }
    };
    let thread_id = match boundaries.run_thread_id(&run_id) {
        Ok(thread_id) => thread_id,
        Err(error) => {
            let failed_launch = RunStartLaunch {
                run_id: run_id.clone(),
                prompt,
                tokens,
                grant,
                cancelled,
                transport,
                adapter,
                permission_answers,
                prepared,
            };
            let _ = boundaries.fail_prepared_run(&failed_launch);
            boundaries.clear_active_run(&run_id);
            return Err(error);
        }
    };
    if let Err(error) = boundaries.open_memory_session(
        &run_id,
        &thread_id,
        grant.minimum_cacheable_prefix_characters,
    ) {
        let failed_launch = RunStartLaunch {
            run_id: run_id.clone(),
            prompt,
            tokens,
            grant,
            cancelled,
            transport,
            adapter,
            permission_answers,
            prepared,
        };
        let _ = boundaries.fail_prepared_run(&failed_launch);
        boundaries.clear_active_run(&run_id);
        return Err(error);
    }
    let attachments = match boundaries.project_attachments(&prepared.1) {
        Ok(attachments) => attachments,
        Err(error) => {
            let failed_launch = RunStartLaunch {
                run_id: run_id.clone(),
                prompt,
                tokens,
                grant,
                cancelled,
                transport,
                adapter,
                permission_answers,
                prepared,
            };
            let _ = boundaries.fail_prepared_run(&failed_launch);
            boundaries.close_memory_session(&run_id);
            boundaries.clear_active_run(&run_id);
            return Err(error);
        }
    };
    let result = SubmitResult {
        run_id: run_id.clone(),
        attachments,
        committed_seq: prepared.0,
        accepted_at: accepted_time_now(),
    };
    let launch = RunStartLaunch {
        run_id,
        prompt,
        tokens,
        grant,
        cancelled,
        transport,
        adapter,
        permission_answers,
        prepared,
    };
    Ok((result, launch))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::attach::RuntimeActivityRegistry;

    use super::*;

    struct FakeRunStartBoundaries {
        active: bool,
        attachment_error: Option<String>,
        memory_error: Option<String>,
        thread_id_error: Option<String>,
        auth_calls: AtomicUsize,
        clear_calls: AtomicUsize,
        close_calls: AtomicUsize,
        fail_calls: AtomicUsize,
        launch_calls: AtomicUsize,
        launched_run: Mutex<Option<String>>,
        runtime_activity: RuntimeActivityRegistry,
    }

    impl FakeRunStartBoundaries {
        fn accepting() -> Self {
            Self {
                active: false,
                attachment_error: None,
                memory_error: None,
                thread_id_error: None,
                auth_calls: AtomicUsize::new(0),
                clear_calls: AtomicUsize::new(0),
                close_calls: AtomicUsize::new(0),
                fail_calls: AtomicUsize::new(0),
                launch_calls: AtomicUsize::new(0),
                launched_run: Mutex::new(None),
                runtime_activity: RuntimeActivityRegistry::new(),
            }
        }
    }

    impl RunAttachBoundaries for FakeRunStartBoundaries {
        #[cfg(target_os = "linux")]
        fn list_threads(
            &self,
            _workspace: &str,
            _request: ThreadListRequest,
        ) -> Result<ThreadListPage, ProtocolError> {
            unreachable!()
        }

        #[cfg(target_os = "linux")]
        fn open_thread(
            &self,
            _workspace: &str,
            _request: ThreadOpenRequest,
        ) -> Result<ThreadOpenPage, ProtocolError> {
            unreachable!()
        }

        #[cfg(target_os = "linux")]
        fn stream_run(
            &self,
            _workspace: &str,
            _run_id: &str,
            _after_run_seq: u64,
        ) -> Result<crate::attach::linux::RunStreamPage, ProtocolError> {
            unreachable!()
        }

        #[cfg(target_os = "linux")]
        fn subscribe_run_commits(
            &self,
            _run_id: &str,
        ) -> Result<crate::journal::CommitSubscription, ProtocolError> {
            unreachable!()
        }

        #[cfg(target_os = "linux")]
        fn queue_attach_permission_answer(
            &self,
            _workspace: &str,
            _run_id: &str,
            _gate_id: &str,
            _answer: ChatPermissionAnswer,
        ) -> Result<std::sync::mpsc::Receiver<Option<u64>>, RunStartError> {
            unreachable!()
        }
    }

    impl RunStartBoundaries for FakeRunStartBoundaries {
        fn mark_active_run(&self) -> RuntimeActivityGuard {
            self.runtime_activity.mark_active_run()
        }

        fn active_run_exists(&self) -> bool {
            self.active
        }

        fn fresh_tokens(&self) -> Result<TokenSet, RunStartError> {
            self.auth_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TokenSet {
                access_token: "access-token".into(),
                refresh_token: None,
                expires_at: None,
                subject: Some("owner".into()),
            })
        }

        fn configure_run(
            &self,
            _run_id: &str,
            _prompt: &str,
            _tokens: &TokenSet,
            _requested_workspace: Option<&str>,
        ) -> Result<ChatGrant, RunStartError> {
            Ok(ChatGrant {
                workspace: "workspace-a".into(),
                gateway_url: "https://gateway.invalid".into(),
                virtual_key: "virtual-key".into(),
                model: None,
                minimum_cacheable_prefix_characters: 8_192,
                receipt_url: "https://receipt.invalid".into(),
            })
        }

        fn install_active_run(&self, _run: ActiveRun) -> Result<(), RunStartError> {
            Ok(())
        }

        fn prepare_run(
            &self,
            _run_id: &str,
            _prompt: &str,
            _grant: &ChatGrant,
            _tokens: &TokenSet,
            _files: Vec<SelectedFile>,
            _provenance: Option<Provenance>,
            _thread_id: Option<&str>,
        ) -> Result<(u64, ChatProjector), RunStartError> {
            Ok((1, ChatProjector::new()))
        }

        fn project_attachments(
            &self,
            _projector: &ChatProjector,
        ) -> Result<Vec<ChatAttachment>, RunStartError> {
            self.attachment_error.as_ref().map_or_else(
                || Ok(Vec::new()),
                |error| Err(RunStartError::Persistence(error.clone())),
            )
        }

        fn run_thread_id(&self, _run_id: &str) -> Result<String, RunStartError> {
            self.thread_id_error.as_ref().map_or_else(
                || Ok("thread-a".into()),
                |error| Err(RunStartError::Persistence(error.clone())),
            )
        }

        fn open_memory_session(
            &self,
            _run_id: &str,
            _thread_id: &str,
            _minimum_cacheable_prefix_characters: usize,
        ) -> Result<(), RunStartError> {
            self.memory_error.as_ref().map_or_else(
                || Ok(()),
                |error| Err(RunStartError::Persistence(error.clone())),
            )
        }

        fn close_memory_session(&self, _run_id: &str) {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn fail_prepared_run(&self, _launch: &RunStartLaunch) -> Result<(), RunStartError> {
            self.fail_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn cancel_run(&self, _workspace: &str, _run_id: &str) -> Result<(), RunStartError> {
            Ok(())
        }

        fn clear_active_run(&self, _run_id: &str) {
            self.clear_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn launch(&self, launch: RunStartLaunch) {
            self.launch_calls.fetch_add(1, Ordering::SeqCst);
            *self.launched_run.lock().unwrap() = Some(launch.run_id);
        }
    }

    fn request() -> RunStartRequest {
        RunStartRequest {
            prompt: "hello".into(),
            files: Vec::new(),
            workspace: None,
            provenance: None,
            thread_id: None,
        }
    }

    #[test]
    fn run_start_coordinator_accepts_through_injected_boundaries() {
        let boundaries = FakeRunStartBoundaries::accepting();

        let result = start_desktop_run(&boundaries, request()).unwrap();

        assert_eq!(boundaries.auth_calls.load(Ordering::SeqCst), 1);
        assert!(result.attachments.is_empty());
        assert_eq!(
            boundaries.launched_run.lock().unwrap().as_deref(),
            Some(result.run_id.as_str())
        );
    }

    #[test]
    fn run_start_coordinator_rejects_when_another_run_is_active() {
        let boundaries = FakeRunStartBoundaries {
            active: true,
            ..FakeRunStartBoundaries::accepting()
        };

        let error = start_desktop_run(&boundaries, request()).err().unwrap();

        assert_eq!(error.into_message(), "A reply is already in progress.");
        assert_eq!(boundaries.auth_calls.load(Ordering::SeqCst), 0);
        assert!(boundaries.launched_run.lock().unwrap().is_none());
    }

    #[test]
    fn memory_session_failure_marks_the_prepared_run_failed() {
        let boundaries = FakeRunStartBoundaries {
            memory_error: Some("memory unavailable".into()),
            ..FakeRunStartBoundaries::accepting()
        };

        let error = start_desktop_run(&boundaries, request()).err().unwrap();

        assert_eq!(error.into_message(), "memory unavailable");
        assert_eq!(boundaries.fail_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.clear_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.launch_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn attachment_projection_failure_marks_the_prepared_run_failed() {
        let boundaries = FakeRunStartBoundaries {
            attachment_error: Some("attachment projection unavailable".into()),
            ..FakeRunStartBoundaries::accepting()
        };

        let error = start_desktop_run(&boundaries, request()).err().unwrap();

        assert_eq!(error.into_message(), "attachment projection unavailable");
        assert_eq!(boundaries.fail_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.clear_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.launch_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn thread_id_failure_marks_the_prepared_run_failed() {
        let boundaries = FakeRunStartBoundaries {
            thread_id_error: Some("thread lookup unavailable".into()),
            ..FakeRunStartBoundaries::accepting()
        };

        let error = start_desktop_run(&boundaries, request()).err().unwrap();

        assert_eq!(error.into_message(), "thread lookup unavailable");
        assert_eq!(boundaries.fail_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.clear_calls.load(Ordering::SeqCst), 1);
        assert_eq!(boundaries.launch_calls.load(Ordering::SeqCst), 0);
    }
}
