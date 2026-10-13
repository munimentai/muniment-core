//! Runtime-owned companion attach listener.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

use muniment_core::attach::linux::{
    approval_waiter_with_claims, run_authenticated_session_with_service_approvals_and_registry,
    serve_desktop_client_session, ApprovalDecision, AttachAcceptError, AttachFilesystem,
    AttachTransport, InstanceLock, ThreadListService,
};
use muniment_core::attach::{
    admit_approval_presenter, admit_desktop_client, bounded_claim, name_attach_connection_route,
    serve_approval_presenter, ApprovalCoordinator, ApprovalPresenterConnection, ApprovalRequest,
    AttachConnectionRoute, CompanionRegistry, SignedWorkspaceApproval,
};
use muniment_core::process_reader::ProcReader;

const PRESENTER_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachListenerError {
    Filesystem,
    InstanceLock,
    Bind,
}

impl fmt::Display for AttachListenerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Filesystem => "runtime attach filesystem setup failed",
            Self::InstanceLock => "runtime attach instance lock could not be acquired",
            Self::Bind => "runtime attach endpoint bind failed",
        })
    }
}

impl std::error::Error for AttachListenerError {}

/// Shared state used by an attach listener.
pub struct AttachListenerInputs<'a> {
    pub companion_registry: &'a CompanionRegistry,
    pub approval: SignedWorkspaceApproval,
    pub approvals: ApprovalCoordinator,
    pub expected_desktop_executable: Option<PathBuf>,
}

/// Owns the profile endpoint and serves companion sessions until `stop` fires.
pub fn run_attach_listener<S, F, E>(
    profile_directory: impl AsRef<Path>,
    inputs: AttachListenerInputs<'_>,
    handoff_nonce: Option<String>,
    service_factory: F,
    stop: Receiver<()>,
) -> Result<(), AttachListenerError>
where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    let filesystem =
        AttachFilesystem::from_runtime_directory(profile_directory.as_ref().as_os_str())
            .map_err(|_| AttachListenerError::Filesystem)?;
    let _instance_lock = filesystem
        .acquire_instance_lock()
        .map_err(|_| AttachListenerError::InstanceLock)?;
    let transport = AttachTransport::bind(&filesystem).map_err(|_| AttachListenerError::Bind)?;
    run_bound_attach_listener(
        _instance_lock,
        transport,
        inputs,
        handoff_nonce,
        service_factory,
        stop,
    )
}

/// Serves companion sessions on an instance lock and transport owned by the caller.
pub fn run_bound_attach_listener<S, F, E>(
    _instance_lock: InstanceLock,
    transport: AttachTransport<'_>,
    inputs: AttachListenerInputs<'_>,
    handoff_nonce: Option<String>,
    service_factory: F,
    stop: Receiver<()>,
) -> Result<(), AttachListenerError>
where
    S: ThreadListService + Send + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    let stop_handle = transport.stop_handle();
    let finished = Arc::new(AtomicBool::new(false));
    let service_factory = Arc::new(service_factory);
    let live_connections = inputs.companion_registry.live_connections();
    let approval = inputs.approval;
    let approvals = inputs.approvals;
    let expected_desktop_executable = inputs.expected_desktop_executable;

    std::thread::scope(|scope| {
        let stop_finished = finished.clone();
        let stop_thread = scope.spawn(move || {
            while !stop_finished.load(Ordering::Acquire) {
                match stop.recv_timeout(Duration::from_millis(10)) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            stop_handle.stop();
        });
        let result = loop {
            let (stream, credentials) = match transport.accept() {
                Ok(accepted) => accepted,
                Err(AttachAcceptError::Closed) => break Ok(()),
                Err(AttachAcceptError::Accept) => {
                    muniment_core::runtime_eprintln!(
                        "muniment-runtime: attach accept failed route=unknown reason=Accept"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(
                    error @ (AttachAcceptError::PeerCredentials | AttachAcceptError::WrongUid(_)),
                ) => {
                    muniment_core::runtime_eprintln!(
                        "muniment-runtime: attach session refused route=unknown reason={error:?}"
                    );
                    continue;
                }
            };
            let service_factory = service_factory.clone();
            let approval = approval.clone();
            let approvals = approvals.clone();
            let live_connections = live_connections.clone();
            let handoff_nonce = handoff_nonce.clone();
            let expected_desktop_executable = expected_desktop_executable.clone();
            std::thread::spawn(move || {
                let route = expected_desktop_executable.as_ref().map_or(
                    AttachConnectionRoute::Companion,
                    |expected_desktop_executable| {
                        name_attach_connection_route(
                            &stream,
                            credentials,
                            expected_desktop_executable,
                            &ProcReader,
                            PRESENTER_ADMISSION_TIMEOUT,
                        )
                    },
                );
                if route == AttachConnectionRoute::Companion {
                    if let Some(expected) = &expected_desktop_executable {
                        let authority = u32::try_from(credentials.pid)
                            .map_err(|_| muniment_core::attach::PeerAuthorityError::PeerUnavailable)
                            .and_then(|pid| {
                                muniment_core::attach::verify_approval_presenter_peer(pid, expected)
                            });
                        if let Err(error) = authority {
                            muniment_core::runtime_eprintln!("muniment-runtime: desktop routes refused route={route:?} peer_pid={} expected_executable={expected:?} reason={error:?}", credentials.pid);
                        }
                    }
                }
                muniment_core::runtime_eprintln!(
                    "muniment-runtime: attach session routed route={route:?} peer_pid={}",
                    credentials.pid
                );
                match route {
                    AttachConnectionRoute::ApprovalPresenter => {
                        let expected_desktop_executable = expected_desktop_executable
                            .as_ref()
                            .expect("the approval presenter route has an expected executable");
                        let (stream, capability) = match admit_approval_presenter(
                            stream,
                            credentials,
                            expected_desktop_executable,
                            &ProcReader,
                            env!("CARGO_PKG_VERSION"),
                            PRESENTER_ADMISSION_TIMEOUT,
                        ) {
                            Ok(admitted) => admitted,
                            Err(error) => {
                                muniment_core::runtime_eprintln!("muniment-runtime: attach session refused route={route:?} reason={error:?}");
                                return;
                            }
                        };
                        let connection = ApprovalPresenterConnection::new(stream, capability);
                        let Some(session) = serve_approval_presenter(approvals, connection) else {
                            muniment_core::runtime_eprintln!("muniment-runtime: attach session closed route={route:?} reason=presenter unavailable");
                            return;
                        };
                        muniment_core::runtime_eprintln!("muniment-runtime: attach session accepted route={route:?} reason=peer authorized");
                        session.wait_until_closed();
                        muniment_core::runtime_eprintln!("muniment-runtime: attach session closed route={route:?} reason=presenter connection ended");
                        return;
                    }
                    AttachConnectionRoute::DesktopClient => {
                        let expected_desktop_executable = expected_desktop_executable
                            .as_ref()
                            .expect("the desktop client route has an expected executable");
                        let (stream, session) = match admit_desktop_client(
                            stream,
                            credentials,
                            expected_desktop_executable,
                            &ProcReader,
                            env!("CARGO_PKG_VERSION"),
                            approval.approval(),
                            PRESENTER_ADMISSION_TIMEOUT,
                        ) {
                            Ok(admitted) => admitted,
                            Err(error) => {
                                muniment_core::runtime_eprintln!("muniment-runtime: attach session refused route={route:?} reason={error:?}");
                                return;
                            }
                        };
                        muniment_core::runtime_eprintln!("muniment-runtime: attach session accepted route={route:?} reason=peer authorized");
                        let Ok(mut service) = service_factory() else {
                            muniment_core::runtime_eprintln!("muniment-runtime: attach session closed route={route:?} reason=service creation failed");
                            return;
                        };
                        let result = serve_desktop_client_session(stream, &session, &mut service);
                        muniment_core::runtime_eprintln!("muniment-runtime: attach session closed route={route:?} reason={result:?}");
                        return;
                    }
                    AttachConnectionRoute::Companion => {}
                }
                let Ok(mut service) = service_factory() else {
                    muniment_core::runtime_eprintln!("muniment-runtime: attach session closed route={route:?} reason=service creation failed");
                    return;
                };
                let waiter = approval_waiter_with_claims(
                    move |challenge: &muniment_core::attach::PairingChallenge,
                          kind: &str,
                          version: &str,
                          remaining: Duration| {
                        Some(request_approval(
                            &approval,
                            &approvals,
                            challenge.as_str(),
                            kind,
                            version,
                            remaining,
                        ))
                    },
                );
                let result = run_authenticated_session_with_service_approvals_and_registry(
                    stream,
                    credentials,
                    env!("CARGO_PKG_VERSION"),
                    &mut service,
                    waiter,
                    &live_connections,
                    handoff_nonce.as_deref(),
                );
                muniment_core::runtime_eprintln!(
                    "muniment-runtime: attach session closed route={route:?} reason={result:?}"
                );
            });
        };
        finished.store(true, Ordering::Release);
        stop_thread
            .join()
            .expect("attach stop thread does not panic");
        result
    })
}

fn request_approval(
    approval: &SignedWorkspaceApproval,
    approvals: &ApprovalCoordinator,
    challenge: &str,
    claimed_kind: &str,
    claimed_version: &str,
    remaining: Duration,
) -> ApprovalDecision {
    let Some(recorded) = approval.approval() else {
        return ApprovalDecision::Deny;
    };
    let approved = approvals.request(
        ApprovalRequest {
            challenge: challenge.to_owned(),
            claimed_kind: bounded_claim(claimed_kind),
            claimed_version: bounded_claim(claimed_version),
            workspace: recorded.workspace.clone(),
            scopes: recorded.scopes.clone(),
        },
        remaining,
    );
    if !approved {
        return ApprovalDecision::Deny;
    }
    match approval.approval() {
        Some(current) if current.workspace == recorded.workspace => {
            ApprovalDecision::Approve(current)
        }
        _ => ApprovalDecision::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn approval_request_bounds_untrusted_claims() {
        let approval = SignedWorkspaceApproval::default();
        approval.record("workspace-a".into());
        let approvals = ApprovalCoordinator::default();
        let (request_tx, request_rx) = mpsc::channel();
        approvals.register_presenter(move |request| {
            request_tx
                .send((
                    request.claimed_kind.clone(),
                    request.claimed_version.clone(),
                ))
                .unwrap();
            false
        });

        assert_eq!(
            request_approval(
                &approval,
                &approvals,
                "challenge",
                &"x".repeat(81),
                "1.0\nmalicious",
                Duration::from_secs(1),
            ),
            ApprovalDecision::Deny
        );

        let (claimed_kind, claimed_version) = request_rx.recv().unwrap();
        assert_eq!(claimed_kind, "unknown");
        assert_eq!(claimed_version, "unknown");
    }
}
