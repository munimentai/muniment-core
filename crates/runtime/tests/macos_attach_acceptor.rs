#![cfg(unix)]

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use muniment_core::attach::{
    approval_waiter_with_claims, bounded_claim, decode_frame,
    serve_macos_attach_session_with_reader_and_state, ApprovalDecision, ApprovalRequest,
    Authorized, DesktopAttachService, Event, EventName, MacosAttachRouteReader, MacosPeerReadError,
    ProtocolError, Welcome,
};
use muniment_runtime_core::{
    MacosAttachAcceptorWithBoundary, MacosAttachBindFailure, MacosAttachServeBoundary,
    RuntimeAttachBoundaries, RuntimeHost, WindowsAttachAcceptBoundary, WindowsAttachAcceptOutcome,
    WindowsAttachStopSignal,
};

mod common;
use common::TemporaryProfile;

type ServiceFactory = Arc<
    dyn Fn() -> Result<DesktopAttachService<RuntimeAttachBoundaries>, ProtocolError> + Send + Sync,
>;

#[derive(Clone)]
struct BlockingStopSignal(Arc<(Mutex<BlockingState>, Condvar)>);

struct BlockingState {
    waiting: bool,
    stopped: bool,
}

impl WindowsAttachStopSignal for BlockingStopSignal {
    fn signal(&self) {
        let (state, wake) = &*self.0;
        state.lock().unwrap().stopped = true;
        wake.notify_all();
    }
}

struct BlockingBoundary {
    state: Arc<(Mutex<BlockingState>, Condvar)>,
}

impl MacosAttachServeBoundary for BlockingBoundary {
    type StopSignal = BlockingStopSignal;

    fn stop_signal(&self) -> Self::StopSignal {
        BlockingStopSignal(Arc::clone(&self.state))
    }

    fn serve_next(&mut self, _service_factory: ServiceFactory) -> WindowsAttachAcceptOutcome {
        let (state, wake) = &*self.state;
        let mut state = state.lock().unwrap();
        state.waiting = true;
        wake.notify_all();
        while !state.stopped {
            state = wake.wait(state).unwrap();
        }
        WindowsAttachAcceptOutcome::Stopped
    }
}

#[test]
fn a_stop_signal_ends_a_pending_accept() {
    let profile = TemporaryProfile::new("macos-acceptor-stop", true);
    let state = Arc::new((
        Mutex::new(BlockingState {
            waiting: false,
            stopped: false,
        }),
        Condvar::new(),
    ));
    let boundary_state = Arc::clone(&state);
    let mut acceptor = MacosAttachAcceptorWithBoundary::bind_with(
        RuntimeHost::default(),
        &profile.profile,
        &profile.config,
        |_| {
            Ok(BlockingBoundary {
                state: boundary_state,
            })
        },
    )
    .unwrap();
    let stop = acceptor.stop_signal();
    let server = thread::spawn(move || acceptor.serve_next());

    let (state_lock, wake) = &*state;
    let mut state_guard = state_lock.lock().unwrap();
    while !state_guard.waiting {
        state_guard = wake.wait(state_guard).unwrap();
    }
    drop(state_guard);
    stop.signal();

    assert_eq!(server.join().unwrap(), WindowsAttachAcceptOutcome::Stopped);
}

struct StoppedBoundary;

impl MacosAttachServeBoundary for StoppedBoundary {
    type StopSignal = BlockingStopSignal;

    fn stop_signal(&self) -> Self::StopSignal {
        unreachable!()
    }

    fn serve_next(&mut self, _service_factory: ServiceFactory) -> WindowsAttachAcceptOutcome {
        WindowsAttachAcceptOutcome::Stopped
    }
}

#[test]
fn maps_a_live_endpoint_bind_to_contended() {
    let profile = TemporaryProfile::new("macos-acceptor-contended", true);
    let expected_path = profile.profile.join("muniment/attach-v1.sock");
    let result = MacosAttachAcceptorWithBoundary::<StoppedBoundary>::bind_with(
        RuntimeHost::default(),
        &profile.profile,
        &profile.config,
        |path| {
            assert_eq!(path, expected_path);
            Err(io::Error::from(io::ErrorKind::AddrInUse))
        },
    );

    assert!(matches!(result, Err(MacosAttachBindFailure::Contended)));
}

#[test]
fn distinguishes_a_socket_bind_failure_from_a_state_open_failure() {
    let profile = TemporaryProfile::new("macos-acceptor-bind-failed", true);
    let result = MacosAttachAcceptorWithBoundary::<StoppedBoundary>::bind_with(
        RuntimeHost::default(),
        &profile.profile,
        &profile.config,
        |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    );
    assert!(matches!(result, Err(MacosAttachBindFailure::Unavailable)));

    let blocked_profile = profile.root.join("blocked-profile");
    std::fs::write(&blocked_profile, "not a directory").unwrap();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct DropBoundary(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropBoundary {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let result = MacosAttachAcceptorWithBoundary::bind_with(
        RuntimeHost::default(),
        &blocked_profile,
        &profile.config,
        |_| Ok(DropBoundary(Arc::clone(&dropped))),
    );
    assert!(matches!(
        result,
        Err(MacosAttachBindFailure::StateOpenFailed)
    ));
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn retains_the_single_opened_activation_state() {
    let profile = TemporaryProfile::new("macos-acceptor-state", true);
    let acceptor = MacosAttachAcceptorWithBoundary::bind_with(
        RuntimeHost::default(),
        &profile.profile,
        &profile.config,
        |_| Ok(StoppedBoundary),
    )
    .unwrap();

    let first = acceptor.retention_state().unwrap();
    let second = acceptor.retention_state().unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    first.attach_service().unwrap();
}

struct CompanionRoute;

impl MacosAttachRouteReader for CompanionRoute {
    fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
        Ok((42, PathBuf::from("/Applications/Other.app/other")))
    }

    fn peer_code_matches(&self, _: &std::path::Path) -> bool {
        false
    }
}

struct SessionBoundary {
    server: Option<UnixStream>,
}

impl MacosAttachServeBoundary for SessionBoundary {
    type StopSignal = BlockingStopSignal;

    fn stop_signal(&self) -> Self::StopSignal {
        unreachable!()
    }

    fn serve_next(&mut self, service_factory: ServiceFactory) -> WindowsAttachAcceptOutcome {
        let mut service = service_factory().unwrap();
        let approval = service.boundaries.signed_workspace_approval();
        let coordinator = service.boundaries.approval_coordinator();
        let live_connections = service.boundaries.live_connections();
        let waiter_approval = approval.clone();
        let waiter_coordinator = coordinator.clone();
        let waiter = approval_waiter_with_claims(
            move |challenge: &muniment_core::attach::PairingChallenge,
                  kind: &str,
                  version: &str,
                  remaining: Duration| {
                let recorded = waiter_approval.approval()?;
                let approved = waiter_coordinator.request(
                    ApprovalRequest {
                        challenge: challenge.as_str().to_owned(),
                        claimed_kind: bounded_claim(kind),
                        claimed_version: bounded_claim(version),
                        workspace: recorded.workspace.clone(),
                        scopes: recorded.scopes.clone(),
                    },
                    remaining,
                );
                approved.then_some(ApprovalDecision::Approve(recorded))
            },
        );
        serve_macos_attach_session_with_reader_and_state(
            self.server.take().unwrap(),
            &CompanionRoute,
            501,
            Path::new("/Applications/Muniment.app/muniment"),
            env!("CARGO_PKG_VERSION"),
            Duration::from_secs(1),
            &mut service,
            approval.approval(),
            coordinator,
            waiter,
            &live_connections,
            |_| {},
        )
        .unwrap();
        WindowsAttachAcceptOutcome::Served
    }
}

fn hello_frame() -> Vec<u8> {
    let body = br#"{"protocol":"muniment.attach/1","client":{"kind":"editor-extension","version":"0.0.1"},"supported":{"min":1,"max":1},"client_nonce":"nonce","authorized_client_id":"018f0000-0000-7000-8000-000000000099"}"#;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

struct PairingBoundary {
    server: Option<UnixStream>,
    ready: std::sync::mpsc::Sender<()>,
}

impl MacosAttachServeBoundary for PairingBoundary {
    type StopSignal = BlockingStopSignal;

    fn stop_signal(&self) -> Self::StopSignal {
        unreachable!()
    }

    fn serve_next(&mut self, service_factory: ServiceFactory) -> WindowsAttachAcceptOutcome {
        let mut service = service_factory().unwrap();
        self.ready.send(()).unwrap();
        let approval = service.boundaries.signed_workspace_approval();
        let coordinator = service.boundaries.approval_coordinator();
        let live_connections = service.boundaries.live_connections();
        let waiter_approval = approval.clone();
        let waiter_coordinator = coordinator.clone();
        let waiter = approval_waiter_with_claims(
            move |challenge: &muniment_core::attach::PairingChallenge,
                  kind: &str,
                  version: &str,
                  remaining: Duration| {
                let recorded = waiter_approval.approval()?;
                let approved = waiter_coordinator.request(
                    ApprovalRequest {
                        challenge: challenge.as_str().to_owned(),
                        claimed_kind: bounded_claim(kind),
                        claimed_version: bounded_claim(version),
                        workspace: recorded.workspace.clone(),
                        scopes: recorded.scopes.clone(),
                    },
                    remaining,
                );
                approved.then_some(ApprovalDecision::Approve(recorded))
            },
        );
        serve_macos_attach_session_with_reader_and_state(
            self.server.take().unwrap(),
            &CompanionRoute,
            501,
            Path::new("/Applications/Muniment.app/muniment"),
            env!("CARGO_PKG_VERSION"),
            Duration::from_secs(1),
            &mut service,
            approval.approval(),
            coordinator,
            waiter,
            &live_connections,
            |_| {},
        )
        .unwrap();
        WindowsAttachAcceptOutcome::Served
    }
}

#[test]
fn companion_pairing_uses_the_activation_presenter_and_live_registry() {
    let profile = TemporaryProfile::new("macos-acceptor-pairing", true);
    // Local mode gives the approval a subject without a signed-in session.
    std::fs::write(
        profile
            .config
            .join(muniment_core::local_mode::LOCAL_MODE_MARKER),
        [],
    )
    .unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut acceptor = MacosAttachAcceptorWithBoundary::bind_with(
        RuntimeHost::default(),
        &profile.profile,
        &profile.config,
        |_| {
            Ok(PairingBoundary {
                server: Some(server),
                ready: ready_tx,
            })
        },
    )
    .unwrap();
    let state = acceptor.retention_state().unwrap();
    state
        .signed_workspace_approval()
        .record("workspace-a".into());
    let coordinator = state.boundaries().approval_coordinator();
    let decider = coordinator.clone();
    coordinator.register_presenter(move |request| decider.decide(&request.challenge, true));
    let server_thread = thread::spawn(move || acceptor.serve_next());

    client.write_all(&hello_frame()).unwrap();
    // Keep service setup outside the socket read timeout.
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let _: Welcome = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
    let authorized: Authorized = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
    state
        .companion_registry()
        .revoke("018f0000-0000-7000-8000-000000000099")
        .unwrap();

    assert!(!authorized.authorized_client_credential.is_empty());
    let event: Event = decode_frame(&read_frame(&mut client)).unwrap().unwrap().0;
    assert_eq!(event.event, EventName::CapabilityRevoked);
    assert_eq!(event.body["capability"], authorized.capability);
    assert_eq!(event.body["reason"], "companion_revoked");
    assert_eq!(
        server_thread.join().unwrap(),
        WindowsAttachAcceptOutcome::Served
    );
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    frame
}

#[test]
fn serves_a_session_with_the_composed_runtime_service() {
    let profile = TemporaryProfile::new("macos-acceptor-service", true);
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&hello_frame()).unwrap();
    let mut acceptor = MacosAttachAcceptorWithBoundary::bind_with(
        RuntimeHost::default(),
        &profile.profile,
        &profile.config,
        |_| {
            Ok(SessionBoundary {
                server: Some(server),
            })
        },
    )
    .unwrap();

    assert_eq!(acceptor.serve_next(), WindowsAttachAcceptOutcome::Served);
    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; 4 + length];
    response[..4].copy_from_slice(&prefix);
    client.read_exact(&mut response[4..]).unwrap();
    let welcome = decode_frame::<Welcome>(&response).unwrap().unwrap().0;
    assert_eq!(welcome.desktop_version, env!("CARGO_PKG_VERSION"));
    assert!(profile.profile.join("attach-idempotency.sqlite3").is_file());
}
