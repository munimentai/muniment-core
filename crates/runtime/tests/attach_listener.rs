#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use muniment_attach::{
    connect_desktop_client_at, encode_frame, handshake as companion_handshake, handshake_stream,
    serve_approval_presenter_at, ApprovalDecision as PresenterDecision, ApprovalPresentRequest,
    ApprovalPresenterStopHandle, Client, Hello, Id, Protocol, VersionRange,
};
use muniment_core::attach::linux::{
    AttachFilesystem, LiveConnectionRegistry, ThreadListPage, ThreadListRequest, ThreadListService,
};
use muniment_core::attach::{
    probe_handoff, ApprovalCoordinator, ApprovalRequest, CompanionRegistry, HandoffProbeError,
    ProtocolError, SignedWorkspaceApproval,
};
use muniment_runtime_core::{run_attach_listener, AttachListenerInputs};

mod common;
use common::TemporaryProfile;

#[derive(Default)]
struct TestService;

impl ThreadListService for TestService {
    fn list_threads(
        &mut self,
        workspace: &str,
        _request: ThreadListRequest,
    ) -> Result<ThreadListPage, ProtocolError> {
        assert_eq!(workspace, "workspace-a");
        Ok(ThreadListPage {
            threads: Vec::new(),
            next_cursor: None,
        })
    }
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    frame
}

fn read_frame_text(stream: &mut UnixStream) -> String {
    String::from_utf8(read_frame(stream)[4..].to_vec()).unwrap()
}

fn handshake(
    approvals: ApprovalCoordinator,
    handoff_nonce: Option<String>,
    expected_desktop_executable: Option<std::path::PathBuf>,
) -> bool {
    let profile = TemporaryProfile::new("attach-listener", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    drop(filesystem);
    let approval = SignedWorkspaceApproval::default();
    approval.record("workspace-a".into());
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        profile.profile.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    let (stop_tx, stop_rx) = mpsc::channel();

    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            run_attach_listener(
                &profile.root,
                AttachListenerInputs {
                    companion_registry: &registry,
                    approval,
                    approvals,
                    expected_desktop_executable,
                },
                handoff_nonce,
                || Ok::<_, ()>(TestService),
                stop_rx,
            )
            .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let stream = loop {
            match UnixStream::connect(&endpoint) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("attach listener did not start: {error}"),
            }
        };
        let result = handshake_stream(
            stream,
            "1.0.0",
            Duration::from_secs(1),
            Duration::from_secs(1),
            || {},
        )
        .is_ok();
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
        result
    })
}

fn probe(handoff_nonce: Option<String>) -> Result<(), HandoffProbeError> {
    let profile = TemporaryProfile::new("attach-listener-probe", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    drop(filesystem);
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        profile.profile.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    let (stop_tx, stop_rx) = mpsc::channel();

    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            run_attach_listener(
                &profile.root,
                AttachListenerInputs {
                    companion_registry: &registry,
                    approval: SignedWorkspaceApproval::default(),
                    approvals: ApprovalCoordinator::default(),
                    expected_desktop_executable: std::env::current_exe().ok(),
                },
                handoff_nonce,
                || Ok::<_, ()>(TestService),
                stop_rx,
            )
            .unwrap()
        });
        let result = probe_handoff(
            &endpoint,
            "prepared-nonce",
            Instant::now() + Duration::from_secs(2),
        )
        .map(|_| ());
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
        result
    })
}

#[test]
fn probe_confirms_the_prepared_handoff_nonce() {
    assert_eq!(probe(Some("prepared-nonce".into())), Ok(()));
}

#[test]
fn probe_rejects_a_welcome_without_a_handoff_nonce() {
    assert_eq!(probe(None), Err(HandoffProbeError::MissingNonce));
}

#[test]
fn handshake_gets_no_grant_without_a_presenter() {
    assert!(!handshake(
        ApprovalCoordinator::default(),
        None,
        std::env::current_exe().ok(),
    ));
}

#[test]
fn handshake_gets_a_grant_when_the_presenter_approves() {
    let approvals = ApprovalCoordinator::default();
    let decisions = approvals.clone();
    approvals.register_presenter(move |request| {
        let decisions = decisions.clone();
        let challenge = request.challenge.clone();
        thread::spawn(move || {
            decisions.decide(&challenge, true);
        });
        true
    });

    assert!(handshake(
        approvals,
        Some("prepared-nonce".into()),
        std::env::current_exe().ok(),
    ));
}

#[test]
fn handshake_gets_a_grant_without_an_expected_desktop_executable() {
    let approvals = ApprovalCoordinator::default();
    let decisions = approvals.clone();
    approvals.register_presenter(move |request| {
        let decisions = decisions.clone();
        let challenge = request.challenge.clone();
        thread::spawn(move || {
            decisions.decide(&challenge, true);
        });
        true
    });

    assert!(handshake(approvals, Some("prepared-nonce".into()), None));
}

#[test]
fn desktop_client_lists_threads_without_a_presenter() {
    let profile = TemporaryProfile::new("attach-listener-desktop-client", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    drop(filesystem);
    let approval = SignedWorkspaceApproval::default();
    approval.record("workspace-a".into());
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        profile.profile.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    let (stop_tx, stop_rx) = mpsc::channel();

    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            run_attach_listener(
                &profile.root,
                AttachListenerInputs {
                    companion_registry: &registry,
                    approval,
                    approvals: ApprovalCoordinator::default(),
                    expected_desktop_executable: Some(std::env::current_exe().unwrap()),
                },
                None,
                || Ok::<_, ()>(TestService),
                stop_rx,
            )
            .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match UnixStream::connect(&endpoint) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("attach listener did not start: {error}"),
            }
        };
        stream
            .write_all(
                &encode_frame(&Hello {
                    protocol: Protocol,
                    client: Client {
                        kind: "desktop-client".into(),
                        version: "1.0.0".into(),
                    },
                    supported: VersionRange { min: 1, max: 1 },
                    client_nonce: "client-nonce".into(),
                    authorized_client_id: Id::new("018f0000-0000-7000-8000-000000000124").unwrap(),
                    authorized_client_credential: None,
                })
                .unwrap(),
            )
            .unwrap();
        let welcome = read_frame_text(&mut stream);
        assert!(welcome.contains("\"selected\":1"));
        let grant = read_frame_text(&mut stream);
        let capability_key = "\"capability\":\"";
        let capability_start = grant.find(capability_key).unwrap() + capability_key.len();
        let capability_end = grant[capability_start..].find('"').unwrap() + capability_start;
        let request = format!(
            "{{\"protocol\":\"muniment.attach/1\",\"request_id\":\"018f0000-0000-7000-8000-000000000125\",\"operation\":\"thread.list\",\"capability\":\"{}\",\"body\":{{\"limit\":20}}}}",
            &grant[capability_start..capability_end]
        );
        stream
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let response = read_frame_text(&mut stream);
        assert!(response.contains("\"ok\":true"));
        assert!(response.contains("\"threads\":[]"));

        drop(stream);
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
    });
}

#[test]
fn desktop_client_without_a_workspace_receives_an_empty_workspace_grant() {
    let profile = TemporaryProfile::new("attach-listener-desktop-client-refusal", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    drop(filesystem);
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        profile.profile.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    let (stop_tx, stop_rx) = mpsc::channel();

    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            run_attach_listener(
                &profile.root,
                AttachListenerInputs {
                    companion_registry: &registry,
                    approval: SignedWorkspaceApproval::default(),
                    approvals: ApprovalCoordinator::default(),
                    expected_desktop_executable: Some(std::env::current_exe().unwrap()),
                },
                None,
                || Ok::<_, ()>(TestService),
                stop_rx,
            )
            .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = loop {
            match connect_desktop_client_at(&endpoint, "1.0.0", Duration::from_secs(1)) {
                Ok(client) => break client,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("attach listener did not start: {error}"),
            }
        };
        assert!(client.workspace_scopes().is_empty());

        drop(client);
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
    });
}

#[test]
fn installed_desktop_child() {
    let Some(endpoint) = std::env::var_os("MUNIMENT_TEST_INSTALLED_ENDPOINT") else {
        return;
    };
    let endpoint = std::path::Path::new(&endpoint);
    let expected = std::env::var("MUNIMENT_TEST_EXPECT_CONNECTED").unwrap() == "true";
    let client = connect_desktop_client_at(endpoint, "1.0.0", Duration::from_secs(2));
    assert_eq!(client.is_ok(), expected, "desktop connection: {client:?}");
    if expected {
        assert!(client.unwrap().workspace_scopes().is_empty());
        let mut events =
            connect_desktop_client_at(endpoint, "1.0.0", Duration::from_secs(2)).unwrap();
        events.subscribe_chat_events().unwrap();
        let _presenter = muniment_attach::connect_approval_presenter_at(
            endpoint,
            "1.0.0",
            Duration::from_secs(2),
        )
        .unwrap();
    }
}

#[test]
fn installed_payload_connects_on_first_launch_but_replaced_alias_is_refused() {
    use std::process::Command;

    struct EventService;
    impl ThreadListService for EventService {
        fn subscribe_chat_events(
            &mut self,
        ) -> Result<muniment_core::run_events::ChatEventSubscription, ProtocolError> {
            let (sender, receiver) = mpsc::channel();
            Ok(muniment_core::run_events::ChatEventSubscription::new(
                receiver,
                move || drop(sender),
            ))
        }
    }

    let profile = TemporaryProfile::new("installed-payload", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let prefix = profile.root.join("usr");
    fs::create_dir_all(prefix.join("bin")).unwrap();
    // The desktop host names this payload for a runtime installed at
    // `lib/muniment/muniment-runtime` under the same prefix.
    let expected = prefix.join("bin/muniment-desktop");
    let alias = prefix.join("bin/muniment");
    fs::copy(std::env::current_exe().unwrap(), &expected).unwrap();
    std::os::unix::fs::symlink("muniment-desktop", &alias).unwrap();
    // GNU install replaces the alias instead of updating the trusted payload.
    assert!(Command::new("install")
        .args(["-m", "0755"])
        .arg(std::env::current_exe().unwrap())
        .arg(&alias)
        .status()
        .unwrap()
        .success());
    assert!(!alias.is_symlink());
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    let instance = filesystem.acquire_instance_lock().unwrap();
    let transport = muniment_core::attach::linux::AttachTransport::bind(&filesystem).unwrap();
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        profile.profile.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    let (stop_tx, stop_rx) = mpsc::channel();
    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            muniment_runtime_core::run_bound_attach_listener(
                instance,
                transport,
                AttachListenerInputs {
                    companion_registry: &registry,
                    approval: SignedWorkspaceApproval::default(),
                    approvals: ApprovalCoordinator::default(),
                    expected_desktop_executable: Some(expected.clone()),
                },
                None,
                || Ok::<_, ()>(EventService),
                stop_rx,
            )
            .unwrap();
        });
        let mut results = Vec::new();
        for (executable, connected) in [
            (&alias, false),
            (&expected, true),
            (&expected, true),
            (&expected, true),
        ] {
            let output = Command::new(executable)
                .args(["--exact", "installed_desktop_child", "--nocapture"])
                .env("MUNIMENT_TEST_INSTALLED_ENDPOINT", &endpoint)
                .env("MUNIMENT_TEST_EXPECT_CONNECTED", connected.to_string())
                .output()
                .unwrap();
            results.push(output);
        }
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
        for result in results {
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
    });
}

#[test]
fn desktop_presenter_answers_an_approval_request() {
    let profile = TemporaryProfile::new("attach-listener-presenter", false);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    drop(filesystem);
    let registry = CompanionRegistry::new(
        Arc::new(Mutex::new(HashMap::new())),
        profile.profile.join("companions.json"),
        LiveConnectionRegistry::default(),
    );
    let approvals = ApprovalCoordinator::default();
    let requests = approvals.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let presenter_stop = ApprovalPresenterStopHandle::new();
    let worker_stop = presenter_stop.clone();
    let (presented_tx, presented_rx) = mpsc::channel();

    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            run_attach_listener(
                &profile.root,
                AttachListenerInputs {
                    companion_registry: &registry,
                    approval: SignedWorkspaceApproval::default(),
                    approvals,
                    expected_desktop_executable: std::env::current_exe().ok(),
                },
                None,
                || Ok::<_, ()>(TestService),
                stop_rx,
            )
            .unwrap()
        });
        let presenter = scope.spawn(|| {
            serve_approval_presenter_at(
                &endpoint,
                "1.0.0",
                Duration::from_secs(1),
                Duration::from_millis(10),
                worker_stop,
                |_| {},
                |request| {
                    presented_tx.send(request.challenge.clone()).unwrap();
                    PresenterDecision::Approve
                },
            )
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut attempt = 0;
        let challenge = loop {
            attempt += 1;
            let challenge = format!("runtime-presenter-{attempt}");
            if requests.request(
                ApprovalRequest {
                    challenge: challenge.clone(),
                    claimed_kind: "editor-extension".into(),
                    claimed_version: "1.0.0".into(),
                    workspace: "workspace-a".into(),
                    scopes: Default::default(),
                },
                Duration::from_millis(100),
            ) {
                break challenge;
            }
            assert!(Instant::now() < deadline, "presenter did not connect");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            presented_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            challenge
        );

        presenter_stop.stop();
        presenter.join().unwrap();
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
    });
}

#[test]
fn companion_pairs_through_the_desktop_presenter() {
    for (decision, authorized) in [
        (PresenterDecision::Approve, true),
        (PresenterDecision::Deny, false),
    ] {
        let profile = TemporaryProfile::new("attach-listener-live-presenter", false);
        fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
        let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
        let endpoint = filesystem.endpoint_path().to_owned();
        drop(filesystem);
        let approval = SignedWorkspaceApproval::default();
        approval.record("workspace-a".into());
        let registry = CompanionRegistry::new(
            Arc::new(Mutex::new(HashMap::new())),
            profile.profile.join("companions.json"),
            LiveConnectionRegistry::default(),
        );
        let approvals = ApprovalCoordinator::default();
        let readiness = approvals.clone();
        let (stop_tx, stop_rx) = mpsc::channel();
        let presenter_stop = ApprovalPresenterStopHandle::new();
        let worker_stop = presenter_stop.clone();
        let (presented_tx, presented_rx) = mpsc::channel();

        let (connected, handshake_result, presented) = thread::scope(|scope| {
            let listener = scope.spawn(|| {
                run_attach_listener(
                    &profile.root,
                    AttachListenerInputs {
                        companion_registry: &registry,
                        approval,
                        approvals,
                        expected_desktop_executable: Some(std::env::current_exe().unwrap()),
                    },
                    None,
                    || Ok::<_, ()>(TestService),
                    stop_rx,
                )
                .unwrap()
            });
            let presenter = scope.spawn(|| {
                serve_approval_presenter_at(
                    &endpoint,
                    "1.0.0",
                    Duration::from_secs(1),
                    Duration::from_millis(10),
                    worker_stop,
                    |_| {},
                    |request| {
                        presented_tx.send(request.clone()).unwrap();
                        if request.challenge.starts_with("presenter-ready-") {
                            PresenterDecision::Approve
                        } else {
                            decision
                        }
                    },
                )
            });

            let deadline = Instant::now() + Duration::from_secs(2);
            let mut attempt = 0;
            let connected = loop {
                attempt += 1;
                if readiness.request(
                    ApprovalRequest {
                        challenge: format!("presenter-ready-{attempt}"),
                        claimed_kind: "test".into(),
                        claimed_version: "1.0.0".into(),
                        workspace: "workspace-a".into(),
                        scopes: Default::default(),
                    },
                    Duration::from_millis(100),
                ) {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                thread::sleep(Duration::from_millis(10));
            };
            let _readiness_request = presented_rx.recv_timeout(Duration::from_secs(1));

            let previous_runtime_directory = std::env::var_os("XDG_RUNTIME_DIR");
            std::env::set_var("XDG_RUNTIME_DIR", &profile.root);
            let handshake_result = companion_handshake("1.0.0", "editor-extension", || {}).is_ok();
            match previous_runtime_directory {
                Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
            let presented = presented_rx.recv_timeout(Duration::from_secs(1));

            presenter_stop.stop();
            presenter.join().unwrap();
            stop_tx.send(()).unwrap();
            listener.join().unwrap();
            (connected, handshake_result, presented)
        });

        assert!(connected, "presenter did not connect");
        assert_eq!(handshake_result, authorized);
        let ApprovalPresentRequest {
            challenge,
            claimed_kind,
            claimed_version,
            workspace,
            ..
        } = presented.unwrap();
        assert!(!challenge.is_empty());
        assert_eq!(claimed_kind, "editor-extension");
        assert_eq!(claimed_version, "1.0.0");
        assert_eq!(workspace, "workspace-a");
    }
}
