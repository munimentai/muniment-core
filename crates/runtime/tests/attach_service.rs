#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use muniment_attach::{connect_desktop_client_at, ClientError, Operation};
use muniment_core::attach::linux::{AttachFilesystem, CompanionProvenance, ThreadListService};
use muniment_core::attach::{
    save_client_credentials, ClientCredential, Id, ProtocolError, RuntimeActivityRegistry,
    SignedWorkspaceApproval, COMPANION_CREDENTIAL_FILE_NAME,
};
use muniment_core::memory_runtime::ApplicationMemoryRuntime;
use muniment_core::pi_execution::PiRuntime;
use muniment_core::session_thread::SessionThread;
use muniment_runtime_core::{
    compose_attach_service, open_companion_registry, open_profile_storage, revoke_companion,
    run_attach_listener, AttachListenerInputs, RuntimeAttachBoundaries, RuntimeAttachState,
    RuntimeHost,
};

mod common;
use common::TemporaryProfile;

const THREAD: &str = "01900000-0000-7000-8000-000000000001";

#[test]
fn history_failures_reach_the_desktop_wire_and_runtime_log() {
    const CHILD: &str = "MUNIMENT_HISTORY_DIAGNOSTICS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Capture the runtime stderr sink without changing the process-wide logging path.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "history_failures_reach_the_desktop_wire_and_runtime_log",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let log = String::from_utf8(output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{log}\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        for operation in [
            "thread.summaries",
            "thread.select",
            "thread.history",
            "thread.create",
            "thread.rename",
            "thread.delete",
            "run.resume",
            "retention.recheck",
        ] {
            for cause in ["poisoned", "no such table:"] {
                assert!(
                    log.lines().any(|line| {
                        line.contains(&format!(
                            "desktop request rejected operation=\"{operation}\""
                        )) && line.contains(cause)
                    }),
                    "missing {operation} cause {cause}: {log}"
                );
            }
        }
        return;
    }
    for poisoned in [false, true] {
        check_history_failures(poisoned);
    }
}

fn check_history_failures(poisoned: bool) {
    let profile = TemporaryProfile::new("history-diagnostics", true);
    fs::set_permissions(&profile.root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        profile
            .config
            .join(muniment_core::local_mode::LOCAL_MODE_MARKER),
        b"",
    )
    .unwrap();
    muniment_core::retention_record::write_retention_choice(
        &profile.config,
        muniment_core::retention_record::RetentionChoice::DeleteAfter30Days,
    )
    .unwrap();
    let storage = open_profile_storage(&profile.profile).unwrap();
    if poisoned {
        let storage = Arc::clone(&storage);
        assert!(thread::spawn(move || {
            let _guard = storage.lock().unwrap();
            panic!("poison the history lock");
        })
        .join()
        .is_err());
    } else {
        common::remove_journal_tables(
            &profile.profile,
            &["thread_events", "run_threads", "run_workspaces", "events"],
        );
    }
    let registry = open_companion_registry(&profile.profile).unwrap();
    let approval = SignedWorkspaceApproval::default();
    approval.record("local".into());
    let filesystem = AttachFilesystem::from_runtime_directory(&profile.root).unwrap();
    let endpoint = filesystem.endpoint_path().to_owned();
    drop(filesystem);
    let (stop_tx, stop_rx) = mpsc::channel();
    thread::scope(|scope| {
        let listener = scope.spawn(|| {
            let profile_directory = profile.profile.clone();
            let config_directory = profile.config.clone();
            let service_registry = registry.clone();
            let service_approval = approval.clone();
            run_attach_listener(
                &profile.root,
                AttachListenerInputs {
                    runtime_version: env!("CARGO_PKG_VERSION"),
                    companion_registry: &registry,
                    approval: approval.clone(),
                    approvals: Default::default(),
                    expected_desktop_executable: Some(std::env::current_exe().unwrap()),
                },
                None,
                move || {
                    let boundaries = RuntimeAttachBoundaries::new(
                        Arc::clone(&storage),
                        Arc::new(Mutex::new(None)),
                        profile_directory.clone(),
                        config_directory.clone(),
                        Arc::new(Mutex::new(None)),
                        Arc::new(ApplicationMemoryRuntime::new(
                            config_directory.clone(),
                            profile_directory.join("memory"),
                        )),
                        RuntimeActivityRegistry::new(),
                        RuntimeHost::default(),
                        service_approval.clone(),
                        Arc::new(SessionThread::default()),
                        service_registry.clone(),
                    );
                    compose_attach_service(
                        boundaries,
                        &service_registry,
                        &profile_directory,
                        &config_directory,
                    )
                },
                stop_rx,
            )
            .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut client = loop {
            match connect_desktop_client_at(&endpoint, "1.0.0", Duration::from_secs(1)) {
                Ok(client) => break client,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    stop_tx.send(()).unwrap();
                    panic!("the desktop connection failed: {error}");
                }
            }
        };
        let cases = [
            (Operation::ThreadSummaries, r#"{"limit":10}"#.into()),
            (
                Operation::ThreadSelect,
                format!(r#"{{"thread_id":"{THREAD}"}}"#),
            ),
            (
                Operation::ThreadHistory,
                format!(r#"{{"thread_id":"{THREAD}","limit":10}}"#),
            ),
            (Operation::ThreadCreate, "{}".into()),
            (
                Operation::ThreadRename,
                format!(r#"{{"thread_id":"{THREAD}","title":"A title"}}"#),
            ),
            (
                Operation::ThreadDelete,
                format!(r#"{{"thread_id":"{THREAD}"}}"#),
            ),
            (Operation::RunResume, format!(r#"{{"run_id":"{THREAD}"}}"#)),
            (Operation::RetentionRecheck, "{}".into()),
        ];
        let results = cases
            .into_iter()
            .enumerate()
            .map(|(index, (operation, body))| {
                let key = format!("01900000-0000-7000-8000-{index:012x}");
                let key = matches!(
                    operation,
                    Operation::ThreadCreate
                        | Operation::ThreadRename
                        | Operation::ThreadDelete
                        | Operation::RunResume
                )
                .then(|| muniment_attach::Id::new(key).unwrap());
                let result = client.request(operation, key, body.parse().unwrap());
                let reason = client.last_request_error().map(ToString::to_string);
                (operation, result, reason)
            })
            .collect::<Vec<_>>();
        drop(client);
        stop_tx.send(()).unwrap();
        listener.join().unwrap();
        for (operation, result, reason) in results {
            assert!(
                matches!(result, Err(ClientError::DesktopFailed)),
                "{operation:?}: {result:?}"
            );
            let reason = reason.unwrap();
            let cause = if poisoned {
                "poisoned"
            } else {
                "no such table:"
            };
            assert!(
                reason.contains("Conversation history"),
                "{operation:?}: {reason}"
            );
            assert!(reason.contains(cause), "{operation:?}: {reason}");
        }
    });
}

fn boundaries(profile: &TemporaryProfile) -> RuntimeAttachBoundaries {
    RuntimeAttachBoundaries::new(
        open_profile_storage(&profile.profile).unwrap(),
        Arc::new(Mutex::new(None)),
        profile.profile.clone(),
        profile.config.clone(),
        Arc::new(Mutex::new(None::<PiRuntime>)),
        Arc::new(ApplicationMemoryRuntime::new(
            profile.config.clone(),
            profile.profile.join("memory"),
        )),
        RuntimeActivityRegistry::new(),
        RuntimeHost::default(),
        SignedWorkspaceApproval::default(),
        Arc::new(SessionThread::default()),
        open_companion_registry(&profile.profile).unwrap(),
    )
}

#[test]
fn ensure_home_reads_a_choice_recorded_after_composition() {
    let profile = TemporaryProfile::new("attach-service-home", false);
    let registry = open_companion_registry(&profile.profile).unwrap();

    let mut service = compose_attach_service(
        boundaries(&profile),
        &registry,
        &profile.profile,
        &profile.config,
    )
    .unwrap();

    let confirmed_home = profile.root.join("confirmed-home");
    muniment_core::home::confirm_home(&profile.config, &confirmed_home).unwrap();
    service.ensure_home().unwrap();

    for directory in ["memory", "agents", "projects", "sessions"] {
        assert!(confirmed_home.join(directory).join("README.md").is_file());
    }
    assert!(profile.profile.join("attach-idempotency.sqlite3").is_file());
    assert_eq!(
        service.credential_path,
        Some(profile.profile.join(COMPANION_CREDENTIAL_FILE_NAME))
    );
    assert!(service.client_identity.is_none());
}

#[test]
fn runtime_attach_services_share_the_drain_state() {
    let profile = TemporaryProfile::new("attach-service-drain", false);
    let state = RuntimeAttachState::open(RuntimeHost::default(), &profile.profile, &profile.config)
        .unwrap();
    let first = state.attach_service().unwrap();
    let second = state.attach_service().unwrap();

    assert!(!first.drain_state.is_set());
    first.drain_state.set();
    assert!(second.drain_state.is_set());
}

#[test]
fn service_credential_map_sees_a_registry_revoke() {
    let profile = TemporaryProfile::new("attach-service-revoke", true);
    let identity = "018f0000-0000-7000-8000-000000000001";
    let credential = ClientCredential {
        credential: "ab".repeat(32),
        claimed_kind: "cli".into(),
        claimed_version: "1.0.0".into(),
        approved_at: Some("2026-08-12T00:00:00Z".into()),
        subject: None,
    };
    save_client_credentials(
        &profile.profile.join(COMPANION_CREDENTIAL_FILE_NAME),
        &HashMap::from([(identity.into(), credential)]),
    )
    .unwrap();
    let registry = open_companion_registry(&profile.profile).unwrap();
    let service = compose_attach_service(
        boundaries(&profile),
        &registry,
        &profile.profile,
        &profile.config,
    )
    .unwrap();

    assert!(service
        .client_credentials
        .lock()
        .unwrap()
        .contains_key(identity));
    revoke_companion(&registry, identity).unwrap();
    assert!(!service
        .client_credentials
        .lock()
        .unwrap()
        .contains_key(identity));
}

#[test]
fn service_lists_and_idempotently_revokes_companions() {
    let profile = TemporaryProfile::new("attach-service-companions", true);
    let identity = "018f0000-0000-7000-8000-000000000001";
    let credential = ClientCredential {
        credential: "ab".repeat(32),
        claimed_kind: "cli".into(),
        claimed_version: "1.0.0".into(),
        approved_at: Some("2026-08-12T00:00:00Z".into()),
        subject: None,
    };
    save_client_credentials(
        &profile.profile.join(COMPANION_CREDENTIAL_FILE_NAME),
        &HashMap::from([(identity.into(), credential)]),
    )
    .unwrap();
    let registry = open_companion_registry(&profile.profile).unwrap();
    let boundaries = RuntimeAttachBoundaries::new(
        open_profile_storage(&profile.profile).unwrap(),
        Arc::new(Mutex::new(None)),
        profile.profile.clone(),
        profile.config.clone(),
        Arc::new(Mutex::new(None::<PiRuntime>)),
        Arc::new(ApplicationMemoryRuntime::new(
            profile.config.clone(),
            profile.profile.join("memory"),
        )),
        RuntimeActivityRegistry::new(),
        RuntimeHost::default(),
        SignedWorkspaceApproval::default(),
        Arc::new(SessionThread::default()),
        registry.clone(),
    );
    let mut service =
        compose_attach_service(boundaries, &registry, &profile.profile, &profile.config).unwrap();
    let provenance = CompanionProvenance {
        profile: "default".into(),
        companion_kind: "cli".into(),
        companion_version: "1.0.0".into(),
        peer_uid: 1000,
        peer_pid: 42,
    };
    let key = Id::new("018f0000-0000-7000-8000-000000000010").unwrap();

    let listed = service.list_companions().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].identity, identity);
    for request_id in [
        "018f0000-0000-7000-8000-000000000011",
        "018f0000-0000-7000-8000-000000000012",
    ] {
        service
            .revoke_companion(
                identity,
                &Id::new(request_id).unwrap(),
                &key,
                provenance.clone(),
            )
            .unwrap();
    }
    assert!(service.list_companions().unwrap().is_empty());

    assert_eq!(
        service
            .revoke_companion(
                "unknown",
                &Id::new("018f0000-0000-7000-8000-000000000013").unwrap(),
                &Id::new("018f0000-0000-7000-8000-000000000014").unwrap(),
                provenance,
            )
            .unwrap_err(),
        ProtocolError::unauthorized()
    );
}
