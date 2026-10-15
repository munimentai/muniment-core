//! The runtime's own attach service over the remote route.

mod common;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use muniment_core::attach::{
    connect_remote_runtime, pair_with_link, ErrorCode, InstallKind, Operation, PairingLinkRequest,
    RemoteAccessOptions, RemoteAccessSettings, RemoteClientOptions, RemoteConnectError,
    RemoteListener, RemoteListenerConfig, RemoteRouteOptions, RemoteSettingsOverrides,
};
use muniment_core::serde_json::json;
use muniment_runtime_core::{RuntimeAttachState, RuntimeHost};

#[test]
fn a_paired_device_reads_the_runtime_and_the_owner_route_shares_remote_access() {
    let temporary = common::TemporaryProfile::new("remote-attach", false);
    let state = Arc::new(
        RuntimeAttachState::open(
            RuntimeHost::default(),
            &temporary.profile,
            &temporary.config,
        )
        .unwrap(),
    );
    assert!(state.attach_service().unwrap().remote_access.is_none());
    let access = state
        .open_remote_access(RemoteAccessOptions {
            runtime_name: Some("Server runtime".into()),
            runtime_version: state.runtime_version().into(),
            install_kind: InstallKind::Server,
        })
        .unwrap();
    assert!(temporary.profile.join("remote/identity.json").exists());
    assert!(state.attach_service().unwrap().remote_access.is_some());

    let listener =
        RemoteListener::bind(RemoteListenerConfig::new("127.0.0.1:0".parse().unwrap())).unwrap();
    access
        .set_advertised_endpoints(vec![listener.local_addr().unwrap().to_string()])
        .unwrap();
    let (stop, stopped) = mpsc::channel();
    let served = Arc::clone(&state);
    let served_access = access.clone();
    let server =
        std::thread::spawn(move || served.serve_remote_listener(listener, served_access, stopped));

    let options = RemoteClientOptions {
        kind: "cli".into(),
        version: "1.0.0".into(),
        device_name: None,
        scopes: None,
        io_timeout: Duration::from_secs(10),
    };
    let link = access
        .create_pairing_link(PairingLinkRequest::default())
        .unwrap()
        .link;
    let (_, record) = pair_with_link(&link, &options).unwrap();
    let mut client = connect_remote_runtime(&record, &options).unwrap();
    assert_eq!(
        client.runtime_info().unwrap().runtime_name,
        "Server runtime"
    );
    let page = client
        .request(Operation::ThreadList, None, json!({"limit": 10}))
        .unwrap();
    assert!(page.body["threads"].is_array());
    // A headless runtime runs in local mode and answers its threads without
    // a sign-in, as `muniment-server` sets up.
    std::fs::write(
        temporary
            .config
            .join(muniment_core::local_mode::LOCAL_MODE_MARKER),
        "1",
    )
    .unwrap();
    let summaries = client
        .request(Operation::ThreadSummaries, None, json!({"limit": 10}))
        .unwrap();
    assert!(summaries.body["summaries"].is_array());
    assert!(client.list_remote_devices().is_err());
    assert_eq!(
        client.last_request_error().map(|error| error.code()),
        Some(ErrorCode::Unauthorized)
    );

    assert!(access
        .revoke_device(record.credential.device_id.as_str())
        .unwrap());
    assert_eq!(
        connect_remote_runtime(&record, &options).err(),
        Some(RemoteConnectError::Unauthorized)
    );
    drop(stop);
    server.join().unwrap().unwrap();
}

#[test]
fn the_runtime_starts_and_stops_its_remote_listener_as_its_settings_change() {
    let temporary = common::TemporaryProfile::new("remote-route", false);
    let state = Arc::new(
        RuntimeAttachState::open(
            RuntimeHost::default(),
            &temporary.profile,
            &temporary.config,
        )
        .unwrap(),
    );
    let route = state
        .start_remote_route(RemoteRouteOptions {
            access: RemoteAccessOptions {
                runtime_name: Some("Routed runtime".into()),
                runtime_version: state.runtime_version().into(),
                install_kind: InstallKind::Server,
            },
            overrides: RemoteSettingsOverrides::default(),
        })
        .unwrap();
    assert_eq!(route.status().listening, None);
    let service = state.attach_service().unwrap();
    assert!(service.remote_route.is_some());
    assert!(service.remote_access.is_some());

    let status = route
        .save(RemoteAccessSettings {
            enabled: true,
            listen: Some("127.0.0.1:0".parse().unwrap()),
            endpoints: Vec::new(),
            allow_public: false,
        })
        .unwrap();
    let address = status.listening.unwrap();
    let options = RemoteClientOptions {
        kind: "cli".into(),
        version: "1.0.0".into(),
        device_name: None,
        scopes: None,
        io_timeout: Duration::from_secs(10),
    };
    let link = route
        .access()
        .create_pairing_link(PairingLinkRequest::default())
        .unwrap()
        .link;
    assert_eq!(link.endpoints, vec![address.to_string()]);
    let (_, record) = pair_with_link(&link, &options).unwrap();
    let mut client = connect_remote_runtime(&record, &options).unwrap();
    assert_eq!(
        client.runtime_info().unwrap().runtime_name,
        "Routed runtime"
    );
    assert!(client
        .request(Operation::ThreadList, None, json!({"limit": 10}))
        .is_ok());
    drop(client);

    route
        .save(RemoteAccessSettings {
            enabled: false,
            ..RemoteAccessSettings::default()
        })
        .unwrap();
    assert_eq!(
        connect_remote_runtime(&record, &options).err(),
        Some(RemoteConnectError::Unreachable)
    );
    state.stop_remote_route();
    assert!(state.remote_route().is_none());
}
