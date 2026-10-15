//! The runtime's own attach service over the remote route.

mod common;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use muniment_core::attach::{
    connect_remote_runtime, pair_with_link, ErrorCode, InstallKind, Operation, PairingLinkRequest,
    RemoteAccessOptions, RemoteClientOptions, RemoteConnectError, RemoteListener,
    RemoteListenerConfig,
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
