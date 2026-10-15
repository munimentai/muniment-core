//! The local desktop route's welcome carries the runtime identity the host
//! announced, the same values the remote route's welcome carries. The
//! announcement is process-wide, so this test runs in its own binary.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use muniment_core::attach::{
    admit_desktop_client_over_stream, handshake_desktop_client, InstallKind, RemoteAccess,
    RemoteAccessOptions,
};

fn admit_once() -> Option<muniment_core::attach::RuntimeInfo> {
    let (mut server, client) = UnixStream::pair().unwrap();
    let runtime = std::thread::spawn(move || {
        admit_desktop_client_over_stream(
            &mut server,
            "3.0.0",
            None,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
    });
    let client = handshake_desktop_client(Box::new(client), "3.0.0", Duration::from_secs(5))
        .expect("the desktop client is admitted");
    runtime.join().unwrap();
    client.runtime_info().cloned()
}

#[test]
fn the_local_welcome_carries_the_announced_runtime_identity() {
    assert_eq!(admit_once(), None);

    let directory =
        std::env::temp_dir().join(format!("muniment-local-runtime-{}", uuid::Uuid::now_v7()));
    let access = RemoteAccess::open(
        &directory,
        RemoteAccessOptions {
            runtime_name: Some("Desk runtime".into()),
            runtime_version: "3.0.0".into(),
            install_kind: InstallKind::Desktop,
        },
    )
    .unwrap();
    access.announce_on_local_route();
    let info = admit_once().expect("the welcome names the runtime");
    assert_eq!(info, access.runtime_info());
    assert_eq!(info.runtime_name, "Desk runtime");
    assert_eq!(info.install_kind, Some(InstallKind::Desktop));
    std::fs::remove_dir_all(directory).unwrap();
}
