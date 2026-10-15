//! Runs the real `muniment-server` remote access commands against a state
//! directory whose remote listener this test serves, as `serve` would in
//! another process.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::time::Duration;

use muniment_core::attach::thread_service::{ThreadListPage, ThreadListRequest};
use muniment_core::attach::{
    connect_remote_runtime, pair_with_link, InstallKind, PairingLink, RemoteAccess,
    RemoteAccessOptions, RemoteClientOptions, RemoteConnectError, RemoteListener,
    RemoteListenerConfig, SignedWorkspaceApproval,
};
use muniment_core::serde_json::{self, Value};

const SERVER: &str = env!("CARGO_BIN_EXE_muniment-server");

struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "muniment-server-remote-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(root: &Root, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(SERVER);
    command
        .args(args)
        .env("MUNIMENT_STATE_DIR", root.state())
        .env("HOME", &root.0)
        .env_remove("MUNIMENT_REMOTE_ACCESS")
        .env_remove("MUNIMENT_REMOTE_LISTEN")
        .env_remove("MUNIMENT_REMOTE_ENDPOINTS")
        .env_remove("MUNIMENT_INSTALL_KIND");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn options() -> RemoteClientOptions {
    RemoteClientOptions {
        kind: "cli".into(),
        version: "1.0.0".into(),
        device_name: Some("Test client".into()),
        scopes: None,
        io_timeout: Duration::from_secs(10),
    }
}

#[test]
fn info_reports_the_identity_and_pair_refuses_while_remote_access_is_off() {
    let root = Root::new("off");
    let info = json(&run(&root, &["info", "--json"], &[]));
    assert_eq!(info["install_kind"], "server");
    assert_eq!(info["remote_access"]["enabled"], false);
    assert_eq!(info["certificate_sha256"].as_str().unwrap().len(), 64);
    let again = json(&run(
        &root,
        &["info", "--json"],
        &[("MUNIMENT_INSTALL_KIND", "container")],
    ));
    assert_eq!(again["runtime_id"], info["runtime_id"]);
    assert_eq!(again["install_kind"], "container");

    let refused = run(&root, &["pair"], &[]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("remote access is off"));
    assert!(!run(
        &root,
        &["pair", "--scopes", "root"],
        &[("MUNIMENT_REMOTE_ACCESS", "on")]
    )
    .status
    .success());
    assert!(!run(&root, &["revoke"], &[]).status.success());
    assert!(!run(&root, &["devices", "--yaml"], &[]).status.success());
}

#[test]
fn pair_devices_and_revoke_work_beside_a_serving_listener() {
    let root = Root::new("serving");
    let access = RemoteAccess::open(
        root.state().join("remote"),
        RemoteAccessOptions {
            runtime_name: Some("Served runtime".into()),
            runtime_version: "1.0.0".into(),
            install_kind: InstallKind::Server,
        },
    )
    .unwrap();
    let listener =
        RemoteListener::bind(RemoteListenerConfig::new("127.0.0.1:0".parse().unwrap())).unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (stop, stopped) = mpsc::channel();
    let served = access.clone();
    let server = std::thread::spawn(move || {
        listener.serve(
            served,
            SignedWorkspaceApproval::default(),
            || {
                Ok::<_, ()>(|_: &str, _: ThreadListRequest| {
                    Ok(ThreadListPage {
                        threads: vec![],
                        next_cursor: None,
                    })
                })
            },
            stopped,
        )
    });
    let env = [
        ("MUNIMENT_REMOTE_ACCESS", "on"),
        ("MUNIMENT_REMOTE_ENDPOINTS", endpoint.as_str()),
    ];

    let created = json(&run(
        &root,
        &["pair", "--json", "--scopes", "thread.read"],
        &env,
    ));
    let link = PairingLink::parse(created["link"].as_str().unwrap()).unwrap();
    assert_eq!(link.endpoints, vec![endpoint.clone()]);
    assert_eq!(created["endpoints"], serde_json::json!([endpoint]));
    assert_eq!(created["scopes"], serde_json::json!(["thread.read"]));
    assert_eq!(
        created["fingerprint"],
        access.certificate_fingerprint().to_hex()
    );
    assert_eq!(created["runtime_id"], access.runtime_info().runtime_id);
    assert!(created["expires_at"].is_string());

    let (_, record) = pair_with_link(&link, &options()).unwrap();
    assert!(pair_with_link(&link, &options()).is_err());
    connect_remote_runtime(&record, &options()).unwrap();

    let plain = run(&root, &["pair"], &env);
    let text = String::from_utf8(plain.stdout).unwrap();
    assert!(PairingLink::parse(text.trim()).is_ok());

    let device_id = record.credential.device_id.as_str();
    let devices = json(&run(&root, &["devices", "--json"], &[]));
    assert_eq!(devices["devices"][0]["device_id"], device_id);
    assert_eq!(devices["devices"][0]["name"], "Test client");
    assert!(!devices.to_string().contains(&record.credential.secret));
    let listed = run(&root, &["devices"], &[]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains(device_id));

    let revoked = run(&root, &["revoke", device_id], &[]);
    assert!(revoked.status.success());
    assert!(!run(&root, &["revoke", device_id], &[]).status.success());
    assert_eq!(
        connect_remote_runtime(&record, &options()).err(),
        Some(RemoteConnectError::Unauthorized)
    );

    drop(stop);
    server.join().unwrap().unwrap();
}
