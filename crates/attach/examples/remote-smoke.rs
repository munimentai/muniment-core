//! Pairs with a runtime over the remote route, or reconnects to one, and
//! reads it once. Smoke tests and the docs use it.
//!
//! `cargo run -p muniment-attach --features client --example remote-smoke -- <link-or-record> [--record <path>]`
//!
//! With a pairing link it redeems the link, saves the record to `--record`
//! (`remote-runtime.json` by default) and reconnects with it. With a record
//! path it reconnects only. Either way it prints the runtime's info and the
//! number of threads on the first page, and exits 1 on any failure.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use muniment_attach::{
    connect_remote_runtime, pair_with_link, DesktopClient, Operation, PairingLink,
    RemoteClientOptions, RemoteRuntimeRecord,
};

const USAGE: &str = "usage: remote-smoke <pairing-link | record-path> [--record <path>]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("remote-smoke: {message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or(USAGE)?;
    let mut record_path = PathBuf::from("remote-runtime.json");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--record" => record_path = args.next().ok_or(USAGE)?.into(),
            _ => return Err(USAGE.into()),
        }
    }
    let options = RemoteClientOptions {
        kind: "cli".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        device_name: Some("remote-smoke".into()),
        scopes: None,
        io_timeout: Duration::from_secs(10),
    };

    let record = if target.starts_with("muniment://") {
        let link = PairingLink::parse(&target).map_err(|error| format!("link: {error}"))?;
        let (_, record) =
            pair_with_link(&link, &options).map_err(|error| format!("pairing failed: {error}"))?;
        record
            .save(&record_path)
            .map_err(|error| format!("{}: {error}", record_path.display()))?;
        println!(
            "paired device_id={} scopes={} record={}",
            record.credential.device_id.as_str(),
            record.scopes.iter().cloned().collect::<Vec<_>>().join(","),
            record_path.display()
        );
        record
    } else {
        RemoteRuntimeRecord::load(target.as_ref()).map_err(|error| format!("{target}: {error}"))?
    };

    let mut client = connect_remote_runtime(&record, &options)
        .map_err(|error| format!("reconnect failed: {error}"))?;
    println!(
        "reconnected device_id={}",
        record.credential.device_id.as_str()
    );
    print_runtime(&mut client)?;
    let page = client
        .request(
            Operation::ThreadList,
            None,
            serde_json::json!({"limit": 50}),
        )
        .map_err(|error| format!("thread.list failed: {error}"))?;
    let threads = page.body["threads"]
        .as_array()
        .ok_or("thread.list answered no thread list")?;
    println!("threads={}", threads.len());
    Ok(())
}

fn print_runtime(client: &mut DesktopClient) -> Result<(), String> {
    let welcome = client
        .runtime_info()
        .ok_or("the runtime's welcome carried no runtime info")?;
    println!(
        "runtime_id={} runtime_name={:?} runtime_version={} install_kind={}",
        welcome.runtime_id,
        welcome.runtime_name,
        welcome.runtime_version,
        welcome.install_kind.map_or("unknown", |kind| kind.as_str())
    );
    let info = client
        .read_runtime_info()
        .map_err(|error| format!("runtime.info failed: {error}"))?;
    println!(
        "certificate_sha256={}",
        info["certificate_sha256"].as_str().unwrap_or("none")
    );
    Ok(())
}
