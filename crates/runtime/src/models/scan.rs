//! The first-run scan for model servers on this computer and for coding tools
//! that already hold a provider sign-in. `muniment_core::models::local_servers`
//! holds the scan. The runtime runs it and saves a found server.

use std::path::Path;
use std::sync::mpsc;
use std::time::Instant;

use serde::Deserialize;

use muniment_core::engine::PiRpcEngine;
use muniment_core::models::local_servers::{
    self, kind, loopback_url, omlx_key, ClaudeCode, Context, Environment, Platform, ProviderScan,
    SCAN_BUDGET,
};

use super::providers;

/// Starts the Claude Code status check beside the port probes.
fn start_claude_code_check() -> mpsc::Receiver<ClaudeCode> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let status = providers::claude_code_status();
        let _ = sender.send(if status.logged_in {
            ClaudeCode::SignedIn
        } else if status.installed {
            ClaudeCode::Installed
        } else {
            ClaudeCode::Absent
        });
    });
    receiver
}

fn claude_code_by(receiver: &mpsc::Receiver<ClaudeCode>, deadline: Instant) -> ClaudeCode {
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(state) => state,
        // The status answers at once without an executable, so a check still running found one.
        Err(mpsc::RecvTimeoutError::Timeout) => ClaudeCode::Installed,
        Err(mpsc::RecvTimeoutError::Disconnected) => ClaudeCode::Absent,
    }
}

/// Finds model servers on this computer and the tools that hold a provider sign-in.
pub(super) fn scan() -> Result<ProviderScan, String> {
    let home = std::env::home_dir().ok_or("Cannot locate the home directory.")?;
    let environment: Environment = std::env::vars_os().collect();
    let context = Context {
        home: &home,
        environment: &environment,
        platform: Platform::current(),
        root: Path::new("/"),
    };
    let deadline = Instant::now() + SCAN_BUDGET;
    let claude_code = start_claude_code_check();
    Ok(local_servers::scan(&context, deadline, || {
        claude_code_by(&claude_code, deadline)
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FoundServer {
    id: String,
    base_url: String,
    #[serde(default)]
    key: Option<String>,
    key_from_file: bool,
}

/// Saves a found server as a provider through the same storage as Settings.
/// Ollama keeps its own provider, LM Studio its endpoint, and any other server
/// a named endpoint. A key from oMLX's settings file goes straight to storage.
pub(super) fn connect_server(
    agent: &Path,
    engine: &PiRpcEngine,
    server: FoundServer,
) -> Result<(), String> {
    let FoundServer {
        id,
        base_url,
        key,
        key_from_file,
    } = server;
    let kind = kind(&id).ok_or("Muniment does not know this server.")?;
    loopback_url(&base_url)?;
    let key = if key_from_file {
        if kind.id != "omlx" {
            return Err("This server keeps no key file.".into());
        }
        let home = std::env::home_dir().ok_or("Cannot locate the home directory.")?;
        let environment: Environment = std::env::vars_os().collect();
        let context = Context {
            home: &home,
            environment: &environment,
            platform: Platform::current(),
            root: Path::new("/"),
        };
        omlx_key(&context).ok_or("The oMLX settings file holds no API key.")?
    } else {
        key.unwrap_or_default().trim().to_owned()
    };
    if kind.id == "ollama" {
        return providers::store_local_provider(agent, &base_url, key.trim());
    }
    let (endpoint, name) = if kind.id == "lmstudio" {
        ("lmstudio", "")
    } else {
        ("custom", kind.name)
    };
    providers::store_endpoint(agent, engine, endpoint, name, &base_url, &key, &[]).map(drop)
}
