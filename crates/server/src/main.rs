//! The headless Muniment runtime.
//!
//! `muniment-server serve` runs the runtime with a host that has no cloud
//! account, no keychain and no OS service manager: secrets live in files
//! under the state root, with overrides from the environment. State lives in
//! the directory `MUNIMENT_STATE_DIR` names, or `~/.muniment`. The attach
//! endpoint sits under `XDG_RUNTIME_DIR`, or under `run` in the state root
//! when that is unset. SIGTERM and SIGINT stop it cleanly.

mod host;

use std::process::ExitCode;

const USAGE: &str = "\
usage: muniment-server [command]

commands:
  serve      run the runtime until SIGTERM or SIGINT (the default)
  health     exit 0 when the runtime's attach endpoint answers
  prepare    install the pinned Pi and its extension packages, then print
             the Pi executable's path

options:
  -h, --help  print this help
  --version   print the version

State lives in MUNIMENT_STATE_DIR, or ~/.muniment. MUNIMENT_PI_ROOT names
the directory that holds the installed Pi.";

/// Docker reads 1 as unhealthy and reserves 2, so every failure exits 1.
const FAILURE: u8 = 1;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("serve");
    if args.len() > 1 {
        eprintln!("muniment-server: unexpected argument {}\n{USAGE}", args[1]);
        return ExitCode::from(FAILURE);
    }
    let result = match command {
        "serve" => serve(),
        "health" => health(),
        "prepare" => prepare(),
        "help" | "-h" | "--help" => {
            println!("{USAGE}");
            Ok(())
        }
        "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("muniment-server: {message}");
            ExitCode::from(FAILURE)
        }
    }
}

#[cfg(target_os = "linux")]
fn serve() -> Result<(), String> {
    use muniment_core::attach::TerminationSignalWait;
    use muniment_runtime_core::{adopt_state_directory, run_runtime, RuntimeDirectories};

    // The signal mask must be set before any thread starts, so every thread
    // the runtime spawns leaves SIGTERM and SIGINT to this wait.
    let termination = TerminationSignalWait::new().map_err(|error| error.to_string())?;
    let state = adopt_state_directory().map_err(|error| error.to_string())?;
    let endpoint = host::prepare_runtime_directory(&state)?;
    eprintln!(
        "muniment-server: started version={} state_directory={} endpoint={}",
        env!("CARGO_PKG_VERSION"),
        state.display(),
        host::endpoint_path(&endpoint)?.display()
    );
    let (stop, stopped) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if termination.wait().is_ok() {
            eprintln!("muniment-server: stopping reason=signal");
            let _ = stop.send(());
        }
    });
    let directories = RuntimeDirectories {
        profile: state.clone(),
        config: state.clone(),
        endpoint,
    };
    run_runtime(host::headless_host(&state), &directories, stopped)
        .map_err(|error| error.to_string())?;
    eprintln!("muniment-server: stopped");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn serve() -> Result<(), String> {
    Err("serve runs on Linux only".into())
}

#[cfg(target_os = "linux")]
fn health() -> Result<(), String> {
    use std::time::{Duration, Instant};

    let state = muniment_core::state_root::state_directory()
        .ok_or("no state directory: set MUNIMENT_STATE_DIR or HOME")?;
    let endpoint = host::endpoint_path(&host::runtime_directory(&state))?;
    muniment_core::attach::read_handoff_probe_welcome(
        &endpoint,
        Instant::now() + Duration::from_secs(5),
    )
    .map(|_| ())
    .map_err(|error| format!("{}: {error}", endpoint.display()))
}

#[cfg(not(target_os = "linux"))]
fn health() -> Result<(), String> {
    Err("health runs on Linux only".into())
}

/// Installs Pi and its packages where `serve` finds them, so a first run
/// needs no download. The install checks the archive's size and SHA-256
/// against the pins this binary was built with.
fn prepare() -> Result<(), String> {
    let state =
        muniment_runtime_core::adopt_state_directory().map_err(|error| error.to_string())?;
    let root = host::pi_install_root(&state);
    let executable = muniment_core::sidecar::pi_install::acquire_pi(
        &root,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .map_err(|error| format!("Pi install in {} failed: {error:?}", root.display()))?;
    muniment_core::pi_packages::prepare_pi_packages(
        &muniment_core::state_root::agent_directory(&state),
        &executable,
    )
    .map_err(|error| format!("Pi package install failed: {error}"))?;
    println!("{}", executable.display());
    Ok(())
}
