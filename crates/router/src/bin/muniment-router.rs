//! The factory router server and its account commands.
//!
//! `muniment-router serve` answers the factory's API until SIGTERM, then
//! drains. `muniment-router accounts …` manages the account pool in the same
//! store and secret source. Settings come from `--config <file>` or
//! `MUNIMENT_ROUTER_CONFIG`, with `MUNIMENT_ROUTER_*` variables over them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use muniment_router::factory::openbao::OpenBao;
use muniment_router::factory::postgres::PgStore;
use muniment_router::factory::settings::{Settings, Storage};
use muniment_router::factory::{self, accounts, token::SigningKey, NoSecrets, Options};
use muniment_router::model_catalog::{self, Reload};
use muniment_router::store::{Backend, FileSecrets, FileStore, RouterStore, SecretSource};

const USAGE: &str = "\
usage: muniment-router [--config <file>] <command>

commands:
  serve                     answer the router API until SIGTERM, then drain
  accounts <subcommand>     manage the account pool (muniment-router accounts help)
  catalog check <file>      check a catalog file without loading it
  health                    exit 0 when the local server answers /healthz

Settings come from the TOML file and MUNIMENT_ROUTER_* variables.";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = std::env::var("MUNIMENT_ROUTER_CONFIG")
        .ok()
        .map(PathBuf::from);
    if let Some(index) = args.iter().position(|arg| arg == "--config") {
        if index + 1 >= args.len() {
            fail("--config needs a file.");
        }
        config = Some(PathBuf::from(args.remove(index + 1)));
        args.remove(index);
    }
    let command = args.first().map(String::as_str).unwrap_or("serve");
    let result = match command {
        "serve" => settings(config.as_deref()).and_then(serve),
        "accounts" => settings(config.as_deref()).and_then(|settings| {
            let backend = backend(&settings)?;
            accounts::run(&backend, &args[1..], &mut std::io::stdout())
        }),
        "catalog" => match (args.get(1).map(String::as_str), args.get(2)) {
            (Some("check"), Some(path)) => std::fs::read_to_string(path)
                .map_err(|error| format!("{path}: {error}"))
                .and_then(|text| model_catalog::parse(&text))
                .map(|models| println!("{path}: {} models", models.len())),
            _ => Err(USAGE.into()),
        },
        "health" => settings(config.as_deref()).and_then(health),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.into()),
    };
    if let Err(message) = result {
        fail(&message);
    }
}

fn fail(message: &str) -> ! {
    eprintln!("muniment-router: {message}");
    std::process::exit(2);
}

fn settings(path: Option<&std::path::Path>) -> Result<Settings, String> {
    Settings::load(path, |name| std::env::var(name).ok())
}

fn backend(settings: &Settings) -> Result<Backend, String> {
    let store: Arc<dyn RouterStore> =
        match &settings.storage {
            Some(Storage::Postgres(url)) => {
                Arc::new(PgStore::connect(url).map_err(|error| format!("Postgres: {error}"))?)
            }
            Some(Storage::Files(dir)) => Arc::new(FileStore::new(dir)),
            None => return Err(
                "Set MUNIMENT_ROUTER_DATABASE_URL, or MUNIMENT_ROUTER_STATE_DIR for a file store."
                    .into(),
            ),
        };
    let secrets: Arc<dyn SecretSource> = match (&settings.openbao, &settings.storage) {
        (Some(openbao), _) => Arc::new(OpenBao::new(openbao.clone())),
        (None, Some(Storage::Files(dir))) => Arc::new(FileSecrets::new(dir)),
        (None, _) => Arc::new(NoSecrets),
    };
    let classifier = settings.classifier.clone();
    let mode = settings.policy_mode;
    let mut backend = Backend::new(store, secrets);
    backend.overlay = Some(Arc::new(move |config| {
        if classifier.ready() {
            config.classifier = classifier.clone();
        }
        config.policy.mode = mode;
        // A run's own budget, when it has one, is the only spend limit here.
        // The desktop's task budget never applies to a run.
        config.policy.task_budget_usd = None;
    }));
    Ok(backend)
}

/// Asks the server on this host's listen port for its health, for a
/// container health check that needs no other tool.
fn health(settings: Settings) -> Result<(), String> {
    let port = settings
        .listen
        .rsplit_once(':')
        .map(|(_, port)| port)
        .ok_or("The listen address has no port.")?;
    let url = format!("http://127.0.0.1:{port}/healthz");
    ureq::get(&url)
        .timeout(Duration::from_secs(5))
        .call()
        .map(|_| ())
        .map_err(|error| format!("{url}: {error}"))
}

fn serve(settings: Settings) -> Result<(), String> {
    let admin_token = settings
        .admin_token
        .clone()
        .filter(|token| token.len() >= 16)
        .ok_or("Set MUNIMENT_ROUTER_ADMIN_TOKEN to at least 16 characters.")?;
    let signing_key = SigningKey::parse(
        settings
            .run_token_signing_key
            .as_deref()
            .ok_or("Set MUNIMENT_ROUTER_RUN_TOKEN_SIGNING_KEY.")?,
    )?;
    if settings.openbao.is_none() && matches!(settings.storage, Some(Storage::Postgres(_))) {
        eprintln!("muniment-router: no OpenBao address is set, so no account can take a turn");
    }
    let mut reloader = settings.catalog.as_ref().map(model_catalog::Reloader::new);
    let report = |result: &Reload| match result {
        Reload::Unchanged => {}
        Reload::Installed(count) => eprintln!("muniment-router: catalog loaded, {count} models"),
        Reload::Rejected(error) => {
            eprintln!("muniment-router: catalog rejected, keeping the last good one: {error}")
        }
    };
    let first = reloader.as_mut().map(|reloader| reloader.poll());
    if let Some(result) = &first {
        report(result);
    }
    let backend = backend(&settings)?;
    let mut handle = factory::start(
        &settings.listen,
        backend.clone(),
        Options {
            admin_token,
            signing_key,
            success: settings.success,
            metrics: settings.metrics,
            langfuse: settings
                .langfuse
                .clone()
                .map(factory::langfuse::Langfuse::start),
        },
    )
    .map_err(|error| format!("{}: {error}", settings.listen))?;
    if let Some(result) = &first {
        handle.catalog_loaded(result);
    }
    eprintln!("muniment-router: listening on {}", handle.address());

    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&stop)).map_err(|e| e.to_string())?;
    }
    if !settings.quota_probe_interval.is_zero() {
        let stop = Arc::clone(&stop);
        let backend = backend.clone();
        let interval = settings.quota_probe_interval;
        std::thread::spawn(move || loop {
            for (id, result) in factory::probe_quotas(&backend, None) {
                if let Err(error) = result {
                    eprintln!("muniment-router: quota probe for {id}: {error}");
                }
            }
            let until = Instant::now() + interval;
            while Instant::now() < until {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    }
    let mut next_poll = Instant::now() + settings.catalog_poll;
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
        if Instant::now() >= next_poll {
            next_poll = Instant::now() + settings.catalog_poll;
            if let Some(reloader) = reloader.as_mut() {
                let result = reloader.poll();
                report(&result);
                handle.catalog_loaded(&result);
            }
        }
    }
    eprintln!(
        "muniment-router: draining {} connections for up to {}s",
        handle.connections(),
        settings.drain_timeout.as_secs()
    );
    if handle.drain(settings.drain_timeout) {
        eprintln!("muniment-router: drained");
    } else {
        eprintln!(
            "muniment-router: {} connections still open at the deadline",
            handle.connections()
        );
    }
    Ok(())
}
