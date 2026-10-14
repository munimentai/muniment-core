//! Web search: the settings record and the built-in search server.
//!
//! The server runs for the runtime's whole life, so the port and token a Pi
//! process read at launch stay valid while it runs. A change to the enabled
//! engines reaches the running server at once. Each change also rewrites
//! pi-web-access's `web-search.json`, which the next Pi launch reads.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::Serialize;

use muniment_core::search_settings::{self, OrderEntry, ProviderKey, SearchSettings, SettingsView};
use muniment_search::{server, Config, EngineId, Metasearch};

const READ_ERROR: &str = "Muniment could not read the web search settings.";
const SAVE_ERROR: &str = "Muniment could not save the web search settings.";

/// The running search server. The lock also orders every settings change.
#[derive(Default)]
pub(super) struct SearchState(Mutex<Option<server::Handle>>);

impl SearchState {
    fn lock(&self) -> MutexGuard<'_, Option<server::Handle>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stops the server and removes the endpoint file it wrote.
    pub(super) fn stop(&self, agent: &Path) {
        if let Some(handle) = self.lock().take() {
            handle.stop();
            let _ = std::fs::remove_file(agent.join(search_settings::ENDPOINT_FILE));
        }
    }
}

/// The settings a client reads, and whether the built-in engine's server runs.
#[derive(Serialize)]
pub(super) struct SearchView {
    #[serde(flatten)]
    settings: SettingsView,
    running: bool,
}

fn engines(settings: &SearchSettings) -> Vec<EngineId> {
    settings
        .engines
        .iter()
        .filter_map(|name| EngineId::from_name(name))
        .collect()
}

/// Starts the server when none runs and gives it the record's engines.
fn apply(
    agent: &Path,
    held: &mut Option<server::Handle>,
    settings: &SearchSettings,
) -> std::io::Result<()> {
    let wanted = engines(settings);
    let metasearch = || {
        Arc::new(Metasearch::new(Config {
            engines: wanted.clone(),
            ..Config::default()
        }))
    };
    match held {
        Some(handle) => {
            if handle.search().engines() != wanted.as_slice() {
                handle.replace_search(metasearch());
            }
        }
        None => {
            let path = agent.join(search_settings::ENDPOINT_FILE);
            *held = Some(server::start(&path, metasearch())?);
        }
    }
    Ok(())
}

/// Starts the server with the recorded engines and writes `web-search.json`.
pub(super) fn restore(state_directory: &Path, agent: &Path, state: &SearchState) {
    let mut held = state.lock();
    let settings = search_settings::load(state_directory).unwrap_or_default();
    if let Err(error) = apply(agent, &mut held, &settings) {
        eprintln!("web_search: the search server did not start: {error}");
    }
    if let Err(error) = muniment_core::pi_settings::store_web_search(state_directory) {
        eprintln!("web_search: web-search.json was not written: {error}");
    }
}

pub(super) fn settings(state_directory: &Path, state: &SearchState) -> Result<SearchView, String> {
    let held = state.lock();
    let settings = search_settings::load(state_directory).map_err(|_| READ_ERROR.to_string())?;
    Ok(SearchView {
        settings: settings.view(),
        running: held.is_some(),
    })
}

/// Changes the record, saves it, applies it to the server and to
/// `web-search.json`, and answers the settings it left.
fn commit(
    state_directory: &Path,
    agent: &Path,
    state: &SearchState,
    change: impl FnOnce(&mut SearchSettings) -> Result<(), String>,
) -> Result<SearchView, String> {
    let mut held = state.lock();
    let mut settings =
        search_settings::load(state_directory).map_err(|_| READ_ERROR.to_string())?;
    change(&mut settings)?;
    search_settings::save(state_directory, &settings).map_err(|_| SAVE_ERROR.to_string())?;
    apply(agent, &mut held, &settings).map_err(|_| SAVE_ERROR.to_string())?;
    muniment_core::pi_settings::store_web_search(state_directory)
        .map_err(|_| SAVE_ERROR.to_string())?;
    Ok(SearchView {
        settings: settings.view(),
        running: held.is_some(),
    })
}

pub(super) fn save_order(
    state_directory: &Path,
    agent: &Path,
    state: &SearchState,
    order: Vec<OrderEntry>,
) -> Result<SearchView, String> {
    commit(state_directory, agent, state, |settings| {
        settings.set_order(order)
    })
}

pub(super) fn save_engines(
    state_directory: &Path,
    agent: &Path,
    state: &SearchState,
    engines: Vec<String>,
) -> Result<SearchView, String> {
    commit(state_directory, agent, state, |settings| {
        settings.set_engines(engines)
    })
}

pub(super) fn set_key(
    state_directory: &Path,
    agent: &Path,
    state: &SearchState,
    provider: &str,
    key: ProviderKey,
) -> Result<SearchView, String> {
    commit(state_directory, agent, state, |settings| {
        settings.set_key(provider, key)
    })
}

pub(super) fn remove_key(
    state_directory: &Path,
    agent: &Path,
    state: &SearchState,
    provider: &str,
) -> Result<SearchView, String> {
    commit(state_directory, agent, state, |settings| {
        settings.remove_key(provider)
    })
}
