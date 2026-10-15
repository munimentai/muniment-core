//! Settings → Models, the router half: the account pools, what each account
//! has served, the routes, the classifier, and the listener the runtime runs.
//!
//! A credential enters through here and never leaves. The settings this
//! answers with carry an account's source and its counters, never its key.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use muniment_core::chrono;
use muniment_core::model_router::config::{
    self, Account, Classifier, Credential, Route, RouterConfig,
};
use muniment_core::model_router::family::FAMILIES;
use muniment_core::model_router::family::{family_for_pi_provider, SUBSCRIPTION_PROVIDERS};
use muniment_core::model_router::model_catalog;
use muniment_core::model_router::quota;
use muniment_core::model_router::usage::{self, AccountUsage};
use muniment_core::model_router::{
    all_options, classify, offered_models, options, pi_provider, server,
};
use muniment_core::serde_json::{self, Value};

use super::connections;
use super::providers::{
    lock_pi_auth_file, pi_models_file, read_json_for_update, replace_default_model,
    write_json_for_update,
};

pub(super) const READ_ERROR: &str =
    "Muniment cannot read the router settings. Check folder access, then retry.";
pub(super) const SAVE_ERROR: &str =
    "Muniment cannot save the router settings. Check folder access, then retry.";
const START_ERROR: &str =
    "The router could not start. Check that nothing else holds the port, then retry.";
pub(super) const CLASSIFIER_TIMEOUT: Duration = Duration::from_secs(10);

/// The running listener. One at a time, owned by the runtime.
#[derive(Default)]
pub(super) struct RouterState(Mutex<Option<server::Handle>>);

impl RouterState {
    /// The endpoint of the listener the runtime runs, when it runs one.
    fn running_endpoint(&self) -> Option<server::Endpoint> {
        self.0
            .lock()
            .ok()?
            .as_ref()
            .map(|handle| handle.endpoint().clone())
    }

    /// The turns each account has in flight, empty while no listener runs.
    fn running_active(&self) -> std::collections::BTreeMap<String, u32> {
        self.0
            .lock()
            .ok()
            .and_then(|held| held.as_ref().map(|handle| handle.active()))
            .unwrap_or_default()
    }

    /// Stops the listener the runtime runs.
    pub(super) fn stop(&self) {
        let handle = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            handle.stop();
        }
    }

    /// Answers which model the router picks for a sample turn and why.
    pub(super) fn test_route(&self, sample: &str) -> Result<server::RouteTest, String> {
        let held = self.0.lock().map_err(|_| "Cannot reach the router.")?;
        let handle = held
            .as_ref()
            .ok_or("Turn on account balancing before testing routing.")?;
        handle.test_route(sample)
    }
}

/// One family a pool can hold.
#[derive(Debug, Serialize)]
pub(super) struct FamilyView {
    id: &'static str,
    name: &'static str,
    base_url: &'static str,
}

/// One account, with what it has served. Never its credential.
#[derive(Debug, Serialize)]
pub(super) struct AccountView {
    id: String,
    family: String,
    label: String,
    /// `key` or `account`.
    source: &'static str,
    servable: bool,
    exclusion_reason: Option<&'static str>,
    base_url: Option<String>,
    models: Vec<String>,
    enabled: bool,
    weight: u32,
    /// Whether this key takes turns once every subscription of its family is
    /// cooling or spent. A key without it never serves beside a subscription.
    overflow: bool,
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    errors: u64,
    last_used_ms: Option<i64>,
    last_error: Option<String>,
    cooldown_until_ms: Option<i64>,
    /// Turns this account has in flight right now.
    active: u32,
    /// Pi's provider id behind a subscription, empty for a key.
    pi_provider: String,
    email: Option<String>,
    plan: Option<String>,
    renews_at_ms: Option<i64>,
    /// What the subscription has left, one entry per metered window.
    windows: Vec<WindowView>,
    banked_resets: Option<u32>,
    /// Unix milliseconds of the last quota probe, none when never probed.
    quota_observed_ms: Option<i64>,
    /// Whether the router has a usage route for this account's provider.
    allowance_readable: bool,
    /// The last 30 days as `[day, requests, input, output, errors]` rows,
    /// oldest first, for the usage bar.
    days: Vec<(String, u64, u64, u64, u64)>,
}

/// One metered window of a subscription, as the card shows it.
#[derive(Debug, Serialize)]
pub(super) struct WindowView {
    label: String,
    scope: String,
    remaining_percent: f64,
    resets_at_ms: Option<i64>,
    limit_reached: bool,
}

/// One sign-in the pool can take.
#[derive(Debug, Serialize)]
pub(super) struct SubscriptionView {
    provider: &'static str,
    family: &'static str,
    label: &'static str,
}

/// One model in the running: what the classifier chooses between.
#[derive(Debug, Serialize)]
pub(super) struct OptionView {
    /// The name the classifier answers with, `family/model` unless renamed.
    key: String,
    /// The statement the classifier reads.
    description: String,
    family: String,
    model: String,
    /// The catalog's name for the model, empty when it describes none.
    name: String,
    /// `deep`, `balanced` or `fast`, empty outside the catalog.
    tier: String,
    /// US dollars per million tokens, zero outside the catalog.
    price: f64,
    output: f64,
    context: String,
    /// Whether the user's own words replaced the catalog statement.
    named: bool,
}

/// What the classifier is, with no key in it.
#[derive(Debug, Serialize)]
pub(super) struct ClassifierView {
    kind: &'static str,
    model: String,
    /// The family a pooled classifier spends, empty for the other kinds.
    family: String,
    base_url: Option<String>,
    configured: bool,
}

/// Everything Settings → Models needs about the router.
#[derive(Debug, Serialize)]
pub(super) struct RouterSettings {
    enabled: bool,
    running: bool,
    /// The loopback URL Pi holds, so a user can see where turns go.
    base_url: Option<String>,
    /// Whether Pi sends its turns to the router.
    is_default: bool,
    families: Vec<FamilyView>,
    /// The sign-ins the pool can take, one per Pi provider.
    subscriptions: Vec<SubscriptionView>,
    accounts: Vec<AccountView>,
    /// Every model an enabled account serves, in the order the classifier sees,
    /// the hidden ones too, so Settings can turn them back on.
    options: Vec<OptionView>,
    /// The `family/model` keys the picker hides, which the router leaves out of the running.
    hidden: Vec<String>,
    routes: Vec<Route>,
    fallback: Option<String>,
    min_confidence: f64,
    classifier: ClassifierView,
    classifier_connections: Vec<connections::ConnectionView>,
    /// Decision-model assistance: whether it is on, and the connection it
    /// asks, empty while it uses the model routing one.
    assist: connections::AssistView,
    served_models: Vec<String>,
}

pub(super) fn load(agent: &Path) -> Result<RouterConfig, String> {
    config::load(agent).map_err(|_| READ_ERROR.to_string())
}

pub(super) fn save(agent: &Path, config: &RouterConfig) -> Result<(), String> {
    config::save(agent, config).map_err(|_| SAVE_ERROR.to_string())
}

fn account_view(
    account: &Account,
    usage: Option<&AccountUsage>,
    active: u32,
    quota: Option<&quota::Quota>,
) -> AccountView {
    let (pi_provider, email, plan, renews_at_ms) = match &account.credential {
        Credential::Subscription {
            provider,
            email,
            plan,
            renews_at_ms,
            ..
        } => (
            provider.clone(),
            email
                .clone()
                .or_else(|| quota.and_then(|quota| quota.email.clone())),
            plan.clone()
                .or_else(|| quota.and_then(|quota| quota.plan.clone())),
            *renews_at_ms,
        ),
        Credential::ApiKey { .. } => (String::new(), None, None, None),
    };
    AccountView {
        id: account.id.clone(),
        family: account.family.clone(),
        label: account.label.clone(),
        source: account.credential.source(),
        servable: account.credential.servable(),
        exclusion_reason: if !account.enabled {
            Some("Account is turned off.")
        } else if account.weight == 0 {
            Some("Account weight is zero.")
        } else if !account.credential.servable() {
            Some("This subscription transport is not supported.")
        } else if usage.is_some_and(|usage| !usage.available(chrono::Utc::now().timestamp_millis()))
        {
            Some("Account is temporarily unavailable.")
        } else {
            None
        },
        base_url: account.base_url.clone(),
        models: account.models.clone(),
        enabled: account.enabled,
        weight: account.weight,
        overflow: account.overflow,
        requests: usage.map(|entry| entry.requests).unwrap_or(0),
        input_tokens: usage.map(|entry| entry.input_tokens).unwrap_or(0),
        output_tokens: usage.map(|entry| entry.output_tokens).unwrap_or(0),
        errors: usage.map(|entry| entry.errors).unwrap_or(0),
        last_used_ms: usage.and_then(|entry| entry.last_used_ms),
        last_error: usage.and_then(|entry| entry.last_error.clone()),
        cooldown_until_ms: usage.and_then(|entry| entry.cooldown_until_ms),
        active,
        pi_provider,
        email,
        plan,
        renews_at_ms,
        windows: quota
            .map(|quota| {
                quota
                    .windows
                    .iter()
                    .map(|window| WindowView {
                        label: window.kind.label().to_owned(),
                        scope: window.scope.clone(),
                        remaining_percent: window.remaining_percent(),
                        resets_at_ms: window.resets_at_ms,
                        limit_reached: window.limit_reached,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        banked_resets: quota.and_then(|quota| quota.banked_resets),
        quota_observed_ms: quota.map(|quota| quota.observed_at_ms),
        allowance_readable: match &account.credential {
            Credential::ApiKey { .. } => false,
            Credential::Subscription { provider, .. } => quota::has_reader(provider),
        },
        days: usage
            .map(|entry| {
                entry
                    .days
                    .iter()
                    .map(|(day, bucket)| {
                        (
                            day.clone(),
                            bucket.requests,
                            bucket.input_tokens,
                            bucket.output_tokens,
                            bucket.errors,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

pub(super) fn classifier_view(classifier: &Classifier) -> ClassifierView {
    let (base_url, family) = match classifier {
        Classifier::None => (None, String::new()),
        Classifier::Typesafe { base_url, .. } => (base_url.clone(), String::new()),
        Classifier::Pooled { family, .. } => (None, family.clone()),
        Classifier::Endpoint { base_url, .. } => (Some(base_url.clone()), String::new()),
    };
    ClassifierView {
        kind: classifier.kind(),
        model: classifier.model().to_owned(),
        family,
        base_url,
        configured: classifier.ready(),
    }
}

fn settings_with(
    agent: &Path,
    running: Option<&server::Endpoint>,
    active: &std::collections::BTreeMap<String, u32>,
) -> Result<RouterSettings, String> {
    settle_default(agent, None, false);
    let config = load(agent)?;
    let ledger = usage::load(agent);
    let quotas = quota::load(agent);
    let settings_file = agent.join("settings.json");
    let is_default = std::fs::read(&settings_file)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Map<String, Value>>(&bytes).ok())
        .is_some_and(|settings| pi_provider::is_default(&settings));
    Ok(RouterSettings {
        enabled: config.enabled,
        running: running.is_some(),
        base_url: running.map(|endpoint| endpoint.base_url()),
        is_default,
        families: FAMILIES
            .iter()
            .map(|family| FamilyView {
                id: family.id,
                name: family.name,
                base_url: family.base_url,
            })
            .collect(),
        subscriptions: SUBSCRIPTION_PROVIDERS
            .iter()
            .map(|(provider, family, label)| SubscriptionView {
                provider,
                family,
                label,
            })
            .collect(),
        accounts: config
            .accounts
            .iter()
            .map(|account| {
                account_view(
                    account,
                    ledger.account(&account.id),
                    active.get(&account.id).copied().unwrap_or(0),
                    quotas.accounts.get(&account.id),
                )
            })
            .collect(),
        options: all_options(&config)
            .into_iter()
            .map(|option| {
                let entry = model_catalog::entry(&option.family, &option.model);
                let named = config.routes.iter().any(|route| {
                    route.family == option.family
                        && route.model == option.model
                        && !route.description.trim().is_empty()
                });
                OptionView {
                    key: option.key,
                    description: option.description,
                    family: option.family,
                    model: option.model,
                    name: entry.map(|entry| entry.name.to_owned()).unwrap_or_default(),
                    tier: entry.map(|entry| entry.tier.to_owned()).unwrap_or_default(),
                    price: entry.map(|entry| entry.price).unwrap_or(0.0),
                    output: entry.map(|entry| entry.output).unwrap_or(0.0),
                    context: entry
                        .map(|entry| entry.context.to_owned())
                        .unwrap_or_default(),
                    named,
                }
            })
            .collect(),
        hidden: config.hidden.clone(),
        routes: config.routes.clone(),
        fallback: config.fallback.clone(),
        min_confidence: config.min_confidence,
        classifier: classifier_view(&config.classifier),
        classifier_connections: connections::views(agent, &config.classifier)?,
        assist: connections::assist_view(agent, &config.classifier)?,
        served_models: offered_models(&config),
    })
}

/// The router settings with what the running listener reports.
pub(super) fn settings(agent: &Path, state: &RouterState) -> Result<RouterSettings, String> {
    settings_with(
        agent,
        state.running_endpoint().as_ref(),
        &state.running_active(),
    )
}

/// The model a router default names when no decision model picks: the most
/// capable model of one family in the running, by the catalog's order, as the
/// id the picker uses for it. The family is `family` when it serves, else the
/// family of the first subscription that can serve, else the first in the
/// running.
fn pooled_default(config: &RouterConfig, family: Option<&str>) -> Option<String> {
    let running = options(config);
    let subscription = config
        .accounts
        .iter()
        .find(|account| {
            !account.is_key()
                && account.enabled
                && account.weight > 0
                && account.credential.servable()
        })
        .map(|account| account.family.as_str());
    let first = running.first().map(|option| option.family.as_str());
    let chosen = [family, subscription, first]
        .into_iter()
        .flatten()
        .find_map(|family| {
            let catalog = model_catalog::family_models(family);
            let rank = |model: &str| {
                catalog
                    .iter()
                    .position(|entry| entry.model == model)
                    .unwrap_or(usize::MAX)
            };
            running
                .iter()
                .filter(|option| option.family == family)
                .min_by_key(|option| rank(&option.model))
                .map(|option| option.key.clone())
        });
    chosen
}

/// The router models only plan refusals keep out: what the router would
/// serve if no account's plan had refused anything, less what it serves.
fn refused_models(config: &RouterConfig) -> Vec<String> {
    let served = options(config);
    let mut unrefused = config.clone();
    unrefused.refused.clear();
    options(&unrefused)
        .into_iter()
        .filter(|option| !served.iter().any(|known| known.key == option.key))
        .map(|option| option.key)
        .collect()
}

/// Names a pooled model as Pi's default where the saved one would route
/// nothing: a saved `muniment-router/auto` default while no decision model is
/// ready, a saved router model the plan of every account refused, and, with
/// `unset`, a default never saved. The router no longer offers such a model,
/// so a default left on it names a model Pi cannot find.
pub(super) fn settle_default(agent: &Path, family: Option<&str>, unset: bool) {
    let Ok(config) = load(agent) else {
        return;
    };
    let ready = config.classifier.ready();
    let refused = refused_models(&config);
    if !config.enabled || (ready && !unset && refused.is_empty()) {
        return;
    }
    let Some(model) = pooled_default(&config, family) else {
        return;
    };
    let _ = replace_default_model(agent, config::ROUTER_PROVIDER, &model, |provider, saved| {
        let routed = provider == Some(config::ROUTER_PROVIDER);
        let auto = routed && saved == Some(config::AUTO_MODEL);
        let gone = routed && saved.is_some_and(|saved| refused.iter().any(|key| key == saved));
        (auto && !ready) || gone || (unset && provider.is_none())
    });
}

/// Starts the listener when the record says on, stops it when it says off,
/// and writes Pi's `models.json` either way.
pub(super) fn apply(
    agent: &Path,
    state: &RouterState,
    config: &RouterConfig,
) -> Result<(), String> {
    let mut held = state.0.lock().map_err(|_| START_ERROR.to_string())?;
    if !config.enabled {
        if let Some(handle) = held.take() {
            handle.stop();
        }
        let _ = std::fs::remove_file(server::endpoint_path(agent));
        return write_models(agent, None, config);
    }
    if held.is_none() {
        let handle = server::start(agent.to_path_buf()).map_err(|_| START_ERROR.to_string())?;
        *held = Some(handle);
    }
    let endpoint = held
        .as_ref()
        .map(|handle| handle.endpoint().clone())
        .ok_or_else(|| START_ERROR.to_string())?;
    write_models(agent, Some(&endpoint), config)
}

/// Adds or removes the router's entry in Pi's `models.json`, under the same
/// lock every other writer of that file takes.
fn write_models(
    agent: &Path,
    endpoint: Option<&server::Endpoint>,
    config: &RouterConfig,
) -> Result<(), String> {
    let path = pi_models_file(agent);
    std::fs::create_dir_all(agent).map_err(|_| SAVE_ERROR.to_string())?;
    let _lock = lock_pi_auth_file(&path).map_err(|_| SAVE_ERROR.to_string())?;
    let mut models = read_json_for_update(&path).map_err(|_| SAVE_ERROR.to_string())?;
    match endpoint {
        Some(endpoint) => pi_provider::register(&mut models, endpoint, config),
        None => {
            if !pi_provider::unregister(&mut models) {
                return Ok(());
            }
        }
    }
    write_json_for_update(&path, &models).map_err(|_| SAVE_ERROR.to_string())
}

/// Starts the router when its record says it is on.
pub(super) fn restore(agent: &Path, state: &RouterState) {
    let Ok(config) = load(agent) else {
        return;
    };
    if !config.enabled {
        return;
    }
    let _ = apply(agent, state, &config);
}

/// Saves a changed record and applies it to the listener, then answers the
/// settings the change left.
fn commit(
    agent: &Path,
    state: &RouterState,
    config: &RouterConfig,
) -> Result<RouterSettings, String> {
    save(agent, config)?;
    apply(agent, state, config)?;
    settings(agent, state)
}

pub(super) fn set_enabled(
    agent: &Path,
    state: &RouterState,
    enabled: bool,
) -> Result<RouterSettings, String> {
    let mut config = load(agent)?;
    config.enabled = enabled;
    commit(agent, state, &config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NewAccount {
    family: String,
    label: String,
    key: String,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    models: Option<Vec<String>>,
}

pub(super) fn add_account(
    agent: &Path,
    state: &RouterState,
    account: NewAccount,
) -> Result<RouterSettings, String> {
    let NewAccount {
        family,
        label,
        key,
        base_url,
        models,
    } = account;
    if muniment_core::model_router::family::family(&family).is_none() {
        return Err("Choose a provider the router serves.".into());
    }
    let key = key.trim().to_owned();
    if key.is_empty() || key.len() > 16 * 1024 {
        return Err("Enter the account's API key.".into());
    }
    let label = label.trim().to_owned();
    if label.is_empty() || label.len() > 120 {
        return Err("Name this account, so its usage is readable.".into());
    }
    let base_url = base_url
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty());
    if let Some(url) = &base_url {
        let parsed = url::Url::parse(url).map_err(|_| "Enter a valid server URL.".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err("Enter a valid server URL.".into());
        }
    }
    let mut config = load(agent)?;
    config.accounts.push(Account {
        id: uuid::Uuid::now_v7().to_string(),
        family,
        label,
        credential: Credential::ApiKey { key },
        base_url,
        models: models
            .unwrap_or_default()
            .into_iter()
            .map(|model| model.trim().to_owned())
            .filter(|model| !model.is_empty())
            .collect(),
        enabled: true,
        weight: 1,
        overflow: false,
    });
    commit(agent, state, &config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountChange {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    weight: Option<u32>,
    #[serde(default)]
    overflow: Option<bool>,
    #[serde(default)]
    models: Option<Vec<String>>,
}

pub(super) fn update_account(
    agent: &Path,
    state: &RouterState,
    change: AccountChange,
) -> Result<RouterSettings, String> {
    let mut config = load(agent)?;
    let account = config
        .accounts
        .iter_mut()
        .find(|account| account.id == change.id)
        .ok_or_else(|| "That account is gone.".to_string())?;
    if let Some(label) = change.label {
        let label = label.trim().to_owned();
        if label.is_empty() || label.len() > 120 {
            return Err("Name this account, so its usage is readable.".into());
        }
        account.label = label;
    }
    if let Some(enabled) = change.enabled {
        account.enabled = enabled;
    }
    if let Some(weight) = change.weight {
        account.weight = weight.min(100);
    }
    if let Some(overflow) = change.overflow {
        account.overflow = overflow;
    }
    if let Some(models) = change.models {
        account.models = models
            .into_iter()
            .map(|model| model.trim().to_owned())
            .filter(|model| !model.is_empty())
            .collect();
    }
    commit(agent, state, &config)
}

pub(super) fn remove_account(
    agent: &Path,
    state: &RouterState,
    id: &str,
) -> Result<RouterSettings, String> {
    let mut config = load(agent)?;
    config.accounts.retain(|account| account.id != id);
    save(agent, &config)?;
    let mut ledger = usage::load(agent);
    ledger.forget(id);
    let _ = usage::save(agent, &ledger);
    apply(agent, state, &config)?;
    settings(agent, state)
}

/// Keeps the models the picker hides out of the running, so a routed turn
/// answers only from a model the picker offers. Each key is `family/model`.
pub(super) fn set_hidden(
    agent: &Path,
    state: &RouterState,
    keys: Vec<String>,
) -> Result<RouterSettings, String> {
    let mut keys: Vec<String> = keys.into_iter().map(|key| key.trim().to_owned()).collect();
    if keys.iter().any(|key| {
        key.len() > 300
            || key
                .split_once('/')
                .is_none_or(|(family, model)| family.is_empty() || model.is_empty())
    }) {
        return Err("Name each hidden model as provider/model.".into());
    }
    keys.sort();
    keys.dedup();
    let mut config = load(agent)?;
    if config.hidden != keys {
        config.hidden = keys;
        save(agent, &config)?;
        apply(agent, state, &config)?;
    }
    settings(agent, state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoutesChange {
    routes: Vec<Route>,
    #[serde(default)]
    fallback: Option<String>,
    #[serde(default)]
    min_confidence: Option<f64>,
}

pub(super) fn save_routes(
    agent: &Path,
    state: &RouterState,
    change: RoutesChange,
) -> Result<RouterSettings, String> {
    let RoutesChange {
        routes,
        fallback,
        min_confidence,
    } = change;
    let mut config = load(agent)?;
    for route in &routes {
        if route.key.trim().is_empty() || route.key.len() > 60 {
            return Err("Give every model a short name.".into());
        }
        if route.model.trim().is_empty() {
            return Err("Name the model this describes.".into());
        }
        if muniment_core::model_router::family::family(&route.family).is_none() {
            return Err("Name a provider the router serves.".into());
        }
        if route.description.len() > 2_000 {
            return Err("Keep a model's statement under two thousand characters.".into());
        }
    }
    config.routes = routes;
    config.fallback = fallback;
    // One name is one model: the classifier answers with a name, and `auto`
    // is the name that asks it to pick. A hidden model keeps its name.
    let running = options(&config);
    let every = all_options(&config);
    let mut keys: Vec<&str> = every.iter().map(|option| option.key.as_str()).collect();
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Two models share a name. Give each its own.".into());
    }
    if keys.contains(&config::AUTO_MODEL) {
        return Err("The name auto asks the classifier to pick. Choose another.".into());
    }
    // The fallback names a model in the running, or none and the cheapest takes it.
    if let Some(named) = &config.fallback {
        if !running.iter().any(|option| &option.key == named) {
            return Err("The fallback must be a model in the running.".into());
        }
    }
    if let Some(confidence) = min_confidence {
        config.min_confidence = confidence.clamp(0.0, 1.0);
    }
    commit(agent, state, &config)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClassifierChange {
    kind: String,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    family: Option<String>,
}

pub(super) fn set_classifier(
    agent: &Path,
    state: &RouterState,
    change: ClassifierChange,
) -> Result<RouterSettings, String> {
    let ClassifierChange {
        kind,
        api_key,
        model,
        base_url,
        family,
    } = change;
    let mut config = load(agent)?;
    let model = model
        .map(|model| model.trim().to_owned())
        .filter(|model| !model.is_empty())
        .unwrap_or_else(|| "jev-latest".to_owned());
    let key = api_key.map(|key| key.trim().to_owned()).unwrap_or_default();
    config.classifier = match kind.as_str() {
        "none" => Classifier::None,
        "typesafe" => {
            // A blank key on an already-configured classifier keeps the key
            // the user saved, because Settings never reads it back to show it.
            let key = if key.is_empty() {
                match &config.classifier {
                    Classifier::Typesafe { api_key, .. } => api_key.clone(),
                    _ => String::new(),
                }
            } else {
                key
            };
            if key.is_empty() {
                return Err("Enter your TypeSafe API key.".into());
            }
            Classifier::Typesafe {
                api_key: key,
                model,
                base_url: base_url
                    .map(|url| url.trim().to_owned())
                    .filter(|url| !url.is_empty()),
                max_options: None,
                limits: Default::default(),
            }
        }
        "pooled" => {
            let family = family.unwrap_or_default();
            if muniment_core::model_router::family::family(&family).is_none() {
                return Err("Choose a provider the router serves.".into());
            }
            if !config
                .accounts
                .iter()
                .any(|account| account.family == family)
            {
                return Err("Add an account for that provider first.".into());
            }
            Classifier::Pooled { family, model }
        }
        "endpoint" => {
            let url = base_url
                .map(|url| url.trim().to_owned())
                .filter(|url| !url.is_empty())
                .ok_or_else(|| "Enter the classifier's URL.".to_string())?;
            let parsed =
                url::Url::parse(&url).map_err(|_| "Enter a valid classifier URL.".to_string())?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
                return Err("Enter a valid classifier URL.".into());
            }
            // A blank key keeps the one saved, as the TypeSafe form does.
            let key = if key.is_empty() {
                match &config.classifier {
                    Classifier::Endpoint {
                        api_key: Some(saved),
                        ..
                    } => saved.clone(),
                    _ => String::new(),
                }
            } else {
                key
            };
            Classifier::Endpoint {
                base_url: url,
                api_key: Some(key).filter(|key| !key.is_empty()),
                model,
                max_options: None,
                limits: Default::default(),
            }
        }
        _ => return Err("Choose a classifier.".into()),
    };
    commit(agent, state, &config)
}

/// Asks the saved classifier one routing question.
pub(super) fn test_classifier(agent: &Path) -> Result<(), String> {
    let config = load(agent)?;
    classify::check(&config.classifier, CLASSIFIER_TIMEOUT)
}

/// Lifts the credential a pool sign-in left in its scratch directory into the
/// router as one more account, and answers with the account id. The probe
/// that names the account by its email runs after, off the sign-in thread.
pub(super) fn import_pi_sign_in(
    agent: &Path,
    state: &RouterState,
    scratch: &Path,
    provider: &str,
) -> Result<String, String> {
    family_for_pi_provider(provider)
        .ok_or_else(|| "This provider has no subscription the router can pool.".to_string())?;
    let auth: serde_json::Map<String, Value> = std::fs::read(scratch.join("auth.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| "The sign-in finished without a credential. Try again.".to_string())?;
    let entry = auth
        .get(provider)
        .ok_or_else(|| "The sign-in finished without a credential. Try again.".to_string())?;
    let credential = Credential::from_pi_auth(provider, entry)
        .ok_or_else(|| "The sign-in left a credential the router cannot hold.".to_string())?;
    import_credential(agent, state, provider, credential, None)
}

/// Imports a subscription credential into its family's pool, named by its email
/// or the name the sign-in learned, else by its place in the pool, and probes
/// what it has left. Answers with the account id.
pub(super) fn import_credential(
    agent: &Path,
    state: &RouterState,
    provider: &str,
    credential: Credential,
    name: Option<String>,
) -> Result<String, String> {
    let family = family_for_pi_provider(provider)
        .ok_or_else(|| "This provider has no subscription the router can pool.".to_string())?;
    let mut credential = credential;
    quota::identify_claude(&mut credential, quota::TIMEOUT);
    // Identify older opaque credentials outside the settings lock. Apply each
    // answer only if another sign-in has not replaced that credential.
    let mut identities = Vec::new();
    if provider == "anthropic" {
        for account in load(agent)?.accounts {
            let original = account.credential;
            let mut identified = original.clone();
            quota::identify_claude(&mut identified, quota::TIMEOUT);
            if identified != original {
                identities.push((account.id, original, identified));
            }
        }
    }
    let lock = lock_pi_auth_file(&config::config_path(agent))?;
    let mut config = load(agent)?;
    for (id, original, identified) in identities {
        if let Some(account) = config
            .accounts
            .iter_mut()
            .find(|account| account.id == id && account.credential == original)
        {
            account.credential = identified;
        }
    }
    // A pooled subscription serves through the router alone, so the account
    // that joins turns the router on.
    config.enabled = true;
    let count = config.pool(family.id).len() + 1;
    let id = config.import_account(Account {
        id: uuid::Uuid::now_v7().to_string(),
        family: family.id.to_owned(),
        label: credential
            .clone()
            .into_email()
            .or(name)
            .unwrap_or_else(|| format!("{} account {count}", family.name)),
        credential,
        base_url: None,
        models: Vec::new(),
        enabled: true,
        weight: 1,
        overflow: false,
    });
    save(agent, &config)?;
    drop(lock);
    apply(agent, state, &config)?;
    settle_default(agent, Some(family.id), true);
    // The probe names the account and fills its windows. It is a network call,
    // so it runs off the sign-in thread and the screen catches up on reload.
    let probe_agent = agent.to_path_buf();
    let probe_id = id.clone();
    std::thread::spawn(move || {
        let _ = refresh_quota(&probe_agent, &probe_id);
    });
    Ok(id)
}

/// Asks the account's upstream what it has left, stores the answer, and names
/// the account by its email when the sign-in did not. Answers whether the
/// upstream said anything.
fn refresh_quota(agent: &Path, id: &str) -> Result<bool, String> {
    let now = chrono::Utc::now().timestamp_millis();
    let account =
        muniment_core::model_router::native_auth::refresh_account(agent, id, now, quota::TIMEOUT)?;
    let original = account.credential.clone();
    let probed = quota::probe(&account, now, quota::TIMEOUT);
    save_probe(agent, id, &original, account.credential.clone(), probed)
}

/// Refreshes what one account has left, or every subscription's when no id
/// is named, then answers the settings.
pub(super) fn refresh_quotas(
    agent: &Path,
    state: &RouterState,
    id: Option<String>,
) -> Result<RouterSettings, String> {
    let ids: Vec<String> = match id {
        Some(id) => vec![id],
        None => load(agent)?
            .accounts
            .iter()
            .filter(|account| account.credential.pi_provider().is_some())
            .map(|account| account.id.clone())
            .collect(),
    };
    for id in ids {
        let _ = refresh_quota(agent, &id);
    }
    settings(agent, state)
}

/// A probe can outlast a sign-in or another pool edit. Apply its answer to
/// the current account only if it still holds the credential we probed.
fn save_probe(
    agent: &Path,
    id: &str,
    original: &Credential,
    refreshed: Credential,
    probed: Option<quota::Quota>,
) -> Result<bool, String> {
    let _lock = lock_pi_auth_file(&config::config_path(agent))?;
    let mut config = load(agent)?;
    let Some(account) = config.accounts.iter_mut().find(|account| account.id == id) else {
        return Ok(false);
    };
    if &account.credential != original {
        return Ok(false);
    }
    account.credential = refreshed;
    let Some(probed) = probed else {
        // The refresh alone is worth keeping.
        save(agent, &config)?;
        return Ok(false);
    };
    // What the upstream said about the account itself outlives the probe: the
    // email names an account the sign-in left unnamed, and the plan is shown.
    let placeholder = account
        .label
        .rsplit_once(" account ")
        .is_some_and(|(prefix, suffix)| {
            suffix.parse::<usize>().is_ok()
                && muniment_core::model_router::family::family(&account.family)
                    .is_some_and(|f| f.name == prefix)
        });
    if let Credential::Subscription { email, plan, .. } = &mut account.credential {
        if email.is_none() && probed.email.is_some() {
            *email = probed.email.clone();
        }
        if probed.plan.is_some() {
            *plan = probed.plan.clone();
        }
    }
    if placeholder {
        if let Some(email) = account.email().map(str::to_owned) {
            account.label = email;
        }
    }
    save(agent, &config)?;
    let mut store = quota::load(agent);
    store.accounts.insert(id.to_owned(), probed);
    quota::save(agent, &store).map_err(|_| SAVE_ERROR.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_core::model_router::usage::Ledger;

    fn account(id: &str) -> Account {
        Account {
            id: id.to_owned(),
            family: "openai".into(),
            label: "work".into(),
            credential: Credential::ApiKey {
                key: "sk-secret".into(),
            },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 2,
            overflow: false,
        }
    }

    #[test]
    fn a_delayed_probe_keeps_new_sign_ins_and_unrelated_pool_edits() {
        let agent = std::env::temp_dir().join(format!("muniment-probe-{}", uuid::Uuid::now_v7()));
        let original = account("first");
        let refreshed = Credential::ApiKey {
            key: "refreshed".into(),
        };
        let other = account("other");
        let mut config = RouterConfig {
            accounts: vec![original.clone(), other.clone()],
            ..RouterConfig::default()
        };
        config::save(&agent, &config).unwrap();
        let probe = quota::Quota {
            plan: Some("pro".into()),
            ..quota::Quota::default()
        };
        assert!(save_probe(
            &agent,
            "first",
            &original.credential,
            refreshed.clone(),
            Some(probe.clone())
        )
        .unwrap());
        config.accounts[0].credential = refreshed;
        assert_eq!(config::load(&agent).unwrap(), config);
        assert_eq!(quota::load(&agent).accounts["first"], probe);

        // A browser sign-in completes while the next probe waits upstream.
        let current = Credential::ApiKey {
            key: "new-sign-in".into(),
        };
        config.accounts[0].credential = current;
        config::save(&agent, &config).unwrap();
        let quota_before = std::fs::read(quota::quota_path(&agent)).unwrap();
        assert!(!save_probe(
            &agent,
            "first",
            &original.credential,
            original.credential.clone(),
            Some(quota::Quota::default())
        )
        .unwrap());
        assert_eq!(config::load(&agent).unwrap(), config);
        assert_eq!(
            std::fs::read(quota::quota_path(&agent)).unwrap(),
            quota_before
        );

        config.accounts.remove(0);
        config::save(&agent, &config).unwrap();
        assert!(!save_probe(
            &agent,
            "first",
            &original.credential,
            original.credential.clone(),
            None
        )
        .unwrap());
        assert_eq!(config::load(&agent).unwrap(), config);
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn an_account_view_carries_its_counters_and_never_its_key() {
        let mut ledger = Ledger::default();
        ledger.record_success("a1", "2026-09-17", 1_000, 300, 40);
        ledger.record_error("a1", "2026-09-17", 2_000, "429 slow down", true);
        let view = account_view(&account("a1"), ledger.account("a1"), 2, None);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("sk-secret"), "{json}");
        assert_eq!(view.source, "key");
        assert_eq!(view.requests, 1);
        assert_eq!(view.input_tokens, 300);
        assert_eq!(view.errors, 1);
        assert_eq!(view.weight, 2);
        assert!(!view.overflow);
        assert!(view.cooldown_until_ms.is_some());
        assert_eq!(view.days.len(), 1);
        assert_eq!(view.days[0].0, "2026-09-17");
        assert_eq!(view.active, 2);
        assert!(!view.allowance_readable);
    }

    fn subscription(id: &str) -> Account {
        let mut account = account(id);
        account.credential = Credential::Subscription {
            provider: "openai-codex".into(),
            access: format!("access-{id}"),
            refresh: None,
            expires_ms: None,
            account_id: Some(id.into()),
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        account
    }

    fn agent_with(config: &RouterConfig) -> std::path::PathBuf {
        let agent =
            std::env::temp_dir().join(format!("muniment-router-default-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&agent).unwrap();
        config::save(&agent, config).unwrap();
        agent
    }

    fn saved_default(agent: &Path) -> (Option<String>, Option<String>) {
        let settings: Value = std::fs::read(agent.join("settings.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let text = |key: &str| settings[key].as_str().map(str::to_owned);
        (text("defaultProvider"), text("defaultModel"))
    }

    fn typesafe() -> Classifier {
        Classifier::Typesafe {
            api_key: "apikey_1".into(),
            model: "jev-latest".into(),
            base_url: None,
            max_options: None,
            limits: Default::default(),
        }
    }

    fn choose_default(agent: &Path, provider: &str, model: &str) {
        super::super::providers::set_default_model(agent, provider, model).unwrap();
    }

    fn router_default(model: &str) -> (Option<String>, Option<String>) {
        (Some("muniment-router".into()), Some(model.into()))
    }

    #[test]
    fn a_saved_automatic_default_becomes_a_pooled_model_while_no_decision_model_is_ready() {
        let mut config = RouterConfig {
            enabled: true,
            accounts: vec![account("k1"), subscription("s1")],
            ..RouterConfig::default()
        };
        let agent = agent_with(&config);
        choose_default(&agent, "muniment-router", "auto");
        settle_default(&agent, None, false);
        // The family's most capable model, as the picker names a router model.
        assert_eq!(saved_default(&agent), router_default("openai/gpt-6-astra"));
        // The rewrite happens once: a model the user picks after it stays.
        choose_default(&agent, "muniment-router", "openai/gpt-5.6-luna");
        settle_default(&agent, None, false);
        assert_eq!(saved_default(&agent), router_default("openai/gpt-5.6-luna"));
        // A ready decision model keeps automatic routing.
        config.classifier = typesafe();
        config::save(&agent, &config).unwrap();
        choose_default(&agent, "muniment-router", "auto");
        settle_default(&agent, None, false);
        assert_eq!(saved_default(&agent), router_default("auto"));
        // Reading the settings rewrites it once the decision model goes, and
        // the settings offer no automatic model.
        config.classifier = Classifier::None;
        config::save(&agent, &config).unwrap();
        let settings = settings_with(&agent, None, &Default::default()).unwrap();
        assert_eq!(saved_default(&agent), router_default("openai/gpt-6-astra"));
        assert!(!settings.served_models.is_empty());
        assert!(settings.served_models.iter().all(|model| model != "auto"));
        config.classifier = typesafe();
        config::save(&agent, &config).unwrap();
        let settings = settings_with(&agent, None, &Default::default()).unwrap();
        assert_eq!(settings.served_models[0], "auto");
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_saved_default_every_plan_refused_becomes_another_pooled_model() {
        let config = RouterConfig {
            enabled: true,
            accounts: vec![subscription("s1"), subscription("s2")],
            classifier: typesafe(),
            ..RouterConfig::default()
        };
        let agent = agent_with(&config);
        choose_default(&agent, "muniment-router", "openai/gpt-6-astra");
        let now = chrono::Utc::now().timestamp_millis();
        let mut ledger = usage::Ledger::default();
        ledger.record_refusal("s1", "gpt-6-astra", now);
        usage::save(&agent, &ledger).unwrap();
        // One account still offers it, so the default stays.
        settle_default(&agent, None, false);
        assert_eq!(saved_default(&agent), router_default("openai/gpt-6-astra"));
        ledger.record_refusal("s2", "gpt-6-astra", now);
        usage::save(&agent, &ledger).unwrap();
        let settings = settings_with(&agent, None, &Default::default()).unwrap();
        let (provider, model) = saved_default(&agent);
        assert_eq!(provider.as_deref(), Some("muniment-router"));
        let model = model.unwrap();
        assert!(model.starts_with("openai/"), "{model}");
        assert_ne!(model, "openai/gpt-6-astra");
        assert!(settings.served_models.contains(&model));
        assert!(!settings
            .served_models
            .contains(&"openai/gpt-6-astra".to_owned()));
        // Once the refusals expire, a default the user picks stays.
        usage::save(&agent, &usage::Ledger::default()).unwrap();
        choose_default(&agent, "muniment-router", "openai/gpt-6-astra");
        settle_default(&agent, None, false);
        assert_eq!(saved_default(&agent), router_default("openai/gpt-6-astra"));
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_sign_in_names_a_pooled_default_and_never_auto() {
        let mut claude = subscription("c1");
        claude.family = "anthropic".into();
        let config = RouterConfig {
            enabled: true,
            accounts: vec![account("k1"), claude],
            ..RouterConfig::default()
        };
        let agent = agent_with(&config);
        // A read never claims a default the user has not saved.
        settle_default(&agent, None, false);
        assert_eq!(saved_default(&agent), (None, None));
        // The sign-in names its own family's model.
        settle_default(&agent, Some("anthropic"), true);
        assert_eq!(
            saved_default(&agent),
            router_default("anthropic/claude-opus-5")
        );
        // A default the user saved stays through the next sign-in.
        choose_default(&agent, "ollama", "llama3.2:3b");
        settle_default(&agent, Some("anthropic"), true);
        assert_eq!(
            saved_default(&agent),
            (Some("ollama".into()), Some("llama3.2:3b".into()))
        );
        // A sign-in replaces a saved automatic default no decision model serves.
        choose_default(&agent, "muniment-router", "auto");
        settle_default(&agent, Some("anthropic"), true);
        assert_eq!(
            saved_default(&agent),
            router_default("anthropic/claude-opus-5")
        );
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn an_account_change_sets_overflow_and_leaves_it_when_unnamed() {
        let config = RouterConfig {
            accounts: vec![account("k1"), subscription("s1")],
            ..RouterConfig::default()
        };
        let agent = agent_with(&config);
        let state = RouterState::default();
        let change: AccountChange =
            serde_json::from_value(serde_json::json!({ "id": "k1", "overflow": true })).unwrap();
        let settings = update_account(&agent, &state, change).unwrap();
        assert!(settings.accounts[0].overflow);
        assert!(!settings.accounts[1].overflow);
        assert!(config::load(&agent).unwrap().accounts[0].overflow);
        let json = serde_json::to_value(&settings).unwrap();
        assert_eq!(json["accounts"][0]["overflow"], true);
        // A change that names no overflow keeps the saved one.
        let change: AccountChange =
            serde_json::from_value(serde_json::json!({ "id": "k1", "weight": 3 })).unwrap();
        let settings = update_account(&agent, &state, change).unwrap();
        assert!(settings.accounts[0].overflow);
        assert_eq!(settings.accounts[0].weight, 3);
        let change: AccountChange =
            serde_json::from_value(serde_json::json!({ "id": "k1", "overflow": false })).unwrap();
        assert!(!update_account(&agent, &state, change).unwrap().accounts[0].overflow);
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn an_account_that_has_served_nothing_reads_as_zero() {
        let view = account_view(&account("a1"), None, 0, None);
        assert_eq!(view.requests, 0);
        assert_eq!(view.last_used_ms, None);
        assert!(view.days.is_empty());
        assert_eq!(view.active, 0);
    }

    #[test]
    fn a_classifier_view_names_its_kind_and_never_its_key() {
        let view = classifier_view(&Classifier::Typesafe {
            api_key: "apikey_secret".into(),
            model: "jev-latest".into(),
            base_url: None,
            max_options: None,
            limits: Default::default(),
        });
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("apikey_secret"), "{json}");
        assert_eq!(view.kind, "typesafe");
        assert_eq!(view.model, "jev-latest");
        assert!(view.configured);

        let off = classifier_view(&Classifier::None);
        assert_eq!(off.kind, "none");
        assert!(!off.configured);
    }

    #[test]
    fn the_router_entry_lands_in_pi_models_and_leaves_when_it_is_turned_off() {
        let agent =
            std::env::temp_dir().join(format!("muniment-router-cmd-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(
            agent.join("models.json"),
            serde_json::json!({ "providers": { "ollama": { "baseUrl": "http://localhost:11434/v1" } } })
                .to_string(),
        )
        .unwrap();
        let config = RouterConfig {
            enabled: true,
            routes: vec![Route {
                key: "fast".into(),
                description: "A short question".into(),
                family: "openai".into(),
                model: "gpt-5.6-mini".into(),
            }],
            fallback: Some("fast".into()),
            ..RouterConfig::default()
        };
        let endpoint = server::Endpoint {
            port: 8421,
            token: "t0ken".into(),
        };
        write_models(&agent, Some(&endpoint), &config).unwrap();
        let written: Value =
            serde_json::from_slice(&std::fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert_eq!(
            written["providers"]["muniment-router"]["baseUrl"],
            "http://127.0.0.1:8421/v1"
        );
        assert!(written["providers"]["ollama"].is_object());

        write_models(&agent, None, &config).unwrap();
        let written: Value =
            serde_json::from_slice(&std::fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert!(written["providers"].get("muniment-router").is_none());
        assert!(written["providers"]["ollama"].is_object());
    }

    #[test]
    fn the_runtime_starts_the_listener_its_record_turns_on_and_stops_it_when_turned_off() {
        let agent =
            std::env::temp_dir().join(format!("muniment-router-run-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&agent).unwrap();
        let state = RouterState::default();
        restore(&agent, &state);
        assert!(state.running_endpoint().is_none());

        let on = set_enabled(&agent, &state, true).unwrap();
        assert!(on.running);
        let endpoint = state.running_endpoint().unwrap();
        assert_eq!(server::read_endpoint(&agent), Some(endpoint.clone()));
        let written: Value =
            serde_json::from_slice(&std::fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert_eq!(
            written["providers"]["muniment-router"]["baseUrl"],
            endpoint.base_url()
        );

        // A restarted runtime finds the record on and starts a new listener.
        state.stop();
        assert!(state.running_endpoint().is_none());
        let restarted = RouterState::default();
        restore(&agent, &restarted);
        let again = restarted.running_endpoint().unwrap();
        let written: Value =
            serde_json::from_slice(&std::fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert_eq!(
            written["providers"]["muniment-router"]["baseUrl"],
            again.base_url()
        );

        let off = set_enabled(&agent, &restarted, false).unwrap();
        assert!(!off.running);
        assert!(restarted.running_endpoint().is_none());
        assert!(server::read_endpoint(&agent).is_none());
        let written: Value =
            serde_json::from_slice(&std::fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert!(written["providers"].get("muniment-router").is_none());
        std::fs::remove_dir_all(agent).unwrap();
    }
}
