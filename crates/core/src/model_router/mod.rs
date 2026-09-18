//! The multi-account model router: many accounts per provider, one loopback
//! endpoint, and an optional classifier that picks the model per turn.
//!
//! Pi reaches one model at a time through one credential per provider id in
//! its `auth.json`. A user with three OpenAI accounts and two Anthropic
//! accounts cannot say so there. The router holds those pools itself, answers
//! as one OpenAI-compatible provider on loopback, and spreads each turn across
//! the accounts of whichever family serves it.
//!
//! Routing is optional at every level. The router off leaves Pi on its own
//! provider. The router on with no classifier still balances a pool. A
//! classifier configured turns one route into a per-turn choice.

pub mod balance;
pub mod classify;
pub mod config;
pub mod family;
pub mod model_catalog;
pub mod pi_provider;
pub mod quota;
pub mod server;
pub mod usage;
pub mod wire;

use classify::Reason;
use config::{Route, RouterConfig, AUTO_MODEL};
use usage::Ledger;

/// Which account serves this turn, on which model, and how it was picked.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    /// The account that takes the turn.
    pub account_id: String,
    pub account_label: String,
    pub family: String,
    /// The model the upstream is asked for.
    pub model: String,
    /// The route that named the model, empty when the request named it.
    pub route: String,
    pub reason: Reason,
    pub confidence: f64,
    /// The account a pooled classifier spent to pick this route, and its cost.
    pub classifier_spent_on: Option<String>,
    pub classifier_spent: wire::Tokens,
}

/// Why a turn could not be served.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveError {
    /// The request named a model the router does not serve.
    UnknownModel(String),
    /// The request asked the classifier to pick, and no route exists.
    NoRoute,
    /// A pool could not answer.
    Pool(balance::PickError),
}

impl ResolveError {
    pub fn message(&self) -> String {
        match self {
            Self::UnknownModel(model) => {
                format!("The router does not serve the model {model}.")
            }
            Self::NoRoute => {
                "No model is in the running. Add an account in Settings → Models.".into()
            }
            Self::Pool(error) => error.message(),
        }
    }
}

/// Every model in the running: each model an enabled account can serve, keyed
/// `family/model` and described by the catalog statement the classifier reads.
///
/// The set is the pool, not a list anyone maintains: connect an account and
/// its models are in the running at once. A user route replaces the entry for
/// its model, taking that entry's place under its own name and words, so one
/// model is never two options.
pub fn options(config: &RouterConfig) -> Vec<Route> {
    let mut options: Vec<Route> = Vec::new();
    for account in config
        .accounts
        .iter()
        .filter(|account| account.enabled && account.weight > 0 && account.credential.servable())
    {
        // An account that names no model serves every model of its family.
        let models: Vec<String> = if account.models.is_empty() {
            model_catalog::family_models(&account.family)
                .iter()
                .map(|entry| entry.model.to_owned())
                .collect()
        } else {
            account.models.clone()
        };
        for model in models {
            let key = format!("{}/{}", account.family, model);
            if options.iter().any(|known| known.key == key) {
                continue;
            }
            // A model the catalog does not describe still runs. Its id is all
            // the classifier gets, so a user route is the way to describe it.
            let description = model_catalog::entry(&account.family, &model)
                .map(|entry| entry.statement())
                .unwrap_or_else(|| format!("The model {model}, which carries no description."));
            options.push(Route {
                key,
                description,
                family: account.family.clone(),
                model,
            });
        }
    }
    for route in &config.routes {
        let Some(existing) = options
            .iter_mut()
            .find(|known| known.family == route.family && known.model == route.model)
        else {
            continue;
        };
        if !route.key.trim().is_empty() {
            existing.key = route.key.clone();
        }
        if !route.description.trim().is_empty() {
            existing.description = route.description.clone();
        }
    }
    options
}

/// The option a turn takes with no classification: the one the configuration
/// names, else the cheapest model in the running, else the first option.
pub fn fallback<'a>(config: &RouterConfig, options: &'a [Route]) -> Option<&'a Route> {
    if let Some(named) = config
        .fallback
        .as_deref()
        .and_then(|key| options.iter().find(|option| option.key == key))
    {
        return Some(named);
    }
    options
        .iter()
        .min_by(|left, right| {
            let price = |route: &Route| {
                model_catalog::entry(&route.family, &route.model)
                    .map(|entry| entry.price)
                    // A model with no catalog price sorts last, never first:
                    // an unknown cost is not a cheap one.
                    .unwrap_or(f64::MAX)
            };
            price(left).total_cmp(&price(right))
        })
        .or_else(|| options.first())
}

/// Whether a turn is classified: it takes a ready classifier and two models in
/// the running to choose between.
pub fn classifies(config: &RouterConfig, options: &[Route]) -> bool {
    config.classifier.ready() && options.len() > 1
}

/// The models the router serves, as an OpenAI-compatible list: `auto` while
/// anything is in the running, then every option by name.
pub fn served_models(config: &RouterConfig) -> Vec<String> {
    let options = options(config);
    let mut models = Vec::new();
    if !options.is_empty() {
        models.push(AUTO_MODEL.to_owned());
    }
    for option in &options {
        if !models.iter().any(|known| known == &option.key) {
            models.push(option.key.clone());
        }
    }
    models
}

/// Where a turn is bound before any account is picked. One turn makes one
/// plan, so a failover picks another account without classifying again.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub family: String,
    pub model: String,
    pub route: String,
    pub reason: Reason,
    pub confidence: f64,
    /// The account a pooled classifier spent to make this plan, and its cost.
    pub classifier_spent_on: Option<String>,
    pub classifier_spent: wire::Tokens,
}

/// The plan for one turn: `auto` classifies, a route key takes that route, and
/// `family/model` takes that pair.
pub fn plan(
    config: &RouterConfig,
    ledger: &Ledger,
    requested: &str,
    state: &str,
    now_ms: i64,
) -> Result<Plan, ResolveError> {
    /// A plan that no classifier made: the request named its own destination.
    fn named(family: String, model: String, route: String) -> Plan {
        Plan {
            family,
            model,
            route,
            reason: Reason::NotClassified,
            confidence: 0.0,
            classifier_spent_on: None,
            classifier_spent: wire::Tokens::default(),
        }
    }

    let options = options(config);
    if requested == AUTO_MODEL {
        let decision = classify::decide(config, &options, ledger, state, now_ms, classify::TIMEOUT)
            .ok_or(ResolveError::NoRoute)?;
        return Ok(Plan {
            family: decision.route.family.clone(),
            model: decision.route.model.clone(),
            route: decision.route.key.clone(),
            reason: decision.reason,
            confidence: decision.confidence,
            classifier_spent_on: decision.spent_on,
            classifier_spent: decision.spent,
        });
    }
    if let Some(option) = options.iter().find(|option| option.key == requested) {
        return Ok(named(
            option.family.clone(),
            option.model.clone(),
            option.key.clone(),
        ));
    }
    // The router serves what it lists and nothing else, so a pair no account
    // serves is not found rather than found and then unservable.
    Err(ResolveError::UnknownModel(requested.to_owned()))
}

/// The account that serves this turn.
pub fn resolve(
    config: &RouterConfig,
    ledger: &Ledger,
    requested_model: &str,
    state: &str,
    now_ms: i64,
) -> Result<Resolution, ResolveError> {
    let plan = plan(config, ledger, requested_model, state, now_ms)?;
    let account = balance::pick(config, ledger, &plan.family, &plan.model, now_ms)
        .map_err(ResolveError::Pool)?;
    Ok(Resolution {
        account_id: account.id.clone(),
        account_label: account.label.clone(),
        family: plan.family,
        model: plan.model,
        route: plan.route,
        reason: plan.reason,
        confidence: plan.confidence,
        classifier_spent_on: plan.classifier_spent_on,
        classifier_spent: plan.classifier_spent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Account, Classifier, Credential, Route};

    fn account(id: &str, family: &str) -> Account {
        Account {
            id: id.to_owned(),
            family: family.to_owned(),
            label: format!("{family} {id}"),
            credential: Credential::ApiKey { key: "sk".into() },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 1,
        }
    }

    /// Two OpenAI accounts and one Anthropic, with two options renamed by the
    /// user. Every catalog model of both families is in the running.
    fn pooled() -> RouterConfig {
        RouterConfig {
            enabled: true,
            accounts: vec![
                account("o1", "openai"),
                account("o2", "openai"),
                account("c1", "anthropic"),
            ],
            classifier: Classifier::None,
            routes: vec![
                Route {
                    key: "fast".into(),
                    description: "A short question".into(),
                    family: "openai".into(),
                    model: "gpt-5.6-luna".into(),
                },
                Route {
                    key: "deep".into(),
                    description: "A long reasoning task".into(),
                    family: "anthropic".into(),
                    model: "claude-opus-5".into(),
                },
            ],
            fallback: Some("fast".into()),
            min_confidence: 0.6,
        }
    }

    #[test]
    fn every_model_an_enabled_account_serves_is_in_the_running() {
        let mut config = pooled();
        let running = options(&config);
        // Four OpenAI models and three Anthropic, from the catalog.
        assert_eq!(running.len(), 7);
        assert!(running.iter().all(|option| !option.description.is_empty()));
        // The user's two routes took their models' places under their names.
        assert_eq!(
            running.iter().filter(|option| option.key == "fast").count(),
            1
        );
        let fast = running.iter().find(|option| option.key == "fast").unwrap();
        assert_eq!(fast.model, "gpt-5.6-luna");
        assert_eq!(fast.description, "A short question");
        // An option the user did not name keeps its pair and its statement.
        let sol = running
            .iter()
            .find(|option| option.model == "gpt-5.6-sol")
            .unwrap();
        assert_eq!(sol.key, "openai/gpt-5.6-sol");
        assert!(sol.description.contains("Agentic coding"));
        // No model appears twice, whatever the account count.
        let mut keys: Vec<&str> = running.iter().map(|option| option.key.as_str()).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before);

        // An account that names models serves those and no others.
        config.accounts[2].models = vec!["claude-opus-5".into()];
        let running = options(&config);
        assert_eq!(running.len(), 5);
        assert!(running
            .iter()
            .all(|option| option.model != "claude-haiku-4-5"));
    }

    #[test]
    fn a_turned_off_account_puts_nothing_in_the_running() {
        let mut config = pooled();
        config.accounts[2].enabled = false;
        assert!(options(&config)
            .iter()
            .all(|option| option.family != "anthropic"));
        config.accounts[0].weight = 0;
        config.accounts[1].weight = 0;
        assert!(options(&config).is_empty());
        assert!(served_models(&config).is_empty());
    }

    #[test]
    fn a_model_the_catalog_does_not_describe_still_runs() {
        let mut config = pooled();
        config.accounts[0].models = vec!["gpt-7-unreleased".into()];
        config.accounts[1].models = vec!["gpt-7-unreleased".into()];
        config.accounts[2].models = vec!["claude-opus-5".into()];
        let running = options(&config);
        let stray = running
            .iter()
            .find(|option| option.model == "gpt-7-unreleased")
            .unwrap();
        assert_eq!(stray.key, "openai/gpt-7-unreleased");
        assert!(stray.description.contains("no description"));
    }

    #[test]
    fn the_router_serves_auto_and_every_model_in_the_running() {
        let served = served_models(&pooled());
        assert_eq!(served[0], "auto");
        assert_eq!(served.len(), 8);
        assert!(served.iter().any(|model| model == "fast"));
        assert!(served.iter().any(|model| model == "deep"));
        assert!(served.iter().any(|model| model == "openai/gpt-6-astra"));
        assert!(served_models(&RouterConfig::default()).is_empty());
    }

    #[test]
    fn the_fallback_is_the_named_one_and_otherwise_the_cheapest_in_the_running() {
        let mut config = pooled();
        let running = options(&config);
        assert_eq!(fallback(&config, &running).unwrap().key, "fast");
        // With none named, the cheapest model in the running takes the turn.
        config.fallback = None;
        assert_eq!(fallback(&config, &running).unwrap().model, "gpt-5.6-luna");
        // A name that no longer matches an option falls back the same way.
        config.fallback = Some("gone".into());
        assert_eq!(fallback(&config, &running).unwrap().model, "gpt-5.6-luna");
        assert_eq!(fallback(&config, &[]), None);
    }

    #[test]
    fn classifying_takes_a_ready_classifier_and_two_models_to_choose_between() {
        let mut config = pooled();
        let running = options(&config);
        assert!(!classifies(&config, &running));
        config.classifier = Classifier::Typesafe {
            api_key: "apikey_1".into(),
            model: "jev-latest".into(),
            base_url: None,
        };
        assert!(classifies(&config, &running));
        assert!(!classifies(&config, &running[..1]));
    }

    #[test]
    fn auto_with_no_classifier_takes_the_fallback_and_spreads_the_pool() {
        let config = pooled();
        let mut ledger = Ledger::default();
        let first = resolve(&config, &ledger, "auto", "hello", 1_000).unwrap();
        assert_eq!(first.family, "openai");
        assert_eq!(first.model, "gpt-5.6-luna");
        assert_eq!(first.route, "fast");
        assert_eq!(first.reason, Reason::NotClassified);
        assert_eq!(first.account_id, "o1");
        ledger.record_success("o1", "2026-09-17", 1_000, 1, 1);
        let second = resolve(&config, &ledger, "auto", "hello", 1_100).unwrap();
        assert_eq!(second.account_id, "o2");
    }

    #[test]
    fn a_model_in_the_running_pins_the_turn_to_itself() {
        let config = pooled();
        let ledger = Ledger::default();
        // By the name the user gave it.
        let named = resolve(&config, &ledger, "deep", "hello", 1_000).unwrap();
        assert_eq!(named.family, "anthropic");
        assert_eq!(named.model, "claude-opus-5");
        assert_eq!(named.account_id, "c1");
        // And by its pair.
        let pair = resolve(&config, &ledger, "openai/gpt-5.6-sol", "hello", 1_000).unwrap();
        assert_eq!(pair.model, "gpt-5.6-sol");
        assert_eq!(pair.route, "openai/gpt-5.6-sol");
    }

    #[test]
    fn a_model_not_in_the_running_is_not_served() {
        let config = pooled();
        let ledger = Ledger::default();
        assert_eq!(
            resolve(&config, &ledger, "gpt-5.6-sol", "hello", 1_000),
            Err(ResolveError::UnknownModel("gpt-5.6-sol".into()))
        );
        // A pair whose family holds no account is not in the running either.
        assert_eq!(
            resolve(&config, &ledger, "kimi/kimi-k3", "hello", 1_000),
            Err(ResolveError::UnknownModel("kimi/kimi-k3".into()))
        );
        assert_eq!(
            resolve(&RouterConfig::default(), &ledger, "auto", "hello", 1_000),
            Err(ResolveError::NoRoute)
        );
        assert!(ResolveError::NoRoute.message().contains("Add an account"));
    }
}
