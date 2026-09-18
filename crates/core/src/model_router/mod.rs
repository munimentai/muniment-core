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
pub mod pi_provider;
pub mod server;
pub mod usage;
pub mod wire;

use classify::Reason;
use config::{RouterConfig, AUTO_MODEL};
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
            Self::NoRoute => "The router has no route. Add one in Settings → Models.".into(),
            Self::Pool(error) => error.message(),
        }
    }
}

/// The models the router serves, as an OpenAI-compatible list: `auto` when
/// there is a route to take, then each route by name, then every
/// `family/model` pair a route names.
pub fn served_models(config: &RouterConfig) -> Vec<String> {
    let mut models = Vec::new();
    if config.fallback_route().is_some() {
        models.push(AUTO_MODEL.to_owned());
    }
    for route in &config.routes {
        if !models.iter().any(|known| known == &route.key) {
            models.push(route.key.clone());
        }
    }
    for route in &config.routes {
        let pair = format!("{}/{}", route.family, route.model);
        if !models.iter().any(|known| known == &pair) {
            models.push(pair);
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

    if requested == AUTO_MODEL {
        let decision = classify::decide(config, ledger, state, now_ms, classify::TIMEOUT)
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
    if let Some(route) = config.route(requested) {
        return Ok(named(
            route.family.clone(),
            route.model.clone(),
            route.key.clone(),
        ));
    }
    if let Some((family, model)) = requested.split_once('/') {
        if family::family(family).is_some() && !model.is_empty() {
            return Ok(named(family.to_owned(), model.to_owned(), String::new()));
        }
    }
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
                    model: "gpt-5.6-mini".into(),
                },
                Route {
                    key: "deep".into(),
                    description: "A long reasoning task".into(),
                    family: "anthropic".into(),
                    model: "claude-opus-5".into(),
                },
            ],
            fallback: Some("fast".into()),
            min_confidence: 0.55,
        }
    }

    #[test]
    fn the_router_serves_auto_every_route_and_every_pair() {
        assert_eq!(
            served_models(&pooled()),
            [
                "auto",
                "fast",
                "deep",
                "openai/gpt-5.6-mini",
                "anthropic/claude-opus-5"
            ]
        );
        assert!(served_models(&RouterConfig::default()).is_empty());
    }

    #[test]
    fn auto_with_no_classifier_takes_the_fallback_and_spreads_the_pool() {
        let config = pooled();
        let mut ledger = Ledger::default();
        let first = resolve(&config, &ledger, "auto", "hello", 1_000).unwrap();
        assert_eq!(first.family, "openai");
        assert_eq!(first.model, "gpt-5.6-mini");
        assert_eq!(first.route, "fast");
        assert_eq!(first.reason, Reason::NotClassified);
        assert_eq!(first.account_id, "o1");
        ledger.record_success("o1", "2026-09-17", 1_000, 1, 1);
        let second = resolve(&config, &ledger, "auto", "hello", 1_100).unwrap();
        assert_eq!(second.account_id, "o2");
    }

    #[test]
    fn a_route_name_pins_the_turn_to_that_route() {
        let config = pooled();
        let ledger = Ledger::default();
        let picked = resolve(&config, &ledger, "deep", "hello", 1_000).unwrap();
        assert_eq!(picked.family, "anthropic");
        assert_eq!(picked.model, "claude-opus-5");
        assert_eq!(picked.account_id, "c1");
        assert_eq!(picked.route, "deep");
    }

    #[test]
    fn a_family_and_model_pair_pins_the_turn_to_that_model() {
        let config = pooled();
        let ledger = Ledger::default();
        let picked = resolve(&config, &ledger, "openai/gpt-5.6", "hello", 1_000).unwrap();
        assert_eq!(picked.family, "openai");
        assert_eq!(picked.model, "gpt-5.6");
        assert!(picked.route.is_empty());
    }

    #[test]
    fn an_unserved_model_and_an_empty_pool_each_name_their_failure() {
        let config = pooled();
        let ledger = Ledger::default();
        assert_eq!(
            resolve(&config, &ledger, "gpt-5.6", "hello", 1_000),
            Err(ResolveError::UnknownModel("gpt-5.6".into()))
        );
        assert_eq!(
            resolve(&config, &ledger, "nobody/m", "hello", 1_000),
            Err(ResolveError::UnknownModel("nobody/m".into()))
        );
        assert_eq!(
            resolve(&RouterConfig::default(), &ledger, "auto", "hello", 1_000),
            Err(ResolveError::NoRoute)
        );
        let mut thin = pooled();
        thin.accounts
            .retain(|account| account.family != "anthropic");
        assert_eq!(
            resolve(&thin, &ledger, "deep", "hello", 1_000),
            Err(ResolveError::Pool(balance::PickError::EmptyPool))
        );
        assert!(!ResolveError::NoRoute.message().is_empty());
        assert!(ResolveError::UnknownModel("m".into())
            .message()
            .contains('m'));
    }
}
