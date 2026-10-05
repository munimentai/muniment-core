//! Authoritative constraints run before any classifier or model receives text.
use super::{
    config::{Classifier, Route, RouterConfig},
    policy::{self, Features, Session},
    wire::Tokens,
};

pub fn loopback(url: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host == "localhost",
        _ => false,
    }
}
/// Whether the configured task budget governs this turn. A run's budget
/// replaces it when a host sets one.
pub fn task_budgeted(config: &RouterConfig) -> bool {
    config.policy.run_budget_usd.is_none() && config.policy.task_budget_usd.is_some()
}
/// What the task may still spend: the run's remaining budget, else the
/// configured task budget less the session's estimated spend.
pub fn remaining(config: &RouterConfig, session: &Session) -> Option<f64> {
    if let Some(left) = config.policy.run_budget_usd {
        return Some(if left.is_finite() { left.max(0.0) } else { 0.0 });
    }
    config.policy.task_budget_usd.map(|limit| {
        if !limit.is_finite() || limit < 0.0 {
            0.0
        } else {
            (limit - session.estimated_cost).max(0.0)
        }
    })
}
pub fn reserve(config: &RouterConfig, route: &Route, features: &Features) -> Option<f64> {
    policy::model(config, route)
        .filter(|m| !m.pricing_unknown)
        .map(|m| {
            m.cost(Tokens {
                input: features.input,
                output: features.output,
                ..Default::default()
            })
        })
}
pub fn filter(
    config: &RouterConfig,
    session: &Session,
    features: &Features,
    automatic: bool,
) -> RouterConfig {
    let mut safe = config.clone();
    let routes = super::options(config);
    for account in &mut safe.accounts {
        if config.policy.offline_only && !account.upstream().is_some_and(|url| loopback(&url)) {
            account.enabled = false;
            continue;
        }
        let allowed: Vec<String> = routes
            .iter()
            .filter(|r| r.family == account.family && account.serves(&r.model))
            .filter(|r| match policy::model(config, r) {
                Some(m) => {
                    if automatic {
                        features.fits(&m)
                    } else {
                        features.fits_direct(&m)
                    }
                }
                None => !automatic && remaining(config, session).is_none(),
            })
            .filter(|r| {
                remaining(config, session).is_none_or(|left| {
                    reserve(config, r, features).is_some_and(|cost| cost <= left)
                })
            })
            .map(|r| r.model.clone())
            .collect();
        if allowed.is_empty() {
            account.enabled = false;
        } else {
            account.models = allowed;
        }
    }
    if config.policy.offline_only {
        let local = match &config.classifier {
            Classifier::None => true,
            Classifier::Typesafe { base_url, .. } => base_url.as_deref().is_some_and(loopback),
            Classifier::Endpoint { base_url, .. } => loopback(base_url),
            Classifier::Pooled { family, model } => safe
                .accounts
                .iter()
                .any(|a| a.enabled && &a.family == family && a.serves(model)),
        };
        if !local {
            safe.classifier = Classifier::None;
        }
    }
    // Budgeted tasks use deterministic selection. A classifier with unknown
    // per-request billing cannot consume an unbounded part of the task budget.
    // Extractive context refresh costs no extra model tokens. A run's budget
    // pays only for upstream attempts, so a run keeps its classifier.
    if task_budgeted(config) {
        safe.classifier = Classifier::None;
    }
    safe
}
#[cfg(test)]
mod tests {
    use super::super::config::{Account, Credential};
    use super::*;
    use serde_json::json;
    fn setup() -> (RouterConfig, Features) {
        let mut c = RouterConfig {
            accounts: vec![
                Account {
                    id: "remote".into(),
                    family: "openai".into(),
                    label: "Remote".into(),
                    credential: Credential::ApiKey { key: "test".into() },
                    base_url: Some("https://example.com/v1".into()),
                    models: vec!["remote-model".into()],
                    enabled: true,
                    weight: 1,
                },
                Account {
                    id: "local".into(),
                    family: "openai".into(),
                    label: "Local".into(),
                    credential: Credential::ApiKey { key: "test".into() },
                    base_url: Some("http://127.0.0.1:8080/v1".into()),
                    models: vec!["local-model".into()],
                    enabled: true,
                    weight: 1,
                },
            ],
            ..RouterConfig::default()
        };
        for (name, cost) in [("remote-model", 10.0), ("local-model", 0.0)] {
            c.policy.models.insert(
                format!("openai/{name}"),
                policy::Model {
                    context: 10000,
                    output_limit: 1000,
                    input: cost,
                    output: cost,
                    ..Default::default()
                },
            );
        }
        (
            c,
            Features::read(&json!({"messages":[{"role":"user","content":"Hi"}],"max_tokens":100})),
        )
    }
    #[test]
    fn privacy_filters_classifier_and_answer_accounts_before_delivery() {
        let (mut c, f) = setup();
        c.policy.offline_only = true;
        c.classifier = Classifier::Endpoint {
            base_url: "https://example.com/classify".into(),
            api_key: None,
            model: "jev-latest".into(),
        };
        let safe = filter(&c, &Session::default(), &f, true);
        assert!(!safe.accounts[0].enabled);
        assert!(safe.accounts[1].enabled);
        assert_eq!(safe.classifier, Classifier::None);
        assert!(!loopback("https://127.0.0.1.example.com"));
        assert!(!loopback("http://10.1.10.105:11434"));
        assert!(loopback("http://[::1]:8080"));
    }
    #[test]
    fn spent_budget_and_capability_limits_cannot_be_overridden_by_a_choice() {
        let (mut c, mut f) = setup();
        c.policy.task_budget_usd = Some(0.01);
        let s = Session {
            estimated_cost: 0.01,
            ..Default::default()
        };
        let safe = filter(&c, &s, &f, true);
        assert!(!safe.accounts[0].enabled);
        assert!(safe.accounts[1].enabled);
        f.images = true;
        assert!(super::super::options(&filter(&c, &s, &f, true)).is_empty());
    }
    #[test]
    fn a_run_budget_replaces_the_task_budget_and_keeps_the_classifier() {
        let (mut c, f) = setup();
        c.classifier = Classifier::Endpoint {
            base_url: "https://example.com/classify".into(),
            api_key: None,
            model: "jev-latest".into(),
        };
        c.policy.task_budget_usd = Some(0.0);
        // The run has room for the remote model, whatever the task budget says.
        c.policy.run_budget_usd = Some(1.0);
        let spent = Session {
            estimated_cost: 5.0,
            ..Default::default()
        };
        assert_eq!(remaining(&c, &spent), Some(1.0));
        let safe = filter(&c, &spent, &f, true);
        assert!(safe.accounts[0].enabled);
        assert!(safe.accounts[1].enabled);
        assert_eq!(safe.classifier, c.classifier);
        // A run with less left than the remote estimate keeps only the free model.
        c.policy.run_budget_usd = Some(0.001);
        let safe = filter(&c, &spent, &f, true);
        assert!(!safe.accounts[0].enabled);
        assert!(safe.accounts[1].enabled);
        c.policy.run_budget_usd = Some(-1.0);
        assert_eq!(remaining(&c, &spent), Some(0.0));
    }
}
