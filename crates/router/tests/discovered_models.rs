//! A model a provider catalog discovers reaches the router's routes.

use muniment_router::{config, options, provider_models};
use serde_json::json;

#[test]
fn a_new_subscription_model_reaches_the_router_without_a_catalog_edit() {
    let models = vec![
        json!({"id":"brand-new-model", "contextWindow":123456, "maxTokens":8192,
        "cost":{"input":2,"output":8}, "input":["text"], "reasoning":true}),
    ];
    let agent = std::env::temp_dir().join(format!("muniment-discovery-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&agent).unwrap();
    let mut settings = config::RouterConfig {
        enabled: true,
        ..Default::default()
    };
    settings.accounts.push(
        serde_json::from_value(json!({
            "id":"claude-account","family":"anthropic","label":"Claude",
            "credential":{"type":"subscription","provider":"anthropic","access":"fixture"},
            "enabled":true,"weight":1,"models":[]
        }))
        .unwrap(),
    );
    config::save(&agent, &settings).unwrap();
    let mut cache = provider_models::Cache::new();
    cache.insert(
        "account:claude-account".into(),
        provider_models::Catalog {
            checked_ms: 1,
            models,
        },
    );
    provider_models::save(&agent, &cache).unwrap();
    let loaded = config::load(&agent).unwrap();
    let routes = options(&loaded);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].model, "brand-new-model");
    std::fs::remove_dir_all(agent).unwrap();
}
