use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use muniment_core::attach::{Id, ModelAction, ModelRequest};
use muniment_core::model_router::config::{self, RouterConfig};
use muniment_core::model_router::native_auth::{
    antigravity_auth_url, OAuthClient, ProviderClients,
};
use muniment_core::model_router::server;
use muniment_core::run_start::RunAttachBoundaries;
use muniment_runtime_core::{
    start_retention_schedule, RetentionScheduleCommand, RuntimeAttachState, RuntimeHost,
};

mod common;
use common::TemporaryProfile;

/// Every test opens the state with the same provider clients, because the
/// runtime registers them for the whole process.
fn fixture_host() -> RuntimeHost {
    RuntimeHost {
        provider_clients: ProviderClients {
            antigravity: Some(OAuthClient {
                id: "fixture-client.apps.example".into(),
                secret: "fixture-secret".into(),
            }),
        },
        ..RuntimeHost::default()
    }
}

fn router_entry(agent: &std::path::Path) -> Option<String> {
    let models: muniment_core::serde_json::Value =
        muniment_core::serde_json::from_slice(&std::fs::read(agent.join("models.json")).ok()?)
            .ok()?;
    models["providers"]["muniment-router"]["baseUrl"]
        .as_str()
        .map(str::to_owned)
}

#[test]
fn the_runtime_starts_the_router_its_record_turns_on_and_stops_it_with_the_schedule() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary = TemporaryProfile::new("models-router", false);
    let agent = muniment_core::state_root::agent_directory(&temporary.profile);
    config::save(
        &agent,
        &RouterConfig {
            enabled: true,
            ..RouterConfig::default()
        },
    )
    .unwrap();
    let state = Arc::new(
        RuntimeAttachState::open(fixture_host(), &temporary.profile, &temporary.config).unwrap(),
    );
    // Opening the state starts nothing: the runtime owns its endpoint first.
    assert!(server::read_endpoint(&agent).is_none());

    let (commands, command_rx) = mpsc::channel();
    let schedule = start_retention_schedule(
        Arc::clone(&state),
        Duration::from_secs(3600),
        command_rx,
        None,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let endpoint = loop {
        // The endpoint file comes before models.json names the router.
        if let Some(endpoint) = server::read_endpoint(&agent) {
            if router_entry(&agent).is_some() {
                break endpoint;
            }
        }
        assert!(Instant::now() < deadline, "the router never started");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(router_entry(&agent), Some(endpoint.base_url()));
    assert!(std::net::TcpStream::connect(("127.0.0.1", endpoint.port)).is_ok());

    // Clients read the running router through the model service.
    let boundaries = state.boundaries();
    let settings = boundaries
        .models_request(
            ModelRequest {
                action: ModelAction::RouterSettings,
                data: muniment_core::serde_json::json!({}),
            },
            None,
        )
        .unwrap();
    assert_eq!(settings["running"], true);
    assert_eq!(settings["base_url"], endpoint.base_url());

    commands.send(RetentionScheduleCommand::Stop).unwrap();
    schedule.join().unwrap();
    let settings = boundaries
        .models_request(
            ModelRequest {
                action: ModelAction::RouterSettings,
                data: muniment_core::serde_json::json!({}),
            },
            None,
        )
        .unwrap();
    assert_eq!(settings["running"], false);
}

#[test]
fn a_sign_in_step_reaches_every_attach_subscriber_and_the_host_supplies_provider_clients() {
    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary = TemporaryProfile::new("models-events", false);
    let state =
        RuntimeAttachState::open(fixture_host(), &temporary.profile, &temporary.config).unwrap();
    let url = antigravity_auth_url("state", "http://127.0.0.1:51121/oauth-callback").unwrap();
    assert!(url.contains("fixture-client.apps.example"), "{url}");
    assert!(!url.contains("fixture-secret"));

    let first = state.boundaries();
    let second = state.boundaries();
    let first_events = first.subscribe_model_events().unwrap();
    let second_events = second.subscribe_model_events().unwrap();
    let key = Id::new(uuid_like(1)).unwrap();
    first
        .models_request(
            ModelRequest {
                action: ModelAction::LoginCancel,
                data: muniment_core::serde_json::json!({}),
            },
            Some(&key),
        )
        .unwrap();
    for events in [first_events, second_events] {
        assert_eq!(
            events.recv_timeout(Duration::from_secs(1)).unwrap(),
            muniment_core::serde_json::json!({"stage": "cancelled"})
        );
    }
}

#[test]
fn the_runtime_runs_the_search_server_and_applies_search_settings_without_a_restart() {
    use muniment_core::search_settings;
    use muniment_core::serde_json::{json, Value};

    // Core and the search crate name the same endpoint file and engines.
    assert_eq!(
        search_settings::ENDPOINT_FILE,
        muniment_search::server::ENDPOINT_FILE
    );
    assert_eq!(
        search_settings::ENGINES,
        muniment_search::EngineId::ALL.map(|engine| engine.name())
    );

    muniment_core::chat_prompt::use_mock_keyring_for_tests();
    let temporary = TemporaryProfile::new("models-search", false);
    let agent = muniment_core::state_root::agent_directory(&temporary.profile);
    let endpoint_file = agent.join(muniment_search::server::ENDPOINT_FILE);
    let web_search = || -> Value {
        muniment_core::serde_json::from_slice(
            &std::fs::read(agent.join("web-search.json")).unwrap(),
        )
        .unwrap()
    };
    let state = Arc::new(
        RuntimeAttachState::open(fixture_host(), &temporary.profile, &temporary.config).unwrap(),
    );
    assert!(!endpoint_file.exists());

    let (commands, command_rx) = mpsc::channel();
    let schedule = start_retention_schedule(
        Arc::clone(&state),
        Duration::from_secs(3600),
        command_rx,
        None,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let endpoint = loop {
        if let Some(endpoint) = muniment_search::server::read_endpoint(&endpoint_file) {
            if agent.join("web-search.json").exists() {
                break endpoint;
            }
        }
        assert!(Instant::now() < deadline, "the search server never started");
        std::thread::sleep(Duration::from_millis(20));
    };
    let health = |port: u16| {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        answer
    };
    assert!(health(endpoint.port).starts_with("HTTP/1.1 200"));
    let written = web_search();
    assert_eq!(written["workflow"], "none");
    assert_eq!(written["searxngBaseUrl"], endpoint.base_url());
    assert_eq!(
        written["searxngHeaders"]["Authorization"],
        endpoint.authorization()
    );
    assert_eq!(
        written["searchRouting"]["providers"],
        json!(["searxng", "exa"])
    );
    assert!(written.get("ssrf").is_none());

    let boundaries = state.boundaries();
    let mut sequence = 100;
    let mut request = |action: ModelAction, data: Value| {
        sequence += 1;
        let key = action
            .mutates()
            .then(|| Id::new(uuid_like(sequence)).unwrap());
        boundaries.models_request(ModelRequest { action, data }, key.as_ref())
    };
    let settings = request(ModelAction::SearchSettings, json!({})).unwrap();
    assert_eq!(settings["running"], true);
    assert_eq!(
        settings["order"],
        json!([
            {"id": "muniment", "enabled": true, "has_key": false},
            {"id": "exa", "enabled": true, "has_key": false}
        ])
    );

    let settings = request(
        ModelAction::SearchSaveEngines,
        json!({"engines": ["wikipedia", "bing"]}),
    )
    .unwrap();
    assert_eq!(
        settings["engines"][1],
        json!({"id": "bing", "enabled": true})
    );
    assert_eq!(
        settings["engines"][0],
        json!({"id": "brave", "enabled": false})
    );
    // The running server keeps its port and token.
    assert_eq!(
        muniment_search::server::read_endpoint(&endpoint_file),
        Some(endpoint.clone())
    );
    assert!(health(endpoint.port).starts_with("HTTP/1.1 200"));

    let settings = request(
        ModelAction::SearchSetKey,
        json!({"provider": "tavily", "api_key": "tvly-fixture-secret-9876"}),
    )
    .unwrap();
    assert!(!settings.to_string().contains("secret"), "{settings}");
    assert_eq!(settings["keys"][0]["last4"], "9876");
    let written = web_search();
    assert_eq!(written["tavilyApiKey"], "tvly-fixture-secret-9876");
    assert_eq!(
        written["searchRouting"]["providers"],
        json!(["searxng", "exa", "tavily"])
    );

    request(
        ModelAction::SearchSaveOrder,
        json!({"order": [
            {"id": "tavily", "enabled": true},
            {"id": "muniment", "enabled": true},
            {"id": "exa", "enabled": false}
        ]}),
    )
    .unwrap();
    assert_eq!(
        web_search()["searchRouting"]["providers"],
        json!(["tavily", "searxng"])
    );
    assert!(request(
        ModelAction::SearchSaveOrder,
        json!({"order": [{"id": "kagi", "enabled": true}]})
    )
    .is_err());

    request(ModelAction::SearchRemoveKey, json!({"provider": "tavily"})).unwrap();
    let written = web_search();
    assert!(written.get("tavilyApiKey").is_none());
    assert_eq!(written["searchRouting"]["providers"], json!(["searxng"]));

    commands.send(RetentionScheduleCommand::Stop).unwrap();
    schedule.join().unwrap();
    assert!(!endpoint_file.exists());
    let settings = request(ModelAction::SearchSettings, json!({})).unwrap();
    assert_eq!(settings["running"], false);
}

fn uuid_like(value: u128) -> String {
    format!("{value:032x}")
}
