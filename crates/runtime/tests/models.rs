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

fn uuid_like(value: u128) -> String {
    format!("{value:032x}")
}
