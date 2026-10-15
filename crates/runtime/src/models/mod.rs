//! The runtime's model service: provider keys, accounts and endpoints, the
//! default and hidden models, the inventory, Claude Code, the model router
//! with its accounts, routes and classifier, the local server scan and
//! provider sign-in. It writes Pi's files and the router config under their
//! locks, and it runs the router listener. It also holds the web search
//! settings and runs the built-in search server, and it reads and writes the
//! memory profile, facts and recall settings. Clients reach it through the
//! `models.request` attach operation and hear sign-in steps as `models.login`
//! events.

mod connections;
mod memory;
mod pool_sign_in;
mod providers;
mod router;
mod scan;
mod search;
mod sign_in;

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use muniment_core::attach::{Id, ModelAction, ModelRequest, ProtocolError};
use muniment_core::engine::PiRpcEngine;
use muniment_core::serde_json::{self, Value};
use muniment_core::sha2::{Digest, Sha256};

use crate::host::SignInPage;

/// How many mutating answers the service keeps for a retried key.
const REPLAYS: usize = 32;

/// The model service of one runtime.
pub struct ModelService {
    state_directory: PathBuf,
    agent: PathBuf,
    engine: PiRpcEngine,
    router: router::RouterState,
    search: search::SearchState,
    sign_ins: sign_in::SignInState,
    pool_sign_ins: pool_sign_in::PoolSignIns,
    sign_in_page: Arc<SignInPage>,
    subscribers: Mutex<Vec<Sender<Value>>>,
    replays: Mutex<VecDeque<Replay>>,
}

/// One mutating answer, by its idempotency key and its request's digest.
struct Replay {
    key: String,
    digest: [u8; 32],
    result: Value,
}

impl ModelService {
    /// A service for the profile's agent directory and Pi install root.
    /// `sign_in_page` renders the page a sign-in's browser lands on.
    pub fn new(profile_directory: &Path, sign_in_page: Arc<SignInPage>) -> Self {
        let agent = muniment_core::state_root::agent_directory(profile_directory);
        let engine = PiRpcEngine::new(None)
            .with_agent_directory(&agent)
            .with_harness_root(
                profile_directory.join(muniment_core::state_root::HARNESS_DIRECTORY_NAME),
            );
        Self {
            state_directory: profile_directory.to_path_buf(),
            agent,
            engine,
            router: router::RouterState::default(),
            search: search::SearchState::default(),
            sign_ins: sign_in::SignInState::default(),
            pool_sign_ins: pool_sign_in::PoolSignIns::default(),
            sign_in_page,
            subscribers: Mutex::new(Vec::new()),
            replays: Mutex::new(VecDeque::new()),
        }
    }

    /// Starts the router listener when its record says on, and writes its
    /// entry in Pi's `models.json`.
    pub fn restore_router(&self) {
        router::restore(&self.agent, &self.router);
    }

    /// Starts the search server with the recorded engines and writes
    /// pi-web-access's `web-search.json`.
    pub fn restore_search(&self) {
        search::restore(&self.state_directory, &self.agent, &self.search);
    }

    /// Stops the router listener, the search server and any sign-in in flight.
    pub fn stop(&self) {
        self.router.stop();
        self.search.stop(&self.agent);
        self.sign_ins.stop();
        self.pool_sign_ins.stop();
    }

    /// Subscribes to the sign-in steps, each a `models.login` event body.
    pub fn subscribe(&self) -> Receiver<Value> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sender);
        receiver
    }

    /// Sends one sign-in step to every subscriber that still listens.
    fn emit(&self, payload: Value) {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|subscriber| subscriber.send(payload.clone()).is_ok());
    }

    fn sign_in_page(&self, provider: Option<&str>) -> String {
        (self.sign_in_page)(provider)
    }

    /// Runs one action and answers its result. A refusal carries the reason a
    /// client shows. A repeated idempotency key answers the first result, and
    /// the same key on another request is a conflict.
    pub fn request(
        self: &Arc<Self>,
        request: ModelRequest,
        idempotency_key: Option<&Id>,
    ) -> Result<Value, ProtocolError> {
        let key = idempotency_key.map(|key| key.as_str().to_owned());
        let digest = key.as_ref().map(|_| digest(&request));
        if let (Some(key), Some(digest)) = (&key, &digest) {
            let replays = self
                .replays
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(replay) = replays.iter().find(|replay| &replay.key == key) {
                if &replay.digest != digest {
                    return Err(ProtocolError::idempotency_conflict());
                }
                return Ok(replay.result.clone());
            }
        }
        let result = self
            .run(request.action, request.data)?
            .map_err(ProtocolError::invalid_request_with_reason)?;
        if let (Some(key), Some(digest)) = (key, digest) {
            let mut replays = self
                .replays
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if replays.len() == REPLAYS {
                replays.pop_front();
            }
            replays.push_back(Replay {
                key,
                digest,
                result: result.clone(),
            });
        }
        Ok(result)
    }

    /// Runs one action. The outer error is malformed data, and the inner one
    /// is the action's refusal.
    fn run(
        self: &Arc<Self>,
        action: ModelAction,
        data: Value,
    ) -> Result<Result<Value, String>, ProtocolError> {
        let agent = self.agent.as_path();
        Ok(match action {
            ModelAction::ProviderStatus => {
                parse::<Empty>(data)?;
                answer(providers::provider_status(agent))
            }
            ModelAction::StoreProviderKey => {
                let data: ProviderKey = parse(data)?;
                answer(providers::store_key(
                    agent,
                    &self.engine,
                    &data.provider,
                    &data.key,
                    &data.env.unwrap_or_default(),
                ))
            }
            ModelAction::StoreLocalProvider => {
                let data: LocalProvider = parse(data)?;
                let key = data.api_key.unwrap_or_default();
                answer(providers::store_local_provider(
                    agent,
                    &data.base_url,
                    key.trim(),
                ))
            }
            ModelAction::ProviderInventory => {
                let data: Inventory = parse(data)?;
                answer(providers::inventory(
                    agent,
                    &self.engine,
                    data.force.unwrap_or(false),
                ))
            }
            ModelAction::SetDefaultModel => {
                let data: ProviderModel = parse(data)?;
                answer(providers::set_default_model(
                    agent,
                    &data.provider,
                    &data.model,
                ))
            }
            ModelAction::SetModelHidden => {
                let data: HiddenModel = parse(data)?;
                answer(providers::set_model_hidden(
                    agent,
                    &data.provider,
                    &data.model,
                    data.hidden,
                ))
            }
            ModelAction::DisconnectProvider => {
                let data: Provider = parse(data)?;
                answer(providers::disconnect_provider(agent, &data.provider))
            }
            ModelAction::StoreEndpoint => {
                let data: Endpoint = parse(data)?;
                answer(providers::store_endpoint(
                    agent,
                    &self.engine,
                    &data.kind,
                    &data.name,
                    &data.base_url,
                    &data.key,
                    &data.models,
                ))
            }
            ModelAction::ClaudeCodeStatus => {
                parse::<Empty>(data)?;
                answer(Ok::<_, String>(providers::claude_code_status()))
            }
            ModelAction::ConnectClaudeCode => {
                let data: ClaudeCode = parse(data)?;
                answer(providers::connect_claude_code(agent, &data.executable))
            }
            ModelAction::RouterSettings => {
                parse::<Empty>(data)?;
                answer(router::settings(agent, &self.router))
            }
            ModelAction::RouterSetEnabled => {
                let data: Enabled = parse(data)?;
                answer(router::set_enabled(agent, &self.router, data.enabled))
            }
            ModelAction::RouterAddAccount => {
                answer(router::add_account(agent, &self.router, parse(data)?))
            }
            ModelAction::RouterUpdateAccount => {
                answer(router::update_account(agent, &self.router, parse(data)?))
            }
            ModelAction::RouterRemoveAccount => {
                let data: Named = parse(data)?;
                answer(router::remove_account(agent, &self.router, &data.id))
            }
            ModelAction::RouterSetHidden => {
                let data: HiddenKeys = parse(data)?;
                answer(router::set_hidden(agent, &self.router, data.keys))
            }
            ModelAction::RouterSaveRoutes => {
                answer(router::save_routes(agent, &self.router, parse(data)?))
            }
            ModelAction::RouterSetClassifier => {
                answer(router::set_classifier(agent, &self.router, parse(data)?))
            }
            ModelAction::RouterTestClassifier => {
                parse::<Empty>(data)?;
                answer(router::test_classifier(agent))
            }
            ModelAction::RouterTestRoute => {
                let data: Sample = parse(data)?;
                answer(self.router.test_route(&data.sample))
            }
            ModelAction::RouterSubscriptionStart => {
                let data: Provider = parse(data)?;
                answer(sign_in::start_into_pool(self, &data.provider))
            }
            ModelAction::RouterRefreshQuota => {
                let data: OptionalId = parse(data)?;
                answer(router::refresh_quotas(agent, &self.router, data.id))
            }
            ModelAction::RouterSetAssist => {
                let data: Assist = parse(data)?;
                answer(connections::set_assist(
                    agent,
                    &self.router,
                    data.enabled,
                    &data.id,
                ))
            }
            ModelAction::RouterConnectClassifier => {
                answer(connections::connect(agent, &self.router, parse(data)?))
            }
            ModelAction::RouterUpdateClassifier => {
                answer(connections::update(agent, &self.router, parse(data)?))
            }
            ModelAction::RouterSelectClassifier => {
                let data: Named = parse(data)?;
                answer(connections::select(agent, &self.router, &data.id))
            }
            ModelAction::RouterDisconnectClassifier => {
                let data: Named = parse(data)?;
                answer(connections::disconnect(agent, &self.router, &data.id))
            }
            ModelAction::ProviderScan => {
                parse::<Empty>(data)?;
                answer(scan::scan())
            }
            ModelAction::ConnectServer => {
                answer(scan::connect_server(agent, &self.engine, parse(data)?))
            }
            ModelAction::LoginStart => {
                let data: Provider = parse(data)?;
                answer(sign_in::start(self, &data.provider))
            }
            ModelAction::LoginAnswer => {
                let data: LoginAnswer = parse(data)?;
                answer(sign_in::answer(
                    &self.sign_ins,
                    &data.id,
                    data.value,
                    data.confirmed,
                ))
            }
            ModelAction::LoginCancel => {
                parse::<Empty>(data)?;
                sign_in::cancel(self);
                Ok(Value::Null)
            }
            ModelAction::SearchSettings => {
                parse::<Empty>(data)?;
                answer(search::settings(&self.state_directory, &self.search))
            }
            ModelAction::SearchSaveOrder => {
                let data: SearchOrder = parse(data)?;
                answer(search::save_order(
                    &self.state_directory,
                    agent,
                    &self.search,
                    data.order,
                ))
            }
            ModelAction::SearchSaveEngines => {
                let data: SearchEngines = parse(data)?;
                answer(search::save_engines(
                    &self.state_directory,
                    agent,
                    &self.search,
                    data.engines,
                ))
            }
            ModelAction::SearchSetKey => {
                let data: SearchKey = parse(data)?;
                answer(search::set_key(
                    &self.state_directory,
                    agent,
                    &self.search,
                    &data.provider,
                    muniment_core::search_settings::ProviderKey {
                        api_key: data.api_key,
                        base_url: data.base_url,
                        extra: data.extra.unwrap_or_default(),
                    },
                ))
            }
            ModelAction::SearchRemoveKey => {
                let data: Provider = parse(data)?;
                answer(search::remove_key(
                    &self.state_directory,
                    agent,
                    &self.search,
                    &data.provider,
                ))
            }
            ModelAction::MemoryProfileRead => {
                parse::<Empty>(data)?;
                answer(muniment_core::memory_files::profile_read(
                    &self.state_directory,
                ))
            }
            ModelAction::MemoryProfileSave => {
                let data: MemoryProfile = parse(data)?;
                muniment_core::memory_files::profile_save(&self.state_directory, &data.content)
                    .map(|()| Value::Null)
            }
            ModelAction::MemoryFacts => answer(memory::facts(&self.state_directory, parse(data)?)),
            ModelAction::MemoryDeletedFacts => {
                answer(memory::deleted_facts(&self.state_directory, parse(data)?))
            }
            ModelAction::MemoryFactSave => {
                let data: MemoryFact = parse(data)?;
                answer(memory::fact_save(
                    &self.state_directory,
                    memory::Scope { agent: data.agent },
                    data.fact,
                ))
            }
            ModelAction::MemoryFactDelete => {
                let data: MemoryFactId = parse(data)?;
                memory::fact_delete(
                    &self.state_directory,
                    memory::Scope { agent: data.agent },
                    &data.id,
                )
            }
            ModelAction::MemoryFactRestore => {
                let data: MemoryFactId = parse(data)?;
                memory::fact_restore(
                    &self.state_directory,
                    memory::Scope { agent: data.agent },
                    &data.id,
                )
            }
            ModelAction::MemoryRecallSettings => {
                parse::<Empty>(data)?;
                memory::recall_settings(&self.state_directory)
            }
            ModelAction::MemoryRecallSettingsSave => {
                let data: MemoryRecall = parse(data)?;
                answer(memory::recall_settings_save(
                    &self.state_directory,
                    data.settings,
                ))
            }
        })
    }
}

impl Drop for ModelService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn parse<T: DeserializeOwned>(data: Value) -> Result<T, ProtocolError> {
    serde_json::from_value(data).map_err(|_| ProtocolError::invalid_request())
}

fn answer<T: Serialize>(result: Result<T, String>) -> Result<Value, String> {
    result.and_then(|value| {
        serde_json::to_value(value).map_err(|_| providers::READ_SETTINGS_ERROR.to_string())
    })
}

fn digest(request: &ModelRequest) -> [u8; 32] {
    let bytes = serde_json::to_vec(request).unwrap_or_default();
    Sha256::digest(bytes).into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderKey {
    provider: String,
    key: String,
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalProvider {
    base_url: String,
    #[serde(default)]
    api_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    #[serde(default)]
    force: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderModel {
    provider: String,
    model: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HiddenModel {
    provider: String,
    model: String,
    hidden: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    provider: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    kind: String,
    name: String,
    base_url: String,
    key: String,
    models: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeCode {
    executable: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enabled {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchOrder {
    order: Vec<muniment_core::search_settings::OrderEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchEngines {
    engines: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchKey {
    provider: String,
    api_key: String,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    extra: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryProfile {
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryFact {
    #[serde(default)]
    agent: Option<String>,
    fact: muniment_core::memory_files::Fact,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryFactId {
    #[serde(default)]
    agent: Option<String>,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryRecall {
    settings: muniment_core::memory_files::RecallSettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Named {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionalId {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HiddenKeys {
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    sample: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assist {
    enabled: bool,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginAnswer {
    id: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    confirmed: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_core::attach::ErrorDetails;

    fn service() -> (Arc<ModelService>, PathBuf) {
        let profile =
            std::env::temp_dir().join(format!("muniment-model-service-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&profile).unwrap();
        let page: Arc<SignInPage> = Arc::new(crate::host::plain_sign_in_page);
        (Arc::new(ModelService::new(&profile, page)), profile)
    }

    fn request(action: ModelAction, data: Value) -> ModelRequest {
        ModelRequest { action, data }
    }

    fn reason(error: &ProtocolError) -> Option<&str> {
        match error.details() {
            Some(ErrorDetails::RequestReason { reason }) => Some(reason),
            _ => None,
        }
    }

    #[test]
    fn a_refusal_carries_the_reason_and_malformed_data_carries_none() {
        let (service, profile) = service();
        let refusal = service
            .request(
                request(
                    ModelAction::SetDefaultModel,
                    serde_json::json!({"provider": "", "model": "x"}),
                ),
                Some(&Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap()),
            )
            .unwrap_err();
        assert_eq!(reason(&refusal), Some("Choose a provider and a model."));
        let malformed = service
            .request(
                request(ModelAction::SetDefaultModel, serde_json::json!({"x": 1})),
                Some(&Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap()),
            )
            .unwrap_err();
        assert_eq!(reason(&malformed), None);
        std::fs::remove_dir_all(profile).unwrap();
    }

    #[test]
    fn a_repeated_key_answers_the_first_result_and_another_request_conflicts() {
        let (service, profile) = service();
        let key = Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap();
        let first = service
            .request(
                request(
                    ModelAction::RouterSetHidden,
                    serde_json::json!({"keys": ["openai/gpt-5"]}),
                ),
                Some(&key),
            )
            .unwrap();
        assert_eq!(first["hidden"], serde_json::json!(["openai/gpt-5"]));
        // The record changes under the key, and a retry still answers the first result.
        service
            .request(
                request(
                    ModelAction::RouterSetHidden,
                    serde_json::json!({"keys": []}),
                ),
                Some(&Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap()),
            )
            .unwrap();
        let replayed = service
            .request(
                request(
                    ModelAction::RouterSetHidden,
                    serde_json::json!({"keys": ["openai/gpt-5"]}),
                ),
                Some(&key),
            )
            .unwrap();
        assert_eq!(replayed, first);
        let conflict = service
            .request(
                request(
                    ModelAction::RouterSetHidden,
                    serde_json::json!({"keys": []}),
                ),
                Some(&key),
            )
            .unwrap_err();
        assert_eq!(
            conflict.code(),
            ProtocolError::idempotency_conflict().code()
        );
        std::fs::remove_dir_all(profile).unwrap();
    }

    #[test]
    fn the_settings_never_carry_a_key_and_a_route_test_needs_the_router() {
        let (service, profile) = service();
        let settings = service
            .request(
                request(
                    ModelAction::RouterAddAccount,
                    serde_json::json!({"family": "openai", "label": "work", "key": "sk-secret"}),
                ),
                Some(&Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap()),
            )
            .unwrap();
        assert!(!settings.to_string().contains("sk-secret"));
        assert_eq!(settings["accounts"][0]["label"], "work");
        let test = service
            .request(
                request(
                    ModelAction::RouterTestRoute,
                    serde_json::json!({"sample": "hi"}),
                ),
                None,
            )
            .unwrap_err();
        assert_eq!(
            reason(&test),
            Some("Turn on account balancing before testing routing.")
        );
        std::fs::remove_dir_all(profile).unwrap();
    }

    #[test]
    fn a_cancel_reaches_every_subscriber() {
        let (service, profile) = service();
        let first = service.subscribe();
        let second = service.subscribe();
        drop(service.subscribe());
        assert_eq!(
            service
                .request(
                    request(ModelAction::LoginCancel, serde_json::json!({})),
                    Some(&Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap()),
                )
                .unwrap(),
            Value::Null
        );
        for receiver in [first, second] {
            assert_eq!(
                receiver.try_recv().unwrap(),
                serde_json::json!({"stage": "cancelled"})
            );
        }
        assert_eq!(service.subscribers.lock().unwrap().len(), 2);
        std::fs::remove_dir_all(profile).unwrap();
    }

    #[test]
    fn memory_actions_serve_settings_and_mark_their_facts_as_the_users() {
        let (service, profile) = service();
        let home = profile.join("Home");
        muniment_core::home::confirm_home(&profile, &home).unwrap();
        let key = || Id::new(uuid::Uuid::now_v7().simple().to_string()).unwrap();
        let run = |action, data: Value, keyed: bool| {
            service.request(request(action, data), keyed.then(key).as_ref())
        };
        assert_eq!(
            run(
                ModelAction::MemoryRecallSettings,
                serde_json::json!({}),
                false
            )
            .unwrap(),
            Value::Null
        );
        let settings = serde_json::json!({"learn": false, "use": true, "ask": true});
        assert_eq!(
            run(
                ModelAction::MemoryRecallSettingsSave,
                serde_json::json!({"settings": settings}),
                true
            )
            .unwrap(),
            settings
        );
        assert_eq!(
            run(
                ModelAction::MemoryRecallSettings,
                serde_json::json!({}),
                false
            )
            .unwrap(),
            settings
        );
        run(
            ModelAction::MemoryProfileSave,
            serde_json::json!({"content": "Call me Sam."}),
            true,
        )
        .unwrap();
        assert_eq!(
            run(ModelAction::MemoryProfileRead, serde_json::json!({}), false).unwrap(),
            "Call me Sam."
        );
        let saved = run(
            ModelAction::MemoryFactSave,
            serde_json::json!({"fact": {"id": "", "title": "Tone", "content": "Use short answers.", "source": "Added in settings", "trust": "external"}}),
            true,
        )
        .unwrap();
        assert_eq!(saved["trust"], "user");
        let id = saved["id"].as_str().unwrap().to_owned();
        assert_eq!(
            run(ModelAction::MemoryFacts, serde_json::json!({}), false).unwrap()[0]["id"],
            id.as_str()
        );
        run(
            ModelAction::MemoryFactDelete,
            serde_json::json!({"id": id}),
            true,
        )
        .unwrap();
        assert_eq!(
            run(ModelAction::MemoryFacts, serde_json::json!({}), false).unwrap(),
            serde_json::json!([])
        );
        assert_eq!(
            run(
                ModelAction::MemoryDeletedFacts,
                serde_json::json!({}),
                false
            )
            .unwrap()[0]["id"],
            id.as_str()
        );
        run(
            ModelAction::MemoryFactRestore,
            serde_json::json!({"id": id}),
            true,
        )
        .unwrap();
        assert!(home.join(format!("memory/facts/{id}.md")).is_file());
        assert!(reason(
            &run(
                ModelAction::MemoryFacts,
                serde_json::json!({"agent": "missing"}),
                false
            )
            .unwrap_err()
        )
        .is_some());
        assert!(reason(
            &run(
                ModelAction::MemoryFacts,
                serde_json::json!({"other": 1}),
                false
            )
            .unwrap_err()
        )
        .is_none());
        std::fs::remove_dir_all(profile).unwrap();
    }
}
