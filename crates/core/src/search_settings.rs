//! The web search settings: which providers Pi's web search tries in which
//! order, which engines the built-in metasearch queries, and the keys of the
//! providers that need one.
//!
//! The record is `search-settings.json` in the state directory, readable by
//! its owner only. pi-web-access never reads it: [`render_web_search`] writes
//! its provider order, keys and the built-in engine's endpoint into
//! `web-search.json`, and leaves every other key in that file alone.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// The record's name inside the state directory.
pub const SETTINGS_FILE: &str = "search-settings.json";
/// pi-web-access's settings file inside the agent directory.
pub const WEB_SEARCH_FILE: &str = "web-search.json";
/// The file the runtime's search server writes its port and token to, inside
/// the agent directory. `muniment_search::server::ENDPOINT_FILE` names the same.
pub const ENDPOINT_FILE: &str = "muniment-search-endpoint.json";
/// The built-in keyless engine. pi-web-access reaches it as `searxng`.
pub const MUNIMENT: &str = "muniment";
/// Exa answers without a key through its public MCP endpoint, and with one
/// through its API.
pub const EXA: &str = "exa";
/// The built-in engines, in the metasearch's default order.
pub const ENGINES: [&str; 5] = ["brave", "bing", "duckduckgo", "yahoo", "wikipedia"];
/// The failures after which pi-web-access tries the next provider in order.
const FALLBACK_ON: [&str; 5] = [
    "transient",
    "quota",
    "network",
    "invalid-response",
    "unsupported",
];

/// A pi-web-access search provider that takes a key, and the
/// `web-search.json` fields it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyedProvider {
    pub id: &'static str,
    pub api_key: &'static str,
    pub base_url: Option<&'static str>,
    pub extra: &'static [&'static str],
}

const fn keyed(id: &'static str, api_key: &'static str) -> KeyedProvider {
    KeyedProvider {
        id,
        api_key,
        base_url: None,
        extra: &[],
    }
}

const fn with_base_url(
    id: &'static str,
    api_key: &'static str,
    base_url: &'static str,
) -> KeyedProvider {
    KeyedProvider {
        id,
        api_key,
        base_url: Some(base_url),
        extra: &[],
    }
}

/// Every provider a key adds, by its pi-web-access routing id, with the
/// field names pi-web-access 0.40 reads. Parallel MCP shares Parallel's key,
/// so only `parallel` is listed.
pub const KEYED_PROVIDERS: &[KeyedProvider] = &[
    with_base_url("exa", "exaApiKey", "exaBaseUrl"),
    with_base_url("brave", "braveApiKey", "braveBaseUrl"),
    with_base_url("tavily", "tavilyApiKey", "tavilyBaseUrl"),
    with_base_url("firecrawl", "firecrawlApiKey", "firecrawlBaseUrl"),
    keyed("perplexity", "perplexityApiKey"),
    keyed("serper", "serperApiKey"),
    keyed("serpapi", "serpapiApiKey"),
    keyed("kagi", "kagiApiKey"),
    keyed("jina", "jinaApiKey"),
    keyed("parallel", "parallelApiKey"),
    keyed("you", "youApiKey"),
    keyed("openai", "openaiApiKey"),
    with_base_url("gemini", "geminiApiKey", "geminiBaseUrl"),
    keyed("tinyfish", "tinyfishApiKey"),
    keyed("search1api", "search1apiApiKey"),
    keyed("searchinfinity", "searchinfinityApiKey"),
    keyed("querit", "queritApiKey"),
    keyed("serpdive", "serpdiveApiKey"),
    keyed("bocha", "bochaApiKey"),
    keyed("ollama", "ollamaApiKey"),
    keyed("anysearch", "anysearchApiKey"),
    keyed("xcrawl", "xcrawlApiKey"),
    keyed("xai", "xaiApiKey"),
    keyed("mistral", "mistralApiKey"),
    KeyedProvider {
        id: "brightdata",
        api_key: "brightdataApiKey",
        base_url: None,
        extra: &["brightdataSerpZone", "brightdataUnlockerZone"],
    },
    keyed("serpbase", "serpbaseApiKey"),
    keyed("serply", "serplyApiKey"),
    keyed("valyu", "valyuApiKey"),
    keyed("baizhi", "baizhiApiKey"),
    keyed("zai", "zaiApiKey"),
    keyed("keenable", "keenableApiKey"),
    keyed("ceramic", "ceramicApiKey"),
    with_base_url("degoog", "degoogApiKey", "degoogBaseUrl"),
];

pub fn keyed_provider(id: &str) -> Option<&'static KeyedProvider> {
    KEYED_PROVIDERS.iter().find(|provider| provider.id == id)
}

/// One provider in the order pi-web-access tries them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderEntry {
    pub id: String,
    pub enabled: bool,
}

/// One provider's key, with the base URL and other fields some providers read.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderKey {
    pub api_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Other fields by their `web-search.json` name, such as a Bright Data zone.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl fmt::Debug for ProviderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderKey")
            .field("api_key", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("extra", &self.extra)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchSettings {
    pub order: Vec<OrderEntry>,
    /// The enabled built-in engines, in [`ENGINES`] order.
    pub engines: Vec<String>,
    pub keys: BTreeMap<String, ProviderKey>,
}

impl Default for SearchSettings {
    fn default() -> Self {
        SearchSettings {
            order: [MUNIMENT, EXA]
                .map(|id| OrderEntry {
                    id: id.to_owned(),
                    enabled: true,
                })
                .to_vec(),
            engines: ENGINES.map(str::to_owned).to_vec(),
            keys: BTreeMap::new(),
        }
    }
}

/// The settings a client reads: every key reduced to whether it is set and
/// its last four characters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingsView {
    pub order: Vec<OrderView>,
    pub engines: Vec<EngineView>,
    pub keys: Vec<KeyView>,
    /// The providers a key can add, and the extra fields each one reads.
    pub providers: Vec<ProviderView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OrderView {
    pub id: String,
    pub enabled: bool,
    pub has_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EngineView {
    pub id: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyView {
    pub provider: String,
    pub has_key: bool,
    /// The key's last four characters, absent for a key of eight or fewer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderView {
    pub id: &'static str,
    pub base_url: bool,
    pub extra: &'static [&'static str],
}

impl SearchSettings {
    /// Keeps every provider that can serve in the order exactly once: the
    /// built-in engine, Exa and each provider with a key. A missing one joins
    /// at the end turned off, and an entry that cannot serve leaves.
    pub fn normalize(&mut self) {
        let mut seen = Vec::new();
        let keys = &self.keys;
        self.order.retain(|entry| {
            let serves = entry.id == MUNIMENT || entry.id == EXA || keys.contains_key(&entry.id);
            let first = !seen.contains(&entry.id);
            seen.push(entry.id.clone());
            serves && first
        });
        let missing: Vec<String> = [MUNIMENT, EXA]
            .into_iter()
            .map(str::to_owned)
            .chain(self.keys.keys().cloned())
            .filter(|id| !self.order.iter().any(|entry| &entry.id == id))
            .collect();
        for id in missing {
            self.order.push(OrderEntry { id, enabled: false });
        }
        self.engines = ENGINES
            .iter()
            .filter(|engine| self.engines.iter().any(|name| name == *engine))
            .map(|engine| (*engine).to_owned())
            .collect();
    }

    /// Replaces the order. Every id must be the built-in engine, Exa or a
    /// provider with a key, once each.
    pub fn set_order(&mut self, order: Vec<OrderEntry>) -> Result<(), String> {
        for (index, entry) in order.iter().enumerate() {
            if order[..index].iter().any(|earlier| earlier.id == entry.id) {
                return Err(format!("{} appears twice in the order.", entry.id));
            }
            if entry.id != MUNIMENT && entry.id != EXA && !self.keys.contains_key(&entry.id) {
                return Err(format!(
                    "{} has no key, so it cannot join the order.",
                    entry.id
                ));
            }
        }
        self.order = order;
        self.normalize();
        Ok(())
    }

    /// Replaces the enabled engines. At least one must stay on.
    pub fn set_engines(&mut self, engines: Vec<String>) -> Result<(), String> {
        if let Some(unknown) = engines
            .iter()
            .find(|name| !ENGINES.contains(&name.as_str()))
        {
            return Err(format!("{unknown} is not a search engine."));
        }
        if engines.is_empty() {
            return Err(
                "Turn on at least one engine, or turn off Muniment search in the order.".into(),
            );
        }
        self.engines = engines;
        self.normalize();
        Ok(())
    }

    /// Stores a provider's key. A provider new to the record joins the end of
    /// the order turned on.
    pub fn set_key(&mut self, provider: &str, key: ProviderKey) -> Result<(), String> {
        let known = keyed_provider(provider)
            .ok_or_else(|| format!("{provider} is not a search provider that takes a key."))?;
        let api_key = key.api_key.trim();
        if api_key.is_empty() {
            return Err("The key is empty.".into());
        }
        let base_url = match key.base_url.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(_) if known.base_url.is_none() => {
                return Err(format!("{provider} takes no base URL."));
            }
            Some(raw) => {
                let parsed = url::Url::parse(raw).map_err(|_| "The base URL is not a URL.")?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err("The base URL must start with http:// or https://.".into());
                }
                Some(raw.to_owned())
            }
        };
        let mut extra = BTreeMap::new();
        for (name, value) in key.extra {
            if !known.extra.contains(&name.as_str()) {
                return Err(format!("{provider} takes no {name} field."));
            }
            let value = value.trim();
            if !value.is_empty() {
                extra.insert(name, value.to_owned());
            }
        }
        let added = !self.keys.contains_key(provider);
        self.keys.insert(
            provider.to_owned(),
            ProviderKey {
                api_key: api_key.to_owned(),
                base_url,
                extra,
            },
        );
        if added && !self.order.iter().any(|entry| entry.id == provider) {
            self.order.push(OrderEntry {
                id: provider.to_owned(),
                enabled: true,
            });
        }
        self.normalize();
        Ok(())
    }

    /// Removes a provider's key. The provider leaves the order, except Exa,
    /// which stays without a key.
    pub fn remove_key(&mut self, provider: &str) -> Result<(), String> {
        if self.keys.remove(provider).is_none() {
            return Err(format!("{provider} has no key."));
        }
        self.normalize();
        Ok(())
    }

    pub fn view(&self) -> SettingsView {
        SettingsView {
            order: self
                .order
                .iter()
                .map(|entry| OrderView {
                    id: entry.id.clone(),
                    enabled: entry.enabled,
                    has_key: self.keys.contains_key(&entry.id),
                })
                .collect(),
            engines: ENGINES
                .iter()
                .map(|engine| EngineView {
                    id: (*engine).to_owned(),
                    enabled: self.engines.iter().any(|name| name == engine),
                })
                .collect(),
            keys: self
                .keys
                .iter()
                .map(|(provider, key)| {
                    let characters: Vec<char> = key.api_key.chars().collect();
                    KeyView {
                        provider: provider.clone(),
                        has_key: true,
                        last4: (characters.len() > 8)
                            .then(|| characters[characters.len() - 4..].iter().collect()),
                        base_url: key.base_url.clone(),
                        extra: key.extra.clone(),
                    }
                })
                .collect(),
            providers: KEYED_PROVIDERS
                .iter()
                .map(|provider| ProviderView {
                    id: provider.id,
                    base_url: provider.base_url.is_some(),
                    extra: provider.extra,
                })
                .collect(),
        }
    }

    /// The providers pi-web-access tries, in order: the enabled entries, with
    /// the built-in engine as `searxng` while its endpoint is known.
    pub fn routing(&self, endpoint: Option<&SearchEndpoint>) -> Vec<String> {
        self.order
            .iter()
            .filter(|entry| entry.enabled)
            .filter_map(|entry| match entry.id.as_str() {
                MUNIMENT => endpoint.map(|_| "searxng".to_owned()),
                id => Some(id.to_owned()),
            })
            .collect()
    }
}

pub fn settings_path(state: &Path) -> PathBuf {
    state.join(SETTINGS_FILE)
}

/// Reads the record. Without one, it starts from the default and takes in the
/// provider keys already written in `web-search.json`, turned off in the
/// order, and saves that as the record.
pub fn load(state: &Path) -> io::Result<SearchSettings> {
    match std::fs::read(settings_path(state)) {
        Ok(bytes) => {
            let mut settings: SearchSettings =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            settings.normalize();
            Ok(settings)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let web_search = crate::state_root::agent_directory(state).join(WEB_SEARCH_FILE);
            let mut settings = SearchSettings::default();
            if let Some(object) = std::fs::read(web_search)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|value| value.as_object().cloned())
            {
                settings.keys = written_keys(&object);
                settings.normalize();
            }
            save(state, &settings)?;
            Ok(settings)
        }
        Err(error) => Err(error),
    }
}

/// Writes the record readable by its owner only, replacing it atomically.
pub fn save(state: &Path, settings: &SearchSettings) -> io::Result<()> {
    std::fs::create_dir_all(state)?;
    crate::model_router::config::write_private(
        &settings_path(state),
        &serde_json::to_vec_pretty(settings)?,
    )
}

/// The provider keys a `web-search.json` object holds as text.
fn written_keys(object: &Map<String, Value>) -> BTreeMap<String, ProviderKey> {
    let text = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    KEYED_PROVIDERS
        .iter()
        .filter_map(|provider| {
            let key = ProviderKey {
                api_key: text(provider.api_key)?,
                base_url: provider.base_url.and_then(text),
                extra: provider
                    .extra
                    .iter()
                    .filter_map(|name| Some(((*name).to_owned(), text(name)?)))
                    .collect(),
            };
            Some((provider.id.to_owned(), key))
        })
        .collect()
}

/// The port and token the runtime's search server listens with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchEndpoint {
    pub port: u16,
    pub token: String,
}

impl SearchEndpoint {
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn authorization(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

/// The endpoint the running search server wrote in the agent directory.
pub fn read_endpoint(agent: &Path) -> Option<SearchEndpoint> {
    serde_json::from_slice(&std::fs::read(agent.join(ENDPOINT_FILE)).ok()?).ok()
}

/// Writes the settings into a `web-search.json` object. Core owns each keyed
/// provider's fields, `searxngBaseUrl`, `searxngHeaders`, `searchRouting` and
/// `webSearch.enabled`; every other key stays as written. With no provider to
/// route to, web search is off: `webSearch.enabled` is false, so
/// pi-web-access registers no `web_search` tool instead of picking providers
/// on its own.
pub fn render_web_search(
    object: &mut Map<String, Value>,
    settings: &SearchSettings,
    endpoint: Option<&SearchEndpoint>,
) {
    for provider in KEYED_PROVIDERS {
        object.remove(provider.api_key);
        if let Some(field) = provider.base_url {
            object.remove(field);
        }
        for field in provider.extra {
            object.remove(*field);
        }
        if let Some(key) = settings.keys.get(provider.id) {
            object.insert(provider.api_key.into(), json!(key.api_key));
            if let (Some(field), Some(url)) = (provider.base_url, &key.base_url) {
                object.insert(field.into(), json!(url));
            }
            for (field, value) in &key.extra {
                object.insert(field.clone(), json!(value));
            }
        }
    }
    let routing = settings.routing(endpoint);
    match endpoint.filter(|_| routing.iter().any(|id| id == "searxng")) {
        Some(endpoint) => {
            object.insert("searxngBaseUrl".into(), json!(endpoint.base_url()));
            object.insert(
                "searxngHeaders".into(),
                json!({ "Authorization": endpoint.authorization() }),
            );
        }
        None => {
            object.remove("searxngBaseUrl");
            object.remove("searxngHeaders");
        }
    }
    let web_search = object
        .entry("webSearch")
        .or_insert_with(|| Value::Object(Map::new()));
    if !web_search.is_object() {
        *web_search = Value::Object(Map::new());
    }
    let web_search = web_search.as_object_mut().expect("an object");
    if routing.is_empty() {
        web_search.insert("enabled".into(), json!(false));
        object.remove("searchRouting");
    } else {
        web_search.remove("enabled");
        if web_search.is_empty() {
            object.remove("webSearch");
        }
        object.insert(
            "searchRouting".into(),
            json!({ "providers": routing, "fallbackOn": FALLBACK_ON }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> SearchEndpoint {
        SearchEndpoint {
            port: 4100,
            token: "t0ken".into(),
        }
    }

    fn key(api_key: &str) -> ProviderKey {
        ProviderKey {
            api_key: api_key.into(),
            ..ProviderKey::default()
        }
    }

    fn ids(settings: &SearchSettings) -> Vec<(&str, bool)> {
        settings
            .order
            .iter()
            .map(|entry| (entry.id.as_str(), entry.enabled))
            .collect()
    }

    #[test]
    fn the_default_tries_the_built_in_engine_then_exa_with_every_engine_on() {
        let settings = SearchSettings::default();
        assert_eq!(ids(&settings), [("muniment", true), ("exa", true)]);
        assert_eq!(settings.engines, ENGINES);
        assert!(settings.keys.is_empty());
        assert_eq!(
            settings.routing(Some(&endpoint())),
            ["searxng".to_owned(), "exa".to_owned()]
        );
        assert_eq!(settings.routing(None), ["exa".to_owned()]);
    }

    #[test]
    fn a_view_shows_whether_a_key_is_set_and_never_the_key() {
        let mut settings = SearchSettings::default();
        settings
            .set_key("tavily", key("  tvly-secret-value-1234 "))
            .unwrap();
        settings.set_key("kagi", key("short")).unwrap();
        let view = settings.view();
        let text = serde_json::to_string(&view).unwrap();
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("short"), "{text}");
        let tavily = view
            .keys
            .iter()
            .find(|key| key.provider == "tavily")
            .unwrap();
        assert!(tavily.has_key);
        assert_eq!(tavily.last4.as_deref(), Some("1234"));
        let kagi = view.keys.iter().find(|key| key.provider == "kagi").unwrap();
        assert_eq!(kagi.last4, None);
        assert!(view
            .order
            .iter()
            .any(|entry| entry.id == "tavily" && entry.has_key));
        assert!(view
            .providers
            .iter()
            .any(|provider| provider.id == "firecrawl"
                && provider.base_url
                && provider.extra.is_empty()));
        assert!(!format!("{settings:?}").contains("secret"));
    }

    #[test]
    fn keys_join_and_leave_the_order_and_exa_stays_without_one() {
        let mut settings = SearchSettings::default();
        settings.set_key("brave", key("brave-key")).unwrap();
        settings.set_key("exa", key("exa-key")).unwrap();
        assert_eq!(
            ids(&settings),
            [("muniment", true), ("exa", true), ("brave", true)]
        );
        settings.remove_key("brave").unwrap();
        settings.remove_key("exa").unwrap();
        assert_eq!(ids(&settings), [("muniment", true), ("exa", true)]);
        assert!(settings.remove_key("exa").is_err());
    }

    #[test]
    fn invalid_ids_fields_and_orders_are_refused() {
        let mut settings = SearchSettings::default();
        assert!(settings.set_key("searxng", key("k")).is_err());
        assert!(settings.set_key("nothing", key("k")).is_err());
        assert!(settings.set_key("tavily", key("  ")).is_err());
        let with_url = |url: &str| ProviderKey {
            api_key: "k".into(),
            base_url: Some(url.into()),
            ..ProviderKey::default()
        };
        assert!(settings
            .set_key("kagi", with_url("https://kagi.example"))
            .is_err());
        assert!(settings
            .set_key("firecrawl", with_url("ftp://x.example"))
            .is_err());
        settings
            .set_key("firecrawl", with_url("http://127.0.0.1:3002"))
            .unwrap();
        let zone = |name: &str| ProviderKey {
            api_key: "k".into(),
            extra: [(name.to_owned(), "zone".to_owned())].into(),
            ..ProviderKey::default()
        };
        assert!(settings
            .set_key("brightdata", zone("brightdataOther"))
            .is_err());
        settings
            .set_key("brightdata", zone("brightdataSerpZone"))
            .unwrap();

        let entry = |id: &str| OrderEntry {
            id: id.into(),
            enabled: true,
        };
        assert!(settings.set_order(vec![entry("tavily")]).is_err());
        assert!(settings
            .set_order(vec![entry("exa"), entry("exa")])
            .is_err());
        settings.set_order(vec![entry("firecrawl")]).unwrap();
        assert_eq!(
            ids(&settings),
            [
                ("firecrawl", true),
                ("muniment", false),
                ("exa", false),
                ("brightdata", false)
            ]
        );

        assert!(settings.set_engines(vec![]).is_err());
        assert!(settings.set_engines(vec!["google".into()]).is_err());
        settings
            .set_engines(vec!["wikipedia".into(), "brave".into()])
            .unwrap();
        assert_eq!(settings.engines, ["brave", "wikipedia"]);
    }

    #[test]
    fn rendering_keeps_unmanaged_keys_and_replaces_managed_ones() {
        let mut settings = SearchSettings::default();
        settings
            .set_key(
                "firecrawl",
                ProviderKey {
                    api_key: "fc-key".into(),
                    base_url: Some("http://127.0.0.1:3002".into()),
                    ..ProviderKey::default()
                },
            )
            .unwrap();
        let mut object: Map<String, Value> = serde_json::from_value(json!({
            "workflow": "none",
            "curatorTimeoutSeconds": 30,
            "tavilyApiKey": "stale",
            "searxngBaseUrl": "http://old.example",
            "webSearch": {"enabled": false, "allowedProviders": ["exa", "searxng", "firecrawl"]},
            "ssrf": {"trustEnvProxy": true}
        }))
        .unwrap();
        render_web_search(&mut object, &settings, Some(&endpoint()));
        assert_eq!(
            Value::Object(object.clone()),
            json!({
                "workflow": "none",
                "curatorTimeoutSeconds": 30,
                "firecrawlApiKey": "fc-key",
                "firecrawlBaseUrl": "http://127.0.0.1:3002",
                "searxngBaseUrl": "http://127.0.0.1:4100",
                "searxngHeaders": {"Authorization": "Bearer t0ken"},
                "webSearch": {"allowedProviders": ["exa", "searxng", "firecrawl"]},
                "searchRouting": {
                    "providers": ["searxng", "exa", "firecrawl"],
                    "fallbackOn": ["transient", "quota", "network", "invalid-response", "unsupported"]
                },
                "ssrf": {"trustEnvProxy": true}
            })
        );

        settings.remove_key("firecrawl").unwrap();
        render_web_search(&mut object, &settings, None);
        assert!(!object.contains_key("firecrawlApiKey"));
        assert!(!object.contains_key("firecrawlBaseUrl"));
        assert!(!object.contains_key("searxngBaseUrl"));
        assert!(!object.contains_key("searxngHeaders"));
        assert_eq!(object["searchRouting"]["providers"], json!(["exa"]));
        assert_eq!(object["ssrf"], json!({"trustEnvProxy": true}));
        assert!(object["ssrf"].get("allowRanges").is_none());
    }

    #[test]
    fn with_nothing_to_route_web_search_is_off() {
        let mut settings = SearchSettings::default();
        for entry in &mut settings.order {
            entry.enabled = false;
        }
        let mut object = Map::new();
        render_web_search(&mut object, &settings, Some(&endpoint()));
        assert_eq!(
            Value::Object(object.clone()),
            json!({"webSearch": {"enabled": false}})
        );

        // The built-in engine alone, while its server is down, routes nowhere.
        settings.order[0].enabled = true;
        render_web_search(&mut object, &settings, None);
        assert_eq!(
            Value::Object(object.clone()),
            json!({"webSearch": {"enabled": false}})
        );
        render_web_search(&mut object, &settings, Some(&endpoint()));
        assert_eq!(object["searchRouting"]["providers"], json!(["searxng"]));
        assert!(!object.contains_key("webSearch"));
    }

    #[test]
    fn a_first_load_takes_in_written_keys_and_saves_a_private_record() {
        let state =
            std::env::temp_dir().join(format!("muniment-search-settings-{}", uuid::Uuid::new_v4()));
        let agent = crate::state_root::agent_directory(&state);
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(
            agent.join(WEB_SEARCH_FILE),
            br#"{"tavilyApiKey":"tvly-hand","brightdataApiKey":"bd","brightdataSerpZone":"serp","provider":"brave"}"#,
        )
        .unwrap();
        let settings = load(&state).unwrap();
        assert_eq!(
            ids(&settings),
            [
                ("muniment", true),
                ("exa", true),
                ("brightdata", false),
                ("tavily", false)
            ]
        );
        assert_eq!(settings.keys["tavily"].api_key, "tvly-hand");
        assert_eq!(
            settings.keys["brightdata"].extra["brightdataSerpZone"],
            "serp"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(settings_path(&state))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The saved record wins over the file from then on.
        std::fs::write(agent.join(WEB_SEARCH_FILE), b"{}").unwrap();
        assert_eq!(load(&state).unwrap(), settings);
        std::fs::remove_dir_all(state).unwrap();
    }
}
