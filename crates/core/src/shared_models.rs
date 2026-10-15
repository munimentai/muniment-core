//! Model connections shared between paired machines.
//!
//! A device that shares sends its bundle: its Pi provider entries and its
//! router accounts. The receiving runtime writes them beside its own and
//! records which device sent each one, so the next bundle from that device,
//! or its revocation, removes exactly what it added. An entry the receiver
//! holds itself always wins.
//!
//! A sign-in whose provider rotates refresh tokens travels without its
//! refresh token. Two holders of one rotating token sign each other out, so
//! only the sharing machine refreshes, and it sends a fresh access token
//! before the old one runs out. A sign-in whose refresh token does not
//! rotate, and an API key, travel whole.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use muniment_models::pi_models;
use muniment_router::config::{self, Account, Credential, SHARED_ACCOUNT_PREFIX};
use muniment_router::store::Backend;
use muniment_router::{constraints, family, native_auth};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The record of what each device shares, beside Pi's `auth.json`.
pub const RECORD_FILE: &str = "muniment-shared.json";
/// How long a shared sign-in has left to live when it leaves this machine.
pub const LEASE_MARGIN_MS: i64 = 30 * 60_000;
/// The providers whose refresh tokens survive use on two machines at once.
const COPYABLE_PROVIDERS: &[&str] = &[
    "antigravity",
    "github-copilot",
    "google-antigravity",
    "google-gemini-cli",
];
const MAX_ENTRIES: usize = 64;
const MAX_LABEL_CHARS: usize = 120;
const REFRESH_TIMEOUT: Duration = Duration::from_secs(15);

/// What a sharing device sends: Pi provider entries by provider id, and
/// router accounts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    #[serde(default)]
    pub pi: Map<String, Value>,
    #[serde(default)]
    pub router: Vec<Account>,
}

impl Bundle {
    pub fn is_empty(&self) -> bool {
        self.pi.is_empty() && self.router.is_empty()
    }
}

/// What one bundle changed on the receiver.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Applied {
    /// The Pi providers the receiver now uses from the device.
    pub pi: Vec<String>,
    /// How many router accounts the receiver now holds from the device.
    pub router: usize,
    /// The Pi providers the receiver kept its own entry for.
    pub kept: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(default)]
    devices: BTreeMap<String, DeviceShare>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceShare {
    /// The SHA-256 of each Pi entry as written, so an entry the receiver
    /// replaced since is never removed.
    #[serde(default)]
    pi: BTreeMap<String, String>,
    #[serde(default)]
    router: Vec<String>,
    /// Whether this device's accounts turned the receiver's router on.
    #[serde(default)]
    enabled_router: bool,
}

type Hook = Arc<dyn Fn() + Send + Sync>;
static ON_CHANGE: RwLock<Option<Hook>> = RwLock::new(None);

/// Registers what runs after shared connections change, such as starting
/// the router listener. A later call replaces it.
pub fn set_on_change(hook: impl Fn() + Send + Sync + 'static) {
    *ON_CHANGE.write().unwrap_or_else(|error| error.into_inner()) = Some(Arc::new(hook));
}

fn changed() {
    let hook = ON_CHANGE
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

const SAVE_ERROR: &str = "This machine cannot save the shared connections. Check folder access.";

/// Replaces everything `device_id` shares with `bundle`. An empty bundle
/// removes it all.
pub fn apply(
    agent: &Path,
    device_id: &str,
    device_name: &str,
    bundle: Bundle,
) -> Result<Applied, String> {
    let (pi, router) = validate(device_id, device_name, bundle)?;
    let record_path = agent.join(RECORD_FILE);
    std::fs::create_dir_all(agent).map_err(|_| SAVE_ERROR.to_string())?;
    let _record_lock = pi_models::lock(&record_path).map_err(|_| SAVE_ERROR.to_string())?;
    let mut record = read_record(&record_path)?;
    let mut share = record.devices.remove(device_id).unwrap_or_default();
    let applied_pi;
    let kept;
    {
        let auth_path = agent.join("auth.json");
        let _auth_lock = pi_models::lock(&auth_path).map_err(|_| SAVE_ERROR.to_string())?;
        let mut auth = pi_models::read_json(&auth_path).map_err(|_| SAVE_ERROR.to_string())?;
        for (provider, digest) in std::mem::take(&mut share.pi) {
            if auth.get(&provider).map(entry_digest).as_deref() == Some(digest.as_str()) {
                auth.remove(&provider);
            }
        }
        let mut taken = Vec::new();
        let mut held = Vec::new();
        for (provider, entry) in pi {
            // The receiver's own entry, or one another device shares, stays.
            if auth.contains_key(&provider) {
                held.push(provider);
                continue;
            }
            share.pi.insert(provider.clone(), entry_digest(&entry));
            auth.insert(provider.clone(), entry);
            taken.push(provider);
        }
        pi_models::write_json(&auth_path, &auth).map_err(|_| SAVE_ERROR.to_string())?;
        applied_pi = taken;
        kept = held;
    }
    let router_count = router.len();
    {
        let config_path = config::config_path(agent);
        let _router_lock = pi_models::lock(&config_path).map_err(|_| SAVE_ERROR.to_string())?;
        let mut settings = config::load(agent).map_err(|_| SAVE_ERROR.to_string())?;
        let was_enabled = settings.enabled;
        let previous: BTreeSet<String> = std::mem::take(&mut share.router).into_iter().collect();
        let touched = !previous.is_empty() || !router.is_empty();
        settings
            .accounts
            .retain(|account| !previous.contains(&account.id));
        share.router = router.iter().map(|account| account.id.clone()).collect();
        settings.accounts.extend(router);
        if !share.router.is_empty() && !settings.enabled {
            settings.enabled = true;
            share.enabled_router = true;
        }
        if share.router.is_empty() && share.enabled_router {
            share.enabled_router = false;
            let others = record.devices.values().any(|other| other.enabled_router);
            if !others && settings.accounts.is_empty() {
                settings.enabled = false;
            }
        }
        if touched || settings.enabled != was_enabled {
            config::save(agent, &settings).map_err(|_| SAVE_ERROR.to_string())?;
        }
    }
    if !share.pi.is_empty() || !share.router.is_empty() || share.enabled_router {
        record.devices.insert(device_id.to_owned(), share);
    }
    write_record(&record_path, &record)?;
    changed();
    Ok(Applied {
        pi: applied_pi,
        router: router_count,
        kept,
    })
}

/// Removes everything `device_id` shares, as its revocation does. Answers
/// whether it shared anything.
pub fn drop_device(agent: &Path, device_id: &str) -> Result<bool, String> {
    let record_path = agent.join(RECORD_FILE);
    let shared = {
        let _record_lock = pi_models::lock(&record_path).map_err(|_| SAVE_ERROR.to_string())?;
        read_record(&record_path)?.devices.contains_key(device_id)
    };
    if shared {
        apply(agent, device_id, "", Bundle::default())?;
    }
    Ok(shared)
}

/// Checks a bundle and names each router account for this device. Answers the
/// Pi entries and the router accounts to write.
fn validate(
    device_id: &str,
    device_name: &str,
    bundle: Bundle,
) -> Result<(Map<String, Value>, Vec<Account>), String> {
    const INVALID: &str = "The shared connections are not valid.";
    if bundle.pi.len() > MAX_ENTRIES || bundle.router.len() > MAX_ENTRIES {
        return Err(INVALID.into());
    }
    let mut pi = Map::new();
    for (provider, entry) in bundle.pi {
        if !is_identifier(&provider) {
            return Err(INVALID.into());
        }
        let mut entry = entry.as_object().cloned().ok_or(INVALID)?;
        let text = |name: &str| {
            entry
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        match entry.get("type").and_then(Value::as_str) {
            Some("api_key") if !text("key").is_empty() => {
                // The variable that holds a key names a variable on the sender.
                entry.remove("env");
            }
            Some("oauth") if !text("access").is_empty() => {
                if !COPYABLE_PROVIDERS.contains(&provider.as_str()) {
                    entry.remove("refresh");
                }
            }
            _ => return Err(INVALID.into()),
        }
        pi.insert(provider, Value::Object(entry));
    }
    let mut router = Vec::new();
    for mut account in bundle.router {
        if !is_identifier(&account.id) || family::family(&account.family).is_none() {
            return Err(INVALID.into());
        }
        match &mut account.credential {
            Credential::ApiKey { key } if !key.trim().is_empty() => {}
            Credential::Subscription {
                provider,
                access,
                refresh,
                ..
            } if !access.trim().is_empty() => {
                if !COPYABLE_PROVIDERS.contains(&provider.as_str()) {
                    *refresh = None;
                }
            }
            _ => return Err(INVALID.into()),
        }
        // A loopback upstream names a server on the sender, not here.
        if account
            .base_url
            .as_deref()
            .is_some_and(constraints::loopback)
        {
            continue;
        }
        account.id = format!("{SHARED_ACCOUNT_PREFIX}{device_id}:{}", account.id);
        let label = if device_name.is_empty() {
            account.label.clone()
        } else {
            format!("{} from {device_name}", account.label)
        };
        account.label = label.chars().take(MAX_LABEL_CHARS).collect();
        router.push(account);
    }
    Ok((pi, router))
}

/// The bundle this machine shares: its own Pi entries and router accounts,
/// with each rotating sign-in refreshed when it has less than
/// [`LEASE_MARGIN_MS`] left. Connections other devices share here stay out,
/// so a bundle never passes another machine's connections along.
pub fn bundle(agent: &Path, now_ms: i64) -> Result<Bundle, String> {
    const READ_ERROR: &str =
        "This computer cannot read its model connections. Check folder access.";
    let record = {
        let record_path = agent.join(RECORD_FILE);
        let _record_lock = pi_models::lock(&record_path).map_err(|_| READ_ERROR.to_string())?;
        read_record(&record_path)?
    };
    let received: BTreeMap<&str, &str> = record
        .devices
        .values()
        .flat_map(|share| share.pi.iter().map(|(p, d)| (p.as_str(), d.as_str())))
        .collect();
    let auth_path = agent.join("auth.json");
    let auth = pi_models::read_json(&auth_path).map_err(|_| READ_ERROR.to_string())?;
    let mut pi = Map::new();
    for (provider, entry) in &auth {
        if received.get(provider.as_str()).copied() == Some(entry_digest(entry).as_str()) {
            continue;
        }
        match entry.get("type").and_then(Value::as_str) {
            Some("api_key") => {
                let mut entry = entry.as_object().cloned().unwrap_or_default();
                if entry
                    .get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| !key.trim().is_empty())
                {
                    entry.remove("env");
                    pi.insert(provider.clone(), Value::Object(entry));
                }
            }
            Some("oauth") => {
                if COPYABLE_PROVIDERS.contains(&provider.as_str()) {
                    pi.insert(provider.clone(), entry.clone());
                    continue;
                }
                let mut fresh = fresh_pi_entry(agent, provider, entry, now_ms);
                let live = Credential::from_pi_auth(provider, &fresh)
                    .is_some_and(|credential| !credential.expired(now_ms));
                if live {
                    if let Some(object) = fresh.as_object_mut() {
                        object.remove("refresh");
                    }
                    pi.insert(provider.clone(), fresh);
                }
            }
            _ => {}
        }
    }
    let settings = config::load(agent).map_err(|_| READ_ERROR.to_string())?;
    let backend = Backend::files(agent);
    let mut router = Vec::new();
    for account in settings.accounts {
        if account.id.starts_with(SHARED_ACCOUNT_PREFIX)
            || !account.enabled
            || account
                .base_url
                .as_deref()
                .is_some_and(constraints::loopback)
        {
            continue;
        }
        let mut account = match &account.credential {
            Credential::Subscription { provider, .. }
                if !COPYABLE_PROVIDERS.contains(&provider.as_str()) =>
            {
                let fresh = native_auth::refresh_account_within(
                    &backend,
                    &account.id,
                    now_ms,
                    LEASE_MARGIN_MS,
                    REFRESH_TIMEOUT,
                )
                .unwrap_or(account);
                if fresh.credential.expired(now_ms) {
                    continue;
                }
                fresh
            }
            _ => account,
        };
        if let Credential::Subscription {
            provider, refresh, ..
        } = &mut account.credential
        {
            if !COPYABLE_PROVIDERS.contains(&provider.as_str()) {
                *refresh = None;
            }
        }
        router.push(account);
    }
    Ok(Bundle { pi, router })
}

/// A Pi sign-in with a fresh access token when it has less than the lease
/// margin left. A subscription copied into the router pool shares its refresh
/// token, so the pool rotates it once and the Pi entry mirrors the result.
fn fresh_pi_entry(agent: &Path, provider: &str, entry: &Value, now_ms: i64) -> Value {
    let Some(credential) = Credential::from_pi_auth(provider, entry) else {
        return entry.clone();
    };
    let pooled = config::load(agent).ok().and_then(|settings| {
        settings.accounts.into_iter().find(|account| {
            matches!(&account.credential,
                Credential::Subscription { provider: p, access, refresh, .. }
                if p == provider && (entry["access"] == *access
                    || refresh.as_deref().is_some_and(|r| entry["refresh"] == r)))
        })
    });
    let refreshed = match pooled {
        Some(account) => Some(
            native_auth::refresh_account_within(
                &Backend::files(agent),
                &account.id,
                now_ms,
                LEASE_MARGIN_MS,
                REFRESH_TIMEOUT,
            )
            .map(|account| account.credential),
        ),
        None => native_auth::refresh_if_expiring_within(
            &credential,
            now_ms,
            LEASE_MARGIN_MS,
            REFRESH_TIMEOUT,
        ),
    };
    let Some(Ok(Credential::Subscription {
        access,
        refresh,
        expires_ms,
        ..
    })) = refreshed
    else {
        return entry.clone();
    };
    let mut current = entry.clone();
    current["access"] = access.into();
    if let Some(refresh) = refresh {
        current["refresh"] = refresh.into();
    }
    if let Some(expires) = expires_ms {
        current["expires"] = expires.into();
    }
    if current == *entry {
        return current;
    }
    // Re-read under the lock so a sign-in made meanwhile survives.
    let auth_path = agent.join("auth.json");
    let Ok(_lock) = pi_models::lock(&auth_path) else {
        return current;
    };
    let Ok(mut latest) = pi_models::read_json(&auth_path) else {
        return current;
    };
    if latest.get(provider) != Some(entry) {
        return latest.get(provider).cloned().unwrap_or(current);
    }
    latest.insert(provider.to_owned(), current.clone());
    let _ = pi_models::write_json(&auth_path, &latest);
    current
}

fn read_record(path: &Path) -> Result<Record, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| "The shared connections record is damaged.".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Record::default()),
        Err(_) => Err(SAVE_ERROR.into()),
    }
}

fn write_record(path: &Path, record: &Record) -> Result<(), String> {
    let value = serde_json::to_value(record).map_err(|_| SAVE_ERROR.to_string())?;
    let Value::Object(map) = value else {
        return Err(SAVE_ERROR.into());
    };
    pi_models::write_json(path, &map).map_err(|_| SAVE_ERROR.to_string())
}

fn entry_digest(entry: &Value) -> String {
    let bytes = serde_json::to_vec(entry).unwrap_or_default();
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn temp_dir() -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "muniment-shared-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn key_entry(key: &str) -> Value {
        serde_json::json!({"type":"api_key","key":key})
    }

    fn oauth_entry(access: &str) -> Value {
        serde_json::json!({"type":"oauth","access":access,"refresh":"r-secret","expires":9_999_999_999_999_i64})
    }

    fn auth(agent: &Path) -> Map<String, Value> {
        pi_models::read_json(&agent.join("auth.json")).unwrap()
    }

    fn router_account(id: &str, credential: Credential) -> Account {
        Account {
            id: id.into(),
            family: "openai".into(),
            label: "Work".into(),
            credential,
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 1,
            overflow: false,
        }
    }

    #[test]
    fn a_bundle_adds_entries_beside_the_receivers_own_and_a_revoke_removes_them() {
        let dir = temp_dir();
        let agent = dir.as_path();
        let mut own = Map::new();
        own.insert("anthropic".into(), key_entry("own-key"));
        pi_models::write_json(&agent.join("auth.json"), &own).unwrap();

        let mut pi = Map::new();
        pi.insert("anthropic".into(), key_entry("their-key"));
        pi.insert("openai-codex".into(), oauth_entry("their-access"));
        pi.insert("github-copilot".into(), oauth_entry("copilot-access"));
        let applied = apply(
            agent,
            "device-a",
            "Laptop",
            Bundle {
                pi,
                router: Vec::new(),
            },
        )
        .unwrap();

        assert_eq!(applied.kept, vec!["anthropic".to_string()]);
        let written = auth(agent);
        assert_eq!(written["anthropic"]["key"], "own-key");
        assert_eq!(written["openai-codex"]["access"], "their-access");
        // A rotating refresh token never reaches the receiver.
        assert!(written["openai-codex"].get("refresh").is_none());
        // A refresh token that does not rotate travels whole.
        assert_eq!(written["github-copilot"]["refresh"], "r-secret");

        assert!(drop_device(agent, "device-a").unwrap());
        let left = auth(agent);
        assert_eq!(left.len(), 1);
        assert_eq!(left["anthropic"]["key"], "own-key");
        assert!(!drop_device(agent, "device-a").unwrap());
    }

    #[test]
    fn a_later_bundle_replaces_the_earlier_one_but_not_an_entry_the_receiver_changed() {
        let dir = temp_dir();
        let agent = dir.as_path();
        let mut pi = Map::new();
        pi.insert("openai".into(), key_entry("k1"));
        pi.insert("xai".into(), key_entry("k2"));
        apply(
            agent,
            "device-a",
            "Laptop",
            Bundle {
                pi,
                router: Vec::new(),
            },
        )
        .unwrap();

        // The receiver's owner replaces one entry with a key of their own.
        let mut current = auth(agent);
        current.insert("xai".into(), key_entry("mine"));
        pi_models::write_json(&agent.join("auth.json"), &current).unwrap();

        let mut next = Map::new();
        next.insert("openai".into(), key_entry("k3"));
        apply(
            agent,
            "device-a",
            "Laptop",
            Bundle {
                pi: next,
                router: Vec::new(),
            },
        )
        .unwrap();
        let written = auth(agent);
        assert_eq!(written["openai"]["key"], "k3");
        assert_eq!(written["xai"]["key"], "mine");
    }

    #[test]
    fn a_second_device_does_not_replace_the_first_devices_entry() {
        let dir = temp_dir();
        let agent = dir.as_path();
        let mut first = Map::new();
        first.insert("openai".into(), key_entry("first"));
        apply(
            agent,
            "device-a",
            "Laptop",
            Bundle {
                pi: first,
                router: Vec::new(),
            },
        )
        .unwrap();
        let mut second = Map::new();
        second.insert("openai".into(), key_entry("second"));
        let applied = apply(
            agent,
            "device-b",
            "Tower",
            Bundle {
                pi: second,
                router: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(applied.kept, vec!["openai".to_string()]);
        assert_eq!(auth(agent)["openai"]["key"], "first");
    }

    #[test]
    fn shared_router_accounts_carry_the_device_and_turn_the_router_on_until_removed() {
        let dir = temp_dir();
        let agent = dir.as_path();
        let subscription = Credential::Subscription {
            provider: "openai-codex".into(),
            access: "a".into(),
            refresh: Some("rotating".into()),
            expires_ms: Some(9_999_999_999_999),
            account_id: None,
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        let router = vec![
            router_account("one", Credential::ApiKey { key: "k".into() }),
            router_account("two", subscription),
        ];
        apply(
            agent,
            "device-a",
            "Laptop",
            Bundle {
                pi: Map::new(),
                router,
            },
        )
        .unwrap();
        let settings = config::load(agent).unwrap();
        assert!(settings.enabled);
        assert_eq!(settings.accounts.len(), 2);
        assert_eq!(settings.accounts[0].id, "shared:device-a:one");
        assert_eq!(settings.accounts[0].label, "Work from Laptop");
        assert!(matches!(
            &settings.accounts[1].credential,
            Credential::Subscription { refresh: None, .. }
        ));

        drop_device(agent, "device-a").unwrap();
        let settings = config::load(agent).unwrap();
        assert!(!settings.enabled);
        assert!(settings.accounts.is_empty());
    }

    #[test]
    fn the_shared_bundle_leaves_out_what_others_shared_here() {
        let dir = temp_dir();
        let agent = dir.as_path();
        let mut received = Map::new();
        received.insert("openai".into(), key_entry("from-elsewhere"));
        apply(
            agent,
            "device-a",
            "Laptop",
            Bundle {
                pi: received,
                router: vec![router_account(
                    "one",
                    Credential::ApiKey { key: "k".into() },
                )],
            },
        )
        .unwrap();
        let mut current = auth(agent);
        current.insert(
            "anthropic".into(),
            serde_json::json!({"type":"api_key","key":"mine","env":"ANTHROPIC_API_KEY"}),
        );
        current.insert("openai-codex".into(), oauth_entry("live"));
        pi_models::write_json(&agent.join("auth.json"), &current).unwrap();

        let shared = bundle(agent, 0).unwrap();
        assert_eq!(
            shared.pi.keys().collect::<Vec<_>>(),
            vec!["anthropic", "openai-codex"]
        );
        assert!(shared.pi["anthropic"].get("env").is_none());
        assert!(shared.pi["openai-codex"].get("refresh").is_none());
        assert!(shared.router.is_empty());
    }

    #[test]
    fn an_invalid_bundle_changes_nothing() {
        let dir = temp_dir();
        let mut pi = Map::new();
        pi.insert("../escape".into(), key_entry("k"));
        assert!(apply(
            dir.as_path(),
            "device-a",
            "Laptop",
            Bundle {
                pi,
                router: Vec::new()
            }
        )
        .is_err());
        let mut empty_key = Map::new();
        empty_key.insert("openai".into(), key_entry(" "));
        assert!(apply(
            dir.as_path(),
            "device-a",
            "Laptop",
            Bundle {
                pi: empty_key,
                router: Vec::new()
            }
        )
        .is_err());
        assert!(!dir.as_path().join("auth.json").exists());
    }
}
