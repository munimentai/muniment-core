//! Where the router keeps its state, and where it reads account secrets.
//!
//! A [`RouterStore`] holds the accounts, the usage ledger, the quota
//! snapshots, the policy sessions, and the factory's run records and
//! outcomes. A [`SecretSource`] holds each account's credential. The desktop
//! keeps both in the agent directory, in the files the router has always
//! written: [`FileStore`] and [`FileSecrets`]. A server host keeps account
//! state in a database and credentials in a secret manager.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::config::{self, Account, Credential, RouterConfig};
use super::policy::Sessions;
use super::quota::{self, Quota, QuotaStore};
use super::usage::{self, Ledger};
use super::wire::Tokens;

/// One factory run: what its token is bound to, and what it has spent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: String,
    pub task_id: String,
    pub repo: String,
    pub role: String,
    pub budget_usd: f64,
    pub created_ms: i64,
    pub expires_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_ms: Option<i64>,
    #[serde(default)]
    pub usage: RunUsage,
    /// The run's most recent request, when the router answered it with an
    /// error status. A later answered request clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<RunFailure>,
}

/// What the router answered a run's failed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFailure {
    /// The HTTP status the client received.
    pub status: u16,
    /// `budget_exhausted`, `routing_constraints`, `routing_budget`,
    /// `upstream_unavailable`, `rate_limited` or `auth`, or none when the
    /// failure is none of those.
    pub error_type: Option<String>,
    /// When the router answered it, in milliseconds since the epoch.
    pub at_ms: i64,
}

/// What a run has spent so far.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunUsage {
    pub spent_usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub requests: u64,
    /// `family/model` to the turns that model served for the run.
    pub models: BTreeMap<String, u64>,
}

impl RunUsage {
    /// Adds one settled turn.
    pub fn add(&mut self, charge: &RunCharge) {
        self.spent_usd += charge.cost_usd.max(0.0);
        self.input_tokens = self.input_tokens.saturating_add(charge.tokens.input);
        self.output_tokens = self.output_tokens.saturating_add(charge.tokens.output);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(charge.tokens.cache_read);
        if let Some(model) = &charge.model {
            self.requests = self.requests.saturating_add(1);
            *self.models.entry(model.clone()).or_insert(0) += 1;
        }
    }
}

/// One settled turn of a run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunCharge {
    pub cost_usd: f64,
    pub tokens: Tokens,
    /// The `family/model` that served the turn. `None` adds cost alone.
    pub model: Option<String>,
}

/// The scope a success rate is measured in. `*` stands for every role or
/// every repository.
pub const ANY: &str = "*";

/// A pass and fail count that halves over a fixed half-life, so recent
/// outcomes outweigh old ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct SuccessStat {
    pub successes: f64,
    pub trials: f64,
    pub updated_ms: i64,
}

impl SuccessStat {
    /// The counts as they stand at `now_ms`.
    pub fn at(&self, now_ms: i64, half_life_ms: i64) -> Self {
        let age = now_ms.saturating_sub(self.updated_ms).max(0) as f64;
        let decay = if half_life_ms > 0 {
            0.5_f64.powf(age / half_life_ms as f64)
        } else {
            1.0
        };
        Self {
            successes: self.successes * decay,
            trials: self.trials * decay,
            updated_ms: now_ms.max(self.updated_ms),
        }
    }

    /// Adds one outcome of `weight` trials, decaying what came before.
    pub fn observe(&mut self, passed: bool, weight: f64, now_ms: i64, half_life_ms: i64) {
        let weight = if weight.is_finite() {
            weight.max(0.0)
        } else {
            0.0
        };
        *self = self.at(now_ms, half_life_ms);
        self.trials += weight;
        if passed {
            self.successes += weight;
        }
    }

    /// The pass rate, once at least `min_samples` decayed trials stand behind it.
    pub fn rate(&self, min_samples: f64) -> Option<f64> {
        (self.trials > 0.0 && self.trials >= min_samples)
            .then(|| (self.successes / self.trials).clamp(0.0, 1.0))
    }
}

/// How measured success rates are read.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SuccessWindow {
    pub half_life_ms: i64,
    pub min_samples: f64,
}

impl Default for SuccessWindow {
    fn default() -> Self {
        Self {
            half_life_ms: 7 * 24 * 60 * 60 * 1000,
            min_samples: 5.0,
        }
    }
}

/// The measured success rate of every model with enough samples, by
/// `family/model`: the role and repository scope first, then the role across
/// repositories, then every run.
pub fn success_rates(
    stats: &BTreeMap<(String, String, String), SuccessStat>,
    role: &str,
    repo: &str,
    now_ms: i64,
    window: SuccessWindow,
) -> BTreeMap<String, f64> {
    let mut rates = BTreeMap::new();
    let models: std::collections::BTreeSet<&String> =
        stats.keys().map(|(model, _, _)| model).collect();
    for model in models {
        let scopes = [(role, repo), (role, ANY), (ANY, ANY)];
        let rate = scopes.iter().find_map(|(role, repo)| {
            stats
                .get(&(model.clone(), (*role).to_owned(), (*repo).to_owned()))
                .and_then(|stat| {
                    stat.at(now_ms, window.half_life_ms)
                        .rate(window.min_samples)
                })
        });
        if let Some(rate) = rate {
            rates.insert(model.clone(), rate);
        }
    }
    rates
}

/// The three scopes one outcome counts in: the run's role and repository,
/// the role everywhere, and every run.
pub fn success_scopes<'a>(role: &'a str, repo: &'a str) -> [(&'a str, &'a str); 3] {
    [(role, repo), (role, ANY), (ANY, ANY)]
}

/// The router's state. Every method is safe to call from many threads.
pub trait RouterStore: Send + Sync {
    /// The accounts and routing settings. A store that keeps credentials
    /// inline answers them; otherwise each account carries a placeholder
    /// credential that a [`SecretSource`] replaces.
    fn load_config(&self) -> io::Result<RouterConfig>;
    /// Adds an account or replaces the one with its id.
    fn upsert_account(&self, account: &Account) -> io::Result<()>;
    fn remove_account(&self, id: &str) -> io::Result<()>;

    fn load_ledger(&self) -> Ledger;
    /// Persists the ledger after the record of `account` changed.
    fn save_ledger(&self, ledger: &Ledger, account: &str) -> io::Result<()>;

    fn load_quotas(&self) -> QuotaStore;
    fn save_quota(&self, account: &str, quota: &Quota) -> io::Result<()>;

    fn load_sessions(&self) -> Sessions;
    /// Persists the sessions after the one keyed `changed` changed, dropping
    /// sessions past their lifetime.
    fn save_sessions(&self, sessions: &mut Sessions, changed: &str, now_ms: i64) -> io::Result<()>;

    /// Records a new run. A run id already present is an error of kind
    /// `AlreadyExists`.
    fn create_run(&self, run: &RunRecord) -> io::Result<()>;
    fn run(&self, run_id: &str) -> io::Result<Option<RunRecord>>;
    fn add_run_usage(&self, run_id: &str, charge: &RunCharge) -> io::Result<()>;
    fn revoke_run(&self, run_id: &str, now_ms: i64) -> io::Result<()>;
    /// Keeps `failure` as the outcome of the run's most recent request. None
    /// clears it after a request the router answered without an error.
    fn record_run_failure(&self, run_id: &str, failure: Option<&RunFailure>) -> io::Result<()>;

    /// Keeps one gate outcome as reported.
    fn record_outcome(&self, run_id: &str, gate: &str, passed: bool, now_ms: i64)
        -> io::Result<()>;
    /// Adds one outcome to the success count of `model` in one scope.
    fn observe_success(
        &self,
        key: (&str, &str, &str),
        passed: bool,
        weight: f64,
        now_ms: i64,
        half_life_ms: i64,
    ) -> io::Result<()>;
    /// The success counts that bear on `role` and `repo`, keyed by model,
    /// role and repository.
    fn success_stats(
        &self,
        role: &str,
        repo: &str,
    ) -> io::Result<BTreeMap<(String, String, String), SuccessStat>>;
}

/// Where each account's credential lives.
pub trait SecretSource: Send + Sync {
    fn read(&self, id: &str) -> Result<Option<Credential>, String>;
    fn write(&self, id: &str, credential: &Credential) -> Result<(), String>;
    fn remove(&self, id: &str) -> Result<(), String>;

    /// Replaces the credential with `next` when it still equals `previous`.
    /// Otherwise another holder rotated it first, and the answer is the
    /// credential in place now.
    fn swap(
        &self,
        id: &str,
        previous: &Credential,
        next: &Credential,
    ) -> Result<Credential, String> {
        match self.read(id)? {
            Some(current) if &current != previous => Ok(current),
            Some(_) => {
                self.write(id, next)?;
                Ok(next.clone())
            }
            None => Err("The account was removed.".into()),
        }
    }

    /// Puts each account's credential in place. An account whose credential
    /// cannot be read leaves the configuration, so no turn goes out without one.
    fn fill(&self, config: &mut RouterConfig) {
        config
            .accounts
            .retain_mut(|account| match self.read(&account.id) {
                Ok(Some(credential)) => {
                    account.credential = credential;
                    true
                }
                Ok(None) => {
                    eprintln!(
                        "muniment-router: account {} has no credential and takes no turn",
                        account.id
                    );
                    false
                }
                Err(error) => {
                    eprintln!(
                        "muniment-router: account {} credential unreadable: {error}",
                        account.id
                    );
                    false
                }
            });
    }
}

/// A host adjustment to every configuration the backend loads, such as the
/// classifier a server names in its own settings.
pub type Overlay = Arc<dyn Fn(&mut RouterConfig) + Send + Sync>;

/// A store and the secret source beside it.
#[derive(Clone)]
pub struct Backend {
    pub store: Arc<dyn RouterStore>,
    pub secrets: Arc<dyn SecretSource>,
    pub overlay: Option<Overlay>,
}

impl Backend {
    pub fn new(store: Arc<dyn RouterStore>, secrets: Arc<dyn SecretSource>) -> Self {
        Self {
            store,
            secrets,
            overlay: None,
        }
    }

    /// The desktop backend: every record in the agent directory.
    pub fn files(agent: &Path) -> Self {
        Self::new(
            Arc::new(FileStore::new(agent)),
            Arc::new(FileSecrets::new(agent)),
        )
    }

    /// The configuration with every credential in place.
    pub fn config(&self) -> io::Result<RouterConfig> {
        let mut config = self.store.load_config()?;
        self.secrets.fill(&mut config);
        if let Some(overlay) = &self.overlay {
            overlay(&mut config);
        }
        Ok(config)
    }

    /// Saves an account and its credential.
    pub fn save_account(&self, account: &Account) -> io::Result<()> {
        self.secrets
            .write(&account.id, &account.credential)
            .map_err(io::Error::other)?;
        self.store.upsert_account(account)
    }

    /// Removes an account, its credential and its usage record.
    pub fn remove_account(&self, id: &str) -> io::Result<()> {
        self.store.remove_account(id)?;
        self.secrets.remove(id).map_err(io::Error::other)?;
        let mut ledger = self.store.load_ledger();
        ledger.forget(id);
        self.store.save_ledger(&ledger, id)
    }
}

/// Runs, outcomes and success counts held in memory for the life of the
/// process. The desktop serves no runs, so its file store keeps them here.
#[derive(Default)]
pub struct MemoryRuns {
    runs: Mutex<BTreeMap<String, RunRecord>>,
    outcomes: Mutex<Vec<(String, String, bool, i64)>>,
    success: Mutex<BTreeMap<(String, String, String), SuccessStat>>,
}

impl MemoryRuns {
    pub fn create_run(&self, run: &RunRecord) -> io::Result<()> {
        let mut runs = lock(&self.runs);
        if runs.contains_key(&run.run_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "The run already exists.",
            ));
        }
        runs.insert(run.run_id.clone(), run.clone());
        Ok(())
    }

    pub fn run(&self, run_id: &str) -> io::Result<Option<RunRecord>> {
        Ok(lock(&self.runs).get(run_id).cloned())
    }

    pub fn add_run_usage(&self, run_id: &str, charge: &RunCharge) -> io::Result<()> {
        if let Some(run) = lock(&self.runs).get_mut(run_id) {
            run.usage.add(charge);
        }
        Ok(())
    }

    pub fn revoke_run(&self, run_id: &str, now_ms: i64) -> io::Result<()> {
        if let Some(run) = lock(&self.runs).get_mut(run_id) {
            run.revoked_ms.get_or_insert(now_ms);
        }
        Ok(())
    }

    pub fn record_run_failure(&self, run_id: &str, failure: Option<&RunFailure>) -> io::Result<()> {
        if let Some(run) = lock(&self.runs).get_mut(run_id) {
            run.last_failure = failure.cloned();
        }
        Ok(())
    }

    pub fn record_outcome(&self, run_id: &str, gate: &str, passed: bool, now_ms: i64) {
        lock(&self.outcomes).push((run_id.into(), gate.into(), passed, now_ms));
    }

    pub fn observe_success(
        &self,
        (model, role, repo): (&str, &str, &str),
        passed: bool,
        weight: f64,
        now_ms: i64,
        half_life_ms: i64,
    ) {
        lock(&self.success)
            .entry((model.into(), role.into(), repo.into()))
            .or_default()
            .observe(passed, weight, now_ms, half_life_ms);
    }

    pub fn success_stats(
        &self,
        role: &str,
        repo: &str,
    ) -> BTreeMap<(String, String, String), SuccessStat> {
        let scopes = success_scopes(role, repo);
        lock(&self.success)
            .iter()
            .filter(|((_, r, p), _)| scopes.contains(&(r.as_str(), p.as_str())))
            .map(|(key, stat)| (key.clone(), *stat))
            .collect()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

/// The desktop store: the router's JSON files in the agent directory.
pub struct FileStore {
    agent: PathBuf,
    /// Serializes read-modify-write of each file within this process.
    writes: Mutex<()>,
    runs: MemoryRuns,
}

impl FileStore {
    pub fn new(agent: &Path) -> Self {
        Self {
            agent: agent.to_owned(),
            writes: Mutex::new(()),
            runs: MemoryRuns::default(),
        }
    }

    pub fn agent(&self) -> &Path {
        &self.agent
    }
}

impl RouterStore for FileStore {
    fn load_config(&self) -> io::Result<RouterConfig> {
        config::load(&self.agent)
    }

    fn upsert_account(&self, account: &Account) -> io::Result<()> {
        let _held = lock(&self.writes);
        let mut saved = config::load(&self.agent)?;
        match saved
            .accounts
            .iter_mut()
            .find(|known| known.id == account.id)
        {
            Some(known) => *known = account.clone(),
            None => saved.accounts.push(account.clone()),
        }
        config::save(&self.agent, &saved)
    }

    fn remove_account(&self, id: &str) -> io::Result<()> {
        let _held = lock(&self.writes);
        let mut saved = config::load(&self.agent)?;
        saved.accounts.retain(|account| account.id != id);
        config::save(&self.agent, &saved)
    }

    fn load_ledger(&self) -> Ledger {
        usage::load(&self.agent)
    }

    fn save_ledger(&self, ledger: &Ledger, _account: &str) -> io::Result<()> {
        usage::save(&self.agent, ledger)
    }

    fn load_quotas(&self) -> QuotaStore {
        quota::load(&self.agent)
    }

    fn save_quota(&self, account: &str, quota: &Quota) -> io::Result<()> {
        let _held = lock(&self.writes);
        let mut store = quota::load(&self.agent);
        store.accounts.insert(account.to_owned(), quota.clone());
        quota::save(&self.agent, &store)
    }

    fn load_sessions(&self) -> Sessions {
        Sessions::load(&self.agent)
    }

    fn save_sessions(
        &self,
        sessions: &mut Sessions,
        _changed: &str,
        now_ms: i64,
    ) -> io::Result<()> {
        sessions.save(&self.agent, now_ms)
    }

    fn create_run(&self, run: &RunRecord) -> io::Result<()> {
        self.runs.create_run(run)
    }

    fn run(&self, run_id: &str) -> io::Result<Option<RunRecord>> {
        self.runs.run(run_id)
    }

    fn add_run_usage(&self, run_id: &str, charge: &RunCharge) -> io::Result<()> {
        self.runs.add_run_usage(run_id, charge)
    }

    fn revoke_run(&self, run_id: &str, now_ms: i64) -> io::Result<()> {
        self.runs.revoke_run(run_id, now_ms)
    }

    fn record_run_failure(&self, run_id: &str, failure: Option<&RunFailure>) -> io::Result<()> {
        self.runs.record_run_failure(run_id, failure)
    }

    fn record_outcome(
        &self,
        run_id: &str,
        gate: &str,
        passed: bool,
        now_ms: i64,
    ) -> io::Result<()> {
        self.runs.record_outcome(run_id, gate, passed, now_ms);
        Ok(())
    }

    fn observe_success(
        &self,
        key: (&str, &str, &str),
        passed: bool,
        weight: f64,
        now_ms: i64,
        half_life_ms: i64,
    ) -> io::Result<()> {
        self.runs
            .observe_success(key, passed, weight, now_ms, half_life_ms);
        Ok(())
    }

    fn success_stats(
        &self,
        role: &str,
        repo: &str,
    ) -> io::Result<BTreeMap<(String, String, String), SuccessStat>> {
        Ok(self.runs.success_stats(role, repo))
    }
}

/// The desktop secret source: credentials inline in `muniment-router.json`.
pub struct FileSecrets {
    agent: PathBuf,
}

impl FileSecrets {
    pub fn new(agent: &Path) -> Self {
        Self {
            agent: agent.to_owned(),
        }
    }
}

/// Holds the cross-process lock on the router record while a refreshed
/// credential is merged into it.
struct RecordLock(PathBuf);

impl Drop for RecordLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn record_lock(agent: &Path) -> Result<RecordLock, String> {
    let path = agent.join(format!("{}.lock", config::CONFIG_FILE));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(RecordLock(path)),
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => return Err("Cannot lock account settings for token refresh.".into()),
        }
    }
}

impl SecretSource for FileSecrets {
    fn read(&self, id: &str) -> Result<Option<Credential>, String> {
        let config = config::load(&self.agent).map_err(|_| "Cannot read account settings.")?;
        Ok(config.account(id).map(|account| account.credential.clone()))
    }

    fn write(&self, id: &str, credential: &Credential) -> Result<(), String> {
        let _held = record_lock(&self.agent)?;
        let mut config = config::load(&self.agent).map_err(|_| "Cannot read account settings.")?;
        if let Some(account) = config.accounts.iter_mut().find(|account| account.id == id) {
            account.credential = credential.clone();
            config::save(&self.agent, &config).map_err(|_| "Cannot save the account.")?;
        }
        Ok(())
    }

    fn remove(&self, _id: &str) -> Result<(), String> {
        // The credential sits inside the account record, which the store removes.
        Ok(())
    }

    fn swap(
        &self,
        id: &str,
        previous: &Credential,
        next: &Credential,
    ) -> Result<Credential, String> {
        let _held = record_lock(&self.agent)?;
        let mut config = config::load(&self.agent).map_err(|_| "Cannot read account settings.")?;
        let entry = config
            .accounts
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or("The account was removed.")?;
        if &entry.credential != previous {
            return Ok(entry.credential.clone());
        }
        entry.credential = next.clone();
        config::save(&self.agent, &config).map_err(|_| "Cannot save the refreshed account.")?;
        Ok(next.clone())
    }

    fn fill(&self, _config: &mut RouterConfig) {
        // The file store already read each credential inline.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("muniment-store-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn key(id: &str) -> Account {
        Account {
            id: id.into(),
            family: "openai".into(),
            label: id.into(),
            credential: Credential::ApiKey {
                key: format!("sk-{id}"),
            },
            base_url: None,
            models: Vec::new(),
            enabled: true,
            weight: 1,
        }
    }

    #[test]
    fn the_file_backend_keeps_the_desktop_files() {
        let agent = tempdir();
        let backend = Backend::files(&agent);
        backend.save_account(&key("a1")).unwrap();
        backend.save_account(&key("a2")).unwrap();
        let mut renamed = key("a1");
        renamed.label = "Work".into();
        backend.save_account(&renamed).unwrap();
        let loaded = config::load(&agent).unwrap();
        assert_eq!(loaded.accounts.len(), 2);
        assert_eq!(loaded.accounts[0].label, "Work");
        assert_eq!(backend.config().unwrap().accounts, loaded.accounts);

        let mut ledger = Ledger::default();
        ledger.record_success("a1", "2026-09-18", 1, 2, 3);
        backend.store.save_ledger(&ledger, "a1").unwrap();
        assert_eq!(usage::load(&agent), ledger);
        backend
            .store
            .save_quota(
                "a1",
                &Quota {
                    observed_at_ms: 5,
                    ..Quota::default()
                },
            )
            .unwrap();
        assert_eq!(quota::load(&agent).accounts["a1"].observed_at_ms, 5);

        let next = Credential::ApiKey {
            key: "sk-new".into(),
        };
        let previous = key("a1").credential;
        assert_eq!(backend.secrets.swap("a1", &previous, &next).unwrap(), next);
        // A second rotation from the stale credential keeps the newer one.
        let stale = Credential::ApiKey {
            key: "sk-other".into(),
        };
        assert_eq!(backend.secrets.swap("a1", &previous, &stale).unwrap(), next);
        assert_eq!(backend.secrets.read("a1").unwrap(), Some(next));

        backend.remove_account("a1").unwrap();
        assert!(config::load(&agent).unwrap().account("a1").is_none());
        assert!(usage::load(&agent).account("a1").is_none());
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn success_decays_and_needs_enough_samples() {
        let half = 1_000;
        let mut stat = SuccessStat::default();
        for _ in 0..4 {
            stat.observe(true, 1.0, 0, half);
        }
        assert_eq!(stat.rate(5.0), None);
        stat.observe(false, 1.0, 0, half);
        assert_eq!(stat.rate(5.0), Some(0.8));
        // One half-life later the old outcomes count half, and a new failure
        // weighs as much as two of them.
        stat.observe(false, 1.0, half, half);
        let now = stat.at(half, half);
        assert!((now.trials - 3.5).abs() < 1e-9);
        assert!((now.successes - 2.0).abs() < 1e-9);
        assert_eq!(now.rate(5.0), None);
        assert!((now.rate(3.0).unwrap() - 2.0 / 3.5).abs() < 1e-9);
        // A weight splits one outcome across the models a run used.
        let mut split = SuccessStat::default();
        split.observe(true, 0.25, 0, half);
        assert_eq!(split.trials, 0.25);
    }

    #[test]
    fn success_rates_prefer_the_narrowest_scope_with_enough_samples() {
        let window = SuccessWindow {
            half_life_ms: 1_000_000,
            min_samples: 2.0,
        };
        let runs = MemoryRuns::default();
        for (role, repo, passed, count) in [
            ("implementer", "app", false, 2),
            ("implementer", ANY, true, 4),
            (ANY, ANY, true, 10),
        ] {
            for _ in 0..count {
                runs.observe_success(("openai/a", role, repo), passed, 1.0, 0, 1_000_000);
            }
        }
        runs.observe_success(("openai/b", ANY, ANY), true, 1.0, 0, 1_000_000);
        runs.observe_success(("openai/c", "reviewer", ANY), true, 5.0, 0, 1_000_000);
        let stats = runs.success_stats("implementer", "app");
        assert!(!stats.keys().any(|(_, role, _)| role == "reviewer"));
        let rates = success_rates(&stats, "implementer", "app", 0, window);
        assert_eq!(rates.get("openai/a"), Some(&0.0));
        // Too few samples anywhere: no measured rate.
        assert_eq!(rates.get("openai/b"), None);
        let rates = success_rates(
            &runs.success_stats("implementer", "other"),
            "implementer",
            "other",
            0,
            window,
        );
        assert_eq!(rates.get("openai/a"), Some(&1.0));
        let rates = success_rates(
            &runs.success_stats("planner", "x"),
            "planner",
            "x",
            0,
            window,
        );
        assert_eq!(rates.get("openai/a"), Some(&1.0));
    }

    #[test]
    fn run_usage_adds_cost_tokens_and_models() {
        let mut usage = RunUsage::default();
        usage.add(&RunCharge {
            cost_usd: 0.5,
            tokens: Tokens {
                input: 10,
                output: 2,
                cache_read: 4,
                ..Tokens::default()
            },
            model: Some("openai/a".into()),
        });
        usage.add(&RunCharge {
            cost_usd: 0.25,
            tokens: Tokens::default(),
            model: None,
        });
        assert_eq!(usage.spent_usd, 0.75);
        assert_eq!(usage.requests, 1);
        assert_eq!(usage.cache_read_tokens, 4);
        assert_eq!(usage.models["openai/a"], 1);
    }
}
