//! The router store in Postgres.
//!
//! Account metadata, routing settings, the usage ledger, quota snapshots,
//! policy sessions, runs, outcomes and success counts each have a table. No
//! table holds secret material: an account row names its kind and provider,
//! and its credential lives in the secret source. Migrations run at connect,
//! in order, under an advisory lock, and each is recorded in
//! `router_migrations`.

use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Account, Classifier, Credential, Route, RouterConfig};
use crate::policy::{self, Sessions};
use crate::quota::{Quota, QuotaStore};
use crate::store::{
    success_scopes, RouterStore, RunCharge, RunFailure, RunRecord, RunUsage, SuccessStat,
};
use crate::usage::Ledger;

/// Every migration, in order. A migration never changes once released.
const MIGRATIONS: &[(i32, &str)] = &[
    (
        1,
        "CREATE TABLE accounts (
        id text PRIMARY KEY,
        position bigserial NOT NULL,
        family text NOT NULL,
        label text NOT NULL,
        kind text NOT NULL CHECK (kind IN ('api_key', 'subscription')),
        provider text,
        email text,
        plan text,
        upstream_account_id text,
        base_url text,
        models jsonb NOT NULL DEFAULT '[]',
        enabled boolean NOT NULL DEFAULT true,
        weight integer NOT NULL DEFAULT 1 CHECK (weight >= 0),
        updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE settings (
        key text PRIMARY KEY,
        value jsonb NOT NULL
    );
    CREATE TABLE account_usage (
        account_id text PRIMARY KEY,
        usage jsonb NOT NULL,
        cache jsonb
    );
    CREATE TABLE quotas (
        account_id text PRIMARY KEY,
        quota jsonb NOT NULL,
        observed_ms bigint NOT NULL
    );
    CREATE TABLE sessions (
        id text PRIMARY KEY,
        session jsonb NOT NULL,
        updated_ms bigint NOT NULL
    );
    CREATE INDEX sessions_updated ON sessions (updated_ms);
    CREATE TABLE runs (
        run_id text PRIMARY KEY,
        task_id text NOT NULL,
        repo text NOT NULL,
        role text NOT NULL,
        budget_usd double precision NOT NULL,
        created_ms bigint NOT NULL,
        expires_ms bigint NOT NULL,
        revoked_ms bigint,
        spent_usd double precision NOT NULL DEFAULT 0,
        input_tokens bigint NOT NULL DEFAULT 0,
        output_tokens bigint NOT NULL DEFAULT 0,
        cache_read_tokens bigint NOT NULL DEFAULT 0,
        requests bigint NOT NULL DEFAULT 0,
        models jsonb NOT NULL DEFAULT '{}'
    );
    CREATE TABLE outcomes (
        id bigserial PRIMARY KEY,
        run_id text NOT NULL,
        gate text NOT NULL,
        passed boolean NOT NULL,
        recorded_ms bigint NOT NULL
    );
    CREATE INDEX outcomes_run ON outcomes (run_id);
    CREATE TABLE model_success (
        model text NOT NULL,
        role text NOT NULL,
        repo text NOT NULL,
        successes double precision NOT NULL,
        trials double precision NOT NULL,
        updated_ms bigint NOT NULL,
        PRIMARY KEY (model, role, repo)
    );",
    ),
    (
        2,
        "ALTER TABLE runs ADD COLUMN last_status integer, ADD COLUMN last_error_type text;",
    ),
    (3, "ALTER TABLE runs ADD COLUMN last_status_ms bigint;"),
    (4, "ALTER TABLE runs ALTER COLUMN budget_usd DROP NOT NULL;"),
];

/// The routing settings row: everything in the router configuration that is
/// neither an account nor the classifier, which the server's own settings name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingSettings {
    pub routes: Vec<Route>,
    pub fallback: Option<String>,
    pub min_confidence: Option<f64>,
    pub policy: Option<policy::Settings>,
}

pub struct PgStore {
    url: String,
    client: Mutex<Option<Client>>,
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn signed(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

impl PgStore {
    /// Connects and brings the schema up to date.
    pub fn connect(url: &str) -> io::Result<Self> {
        let store = Self {
            url: url.to_owned(),
            client: Mutex::new(None),
        };
        store.with(migrate)?;
        Ok(store)
    }

    /// Runs `work` on the connection, reconnecting once when the connection
    /// has dropped.
    fn with<T>(
        &self,
        mut work: impl FnMut(&mut Client) -> Result<T, postgres::Error>,
    ) -> io::Result<T> {
        let mut slot = self.client.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..2 {
            if slot.as_ref().is_none_or(Client::is_closed) {
                *slot = Some(Client::connect(&self.url, NoTls).map_err(other)?);
            }
            let client = slot.as_mut().expect("connected above");
            match work(client) {
                Ok(value) => return Ok(value),
                Err(error) if attempt == 0 && client.is_closed() => {
                    let _ = error;
                    *slot = None;
                }
                Err(error) => return Err(other(error)),
            }
        }
        Err(other("The database connection keeps closing."))
    }

    /// The routing settings row as stored.
    pub fn routing_settings(&self) -> io::Result<RoutingSettings> {
        let value: Option<Value> = self.with(|client| {
            Ok(client
                .query_opt("SELECT value FROM settings WHERE key = 'routing'", &[])?
                .map(|row| row.get(0)))
        })?;
        Ok(value
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default())
    }

    pub fn save_routing_settings(&self, settings: &RoutingSettings) -> io::Result<()> {
        let value = serde_json::to_value(settings).map_err(other)?;
        self.with(|client| {
            client.execute(
                "INSERT INTO settings (key, value) VALUES ('routing', $1)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[&value],
            )
        })
        .map(|_| ())
    }
}

fn migrate(client: &mut Client) -> Result<(), postgres::Error> {
    let mut transaction = client.transaction()?;
    // One router migrates at a time; the others wait and then find it done.
    transaction.execute("SELECT pg_advisory_xact_lock(7210469117)", &[])?;
    transaction.batch_execute(
        "CREATE TABLE IF NOT EXISTS router_migrations (
            version integer PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )?;
    let applied: Vec<i32> = transaction
        .query("SELECT version FROM router_migrations", &[])?
        .iter()
        .map(|row| row.get(0))
        .collect();
    for (version, sql) in MIGRATIONS {
        if applied.contains(version) {
            continue;
        }
        transaction.batch_execute(sql)?;
        transaction.execute(
            "INSERT INTO router_migrations (version) VALUES ($1)",
            &[version],
        )?;
    }
    transaction.commit()
}

/// The credential an account row stands for, with no secret in it.
fn placeholder(
    kind: &str,
    provider: Option<String>,
    email: Option<String>,
    plan: Option<String>,
    upstream: Option<String>,
) -> Credential {
    match (kind, provider) {
        ("subscription", Some(provider)) => Credential::Subscription {
            provider,
            access: String::new(),
            refresh: None,
            expires_ms: None,
            account_id: upstream,
            email,
            plan,
            renews_at_ms: None,
        },
        _ => Credential::ApiKey { key: String::new() },
    }
}

impl RouterStore for PgStore {
    fn load_config(&self) -> io::Result<RouterConfig> {
        let accounts = self.with(|client| {
            client.query(
                "SELECT id, family, label, kind, provider, email, plan, upstream_account_id,
                        base_url, models, enabled, weight
                 FROM accounts ORDER BY position, id",
                &[],
            )
        })?;
        let accounts = accounts
            .iter()
            .map(|row| Account {
                id: row.get(0),
                family: row.get(1),
                label: row.get(2),
                credential: placeholder(row.get(3), row.get(4), row.get(5), row.get(6), row.get(7)),
                base_url: row.get(8),
                models: serde_json::from_value(row.get(9)).unwrap_or_default(),
                enabled: row.get(10),
                weight: row.get::<_, i32>(11).max(0) as u32,
            })
            .collect();
        let settings = self.routing_settings()?;
        let mut config = RouterConfig {
            enabled: true,
            accounts,
            classifier: Classifier::None,
            routes: settings.routes,
            fallback: settings.fallback,
            ..RouterConfig::default()
        };
        if let Some(min_confidence) = settings.min_confidence {
            config.min_confidence = min_confidence;
        }
        if let Some(policy) = settings.policy {
            config.policy = policy;
        }
        Ok(config)
    }

    fn upsert_account(&self, account: &Account) -> io::Result<()> {
        let (kind, provider, email, plan, upstream) = match &account.credential {
            Credential::ApiKey { .. } => ("api_key", None, None, None, None),
            Credential::Subscription {
                provider,
                email,
                plan,
                account_id,
                ..
            } => (
                "subscription",
                Some(provider.clone()),
                email.clone(),
                plan.clone(),
                account_id.clone(),
            ),
        };
        let models = serde_json::to_value(&account.models).map_err(other)?;
        let weight = account.weight.min(i32::MAX as u32) as i32;
        self.with(|client| {
            client.execute(
                "INSERT INTO accounts (id, family, label, kind, provider, email, plan,
                     upstream_account_id, base_url, models, enabled, weight)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                 ON CONFLICT (id) DO UPDATE SET
                     family = EXCLUDED.family, label = EXCLUDED.label, kind = EXCLUDED.kind,
                     provider = EXCLUDED.provider, email = EXCLUDED.email, plan = EXCLUDED.plan,
                     upstream_account_id = EXCLUDED.upstream_account_id,
                     base_url = EXCLUDED.base_url, models = EXCLUDED.models,
                     enabled = EXCLUDED.enabled, weight = EXCLUDED.weight, updated_at = now()",
                &[
                    &account.id,
                    &account.family,
                    &account.label,
                    &kind,
                    &provider,
                    &email,
                    &plan,
                    &upstream,
                    &account.base_url,
                    &models,
                    &account.enabled,
                    &weight,
                ],
            )
        })
        .map(|_| ())
    }

    fn remove_account(&self, id: &str) -> io::Result<()> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute("DELETE FROM accounts WHERE id = $1", &[&id])?;
            transaction.execute("DELETE FROM quotas WHERE account_id = $1", &[&id])?;
            transaction.commit()
        })
    }

    fn load_ledger(&self) -> Ledger {
        let rows = self
            .with(|client| client.query("SELECT account_id, usage, cache FROM account_usage", &[]))
            .unwrap_or_default();
        let mut ledger = Ledger::default();
        for row in rows {
            let id: String = row.get(0);
            if let Ok(usage) = serde_json::from_value(row.get(1)) {
                ledger.accounts.insert(id.clone(), usage);
            }
            if let Some(cache) = row
                .get::<_, Option<Value>>(2)
                .and_then(|value| serde_json::from_value(value).ok())
            {
                ledger.cache.insert(id, cache);
            }
        }
        ledger
    }

    fn save_ledger(&self, ledger: &Ledger, account: &str) -> io::Result<()> {
        let Some(usage) = ledger.accounts.get(account) else {
            return self
                .with(|client| {
                    client.execute(
                        "DELETE FROM account_usage WHERE account_id = $1",
                        &[&account],
                    )
                })
                .map(|_| ());
        };
        let usage = serde_json::to_value(usage).map_err(other)?;
        let cache = ledger
            .cache
            .get(account)
            .map(serde_json::to_value)
            .transpose()
            .map_err(other)?;
        self.with(|client| {
            client.execute(
                "INSERT INTO account_usage (account_id, usage, cache) VALUES ($1, $2, $3)
                 ON CONFLICT (account_id) DO UPDATE SET usage = EXCLUDED.usage, cache = EXCLUDED.cache",
                &[&account, &usage, &cache],
            )
        })
        .map(|_| ())
    }

    fn load_quotas(&self) -> QuotaStore {
        let rows = self
            .with(|client| client.query("SELECT account_id, quota FROM quotas", &[]))
            .unwrap_or_default();
        QuotaStore {
            accounts: rows
                .iter()
                .filter_map(|row| {
                    let quota: Quota = serde_json::from_value(row.get(1)).ok()?;
                    Some((row.get(0), quota))
                })
                .collect(),
        }
    }

    fn save_quota(&self, account: &str, quota: &Quota) -> io::Result<()> {
        let value = serde_json::to_value(quota).map_err(other)?;
        self.with(|client| {
            client.execute(
                "INSERT INTO quotas (account_id, quota, observed_ms) VALUES ($1, $2, $3)
                 ON CONFLICT (account_id) DO UPDATE SET quota = EXCLUDED.quota, observed_ms = EXCLUDED.observed_ms",
                &[&account, &value, &quota.observed_at_ms],
            )
        })
        .map(|_| ())
    }

    fn load_sessions(&self) -> Sessions {
        let rows = self
            .with(|client| client.query("SELECT id, session FROM sessions", &[]))
            .unwrap_or_default();
        Sessions {
            entries: rows
                .iter()
                .filter_map(|row| Some((row.get(0), serde_json::from_value(row.get(1)).ok()?)))
                .collect(),
        }
    }

    fn save_sessions(&self, sessions: &mut Sessions, changed: &str, now_ms: i64) -> io::Result<()> {
        sessions.prune(now_ms);
        let session = sessions
            .entries
            .get(changed)
            .map(|session| serde_json::to_value(session).map(|value| (value, session.updated_ms)))
            .transpose()
            .map_err(other)?;
        let horizon = now_ms.saturating_sub(policy::SESSION_TTL_MS);
        self.with(|client| {
            if let Some((value, updated)) = &session {
                client.execute(
                    "INSERT INTO sessions (id, session, updated_ms) VALUES ($1, $2, $3)
                     ON CONFLICT (id) DO UPDATE SET session = EXCLUDED.session, updated_ms = EXCLUDED.updated_ms",
                    &[&changed, value, updated],
                )?;
            }
            client.execute("DELETE FROM sessions WHERE updated_ms < $1", &[&horizon])
        })
        .map(|_| ())
    }

    fn create_run(&self, run: &RunRecord) -> io::Result<()> {
        let inserted = self.with(|client| {
            client.execute(
                "INSERT INTO runs (run_id, task_id, repo, role, budget_usd, created_ms, expires_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (run_id) DO NOTHING",
                &[
                    &run.run_id,
                    &run.task_id,
                    &run.repo,
                    &run.role,
                    &run.budget_usd,
                    &run.created_ms,
                    &run.expires_ms,
                ],
            )
        })?;
        if inserted == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "The run already exists.",
            ));
        }
        Ok(())
    }

    fn run(&self, run_id: &str) -> io::Result<Option<RunRecord>> {
        let row = self.with(|client| {
            client.query_opt(
                "SELECT run_id, task_id, repo, role, budget_usd, created_ms, expires_ms, revoked_ms,
                        spent_usd, input_tokens, output_tokens, cache_read_tokens, requests, models,
                        last_status, last_error_type, last_status_ms
                 FROM runs WHERE run_id = $1",
                &[&run_id],
            )
        })?;
        Ok(row.map(|row| {
            let models: BTreeMap<String, u64> =
                serde_json::from_value(row.get(13)).unwrap_or_default();
            let count = |index: usize| row.get::<_, i64>(index).max(0) as u64;
            RunRecord {
                run_id: row.get(0),
                task_id: row.get(1),
                repo: row.get(2),
                role: row.get(3),
                budget_usd: row.get(4),
                created_ms: row.get(5),
                expires_ms: row.get(6),
                revoked_ms: row.get(7),
                usage: RunUsage {
                    spent_usd: row.get(8),
                    input_tokens: count(9),
                    output_tokens: count(10),
                    cache_read_tokens: count(11),
                    requests: count(12),
                    models,
                },
                last_failure: row.get::<_, Option<i32>>(14).map(|status| RunFailure {
                    status: status.clamp(0, i32::from(u16::MAX)) as u16,
                    error_type: row.get(15),
                    at_ms: row.get::<_, Option<i64>>(16).unwrap_or(0),
                }),
            }
        }))
    }

    fn add_run_usage(&self, run_id: &str, charge: &RunCharge) -> io::Result<()> {
        let requests: i64 = i64::from(charge.model.is_some());
        let tokens = charge.tokens;
        self.with(|client| {
            client.execute(
                "UPDATE runs SET
                     spent_usd = spent_usd + $2,
                     input_tokens = input_tokens + $3,
                     output_tokens = output_tokens + $4,
                     cache_read_tokens = cache_read_tokens + $5,
                     requests = requests + $6,
                     models = CASE WHEN $7::text IS NULL THEN models
                         ELSE jsonb_set(models, ARRAY[$7::text],
                             to_jsonb(COALESCE((models ->> $7::text)::bigint, 0) + 1)) END
                 WHERE run_id = $1",
                &[
                    &run_id,
                    &charge.cost_usd.max(0.0),
                    &signed(tokens.input),
                    &signed(tokens.output),
                    &signed(tokens.cache_read),
                    &requests,
                    &charge.model,
                ],
            )
        })
        .map(|_| ())
    }

    fn revoke_run(&self, run_id: &str, now_ms: i64) -> io::Result<()> {
        self.with(|client| {
            client.execute(
                "UPDATE runs SET revoked_ms = COALESCE(revoked_ms, $2) WHERE run_id = $1",
                &[&run_id, &now_ms],
            )
        })
        .map(|_| ())
    }

    fn record_run_failure(&self, run_id: &str, failure: Option<&RunFailure>) -> io::Result<()> {
        let status = failure.map(|failure| i32::from(failure.status));
        let error_type = failure.and_then(|failure| failure.error_type.clone());
        let at_ms = failure.map(|failure| failure.at_ms);
        self.with(|client| {
            client.execute(
                "UPDATE runs SET last_status = $2, last_error_type = $3, last_status_ms = $4
                 WHERE run_id = $1",
                &[&run_id, &status, &error_type, &at_ms],
            )
        })
        .map(|_| ())
    }

    fn record_outcome(
        &self,
        run_id: &str,
        gate: &str,
        passed: bool,
        now_ms: i64,
    ) -> io::Result<()> {
        self.with(|client| {
            client.execute(
                "INSERT INTO outcomes (run_id, gate, passed, recorded_ms) VALUES ($1, $2, $3, $4)",
                &[&run_id, &gate, &passed, &now_ms],
            )
        })
        .map(|_| ())
    }

    fn observe_success(
        &self,
        (model, role, repo): (&str, &str, &str),
        passed: bool,
        weight: f64,
        now_ms: i64,
        half_life_ms: i64,
    ) -> io::Result<()> {
        self.with(|client| {
            let mut transaction = client.transaction()?;
            transaction.execute(
                "INSERT INTO model_success (model, role, repo, successes, trials, updated_ms)
                 VALUES ($1, $2, $3, 0, 0, $4) ON CONFLICT DO NOTHING",
                &[&model, &role, &repo, &now_ms],
            )?;
            let row = transaction.query_one(
                "SELECT successes, trials, updated_ms FROM model_success
                 WHERE model = $1 AND role = $2 AND repo = $3 FOR UPDATE",
                &[&model, &role, &repo],
            )?;
            let mut stat = SuccessStat {
                successes: row.get(0),
                trials: row.get(1),
                updated_ms: row.get(2),
            };
            stat.observe(passed, weight, now_ms, half_life_ms);
            transaction.execute(
                "UPDATE model_success SET successes = $4, trials = $5, updated_ms = $6
                 WHERE model = $1 AND role = $2 AND repo = $3",
                &[
                    &model,
                    &role,
                    &repo,
                    &stat.successes,
                    &stat.trials,
                    &stat.updated_ms,
                ],
            )?;
            transaction.commit()
        })
    }

    fn success_stats(
        &self,
        role: &str,
        repo: &str,
    ) -> io::Result<BTreeMap<(String, String, String), SuccessStat>> {
        let [(r1, p1), (r2, p2), (r3, p3)] = success_scopes(role, repo);
        let rows = self.with(|client| {
            client.query(
                "SELECT model, role, repo, successes, trials, updated_ms FROM model_success
                 WHERE (role = $1 AND repo = $2) OR (role = $3 AND repo = $4) OR (role = $5 AND repo = $6)",
                &[&r1, &p1, &r2, &p2, &r3, &p3],
            )
        })?;
        Ok(rows
            .iter()
            .map(|row| {
                (
                    (row.get(0), row.get(1), row.get(2)),
                    SuccessStat {
                        successes: row.get(3),
                        trials: row.get(4),
                        updated_ms: row.get(5),
                    },
                )
            })
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::store::ANY;
    use crate::wire::Tokens;

    /// A store in a fresh schema of the test database, dropped afterwards.
    /// Answers none when `MUNIMENT_ROUTER_TEST_DATABASE_URL` is unset.
    pub(crate) struct Scratch {
        pub store: PgStore,
        pub url: String,
        admin: String,
        schema: String,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Ok(mut client) = Client::connect(&self.admin, NoTls) {
                let _ = client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
            }
        }
    }

    pub(crate) fn scratch() -> Option<Scratch> {
        let Ok(admin) = std::env::var("MUNIMENT_ROUTER_TEST_DATABASE_URL") else {
            eprintln!("MUNIMENT_ROUTER_TEST_DATABASE_URL is unset; skipping a Postgres test");
            return None;
        };
        let schema = format!("router_test_{}", uuid::Uuid::new_v4().simple());
        Client::connect(&admin, NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap();
        let separator = if admin.contains('?') { '&' } else { '?' };
        let url = format!("{admin}{separator}options=-c%20search_path%3D{schema}");
        Some(Scratch {
            store: PgStore::connect(&url).unwrap(),
            url,
            admin,
            schema,
        })
    }

    #[test]
    fn accounts_and_settings_keep_no_secret_and_keep_their_order() {
        let Some(scratch) = scratch() else { return };
        let store = &scratch.store;
        // Connecting again finds every migration applied.
        PgStore::connect(&scratch.url).unwrap();
        let subscription = Account {
            id: "s1".into(),
            family: "anthropic".into(),
            label: "Max".into(),
            credential: Credential::Subscription {
                provider: "anthropic".into(),
                access: "SECRET-ACCESS".into(),
                refresh: Some("SECRET-REFRESH".into()),
                expires_ms: Some(5),
                account_id: Some("org-1".into()),
                email: Some("a@example.com".into()),
                plan: Some("max".into()),
                renews_at_ms: None,
            },
            base_url: None,
            models: vec!["claude-opus-5".into()],
            enabled: true,
            weight: 2,
        };
        let key = Account {
            id: "k1".into(),
            family: "openai".into(),
            label: "Key".into(),
            credential: Credential::ApiKey {
                key: "SECRET-KEY".into(),
            },
            base_url: Some("http://gateway/v1".into()),
            models: Vec::new(),
            enabled: false,
            weight: 1,
        };
        store.upsert_account(&subscription).unwrap();
        store.upsert_account(&key).unwrap();
        let mut renamed = subscription.clone();
        renamed.label = "Max 2".into();
        store.upsert_account(&renamed).unwrap();
        let config = store.load_config().unwrap();
        assert_eq!(config.accounts.len(), 2);
        assert_eq!(config.accounts[0].label, "Max 2");
        assert_eq!(config.accounts[0].weight, 2);
        assert_eq!(
            config.accounts[0].credential.pi_provider(),
            Some("anthropic")
        );
        assert_eq!(config.accounts[0].email(), Some("a@example.com"));
        assert_eq!(
            config.accounts[1].base_url.as_deref(),
            Some("http://gateway/v1")
        );
        assert!(!config.accounts[1].enabled);
        let dump: Vec<String> = Client::connect(&scratch.url, NoTls)
            .unwrap()
            .query("SELECT row_to_json(accounts)::text FROM accounts", &[])
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert!(dump.iter().all(|row| !row.contains("SECRET")));

        store
            .save_routing_settings(&RoutingSettings {
                fallback: Some("anthropic/claude-opus-5".into()),
                min_confidence: Some(0.8),
                ..RoutingSettings::default()
            })
            .unwrap();
        let config = store.load_config().unwrap();
        assert_eq!(config.fallback.as_deref(), Some("anthropic/claude-opus-5"));
        assert_eq!(config.min_confidence, 0.8);
        store.remove_account("k1").unwrap();
        assert_eq!(store.load_config().unwrap().accounts.len(), 1);
    }

    #[test]
    fn ledger_quotas_and_sessions_round_trip() {
        let Some(scratch) = scratch() else { return };
        let store = &scratch.store;
        let mut ledger = Ledger::default();
        ledger.record_success("a1", "2026-10-01", 1_000, 10, 2);
        ledger.record_cache(
            "a1",
            Tokens {
                input: 10,
                ..Tokens::default()
            },
        );
        ledger.record_error("a2", "2026-10-01", 1_000, "429", true);
        store.save_ledger(&ledger, "a1").unwrap();
        store.save_ledger(&ledger, "a2").unwrap();
        assert_eq!(store.load_ledger(), ledger);
        ledger.forget("a2");
        store.save_ledger(&ledger, "a2").unwrap();
        assert_eq!(store.load_ledger(), ledger);

        let quota = Quota {
            plan: Some("max".into()),
            observed_at_ms: 7,
            ..Quota::default()
        };
        store.save_quota("a1", &quota).unwrap();
        assert_eq!(store.load_quotas().accounts["a1"], quota);

        let mut sessions = Sessions::default();
        let now = 10 * policy::SESSION_TTL_MS;
        sessions.entries.insert(
            "old".into(),
            policy::Session {
                updated_ms: now - policy::SESSION_TTL_MS - 1,
                ..Default::default()
            },
        );
        store
            .save_sessions(&mut sessions, "old", now - policy::SESSION_TTL_MS)
            .unwrap();
        sessions.entries.insert(
            "new".into(),
            policy::Session {
                route: "fast".into(),
                updated_ms: now,
                ..Default::default()
            },
        );
        store.save_sessions(&mut sessions, "new", now).unwrap();
        let loaded = store.load_sessions();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries["new"].route, "fast");
    }

    #[test]
    fn runs_add_usage_atomically_and_outcomes_feed_success_counts() {
        let Some(scratch) = scratch() else { return };
        let store = &scratch.store;
        let run = RunRecord {
            run_id: "r1".into(),
            task_id: "t1".into(),
            repo: "factory/app".into(),
            role: "implementer".into(),
            budget_usd: Some(2.0),
            created_ms: 1,
            expires_ms: 1_000,
            revoked_ms: None,
            usage: RunUsage::default(),
            last_failure: None,
        };
        store.create_run(&run).unwrap();
        assert_eq!(
            store.create_run(&run).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let open = RunRecord {
            run_id: "open".into(),
            budget_usd: None,
            ..run.clone()
        };
        store.create_run(&open).unwrap();
        assert_eq!(store.run("open").unwrap().unwrap().budget_usd, None);
        let charge = RunCharge {
            cost_usd: 0.25,
            tokens: Tokens {
                input: 100,
                output: 10,
                cache_read: 40,
                ..Tokens::default()
            },
            model: Some("openai/gpt-5.6-sol".into()),
        };
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| store.add_run_usage("r1", &charge).unwrap());
            }
        });
        store
            .add_run_usage(
                "r1",
                &RunCharge {
                    cost_usd: 0.5,
                    ..RunCharge::default()
                },
            )
            .unwrap();
        let loaded = store.run("r1").unwrap().unwrap();
        assert_eq!(loaded.usage.spent_usd, 1.5);
        assert_eq!(loaded.usage.requests, 4);
        assert_eq!(loaded.usage.input_tokens, 400);
        assert_eq!(loaded.usage.cache_read_tokens, 160);
        assert_eq!(loaded.usage.models["openai/gpt-5.6-sol"], 4);
        store.revoke_run("r1", 50).unwrap();
        store.revoke_run("r1", 60).unwrap();
        assert_eq!(store.run("r1").unwrap().unwrap().revoked_ms, Some(50));
        assert!(store.run("nope").unwrap().is_none());
        assert_eq!(store.run("r1").unwrap().unwrap().last_failure, None);
        for failure in [
            Some(RunFailure {
                status: 429,
                error_type: Some("rate_limited".into()),
                at_ms: 70,
            }),
            Some(RunFailure {
                status: 400,
                error_type: None,
                at_ms: 80,
            }),
            None,
        ] {
            store.record_run_failure("r1", failure.as_ref()).unwrap();
            assert_eq!(store.run("r1").unwrap().unwrap().last_failure, failure);
        }

        store.record_outcome("r1", "unit_tests", true, 70).unwrap();
        for (role, repo) in success_scopes("implementer", "factory/app") {
            store
                .observe_success(("openai/gpt-5.6-sol", role, repo), true, 1.0, 70, 1_000)
                .unwrap();
            store
                .observe_success(("openai/gpt-5.6-sol", role, repo), false, 1.0, 1_070, 1_000)
                .unwrap();
        }
        store
            .observe_success(
                ("openai/gpt-5.6-sol", "reviewer", ANY),
                true,
                1.0,
                70,
                1_000,
            )
            .unwrap();
        let stats = store.success_stats("implementer", "factory/app").unwrap();
        assert_eq!(stats.len(), 3);
        let stat = stats[&("openai/gpt-5.6-sol".into(), ANY.into(), ANY.into())];
        assert!((stat.trials - 1.5).abs() < 1e-9);
        assert!((stat.successes - 0.5).abs() < 1e-9);
        assert_eq!(stat.updated_ms, 1_070);
    }
}
