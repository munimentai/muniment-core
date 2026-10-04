//! Secret-free shadow decisions with durable job affinity. This module never executes a provider.
use super::{balance, classify, config, policy, usage, wire};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, time::Duration};

pub const VERSION: &str = "muniment-routing-shadow/1";
pub const MAX_REQUEST_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub version: String,
    #[serde(flatten)]
    pub operation: Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Inspect {
        job: Job,
        snapshot: Snapshot,
    },
    Reserve {
        job: Job,
        snapshot: Snapshot,
        observation: Option<Observation>,
    },
    Release {
        job_id: String,
        session_id: String,
        trace_id: String,
        outcome: Outcome,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub job_id: String,
    pub session_id: String,
    pub trace_id: String,
    pub role: Role,
    pub task_context: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tools: bool,
    pub images: bool,
    pub minimum_capability: u8,
    pub budget_usd: f64,
    pub baseline: Selection,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Plan,
    Implement,
    Review,
    Test,
    General,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub account: String,
    pub family: String,
    pub model: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub revision: u64,
    pub accounts: Vec<Account>,
    pub models: Vec<Model>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub family: String,
    pub weight: u32,
    pub enabled: bool,
    pub cooldown_until_ms: i64,
    pub models: BTreeMap<String, Cap>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cap {
    pub epoch: u64,
    pub limit: u32,
    pub resets_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub family: String,
    pub model: String,
    pub context: u64,
    pub output_limit: u64,
    pub tools: bool,
    pub images: bool,
    pub input_price: f64,
    pub output_price: f64,
    pub capability: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub revision: String,
    pub trace_id: String,
    pub eligible_digest: String,
    pub request_digest: String,
    pub elapsed_ms: u64,
    pub status: ObservationStatus,
    pub answer: Option<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Answer,
    Timeout,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failed,
    Refused,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    None,
    NotConfigured,
    InvalidOutput,
    LowConfidence,
    Timeout,
    ClassifierFailed,
    StaleObservation,
}

/// Only these enum fields belong in metric labels. Identifiers belong in traces.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub version: String,
    pub policy_version: String,
    pub mode: String,
    pub trace_id: String,
    pub role: Role,
    pub baseline: Selection,
    pub selected: Option<Selection>,
    pub eligible: Vec<Selection>,
    pub eligible_digest: String,
    pub request_digest: String,
    pub decision_reason: String,
    pub classifier_revision: Option<String>,
    pub confidence: f64,
    pub classifier_ms: u64,
    pub routing_ms: u64,
    pub fallback: Fallback,
    pub reused: bool,
    pub outcome: Option<Outcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidRequest,
    UnsupportedVersion,
    Storage,
    StaleSnapshot,
    IdentityConflict,
    Completed,
    AffinityUnavailable,
    NoEligibleChoice,
    UnknownJob,
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn valid_selection(value: &Selection) -> bool {
    reference(&value.account) && reference(&value.family) && reference(&value.model)
}
fn encode(value: &impl Serialize) -> Result<String, Error> {
    serde_json::to_string(value).map_err(|_| Error::InvalidRequest)
}
fn decode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, Error> {
    serde_json::from_str(value).map_err(|_| Error::Storage)
}

impl Job {
    fn validate(&self) -> Result<(), Error> {
        if ![&self.job_id, &self.session_id, &self.trace_id]
            .into_iter()
            .all(|v| reference(v))
            || !valid_selection(&self.baseline)
            || self.task_context.len() > classify::STATE_LIMIT
            || self.input_tokens == 0
            || self.output_tokens == 0
            || self.input_tokens.checked_add(self.output_tokens).is_none()
            || !self.budget_usd.is_finite()
            || self.budget_usd < 0.0
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
    fn fingerprint(&self) -> Result<String, Error> {
        // Context can change after Pi compacts a resumed session. Constraints cannot.
        let mut stable = self.clone();
        stable.task_context.clear();
        Ok(policy::digest(&encode(&stable)?))
    }
    fn features(&self) -> policy::Features {
        policy::Features {
            input: self.input_tokens,
            output: self.output_tokens,
            tools: self.tools,
            images: self.images,
            unsupported: false,
            objective: String::new(),
            prefix: Vec::new(),
            evidence: String::new(),
            failed: false,
        }
    }
}

impl Model {
    fn metadata(&self) -> policy::Model {
        policy::Model {
            context: self.context,
            output_limit: self.output_limit,
            tools: self.tools,
            images: self.images,
            input: self.input_price,
            output: self.output_price,
            capability: self.capability,
            ..Default::default()
        }
    }
}

/// One local SQLite file defines one shadow pool. Use a separate file from live state.
pub struct Router {
    db: Connection,
}
impl Router {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > 1 {
            return Err(Error::UnsupportedVersion);
        }
        // Commit the schema once, not once per statement, even on slow storage.
        if version == 0 {
            tx.execute_batch("
            CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS caps (account TEXT NOT NULL, model TEXT NOT NULL, epoch INTEGER NOT NULL, cap_limit INTEGER NOT NULL, resets INTEGER NOT NULL, PRIMARY KEY(account,model));
            CREATE TABLE IF NOT EXISTS jobs (job TEXT PRIMARY KEY, session TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL, account TEXT NOT NULL, model TEXT NOT NULL, epoch INTEGER NOT NULL, response TEXT NOT NULL, outcome TEXT);
            CREATE TABLE IF NOT EXISTS refusals (account TEXT PRIMARY KEY, strikes INTEGER NOT NULL, until_ms INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS job_caps ON jobs(account,model,epoch);
            CREATE INDEX IF NOT EXISTS job_active ON jobs(account,outcome);
            PRAGMA user_version=1;")?;
        }
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn handle(&mut self, request: Request) -> Result<Response, Error> {
        self.handle_at(request, chrono::Utc::now().timestamp_millis())
    }

    fn handle_at(&mut self, request: Request, now: i64) -> Result<Response, Error> {
        let started = std::time::Instant::now();
        if request.version != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if encode(&request)?.len() > MAX_REQUEST_BYTES {
            return Err(Error::InvalidRequest);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = match request.operation {
            Operation::Release {
                job_id,
                session_id,
                trace_id,
                outcome,
            } => release(&tx, &job_id, &session_id, &trace_id, outcome, now),
            Operation::Inspect { job, snapshot } => {
                job.validate()?;
                let snapshot = accept_snapshot(&tx, snapshot)?;
                let (_, eligible, _) = candidates(&tx, &snapshot, &job, now, None)?;
                evidence(&job, &snapshot, eligible)
            }
            Operation::Reserve {
                job,
                snapshot,
                observation,
            } => {
                job.validate()?;
                let snapshot = accept_snapshot(&tx, snapshot)?;
                reserve(&tx, &snapshot, &job, observation.as_ref(), now)
            }
        };
        let mut response = match result {
            Ok(response) => response,
            Err(
                error @ (Error::AffinityUnavailable
                | Error::NoEligibleChoice
                | Error::IdentityConflict
                | Error::Completed
                | Error::UnknownJob),
            ) => {
                // Keep valid metadata even when the job cannot proceed.
                tx.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        tx.commit()?;
        response.routing_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        Ok(response)
    }
}

fn accept_snapshot(tx: &Transaction<'_>, mut snapshot: Snapshot) -> Result<Snapshot, Error> {
    if snapshot.revision > i64::MAX as u64
        || snapshot.accounts.len() > 256
        || snapshot.models.len() > 256
    {
        return Err(Error::InvalidRequest);
    }
    snapshot.accounts.sort_by(|a, b| a.id.cmp(&b.id));
    snapshot
        .models
        .sort_by(|a, b| (&a.family, &a.model).cmp(&(&b.family, &b.model)));
    if snapshot.accounts.windows(2).any(|a| a[0].id == a[1].id)
        || snapshot.models.windows(2).any(|m| {
            (m[0].family.as_str(), m[0].model.as_str())
                == (m[1].family.as_str(), m[1].model.as_str())
        })
    {
        return Err(Error::InvalidRequest);
    }
    for m in &snapshot.models {
        if !reference(&m.family)
            || !reference(&m.model)
            || m.context == 0
            || m.output_limit == 0
            || m.output_limit > m.context
            || ![m.input_price, m.output_price]
                .into_iter()
                .all(|v| v.is_finite() && v >= 0.0)
        {
            return Err(Error::InvalidRequest);
        }
    }
    for a in &snapshot.accounts {
        if !reference(&a.id)
            || !reference(&a.family)
            || a.cooldown_until_ms < 0
            || a.models.len() > 256
        {
            return Err(Error::InvalidRequest);
        }
        for (model, cap) in &a.models {
            if cap.epoch > i64::MAX as u64
                || cap.resets_at_ms <= 0
                || !snapshot
                    .models
                    .iter()
                    .any(|m| m.family == a.family && m.model == *model)
            {
                return Err(Error::InvalidRequest);
            }
            let old = tx
                .query_row(
                    "SELECT epoch, cap_limit, resets FROM caps WHERE account=?1 AND model=?2",
                    params![a.id, model],
                    |r| {
                        Ok((
                            r.get::<_, u64>(0)?,
                            r.get::<_, u32>(1)?,
                            r.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            if old.is_some_and(|(epoch, limit, resets)| {
                cap.epoch < epoch
                    || (cap.epoch == epoch && (cap.limit > limit || cap.resets_at_ms != resets))
            }) {
                return Err(Error::StaleSnapshot);
            }
            tx.execute("INSERT INTO caps VALUES (?1,?2,?3,?4,?5) ON CONFLICT(account,model) DO UPDATE SET epoch=excluded.epoch, cap_limit=excluded.cap_limit, resets=excluded.resets", params![a.id, model, cap.epoch, cap.limit, cap.resets_at_ms])?;
        }
    }
    let digest = policy::digest(&encode(&snapshot)?);
    let old = tx
        .query_row("SELECT revision,digest FROM snapshot WHERE id=1", [], |r| {
            Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
        })
        .optional()?;
    if old.is_some_and(|(revision, hash)| {
        snapshot.revision < revision || (snapshot.revision == revision && hash != digest)
    }) {
        return Err(Error::StaleSnapshot);
    }
    tx.execute("INSERT INTO snapshot VALUES (1,?1,?2) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest", params![snapshot.revision,digest])?;
    Ok(snapshot)
}

fn candidates(
    tx: &Transaction<'_>,
    snapshot: &Snapshot,
    job: &Job,
    now: i64,
    pinned: Option<&Selection>,
) -> Result<(config::RouterConfig, Vec<Selection>, usage::Ledger), Error> {
    let mut config = config::RouterConfig {
        min_confidence: config::DEFAULT_MIN_CONFIDENCE,
        ..Default::default()
    };
    let mut eligible = Vec::new();
    let mut ledger = usage::Ledger::default();
    let features = job.features();
    for m in &snapshot.models {
        let metadata = m.metadata();
        let cost = metadata.cost(wire::Tokens {
            input: job.input_tokens,
            output: job.output_tokens,
            ..Default::default()
        });
        if features.fits(&metadata)
            && m.capability >= job.minimum_capability
            && cost.is_finite()
            && cost <= job.budget_usd
        {
            config
                .policy
                .models
                .insert(format!("{}/{}", m.family, m.model), metadata);
        }
    }
    for a in &snapshot.accounts {
        let refused: Option<i64> = tx
            .query_row(
                "SELECT until_ms FROM refusals WHERE account=?1",
                [&a.id],
                |r| r.get(0),
            )
            .optional()?;
        let served: u64 = tx.query_row(
            "SELECT count(*) FROM jobs WHERE account=?1 AND outcome IS NOT NULL",
            [&a.id],
            |r| r.get(0),
        )?;
        ledger.accounts.insert(
            a.id.clone(),
            usage::AccountUsage {
                requests: served,
                // Undecayed: the shadow balances on its whole job history.
                recent_milli: served.saturating_mul(1000),
                ..Default::default()
            },
        );
        if !a.enabled
            || a.weight == 0
            || a.cooldown_until_ms > now
            || refused.is_some_and(|until| until > now)
        {
            continue;
        }
        let mut models = Vec::new();
        for (model, cap) in &a.models {
            let used: u64 = tx.query_row(
                "SELECT count(*) FROM jobs WHERE account=?1 AND model=?2 AND epoch=?3",
                params![a.id, model, cap.epoch],
                |r| r.get(0),
            )?;
            let is_pinned = pinned
                .is_some_and(|s| s.account == a.id && s.family == a.family && s.model == *model);
            // A reservation spends its cap once. A retry does not spend it again.
            if !config
                .policy
                .models
                .contains_key(&format!("{}/{}", a.family, model))
                || cap.resets_at_ms <= now
                || (!is_pinned && used >= u64::from(cap.limit))
                || cap.limit == 0
            {
                continue;
            }
            models.push(model.clone());
            eligible.push(Selection {
                account: a.id.clone(),
                family: a.family.clone(),
                model: model.clone(),
            });
        }
        if !models.is_empty() {
            config.accounts.push(config::Account {
                id: a.id.clone(),
                label: a.id.clone(),
                family: a.family.clone(),
                models,
                weight: a.weight,
                enabled: true,
                base_url: None,
                // A marker satisfies the shared metadata policy. No transport receives it.
                credential: config::Credential::ApiKey { key: String::new() },
            });
        }
    }
    Ok((config, eligible, ledger))
}

fn evidence(job: &Job, snapshot: &Snapshot, eligible: Vec<Selection>) -> Result<Response, Error> {
    let digest = policy::digest(&encode(&(policy::VERSION, snapshot, &eligible))?);
    let request_digest = policy::digest(&encode(&(
        job.fingerprint()?,
        policy::digest(&job.task_context),
    ))?);
    Ok(Response {
        version: VERSION.into(),
        policy_version: policy::VERSION.into(),
        mode: "shadow".into(),
        trace_id: job.trace_id.clone(),
        role: job.role,
        baseline: job.baseline.clone(),
        selected: None,
        eligible,
        eligible_digest: digest,
        request_digest,
        decision_reason: "inspect".into(),
        classifier_revision: None,
        confidence: 0.0,
        classifier_ms: 0,
        routing_ms: 0,
        fallback: Fallback::NotConfigured,
        reused: false,
        outcome: None,
    })
}

fn reserve(
    tx: &Transaction<'_>,
    snapshot: &Snapshot,
    job: &Job,
    observation: Option<&Observation>,
    now: i64,
) -> Result<Response, Error> {
    let prior = tx
        .query_row(
            "SELECT job,session,fingerprint,response,outcome FROM jobs WHERE job=?1 OR session=?2",
            params![job.job_id, job.session_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((id, session, fingerprint, response, outcome)) = prior {
        if id != job.job_id || session != job.session_id || fingerprint != job.fingerprint()? {
            return Err(Error::IdentityConflict);
        }
        if outcome.is_some() {
            return Err(Error::Completed);
        }
        let mut response: Response = decode(&response)?;
        let selected = response.selected.as_ref().ok_or(Error::Storage)?;
        let (_, eligible, _) = candidates(tx, snapshot, job, now, Some(selected))?;
        if !eligible.contains(selected) {
            return Err(Error::AffinityUnavailable);
        }
        response.reused = true;
        return Ok(response);
    }
    let (config, eligible, ledger) = candidates(tx, snapshot, job, now, None)?;
    let routes = super::options(&config);
    let mut response = evidence(job, snapshot, eligible)?;
    let mut answer = None;
    if let Some(o) = observation {
        if !reference(&o.revision)
            || !reference(&o.trace_id)
            || o.eligible_digest.len() != 64
            || o.request_digest.len() != 64
        {
            return Err(Error::InvalidRequest);
        }
        response.classifier_revision = Some(o.revision.clone());
        response.classifier_ms = o.elapsed_ms;
        response.fallback = if o.trace_id != job.trace_id
            || o.eligible_digest != response.eligible_digest
            || o.request_digest != response.request_digest
        {
            Fallback::StaleObservation
        } else if o.status == ObservationStatus::Timeout
            || o.elapsed_ms >= classify::TIMEOUT.as_millis() as u64
        {
            Fallback::Timeout
        } else if o.status == ObservationStatus::Failed {
            Fallback::ClassifierFailed
        } else {
            answer = o.answer.as_ref().and_then(classify::parse);
            Fallback::InvalidOutput
        };
    }
    let decision = classify::select(&config, &routes, answer).ok_or(Error::NoEligibleChoice)?;
    if decision.reason == classify::Reason::Classified {
        response.fallback = Fallback::None;
    }
    if decision.reason == classify::Reason::LowConfidence {
        response.fallback = Fallback::LowConfidence;
    }
    response.confidence = decision.confidence;
    let (route, reason) = policy::choose(
        &config,
        &routes,
        policy::Proposal {
            route: &decision.route.key,
            confident: decision.reason == classify::Reason::Classified,
        },
        &policy::Session::default(),
        &job.features(),
        true,
        now,
    )
    .map_err(|_| Error::NoEligibleChoice)?;
    let mut active = BTreeMap::new();
    let mut query =
        tx.prepare("SELECT account,count(*) FROM jobs WHERE outcome IS NULL GROUP BY account")?;
    for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?)))? {
        let (account, count) = row?;
        active.insert(account, count);
    }
    let account =
        balance::pick_with_active(&config, &ledger, &route.family, &route.model, now, &active)
            .map_err(|_| Error::NoEligibleChoice)?;
    response.selected = Some(Selection {
        account: account.id.clone(),
        family: route.family,
        model: route.model.clone(),
    });
    response.decision_reason = reason;
    let cap = &snapshot
        .accounts
        .iter()
        .find(|a| a.id == account.id)
        .ok_or(Error::Storage)?
        .models[&route.model];
    tx.execute(
        "INSERT INTO jobs VALUES (?1,?2,?3,?4,?5,?6,?7,NULL)",
        params![
            job.job_id,
            job.session_id,
            job.fingerprint()?,
            account.id,
            route.model,
            cap.epoch,
            encode(&response)?
        ],
    )?;
    Ok(response)
}

fn release(
    tx: &Transaction<'_>,
    job: &str,
    session: &str,
    trace: &str,
    outcome: Outcome,
    now: i64,
) -> Result<Response, Error> {
    if ![job, session, trace].into_iter().all(reference) {
        return Err(Error::InvalidRequest);
    }
    let prior = tx
        .query_row(
            "SELECT session,response,outcome FROM jobs WHERE job=?1",
            [job],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(Error::UnknownJob)?;
    let mut response: Response = decode(&prior.1)?;
    if prior.0 != session || response.trace_id != trace {
        return Err(Error::IdentityConflict);
    }
    let encoded = encode(&outcome)?;
    if let Some(old) = prior.2 {
        if old != encoded {
            return Err(Error::IdentityConflict);
        }
        response.reused = true;
    } else {
        if outcome == Outcome::Refused {
            // Only the baseline ran. Its refusal cannot cool a different shadow account.
            let account = &response.baseline.account;
            let strikes: u32 = tx
                .query_row(
                    "SELECT strikes FROM refusals WHERE account=?1",
                    [account],
                    |r| r.get::<_, u32>(0),
                )
                .optional()?
                .unwrap_or(0)
                .saturating_add(1);
            tx.execute("INSERT INTO refusals VALUES (?1,?2,?3) ON CONFLICT(account) DO UPDATE SET strikes=excluded.strikes,until_ms=excluded.until_ms", params![account,strikes,now.saturating_add(usage::cooldown_ms(strikes))])?;
        }
        if outcome == Outcome::Success {
            tx.execute(
                "DELETE FROM refusals WHERE account=?1",
                [&response.baseline.account],
            )?;
        }
        tx.execute(
            "UPDATE jobs SET outcome=?1 WHERE job=?2",
            params![encoded, job],
        )?;
    }
    response.outcome = Some(outcome);
    Ok(response)
}
