//! The loopback endpoint Pi talks to.
//!
//! The router answers the OpenAI chat wire on `127.0.0.1` at an ephemeral
//! port, behind a token it writes beside its record. Pi holds that port and
//! token as one more custom endpoint, so every turn arrives here, gets a route
//! and an account, and goes out on that account's credential. Nothing off the
//! machine can reach the port, and the token keeps another process on the
//! machine from spending the user's accounts.
//!
//! A refused turn fails over: the account that refused goes into cooldown and
//! the next account takes the turn, then another enabled model if the pool fails.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::config::{self, RouterConfig};
use super::usage::{self, Ledger};
use super::{balance, plan, served_models, wire, ResolveError};
use super::{native_auth, transport};

/// Where the router writes the port and token Pi needs.
pub const ENDPOINT_FILE: &str = "muniment-router-endpoint.json";
/// The longest a request head may be, and the longest a request body may be.
const HEAD_LIMIT: usize = 64 * 1024;
const BODY_LIMIT: usize = 32 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(600);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// How long a token refresh may take before the turn moves on.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(12);

/// The port and token Pi reaches the router on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
}

impl Endpoint {
    /// The base URL Pi stores for the router provider.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }
}

/// The endpoint record inside an agent directory.
pub fn endpoint_path(agent: &Path) -> PathBuf {
    agent.join(ENDPOINT_FILE)
}

/// The running router's endpoint, when one has started.
pub fn read_endpoint(agent: &Path) -> Option<Endpoint> {
    serde_json::from_slice(&std::fs::read(endpoint_path(agent)).ok()?).ok()
}

fn write_endpoint(agent: &Path, endpoint: &Endpoint) -> io::Result<()> {
    std::fs::create_dir_all(agent)?;
    config::write_private(&endpoint_path(agent), &serde_json::to_vec_pretty(endpoint)?)
}

/// A random 32-byte token in hex.
fn token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("the platform's random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// How many turns each account has in flight right now, by account id.
pub type Active = Arc<Mutex<BTreeMap<String, u32>>>;

/// A started router. Dropping the handle stops the listener.
pub struct Handle {
    endpoint: Endpoint,
    stop: Arc<AtomicBool>,
    active: Active,
    state: Arc<State>,
}

impl Handle {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The turns in flight per account, for the pools screen.
    pub fn active(&self) -> BTreeMap<String, u32> {
        self.active
            .lock()
            .map(|active| active.clone())
            .unwrap_or_default()
    }

    /// Uses the running router's ledger without generating an assistant reply.
    pub fn test_route(&self, sample: &str) -> Result<RouteTest, String> {
        self.state.test_route(sample)
    }

    /// Stops the accept loop. Turns already in flight finish.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What the router keeps between turns: where its files are, and the counters
/// it has not yet written down.
struct State {
    progress: super::progress::Progress,
    agent: PathBuf,
    ledger: Mutex<Ledger>,
    /// The turns in flight, counted up while an upstream call is open.
    active: Active,
    /// The clock, so a test can hold time still.
    now_ms: fn() -> i64,
}

/// One turn's place in the in-flight count. It clears when the turn ends,
/// whichever way it ends.
struct InFlight {
    active: Active,
    account: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Ok(mut held) = self.active.lock() {
            if let Some(count) = held.get_mut(&self.account) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(&self.account);
                }
            }
        }
    }
}

#[derive(Serialize)]
pub struct RouteTest {
    pub model: String,
    pub reason: &'static str,
    pub confidence: Option<f64>,
    pub elapsed_ms: u128,
    pub eligible_models: Vec<String>,
    pub exclusions: Vec<RouteExclusion>,
    pub fallback_reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct RouteExclusion {
    pub model: String,
    pub reason: String,
}

fn route_availability(
    config: &RouterConfig,
    ledger: &Ledger,
    now_ms: i64,
) -> (Vec<String>, Vec<RouteExclusion>) {
    let mut models = std::collections::BTreeSet::new();
    for account in &config.accounts {
        let names = if account.models.is_empty() {
            super::model_catalog::family_models(&account.family)
                .iter()
                .map(|entry| entry.model.to_owned())
                .collect()
        } else {
            account.models.clone()
        };
        for model in names {
            models.insert((account.family.clone(), model));
        }
    }
    let mut eligible = Vec::new();
    let mut excluded = Vec::new();
    for (family, model) in models {
        let name = format!("{family}/{model}");
        match balance::pick(config, ledger, &family, &model, now_ms) {
            Ok(_) => eligible.push(name),
            Err(error) => excluded.push(RouteExclusion {
                model: name,
                reason: error.message(),
            }),
        }
    }
    (eligible, excluded)
}

impl State {
    fn classifier_config(&self) -> RouterConfig {
        let config = self.config();
        if let config::Classifier::Pooled { family, model } = &config.classifier {
            if let Ok(account) =
                balance::pick(&config, &self.ledger(), family, model, (self.now_ms)())
            {
                if let Err(error) = native_auth::refresh_account(
                    &self.agent,
                    &account.id,
                    (self.now_ms)(),
                    REFRESH_TIMEOUT,
                ) {
                    self.record_error(&account.id, &error, true);
                }
            }
        }
        self.config()
    }

    fn test_route(&self, sample: &str) -> Result<RouteTest, String> {
        if sample.trim().is_empty() || sample.len() > 32_000 {
            return Err("Enter a sample of 1 to 32,000 bytes.".into());
        }
        let started = std::time::Instant::now();
        let config = self.classifier_config();
        let decision = super::classify::decide(
            &config,
            &super::options(&config),
            &self.ledger(),
            sample,
            (self.now_ms)(),
            super::classify::TIMEOUT,
        )
        .ok_or("Connect an eligible account before testing.")?;
        if let Some(account) = &decision.spent_on {
            self.record_success(account, decision.spent);
        }
        let (eligible_models, exclusions) =
            route_availability(&config, &self.ledger(), (self.now_ms)());
        Ok(RouteTest {
            eligible_models,
            exclusions,
            fallback_reason: match decision.reason {
                super::classify::Reason::Classified => None,
                super::classify::Reason::NotClassified => {
                    Some("Classification is not active for this request.")
                }
                super::classify::Reason::LowConfidence => {
                    Some("Classifier confidence is below the configured minimum.")
                }
                super::classify::Reason::Failed => {
                    Some("The classifier did not return a valid choice.")
                }
            },
            model: format!("{}/{}", decision.route.family, decision.route.model),
            reason: match decision.reason {
                super::classify::Reason::Classified => "Classifier selected the model",
                super::classify::Reason::NotClassified => "Fallback used without classification",
                super::classify::Reason::LowConfidence => {
                    "Fallback used because confidence was low"
                }
                super::classify::Reason::Failed => "Fallback used because the classifier failed",
            },
            confidence: (decision.reason == super::classify::Reason::Classified
                || decision.reason == super::classify::Reason::LowConfidence)
                .then_some(decision.confidence),
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    /// The configuration as it stands right now. It is read per turn, so a
    /// change in Settings takes the next turn with no restart.
    fn reserve(
        &self,
        config: &RouterConfig,
        family: &str,
        model: &str,
    ) -> Result<(config::Account, InFlight), balance::PickError> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut ledger = self.ledger();
        let now = (self.now_ms)();
        // Respect known account-wide exhaustion until its reset. Unknown or
        // stale windows do not disable an account indefinitely.
        for (id, quota) in super::quota::load(&self.agent).accounts {
            let reset = quota
                .windows
                .iter()
                .filter(|window| {
                    window.scope.is_empty()
                        && (window.limit_reached || window.used_percent >= 100.0)
                })
                .filter_map(|window| window.resets_at_ms.filter(|reset| *reset > now))
                .max();
            if let Some(reset) = reset {
                let usage = ledger.accounts.entry(id).or_default();
                usage.cooldown_until_ms = Some(usage.cooldown_until_ms.unwrap_or(0).max(reset));
            }
        }
        let account =
            balance::pick_with_active(config, &ledger, family, model, (self.now_ms)(), &active)?
                .clone();
        *active.entry(account.id.clone()).or_insert(0) += 1;
        let guard = InFlight {
            active: Arc::clone(&self.active),
            account: account.id.clone(),
        };
        Ok((account, guard))
    }

    fn config(&self) -> RouterConfig {
        config::load(&self.agent).unwrap_or_default()
    }

    fn record_success(&self, account: &str, tokens: wire::Tokens) {
        let now = (self.now_ms)();
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.record_success(account, &day(now), now, tokens.input, tokens.output);
            let _ = usage::save(&self.agent, &ledger);
        }
    }

    fn record_error(&self, account: &str, message: &str, cools: bool) {
        let now = (self.now_ms)();
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.record_error(account, &day(now), now, message, cools);
            let _ = usage::save(&self.agent, &ledger);
        }
    }

    fn ledger(&self) -> Ledger {
        self.ledger
            .lock()
            .map(|ledger| ledger.clone())
            .unwrap_or_default()
    }
}

/// The `YYYY-MM-DD` bucket a moment falls in, in the machine's own zone.
fn day(now_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(now_ms)
        .map(|moment| {
            chrono::DateTime::<chrono::Local>::from(moment)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|| "1970-01-01".to_owned())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Binds the loopback listener, writes the endpoint record, and serves until
/// the handle stops or drops.
pub fn start(agent: PathBuf) -> io::Result<Handle> {
    start_with_clock(agent, now_ms)
}

fn start_with_clock(agent: PathBuf, clock: fn() -> i64) -> io::Result<Handle> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let endpoint = Endpoint {
        port,
        token: token(),
    };
    write_endpoint(&agent, &endpoint)?;
    let active: Active = Arc::new(Mutex::new(BTreeMap::new()));
    let state = Arc::new(State {
        progress: Default::default(),
        ledger: Mutex::new(usage::load(&agent)),
        agent,
        active: Arc::clone(&active),
        now_ms: clock,
    });
    let stop = Arc::new(AtomicBool::new(false));
    let accept_stop = Arc::clone(&stop);
    let accept_token = endpoint.token.clone();
    let handle_state = Arc::clone(&state);
    std::thread::spawn(move || {
        while !accept_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = Arc::clone(&state);
                    let token = accept_token.clone();
                    std::thread::spawn(move || {
                        let _ = stream.set_nonblocking(false);
                        serve(stream, &state, &token);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(_) => break,
            }
        }
    });
    Ok(Handle {
        endpoint,
        stop,
        active,
        state: handle_state,
    })
}

/// One request's head: the method, the target and the headers.
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, value)| value.as_str())
    }

    /// The path with any query string removed.
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }
}

fn read_head(reader: &mut BufReader<TcpStream>) -> Option<Head> {
    let mut line = String::new();
    let mut read = 0;
    reader.read_line(&mut line).ok()?;
    read += line.len();
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        read += line.len();
        if read > HEAD_LIMIT {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    Some(Head {
        method,
        target,
        headers,
    })
}

fn read_body(reader: &mut BufReader<TcpStream>, head: &Head) -> Option<Vec<u8>> {
    let length: usize = head.header("content-length")?.parse().ok()?;
    if length > BODY_LIMIT {
        return None;
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).ok()?;
    Some(body)
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &Value) {
    let payload = body.to_string();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(payload.as_bytes());
    let _ = stream.flush();
}

fn serve(stream: TcpStream, state: &State, token: &str) {
    let Ok(peer) = stream.peer_addr() else {
        return;
    };
    // Belt on top of the loopback bind: nothing off the machine is served.
    if !peer.ip().is_loopback() {
        return;
    }
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });
    let mut stream = stream;
    let Some(head) = read_head(&mut reader) else {
        respond(
            &mut stream,
            400,
            "Bad Request",
            &wire::error_body("The router could not read the request.", "router_error"),
        );
        return;
    };
    if head.path() == "/healthz" {
        respond(&mut stream, 200, "OK", &serde_json::json!({ "ok": true }));
        return;
    }
    let presented = head
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_time_eq(presented.as_bytes(), token.as_bytes()) {
        respond(
            &mut stream,
            401,
            "Unauthorized",
            &wire::error_body("The router refused this token.", "router_error"),
        );
        return;
    }
    match (head.method.as_str(), head.path()) {
        ("GET", path) if path.starts_with("/v1/routing-progress/") => {
            let id = path.trim_start_matches("/v1/routing-progress/");
            if let Some(snapshot) = state.progress.get(id, (state.now_ms)()) {
                respond(
                    &mut stream,
                    200,
                    "OK",
                    &serde_json::to_value(snapshot).unwrap(),
                );
            } else {
                respond(&mut stream, 404, "Not Found", &serde_json::json!({}));
            }
        }
        ("GET", "/v1/models") | ("GET", "/models") => {
            let models = served_models(&state.config());
            respond(&mut stream, 200, "OK", &wire::model_list(&models));
        }
        ("POST", "/v1/chat/completions") | ("POST", "/chat/completions") => {
            let Some(body) = read_body(&mut reader, &head) else {
                respond(
                    &mut stream,
                    400,
                    "Bad Request",
                    &wire::error_body(
                        "The router could not read the request body.",
                        "router_error",
                    ),
                );
                return;
            };
            let Ok(request) = serde_json::from_slice::<Value>(&body) else {
                respond(
                    &mut stream,
                    400,
                    "Bad Request",
                    &wire::error_body("The request body is not JSON.", "router_error"),
                );
                return;
            };
            let progress = state
                .progress
                .start(head.header("x-muniment-routing-id"), (state.now_ms)());
            complete(&mut stream, state, &request, progress.as_deref());
            state.progress.finish(progress.as_deref());
        }
        _ => respond(
            &mut stream,
            404,
            "Not Found",
            &wire::error_body("The router does not serve this route.", "router_error"),
        ),
    }
}

/// Compares two secrets without leaking their length through timing.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |seen, (a, b)| seen | (a ^ b))
        == 0
}

/// Classify once, try the selected pool, then eligible fallback models.
/// Once response output starts, never replay the request on another model.
fn complete(stream: &mut TcpStream, state: &State, request: &Value, progress: Option<&str>) {
    state
        .progress
        .stage(progress, "choosing-model", (state.now_ms)());
    let config = state.classifier_config();
    let requested = wire::requested_model(request).unwrap_or(config::AUTO_MODEL);
    let text = wire::classifier_state(request);
    // Reuse the decision across attempts so failure never spends the classifier twice.
    let classification_started = std::time::Instant::now();
    let plan = match plan(&config, &state.ledger(), requested, &text, (state.now_ms)()) {
        Ok(plan) => plan,
        Err(error) => {
            let status = match error {
                ResolveError::UnknownModel(_) => 404,
                _ => 503,
            };
            respond(
                stream,
                status,
                "Router",
                &wire::error_body(&error.message(), "router_error"),
            );
            return;
        }
    };
    if let Some(spent_on) = &plan.classifier_spent_on {
        state.record_success(spent_on, plan.classifier_spent);
    }
    let classification_ms = classification_started
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let (_, exclusions) = route_availability(&config, &state.ledger(), (state.now_ms)());
    let mut refusals: Vec<String> = Vec::new();
    let mut routes = super::options(&config);
    // Prefer the configured fallback, then another provider, then remaining models.
    routes.sort_by_key(|route| {
        (
            config.fallback.as_deref() != Some(route.key.as_str()),
            route.family == plan.family,
        )
    });
    routes.retain(|route| route.family != plan.family || route.model != plan.model);
    routes.insert(
        0,
        config::Route {
            key: plan.route.clone(),
            description: String::new(),
            family: plan.family.clone(),
            model: plan.model.clone(),
        },
    );
    let mut last_failure = (503, "No eligible model served this turn.".to_owned());
    let mut attempted = false;
    for route in routes {
        let mut candidates = config.clone();
        loop {
            let (account, _in_flight) =
                match state.reserve(&candidates, &route.family, &route.model) {
                    Ok(account) => account,
                    Err(error) => {
                        refusals.push(format!(
                            "{}/{}: {}",
                            route.family,
                            route.model,
                            error.message()
                        ));
                        break;
                    }
                };
            if attempted
                || matches!(
                    plan.reason,
                    super::classify::Reason::Failed | super::classify::Reason::LowConfidence
                )
            {
                state.progress.stage(progress, "fallback", (state.now_ms)());
            } else {
                state
                    .progress
                    .stage(progress, "waiting-for-account", (state.now_ms)());
            }
            attempted = true;
            // Try each account at most once for this model, even if cooldown expires.
            if let Some(candidate) = candidates.accounts.iter_mut().find(|a| a.id == account.id) {
                candidate.enabled = false;
            }
            // A token inside a minute of dying is traded for a fresh one first, and
            // the pool keeps the fresh one, so this turn and the ones behind it go
            // out on a live token. A refused refresh is the account refused.
            let account = match native_auth::refresh_account(
                &state.agent,
                &account.id,
                (state.now_ms)(),
                REFRESH_TIMEOUT,
            ) {
                Ok(account) => account,
                Err(message) => {
                    state.record_error(&account.id, &message, true);
                    refusals.push(message);
                    continue;
                }
            };
            let prepared = match transport::prepare(&account, request, &route.model) {
                Ok(prepared) => prepared,
                Err(message) => {
                    last_failure = (400, message);
                    break;
                }
            };
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(CONNECT_TIMEOUT)
                .timeout_read(READ_TIMEOUT)
                .build();
            let mut call = agent
                .post(&prepared.url)
                .set("content-type", "application/json");
            for (name, value) in &prepared.headers {
                call = call.set(name, value);
            }
            let call = call.send_json(&prepared.body);
            match call {
                Ok(response) => {
                    state.progress.stage(progress, "thinking", (state.now_ms)());
                    let response_id = wire::evidenced_response_id(
                        &route.family,
                        &route.model,
                        plan.classifier.as_ref(),
                        wire::RoutingEvidence {
                            account: account.label.clone(),
                            selected_model: format!("{}/{}", plan.family, plan.model),
                            decision: match plan.reason {
                                super::classify::Reason::Classified => {
                                    "Classifier selected the model"
                                }
                                super::classify::Reason::NotClassified
                                    if requested != config::AUTO_MODEL =>
                                {
                                    "User selected the model"
                                }
                                super::classify::Reason::NotClassified => {
                                    "Fallback used without classification"
                                }
                                super::classify::Reason::LowConfidence => {
                                    "Fallback used because classifier confidence was low"
                                }
                                super::classify::Reason::Failed => {
                                    "Fallback used because the classifier failed"
                                }
                            }
                            .into(),
                            confidence: matches!(
                                plan.reason,
                                super::classify::Reason::Classified
                                    | super::classify::Reason::LowConfidence
                            )
                            .then_some(plan.confidence),
                            classification_ms,
                            exclusions: exclusions
                                .iter()
                                .map(|item| format!("{}: {}", item.model, item.reason))
                                .collect(),
                            fallback_causes: refusals.clone(),
                        },
                    );
                    if prepared.protocol != transport::Protocol::Chat {
                        let result = relay_native(
                            stream,
                            state,
                            &account.id,
                            response,
                            request,
                            &route.model,
                            &response_id,
                        );
                        match result {
                            Ok(()) => return,
                            Err(message) => {
                                last_failure = (502, message);
                                continue;
                            }
                        }
                    }
                    let result = if wire::streams(request) {
                        relay_stream(
                            stream,
                            state,
                            &account.id,
                            response,
                            wire::wants_usage(request),
                            &response_id,
                        )
                    } else {
                        relay_once(stream, state, &account.id, response, &response_id)
                    };
                    match result {
                        Ok(()) => return,
                        Err(message) => last_failure = (502, message),
                    }
                }
                Err(ureq::Error::Status(status, response)) => {
                    let retry_after = response
                        .header("retry-after")
                        .and_then(|s| s.parse::<u64>().ok());
                    let limit_headers = [
                        "retry-after",
                        "anthropic-ratelimit-unified-status",
                        "anthropic-ratelimit-unified-reset",
                        "anthropic-ratelimit-unified-representative-claim",
                    ]
                    .iter()
                    .filter_map(|name| {
                        response.header(name).map(|value| {
                            format!("{name}={}", value.chars().take(200).collect::<String>())
                        })
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                    let detail = response
                        .into_string()
                        .unwrap_or_else(|_| format!("The provider answered {status}."));
                    let cools = usage::status_cools(status);
                    state.record_error(
                        &account.id,
                        &format!(
                            "HTTP {status} model={} {limit_headers} {detail}",
                            route.model
                        ),
                        cools,
                    );
                    if let Some(seconds) = retry_after {
                        let mut ledger = state
                            .ledger
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(entry) = ledger.accounts.get_mut(&account.id) {
                            let until =
                                (state.now_ms)().saturating_add(seconds.min(86400) as i64 * 1000);
                            entry.cooldown_until_ms =
                                Some(entry.cooldown_until_ms.unwrap_or(0).max(until));
                        }
                        let _ = usage::save(&state.agent, &ledger);
                    }
                    last_failure = (status, detail);
                    refusals.push(format!("{} answered {status}.", account.label));
                    if !cools {
                        // Another model may accept the request, but repeating it on
                        // the same model's other accounts does not help.
                        break;
                    }
                }
                Err(ureq::Error::Transport(error)) => {
                    state.record_error(&account.id, &error.to_string(), true);
                    refusals.push(format!("{} did not answer.", account.label));
                }
            }
        }
    }
    respond(
        stream,
        last_failure.0,
        "Router",
        &wire::error_body(
            &format!(
                "No eligible model served this turn. {} {}",
                last_failure.1,
                refusals.join(" ")
            ),
            "router_error",
        ),
    );
}

/// Native providers stream even when the caller wants one complete answer.
/// Once a delta is delivered, errors end this turn and never replay it.
fn relay_native(
    stream: &mut TcpStream,
    state: &State,
    account: &str,
    response: ureq::Response,
    request: &Value,
    model: &str,
    response_id: &str,
) -> Result<(), String> {
    let streaming = wire::streams(request);
    let mut started = false;
    let mut decoder = transport::Decoder::new(model);
    decoder.response_id = response_id.to_owned();
    let mut reader = BufReader::new(response.into_reader().take(BODY_LIMIT as u64));
    let mut line = String::new();
    let mut data = String::new();
    let mut failure = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => {
                failure = Some("The provider stream ended unexpectedly.".to_owned());
                break;
            }
        }
        if data.len() + line.len() > BODY_LIMIT {
            failure = Some("The provider event exceeds the size limit.".to_owned());
            break;
        }
        if let Some(part) = line.trim_end().strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(part.trim_start());
        }
        if !line.trim().is_empty() || data.is_empty() {
            continue;
        }
        if data == "[DONE]" {
            break;
        }
        let event: Value = match serde_json::from_str(&data) {
            Ok(event) => event,
            Err(_) => {
                failure = Some("The provider sent an invalid event.".to_owned());
                break;
            }
        };
        data.clear();
        match decoder.event(&event) {
            Ok(Some(chunk)) if streaming => {
                if !started {
                    if stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\nconnection: close\r\n\r\n").is_err() { return Ok(()); }
                    started = true;
                }
                if write_event(stream, &chunk).is_err() {
                    state.record_error(account, "The client closed the stream.", false);
                    return Ok(());
                }
            }
            Ok(_) => {}
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
        if decoder.finished {
            break;
        }
    }
    if !decoder.finished || failure.is_some() {
        let message =
            failure.unwrap_or_else(|| "The provider stream ended before completion.".into());
        state.record_error(account, &message, false);
        if started {
            let _ = write_event(stream, &wire::error_body(&message, "provider_error"));
        } else {
            return Err(message);
        }
        return Ok(());
    }
    state.record_success(account, decoder.tokens);
    if streaming {
        if !started && stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n").is_err() { return Ok(()); }
        if write_event(stream, &decoder.final_chunk()).is_err() {
            return Ok(());
        }
        if wire::wants_usage(request) && write_event(stream, &decoder.usage_chunk()).is_err() {
            return Ok(());
        }
        let _ = stream.write_all(b"data: [DONE]\n\n");
        let _ = stream.flush();
    } else {
        respond(stream, 200, "OK", &decoder.completion());
    }
    Ok(())
}

fn write_event(stream: &mut TcpStream, value: &Value) -> io::Result<()> {
    write!(stream, "data: {value}\n\n")?;
    stream.flush()
}

/// One whole answer: forward the body and count what it says it spent.
fn relay_once(
    stream: &mut TcpStream,
    state: &State,
    account: &str,
    response: ureq::Response,
    response_id: &str,
) -> Result<(), String> {
    let Ok(mut value) = response.into_json::<Value>() else {
        state.record_error(
            account,
            "The provider answered with something that is not JSON.",
            false,
        );
        return Err("The provider answered with something that is not JSON.".into());
    };
    if value.get("error").is_some() || !value["choices"].is_array() {
        let message = "The provider returned no completion.";
        state.record_error(account, message, false);
        return Err(message.into());
    }
    if let Some(object) = value.as_object_mut() {
        object.insert("id".into(), Value::String(response_id.into()));
    }
    state.record_success(account, wire::tokens(&value).unwrap_or_default());
    respond(stream, 200, "OK", &value);
    Ok(())
}

/// A streamed answer: forward every frame as it arrives, and keep the usage
/// frame the router asked for off the client's wire unless `keep_usage` says
/// the client asked for it too.
fn relay_stream(
    stream: &mut TcpStream,
    state: &State,
    account: &str,
    response: ureq::Response,
    keep_usage: bool,
    response_id: &str,
) -> Result<(), String> {
    let mut reader = BufReader::new(response.into_reader().take(BODY_LIMIT as u64));
    let mut tokens = wire::Tokens::default();
    let mut line = String::new();
    let mut started = false;
    let mut finished = false;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(payload) = line.trim_end().strip_prefix("data:").map(str::trim_start) else {
            continue;
        };
        if payload == "[DONE]" {
            finished = started;
            if started {
                let _ = stream.write_all(b"data: [DONE]\n\n");
            }
            break;
        }
        let Ok(mut chunk) = serde_json::from_str::<Value>(payload) else {
            break;
        };
        if chunk.get("error").is_some() || !chunk["choices"].is_array() {
            break;
        }
        if let Some(counted) = wire::tokens(&chunk) {
            tokens = counted;
        }
        if !keep_usage && wire::usage_only_chunk(&chunk) {
            continue;
        }
        if !started {
            if stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\nconnection: close\r\n\r\n").is_err() { return Ok(()); }
            started = true;
        }
        chunk["id"] = Value::String(response_id.into());
        if write_event(stream, &chunk).is_err() {
            break;
        }
    }
    if finished {
        state.record_success(account, tokens);
    } else {
        let message = "The provider stream ended before completion.";
        state.record_error(account, message, false);
        if !started {
            return Err(message.into());
        }
        let _ = write_event(stream, &wire::error_body(message, "provider_error"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_router::config::{Account, Credential, Route, RouterConfig};
    use serde_json::json;

    /// The clock every server test reads, so a day bucket never drifts.
    fn fixed_clock() -> i64 {
        1_789_000_000_000
    }

    fn agent_dir() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("muniment-router-server-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn account(id: &str, base_url: &str) -> Account {
        Account {
            id: id.to_owned(),
            family: "openai".to_owned(),
            label: id.to_owned(),
            credential: Credential::ApiKey {
                key: format!("sk-{id}"),
            },
            base_url: Some(base_url.to_owned()),
            // The one model this pool serves, so the option set is exactly it.
            models: vec!["gpt-5.6-mini".to_owned()],
            enabled: true,
            weight: 1,
        }
    }

    fn config(accounts: Vec<Account>) -> RouterConfig {
        RouterConfig {
            enabled: true,
            accounts,
            routes: vec![Route {
                key: "fast".into(),
                description: "A short question".into(),
                family: "openai".into(),
                model: "gpt-5.6-mini".into(),
            }],
            fallback: Some("fast".into()),
            ..RouterConfig::default()
        }
    }

    #[test]
    fn route_test_availability_uses_runtime_pool_readiness() {
        let ready = account("ready", "http://localhost");
        let mut disabled = account("disabled", "http://localhost");
        disabled.models = vec!["disabled-model".into()];
        disabled.enabled = false;
        let mut cooling = account("cooling", "http://localhost");
        cooling.models = vec!["cooling-model".into()];
        let config = config(vec![ready, disabled, cooling]);
        let mut ledger = Ledger::default();
        ledger
            .accounts
            .entry("cooling".into())
            .or_default()
            .cooldown_until_ms = Some(fixed_clock() + 1000);
        let (eligible, excluded) = route_availability(&config, &ledger, fixed_clock());
        assert_eq!(eligible, vec!["openai/gpt-5.6-mini"]);
        assert_eq!(excluded.len(), 2);
        assert_eq!(excluded[0].model, "openai/cooling-model");
        assert!(excluded[0].reason.contains("temporarily unavailable"));
        assert_eq!(excluded[1].model, "openai/disabled-model");
        assert!(excluded[1].reason.contains("serves this model"));
        let (eligible, _) = route_availability(&config, &ledger, fixed_clock() + 1000);
        assert!(eligible.contains(&"openai/cooling-model".to_owned()));
    }

    /// One request to the running router, answered whole.
    fn call(
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        body: Option<&Value>,
        token: &str,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", endpoint.port)).unwrap();
        let payload = body.map(|value| value.to_string()).unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            payload.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(payload.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        let status: u16 = answer
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = answer.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
        (status, body)
    }

    /// A stand-in provider. Each connection is answered by `answer`, which
    /// reads the request body and writes the whole HTTP response.
    fn upstream(answers: Vec<(u16, String, bool)>) -> (String, std::sync::mpsc::Receiver<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, seen) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (status, payload, sse) in answers {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let length: usize = text
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|line| line.split(':').nth(1)?.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0_u8; length];
                let _ = stream.read_exact(&mut body);
                let mut request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if let Some(object) = request.as_object_mut() {
                    let bearer = text
                        .lines()
                        .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                        .map(|line| line["authorization:".len()..].trim().to_owned())
                        .unwrap_or_default();
                    object.insert("__authorization".into(), Value::String(bearer));
                }
                let _ = sender.send(request);
                let kind = if sse {
                    "text/event-stream"
                } else {
                    "application/json"
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}/v1"), seen)
    }

    fn answer(text: &str, input: u64, output: u64) -> String {
        json!({
            "id": "c1",
            "object": "chat.completion",
            "choices": [{ "index": 0, "message": { "role": "assistant", "content": text } }],
            "usage": { "prompt_tokens": input, "completion_tokens": output }
        })
        .to_string()
    }

    fn turn(model: &str, stream: bool) -> Value {
        json!({
            "model": model,
            "stream": stream,
            "messages": [{ "role": "user", "content": "Why did the build fail?" }]
        })
    }

    #[test]
    fn progress_endpoint_reports_real_fallback_and_requires_authentication() {
        let agent = agent_dir();
        let (url, _) = upstream(vec![
            (429, "limited".into(), false),
            (200, answer("hello", 1, 1), false),
        ]);
        config::save(
            &agent,
            &config(vec![account("a", &url), account("b", &url)]),
        )
        .unwrap();
        let handle = start_with_clock(agent, fixed_clock).unwrap();
        let endpoint = handle.endpoint();
        let id = uuid::Uuid::new_v4().to_string();
        ureq::post(&format!("{}/chat/completions", endpoint.base_url()))
            .set("authorization", &format!("Bearer {}", endpoint.token))
            .set("x-muniment-routing-id", &id)
            .send_json(turn("auto", false))
            .unwrap()
            .into_string()
            .unwrap();
        let path = format!("/v1/routing-progress/{id}");
        assert_eq!(call(endpoint, "GET", &path, None, "wrong").0, 401);
        let (status, body) = call(endpoint, "GET", &path, None, &endpoint.token);
        assert_eq!(status, 200);
        let snapshot: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            snapshot["stages"],
            json!([
                "choosing-model",
                "waiting-for-account",
                "fallback",
                "thinking"
            ])
        );
        assert_eq!(snapshot["done"], true);
        assert_eq!(
            call(
                endpoint,
                "GET",
                &format!("/v1/routing-progress/{}", uuid::Uuid::new_v4()),
                None,
                &endpoint.token
            )
            .0,
            404
        );
    }

    #[test]
    fn native_subscription_streams_fail_over_and_count_only_complete_answers() {
        let agent = agent_dir();
        let payload = [
            json!({"type":"response.output_text.delta","delta":"hello"}),
            json!({"type":"response.completed","response":{"usage":{"input_tokens":11,"output_tokens":2}}}),
        ].iter().map(|event| format!("data: {event}\n\n")).collect::<String>();
        let (url, seen) = upstream(vec![(429, "limited".into(), false), (200, payload, true)]);
        let mut accounts = vec![account("s1", &url), account("s2", &url)];
        for account in &mut accounts {
            account.credential = Credential::Subscription {
                provider: "openai-codex".into(),
                access: format!("token-{}", account.id),
                refresh: None,
                expires_ms: None,
                account_id: Some(account.id.clone()),
                email: None,
                plan: None,
                renews_at_ms: None,
            };
        }
        config::save(&agent, &config(accounts)).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", true)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200);
        let chunks: Vec<Value> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let id = chunks[0]["id"].as_str().unwrap();
        assert_eq!(
            wire::response_model(id),
            Some(("openai".into(), "gpt-5.6-mini".into()))
        );
        assert!(chunks.iter().all(|chunk| chunk["id"] == id));
        assert!(body.contains("hello"));
        assert!(body.contains("[DONE]"));
        assert_eq!(seen.try_iter().count(), 2);
        let ledger = usage::load(&agent);
        assert_eq!(ledger.account("s1").unwrap().errors, 1);
        assert_eq!(ledger.account("s2").unwrap().input_tokens, 11);
        assert_eq!(ledger.account("s2").unwrap().requests, 1);
    }

    #[test]
    fn a_truncated_native_stream_is_not_counted_as_success_or_replayed() {
        let agent = agent_dir();
        let (url, seen) = upstream(vec![(200, "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n".into(), true)]);
        let mut native = account("s1", &url);
        native.family = "anthropic".into();
        native.credential = Credential::Subscription {
            provider: "anthropic".into(),
            access: "token".into(),
            refresh: None,
            expires_ms: None,
            account_id: None,
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        let mut saved = config(vec![native]);
        saved.routes.clear();
        saved.fallback = None;
        config::save(&agent, &saved).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", true)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200);
        assert!(body.contains("partial"));
        assert!(body.contains("provider_error"));
        assert!(!body.contains("[DONE]"));
        assert_eq!(seen.try_iter().count(), 1);
        let ledger = usage::load(&agent);
        let usage = ledger.account("s1").unwrap();
        assert_eq!(usage.requests, 0);
        assert_eq!(usage.errors, 1);
    }

    #[test]
    fn reservations_distribute_concurrent_turns_and_release_on_drop() {
        let agent = agent_dir();
        let state = State {
            progress: Default::default(),
            agent,
            ledger: Mutex::new(Ledger::default()),
            active: Arc::new(Mutex::new(BTreeMap::new())),
            now_ms: fixed_clock,
        };
        let saved = config(vec![
            account("a", "http://unused"),
            account("b", "http://unused"),
        ]);
        let (first, first_guard) = state.reserve(&saved, "openai", "gpt-5.6-mini").unwrap();
        let (second, second_guard) = state.reserve(&saved, "openai", "gpt-5.6-mini").unwrap();
        assert_ne!(first.id, second.id);
        drop(first_guard);
        drop(second_guard);
        assert!(state.active.lock().unwrap().is_empty());
    }

    #[test]
    fn a_turn_reaches_the_pool_and_lands_in_the_ledger() {
        let agent = agent_dir();
        let (url, seen) = upstream(vec![(200, answer("because", 312, 48), false)]);
        config::save(&agent, &config(vec![account("a1", &url)])).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", false)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200);
        let answered: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(answered["choices"][0]["message"]["content"], "because");

        let sent = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(sent["model"], "gpt-5.6-mini");
        assert_eq!(sent["__authorization"], "Bearer sk-a1");

        let ledger = usage::load(&agent);
        let usage = ledger.account("a1").unwrap();
        assert_eq!(usage.requests, 1);
        assert_eq!(usage.input_tokens, 312);
        assert_eq!(usage.output_tokens, 48);
    }

    #[test]
    fn a_refused_account_cools_and_the_next_one_serves_the_turn() {
        let agent = agent_dir();
        let (refusing, _first) = upstream(vec![(
            429,
            json!({ "error": "slow down" }).to_string(),
            false,
        )]);
        let (serving, _second) = upstream(vec![(200, answer("second", 10, 2), false)]);
        config::save(
            &agent,
            &config(vec![account("a1", &refusing), account("a2", &serving)]),
        )
        .unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", false)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200);
        assert!(body.contains("second"));

        let ledger = usage::load(&agent);
        let refused = ledger.account("a1").unwrap();
        assert_eq!(refused.errors, 1);
        assert!(refused.cooldown_until_ms.is_some());
        assert!(refused.last_error.as_ref().unwrap().contains("slow down"));
        assert_eq!(ledger.account("a2").unwrap().requests, 1);
    }

    #[test]
    fn exhausted_provider_falls_back_and_reports_the_successful_model() {
        let agent = agent_dir();
        let (limited, seen_limited) = upstream(vec![
            (429, "limited".into(), false),
            (429, "limited".into(), false),
        ]);
        let (serving, seen_serving) = upstream(vec![(200, answer("fallback reply", 12, 3), false)]);
        let mut spare = account("spare", &serving);
        spare.family = "xai".into();
        spare.models = vec!["grok-test".into()];
        let mut disabled = spare.clone();
        disabled.id = "disabled".into();
        disabled.enabled = false;
        let mut configuration = config(vec![
            account("a1", &limited),
            account("a2", &limited),
            disabled,
            spare,
        ]);
        configuration.fallback = Some("xai/grok-test".into());
        config::save(&agent, &configuration).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("fast", false)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("fallback reply"));
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            wire::response_model(body["id"].as_str().unwrap()),
            Some(("xai".into(), "grok-test".into()))
        );
        assert_eq!(seen_limited.try_iter().count(), 2);
        assert_eq!(seen_serving.try_iter().count(), 1);
        let ledger = usage::load(&agent);
        assert_eq!(ledger.account("spare").unwrap().requests, 1);
        assert!(ledger.account("disabled").is_none());
    }

    #[test]
    fn model_rejection_tries_another_model_without_repeating_the_rejected_one() {
        let agent = agent_dir();
        let (url, seen) = upstream(vec![
            (404, "model unavailable".into(), false),
            (200, answer("alternate", 1, 1), false),
        ]);
        let mut a = account("a", &url);
        a.models.push("alternate-model".into());
        config::save(&agent, &config(vec![a])).unwrap();
        let handle = start_with_clock(agent, fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("fast", false)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200, "{body}");
        let response: Value = serde_json::from_str(&body).unwrap();
        let routing = wire::response_routing(response["id"].as_str().unwrap()).unwrap();
        assert_eq!(routing.fallback_causes, ["a answered 404."]);
        assert_eq!(routing.account, "a");
        assert_eq!(routing.selected_model, "openai/gpt-5.6-mini");
        let models: Vec<_> = seen
            .try_iter()
            .map(|r| r["model"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(models, vec!["gpt-5.6-mini", "alternate-model"]);
    }

    #[test]
    fn native_error_before_output_can_use_another_provider() {
        let agent = agent_dir();
        let (broken, _) = upstream(vec![(
            200,
            "data: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}\n\n".into(),
            true,
        )]);
        let mut native = account("native", &broken);
        native.family = "anthropic".into();
        native.models = vec!["claude-test".into()];
        let (serving, _) = upstream(vec![(200, answer("recovered", 1, 1), false)]);
        config::save(&agent, &config(vec![native, account("spare", &serving)])).unwrap();
        let handle = start_with_clock(agent, fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("anthropic/claude-test", false)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("recovered"));
    }

    #[test]
    fn a_rejected_request_comes_straight_back_and_spends_no_second_account() {
        let agent = agent_dir();
        let (rejecting, _first) = upstream(vec![(
            400,
            json!({ "error": "no such model" }).to_string(),
            false,
        )]);
        let (spare, _second) = upstream(vec![(200, answer("unused", 1, 1), false)]);
        config::save(
            &agent,
            &config(vec![account("a1", &rejecting), account("a2", &spare)]),
        )
        .unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, body) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", false)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 400);
        assert!(body.contains("no such model"));
        let ledger = usage::load(&agent);
        assert_eq!(ledger.account("a1").unwrap().errors, 1);
        assert!(ledger.account("a1").unwrap().cooldown_until_ms.is_none());
        assert!(ledger.account("a2").is_none());
    }

    #[test]
    fn a_streamed_turn_forwards_every_frame_and_counts_the_usage_frame_away() {
        let agent = agent_dir();
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"be\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"cause\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":7}}\n\n",
            "data: [DONE]\n\n"
        );
        let (url, seen) = upstream(vec![(200, body.to_owned(), true)]);
        config::save(&agent, &config(vec![account("a1", &url)])).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let (status, answered) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", true)),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200);
        assert!(answered.contains("\"be\""));
        assert!(answered.contains("\"cause\""));
        assert!(answered.contains("[DONE]"));
        assert!(!answered.contains("prompt_tokens"));

        let sent = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(sent["stream_options"]["include_usage"], true);
        let usage = usage::load(&agent);
        let counted = usage.account("a1").unwrap();
        assert_eq!(counted.requests, 1);
        assert_eq!(counted.input_tokens, 100);
        assert_eq!(counted.output_tokens, 7);
    }

    #[test]
    fn a_client_that_asked_for_usage_keeps_the_usage_frame() {
        let agent = agent_dir();
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"be\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":7}}\n\n",
            "data: [DONE]\n\n"
        );
        let (url, _seen) = upstream(vec![(200, body.to_owned(), true)]);
        config::save(&agent, &config(vec![account("a1", &url)])).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let mut request = turn("auto", true);
        request["stream_options"] = json!({ "include_usage": true });
        let (status, answered) = call(
            handle.endpoint(),
            "POST",
            "/v1/chat/completions",
            Some(&request),
            &handle.endpoint().token,
        );
        assert_eq!(status, 200);
        assert!(answered.contains("prompt_tokens"));
        assert_eq!(usage::load(&agent).account("a1").unwrap().input_tokens, 100);
    }

    #[test]
    fn the_router_serves_its_model_list_and_refuses_a_wrong_token() {
        let agent = agent_dir();
        config::save(
            &agent,
            &config(vec![account("a1", "http://127.0.0.1:9/v1")]),
        )
        .unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let endpoint = handle.endpoint();
        let (status, body) = call(endpoint, "GET", "/v1/models", None, &endpoint.token);
        assert_eq!(status, 200);
        assert!(body.contains("\"auto\""));
        assert!(body.contains("\"fast\""));

        let (status, _) = call(endpoint, "GET", "/v1/models", None, "wrong-token");
        assert_eq!(status, 401);
        let (status, _) = call(endpoint, "GET", "/v1/nothing", None, &endpoint.token);
        assert_eq!(status, 404);
        // Health needs no token, so a caller can see the router is up.
        let (status, _) = call(endpoint, "GET", "/healthz", None, "");
        assert_eq!(status, 200);

        assert_eq!(read_endpoint(&agent).as_ref(), Some(endpoint));
        assert_eq!(
            endpoint.base_url(),
            format!("http://127.0.0.1:{}/v1", endpoint.port)
        );
    }

    #[test]
    fn an_empty_pool_says_so_and_an_unknown_model_is_not_found() {
        let agent = agent_dir();
        config::save(&agent, &config(Vec::new())).unwrap();
        let handle = start_with_clock(agent.clone(), fixed_clock).unwrap();
        let endpoint = handle.endpoint();
        let (status, body) = call(
            endpoint,
            "POST",
            "/v1/chat/completions",
            Some(&turn("auto", false)),
            &endpoint.token,
        );
        assert_eq!(status, 503);
        assert!(body.contains("No model is in the running"));
        let (status, _) = call(
            endpoint,
            "POST",
            "/v1/chat/completions",
            Some(&turn("nobody", false)),
            &endpoint.token,
        );
        assert_eq!(status, 404);
        let (status, _) = call(
            endpoint,
            "POST",
            "/v1/chat/completions",
            None,
            &endpoint.token,
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn two_tokens_of_the_same_length_compare_without_matching() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert_eq!(token().len(), 64);
        assert_ne!(token(), token());
    }
}
