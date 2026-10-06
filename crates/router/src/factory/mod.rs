//! The factory router server: run tokens, budgets, outcomes and metrics in
//! front of the same routing the desktop uses.
//!
//! The server answers the factory's API. An admin token creates a run and
//! gets back a signed run token bound to the run's task, repository, role,
//! optional budget and expiry. Every model call carries a run token. The
//! server reserves the call's uncached cost estimate before it goes upstream
//! and settles the priced cost after. A run with a budget gets 402
//! `budget_exhausted` once it has spent it. A run without one is never
//! refused on spend. Gate outcomes feed a decayed success rate per model,
//! role and repository, and policy reads it at task boundaries.

pub mod accounts;
pub mod langfuse;
pub mod metrics;
pub mod openbao;
pub mod postgres;
pub mod settings;
pub mod token;

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::{Account, Route};
use crate::server::{self, Attempt, Hooks, State};
use crate::store::{self, Backend, RunCharge, RunFailure, RunRecord, SuccessWindow};
use crate::{model_catalog, native_auth, quota, served_models, usage, wire};

use metrics::Metrics;
use token::{Claims, SigningKey};

const ACCEPT_POLL: Duration = Duration::from_millis(50);
const LONGEST_RUN_S: u64 = 7 * 24 * 60 * 60;
const REFRESH_TIMEOUT: Duration = Duration::from_secs(12);
/// How much of an error answer the server keeps to read its error type.
const ERROR_CAPTURE: usize = 16 * 1024;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The secret source of a server with no secret manager configured: every
/// account reads as having no credential, so none takes a turn.
pub struct NoSecrets;

impl store::SecretSource for NoSecrets {
    fn read(&self, _id: &str) -> Result<Option<crate::config::Credential>, String> {
        Ok(None)
    }

    fn write(&self, _id: &str, _credential: &crate::config::Credential) -> Result<(), String> {
        Err("No secret source is configured. Set MUNIMENT_ROUTER_OPENBAO_ADDRESS.".into())
    }

    fn remove(&self, _id: &str) -> Result<(), String> {
        Ok(())
    }
}

/// What the server needs beyond the routing state.
pub struct Options {
    pub admin_token: String,
    pub signing_key: SigningKey,
    pub success: SuccessWindow,
    pub metrics: bool,
    /// Where each chat completion goes as a Langfuse generation.
    pub langfuse: Option<langfuse::Langfuse>,
}

/// Budget held by turns in flight, per run, and what this process has seen
/// each run spend.
#[derive(Default)]
struct Budgets(Mutex<HashMap<String, Budget>>);

#[derive(Clone, Copy, Default)]
struct Budget {
    /// `None` for a run without a budget.
    budget: Option<f64>,
    spent: f64,
    reserved: f64,
    expires_ms: i64,
    revoked: bool,
}

impl Budget {
    /// What the run has left, or `None` for a run without a budget.
    fn remaining(&self) -> Option<f64> {
        self.budget
            .map(|budget| budget - self.spent - self.reserved)
    }

    fn exhausted(&self) -> bool {
        self.remaining().is_some_and(|left| left <= 0.0)
    }
}

impl Budgets {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Budget>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The run's budget as this process holds it, read from the store the
    /// first time.
    fn seed(&self, run: &RunRecord) {
        self.lock().entry(run.run_id.clone()).or_insert(Budget {
            budget: run.budget_usd,
            spent: run.usage.spent_usd,
            reserved: 0.0,
            expires_ms: run.expires_ms,
            revoked: run.revoked_ms.is_some(),
        });
    }

    fn get(&self, run_id: &str) -> Option<Budget> {
        self.lock().get(run_id).copied()
    }

    /// Reserves up to `estimate` of what remains, or all of it for a run
    /// without a budget. `None` means nothing remains.
    fn reserve(&self, run_id: &str, estimate: f64) -> Option<f64> {
        let mut budgets = self.lock();
        let entry = budgets.get_mut(run_id)?;
        let remaining = entry.remaining().unwrap_or(f64::INFINITY);
        if remaining <= 0.0 {
            return None;
        }
        let held = estimate.max(0.0).min(remaining);
        entry.reserved += held;
        Some(held)
    }

    fn settle(&self, run_id: &str, held: f64, cost: f64) {
        if let Some(entry) = self.lock().get_mut(run_id) {
            entry.reserved = (entry.reserved - held).max(0.0);
            entry.spent += cost.max(0.0);
        }
    }

    fn revoke(&self, run_id: &str) {
        if let Some(entry) = self.lock().get_mut(run_id) {
            entry.revoked = true;
        }
    }
}

struct Server {
    state: Arc<State>,
    options: Options,
    budgets: Budgets,
    metrics: Metrics,
    draining: AtomicBool,
    connections: AtomicUsize,
}

/// A running server. Dropping the handle stops accepting.
pub struct Handle {
    address: SocketAddr,
    server: Arc<Server>,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Handle {
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stops accepting connections, then waits for every open connection,
    /// streams included, to finish or for `deadline` to pass. Answers whether
    /// every connection finished.
    pub fn drain(&mut self, deadline: Duration) -> bool {
        self.server.draining.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        let until = Instant::now() + deadline;
        while self.server.connections.load(Ordering::SeqCst) > 0 {
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(langfuse) = &self.server.options.langfuse {
            langfuse.flush(until.saturating_duration_since(Instant::now()));
        }
        true
    }

    /// Connections open right now.
    pub fn connections(&self) -> usize {
        self.server.connections.load(Ordering::SeqCst)
    }

    /// Counts one catalog load in the metrics.
    pub fn catalog_loaded(&self, result: &model_catalog::Reload) {
        let label = match result {
            model_catalog::Reload::Unchanged => return,
            model_catalog::Reload::Installed(_) => "installed",
            model_catalog::Reload::Rejected(_) => "rejected",
        };
        self.server.metrics.add(
            "muniment_router_catalog_reloads_total",
            &[("result", label)],
            1.0,
        );
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Binds `listen` and serves until the handle drains or drops.
pub fn start(listen: &str, backend: Backend, options: Options) -> io::Result<Handle> {
    start_with_clock(listen, backend, options, now_ms)
}

fn start_with_clock(
    listen: &str,
    backend: Backend,
    options: Options,
    clock: fn() -> i64,
) -> io::Result<Handle> {
    let listener = TcpListener::bind(listen)?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let server = Arc::new(Server {
        state: Arc::new(State::new(backend, None, clock)),
        options,
        budgets: Budgets::default(),
        metrics: Metrics::default(),
        draining: AtomicBool::new(false),
        connections: AtomicUsize::new(0),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let accept_stop = Arc::clone(&stop);
    let accept_server = Arc::clone(&server);
    let accept = std::thread::spawn(move || {
        while !accept_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = Arc::clone(&accept_server);
                    server.connections.fetch_add(1, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let _ = stream.set_nonblocking(false);
                        serve(stream, &server);
                        server.connections.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(_) => std::thread::sleep(ACCEPT_POLL),
            }
        }
        // The listener closes here, so new connections are refused.
    });
    Ok(Handle {
        address,
        server,
        stop,
        accept: Some(accept),
    })
}

/// Records the status line of whatever the router writes back, and the start
/// of an error answer.
struct Recorder<'a> {
    inner: &'a mut TcpStream,
    status: Option<u16>,
    error: Vec<u8>,
}

impl Recorder<'_> {
    /// The status and the `error.type` of an answer of 400 or above.
    fn failure(&self) -> Option<(u16, Option<String>)> {
        let status = self.status.filter(|status| *status >= 400)?;
        let text = String::from_utf8_lossy(&self.error);
        let kind = text
            .split_once("\r\n\r\n")
            .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
            .and_then(|body| body["error"]["type"].as_str().map(str::to_owned));
        Some((status, kind))
    }
}

impl Write for Recorder<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.status.is_none() {
            self.status = std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| text.strip_prefix("HTTP/1.1 "))
                .and_then(|rest| rest.get(..3))
                .and_then(|code| code.parse().ok());
        }
        let written = self.inner.write(bytes)?;
        if self.status.is_some_and(|status| status >= 400) {
            let room = ERROR_CAPTURE.saturating_sub(self.error.len());
            self.error.extend_from_slice(&bytes[..written.min(room)]);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn error(message: &str, kind: &str) -> Value {
    wire::error_body(message, kind)
}

fn serve(stream: TcpStream, server: &Server) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });
    let mut stream = stream;
    let mut out = Recorder {
        inner: &mut stream,
        status: None,
        error: Vec::new(),
    };
    let Some(head) = server::read_head(&mut reader) else {
        server::respond(
            &mut out,
            400,
            "Bad Request",
            &error("The router could not read the request.", "router_error"),
        );
        return;
    };
    let path = head.path().to_owned();
    let route = route_label(&head.method, &path);
    handle(&head, &mut reader, &mut out, server);
    let status = out
        .status
        .map(|code| code.to_string())
        .unwrap_or_else(|| "none".into());
    server.metrics.add(
        "muniment_router_http_requests_total",
        &[("route", route), ("status", &status)],
        1.0,
    );
}

fn route_label(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("GET", "/healthz") => "healthz",
        ("GET", "/metrics") => "metrics",
        ("POST", "/v1/runs") => "create_run",
        ("GET", p) if p.starts_with("/v1/runs/") => "get_run",
        ("DELETE", p) if p.starts_with("/v1/runs/") => "delete_run",
        ("POST", "/v1/outcomes") => "outcomes",
        ("POST", "/v1/chat/completions" | "/chat/completions") => "chat_completions",
        ("GET", "/v1/models" | "/models") => "models",
        _ => "other",
    }
}

fn bearer(head: &server::Head) -> &str {
    head.header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim()
}

fn handle(
    head: &server::Head,
    reader: &mut BufReader<TcpStream>,
    out: &mut Recorder<'_>,
    server: &Server,
) {
    let path = head.path();
    match (head.method.as_str(), path) {
        ("GET", "/healthz") => {
            if server.draining.load(Ordering::SeqCst) {
                server::respond(
                    out,
                    503,
                    "Service Unavailable",
                    &json!({"ok": false, "draining": true}),
                );
            } else {
                server::respond(out, 200, "OK", &json!({"ok": true}));
            }
            return;
        }
        ("GET", "/metrics") if server.options.metrics => {
            let text = render_metrics(server);
            let _ = write!(
                out,
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                text.len()
            );
            let _ = out.flush();
            return;
        }
        _ => {}
    }
    let admin = server::constant_time_eq(
        bearer(head).as_bytes(),
        server.options.admin_token.as_bytes(),
    );
    let body = |reader: &mut BufReader<TcpStream>| -> Result<Value, Value> {
        let bytes = server::read_body(reader, head).ok_or_else(|| {
            error(
                "The router could not read the request body.",
                "router_error",
            )
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|_| error("The request body is not JSON.", "router_error"))
    };
    match (head.method.as_str(), path) {
        ("POST", "/v1/runs") | ("POST", "/v1/outcomes") | ("GET", _) | ("DELETE", _)
            if path.starts_with("/v1/runs") || path == "/v1/outcomes" =>
        {
            if !admin {
                server::respond(
                    out,
                    401,
                    "Unauthorized",
                    &error("The router refused this admin token.", "router_error"),
                );
                return;
            }
            let run_id = path.strip_prefix("/v1/runs/").unwrap_or("");
            let (status, answer) = match (head.method.as_str(), path) {
                ("POST", "/v1/runs") => match body(reader) {
                    Ok(value) => create_run(server, value),
                    Err(value) => (400, value),
                },
                ("POST", "/v1/outcomes") => match body(reader) {
                    Ok(value) => outcome(server, value),
                    Err(value) => (400, value),
                },
                ("GET", _) if !run_id.is_empty() => get_run(server, run_id, false),
                ("DELETE", _) if !run_id.is_empty() => get_run(server, run_id, true),
                _ => (
                    404,
                    error("The router does not serve this route.", "router_error"),
                ),
            };
            server::respond(out, status, "Router", &answer);
        }
        ("GET", "/v1/models") | ("GET", "/models") => {
            if !admin {
                if let Err((status, answer)) = run_from(server, head) {
                    server::respond(out, status, "Router", &answer);
                    return;
                }
            }
            server::respond(
                out,
                200,
                "OK",
                &wire::model_list(&served_models(&server.state.config())),
            );
        }
        ("POST", "/v1/chat/completions") | ("POST", "/chat/completions") => {
            let run = match run_from(server, head) {
                Ok(run) => run,
                Err((status, answer)) => {
                    server::respond(out, status, "Router", &answer);
                    return;
                }
            };
            let started = chrono::Utc::now();
            let attempts = chat(head, reader, out, server, &run);
            record_failure(server, &run, out);
            if let Some(langfuse) = &server.options.langfuse {
                let trace = langfuse::trace_header(head.header("x-muniment-trace"));
                trace_generation(langfuse, &run, trace, started, &attempts, out);
            }
        }
        _ => server::respond(
            out,
            404,
            "Not Found",
            &error("The router does not serve this route.", "router_error"),
        ),
    }
}

/// Routes one run-token turn. Answers every upstream attempt it made.
fn chat(
    head: &server::Head,
    reader: &mut BufReader<TcpStream>,
    out: &mut Recorder<'_>,
    server: &Server,
    run: &RunRecord,
) -> Vec<Attempt> {
    let budget = server.budgets.get(&run.run_id).unwrap_or_default();
    if budget.exhausted() {
        server.metrics.add(
            "muniment_router_budget_rejections_total",
            &[("role", &run.role)],
            1.0,
        );
        server::respond(out, 402, "Payment Required", &exhausted(run, budget));
        return Vec::new();
    }
    let request = match server::read_body(reader, head)
        .ok_or_else(|| {
            error(
                "The router could not read the request body.",
                "router_error",
            )
        })
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|_| error("The request body is not JSON.", "router_error"))
        }) {
        Ok(request) => request,
        Err(answer) => {
            server::respond(out, 400, "Bad Request", &answer);
            return Vec::new();
        }
    };
    let hooks = RunHooks {
        server,
        run,
        held: Mutex::new(0.0),
        attempts: Mutex::new(Vec::new()),
    };
    let thread = head
        .header("x-muniment-thread")
        .filter(|id| id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_owned)
        .unwrap_or_else(|| crate::policy::digest(&format!("run:{}", run.run_id)));
    server::complete(
        out,
        &server.state,
        &hooks,
        &request,
        None,
        Some(&thread),
        head.header("x-muniment-task").unwrap_or(&run.task_id),
        head.header("x-muniment-validation-failures")
            .and_then(|value| value.trim().parse::<u32>().ok()),
        head.header("x-muniment-request-purpose"),
    );
    hooks
        .attempts
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
}

/// Sends one turn to Langfuse as a generation in `trace`, or in the task's
/// own trace when the request named none.
fn trace_generation(
    langfuse: &langfuse::Langfuse,
    run: &RunRecord,
    trace: Option<String>,
    started: chrono::DateTime<chrono::Utc>,
    attempts: &[Attempt],
    out: &Recorder<'_>,
) {
    let ended = chrono::Utc::now();
    let trace_id = match trace {
        Some(trace) => trace,
        None => {
            let trace = langfuse::task_trace_id(&run.task_id);
            langfuse.send(langfuse::event(
                "trace-create",
                json!({"id": trace, "metadata": {"task_id": run.task_id, "repo": run.repo}}),
            ));
            trace
        }
    };
    let time =
        |at: chrono::DateTime<chrono::Utc>| at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let served = attempts.iter().rev().find(|attempt| attempt.served);
    let last = served.or(attempts.last());
    let failure = out.failure();
    let mut body = json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "traceId": trace_id,
        "name": format!("{} chat completion", run.role),
        "startTime": time(started),
        "endTime": time(ended),
        "model": last.map(|attempt| format!("{}/{}", attempt.route.family, attempt.route.model)),
        "costDetails": {"total": attempts.iter().map(|attempt| attempt.cost_usd).sum::<f64>()},
        "metadata": {
            "run_id": run.run_id,
            "task_id": run.task_id,
            "repo": run.repo,
            "role": run.role,
            "account": last.map(|attempt| attempt.account.clone()),
            "attempts": attempts.len(),
            "latency_ms": ended.timestamp_millis() - started.timestamp_millis(),
            "status": out.status,
        },
        "level": if failure.is_some() { "ERROR" } else { "DEFAULT" },
    });
    if let Some(tokens) = served.and_then(|attempt| attempt.tokens) {
        body["usageDetails"] = json!({
            "input": tokens.input,
            "output": tokens.output,
            "cache_read_input_tokens": tokens.cache_read,
            "cache_creation_input_tokens": tokens.cache_write,
        });
    }
    if let Some((status, kind)) = failure {
        let kind = failure_type(status, kind.as_deref()).or(kind.as_deref());
        body["statusMessage"] = json!(format!("{status} {}", kind.unwrap_or("error")));
    }
    langfuse.send(langfuse::event("generation-create", body));
}

/// The failure type a run reports for an answer of `status` whose body named
/// the error type `kind`.
fn failure_type(status: u16, kind: Option<&str>) -> Option<&'static str> {
    match kind {
        Some("budget_exhausted") => return Some("budget_exhausted"),
        Some("routing_constraints" | "routing_capability") => return Some("routing_constraints"),
        Some("routing_budget") => return Some("routing_budget"),
        _ => {}
    }
    match status {
        401 | 403 => Some("auth"),
        429 => Some("rate_limited"),
        402 | 500..=599 => Some("upstream_unavailable"),
        _ => None,
    }
}

/// Keeps the outcome of the run's most recent request for `GET /v1/runs/{id}`:
/// the failure when the answer failed, and nothing once a later answer did not.
fn record_failure(server: &Server, run: &RunRecord, out: &Recorder<'_>) {
    let store = &server.state.backend.store;
    let Some((status, kind)) = out.failure() else {
        if out.status.is_some() && run.last_failure.is_some() {
            if let Err(error) = store.record_run_failure(&run.run_id, None) {
                eprintln!(
                    "muniment-router: run {} failure not cleared: {error}",
                    run.run_id
                );
            }
        }
        return;
    };
    let failure = RunFailure {
        status,
        error_type: failure_type(status, kind.as_deref()).map(str::to_owned),
        at_ms: (server.state.now_ms)(),
    };
    server.metrics.add(
        "muniment_router_run_errors_total",
        &[
            ("type", failure.error_type.as_deref().unwrap_or("other")),
            ("status", &status.to_string()),
        ],
        1.0,
    );
    if let Err(error) = store.record_run_failure(&run.run_id, Some(&failure)) {
        eprintln!(
            "muniment-router: run {} failure not saved: {error}",
            run.run_id
        );
    }
}

fn exhausted(run: &RunRecord, budget: Budget) -> Value {
    json!({"error": {
        "type": "budget_exhausted",
        "message": "This run has spent its budget.",
        "run_id": run.run_id,
        "budget_usd": budget.budget,
        "spent_usd": budget.spent,
        "reserved_usd": budget.reserved,
    }})
}

/// The run a request's token names, after the signature, the expiry, the
/// revocation and every bound claim check out.
fn run_from(server: &Server, head: &server::Head) -> Result<RunRecord, (u16, Value)> {
    let refused = |message: &str| (401, error(message, "invalid_run_token"));
    let now = (server.state.now_ms)();
    let claims = server
        .options
        .signing_key
        .verify(bearer(head), now)
        .map_err(|refusal| match refusal {
            token::Refusal::Expired => refused("This run token has expired."),
            _ => refused("The router refused this run token."),
        })?;
    let run = server
        .state
        .backend
        .store
        .run(&claims.run_id)
        .map_err(|_| {
            (
                503,
                error("The router could not read its run records.", "router_error"),
            )
        })?
        .ok_or_else(|| refused("The router knows no such run."))?;
    let bound = run.task_id == claims.task_id
        && run.repo == claims.repo
        && run.role == claims.role
        && run.budget_usd == claims.budget_usd
        && run.expires_ms == claims.expires_ms;
    if !bound {
        return Err(refused("The router refused this run token."));
    }
    server.budgets.seed(&run);
    let budget = server.budgets.get(&run.run_id).unwrap_or_default();
    if run.revoked_ms.is_some() || budget.revoked {
        return Err(refused("This run has ended."));
    }
    if now >= run.expires_ms {
        return Err(refused("This run token has expired."));
    }
    Ok(run)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRun {
    run_id: String,
    task_id: String,
    repo: String,
    role: String,
    #[serde(default)]
    budget_usd: Option<f64>,
    expires_in_s: u64,
}

fn create_run(server: &Server, body: Value) -> (u16, Value) {
    let Ok(new) = serde_json::from_value::<NewRun>(body) else {
        return (
            400,
            error(
                "The run needs run_id, task_id, repo, role and expires_in_s.",
                "invalid_request",
            ),
        );
    };
    let text_ok = |text: &str| {
        !text.trim().is_empty() && text.len() <= 256 && !text.chars().any(char::is_control)
    };
    if ![&new.run_id, &new.task_id, &new.repo, &new.role]
        .iter()
        .all(|text| text_ok(text))
        || !new
            .budget_usd
            .is_none_or(|budget| budget.is_finite() && budget > 0.0)
        || !(1..=LONGEST_RUN_S).contains(&new.expires_in_s)
    {
        return (
            400,
            error("The run has an empty or invalid field.", "invalid_request"),
        );
    }
    let now = (server.state.now_ms)();
    let mut record = RunRecord {
        run_id: new.run_id,
        task_id: new.task_id,
        repo: new.repo,
        role: new.role,
        budget_usd: new.budget_usd,
        created_ms: now,
        expires_ms: now + new.expires_in_s as i64 * 1000,
        revoked_ms: None,
        usage: store::RunUsage::default(),
        last_failure: None,
    };
    let store = &server.state.backend.store;
    match store.create_run(&record) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // A retried create gets a token for the run it made the first
            // time, as long as it asks for the same run.
            match store.run(&record.run_id) {
                Ok(Some(existing))
                    if existing.task_id == record.task_id
                        && existing.repo == record.repo
                        && existing.role == record.role
                        && existing.budget_usd == record.budget_usd
                        && existing.revoked_ms.is_none()
                        && existing.expires_ms > now =>
                {
                    record = existing;
                }
                Ok(_) => {
                    return (
                        409,
                        self::error("A different run already has this run_id.", "run_conflict"),
                    )
                }
                Err(_) => {
                    return (
                        503,
                        self::error("The router could not read its run records.", "router_error"),
                    )
                }
            }
        }
        Err(_) => {
            return (
                503,
                self::error("The router could not save the run.", "router_error"),
            )
        }
    }
    server.budgets.seed(&record);
    let token = server.options.signing_key.sign(&Claims {
        run_id: record.run_id.clone(),
        task_id: record.task_id.clone(),
        repo: record.repo.clone(),
        role: record.role.clone(),
        budget_usd: record.budget_usd,
        expires_ms: record.expires_ms,
        nonce: token::nonce(),
    });
    (
        200,
        json!({"token": token, "run_id": record.run_id, "expires_ms": record.expires_ms}),
    )
}

fn usage_body(run: &RunRecord, budget: Option<Budget>) -> Value {
    let reserved = budget.map(|budget| budget.reserved).unwrap_or(0.0);
    json!({
        "run_id": run.run_id,
        "task_id": run.task_id,
        "repo": run.repo,
        "role": run.role,
        "budget_usd": run.budget_usd,
        "spent_usd": run.usage.spent_usd,
        "reserved_usd": reserved,
        "input_tokens": run.usage.input_tokens,
        "output_tokens": run.usage.output_tokens,
        "cache_read_tokens": run.usage.cache_read_tokens,
        "requests": run.usage.requests,
        "models": run.usage.models,
        "expires_ms": run.expires_ms,
        "revoked": run.revoked_ms.is_some(),
        "last_status": run.last_failure.as_ref().map(|failure| failure.status),
        "last_error_type": run.last_failure.as_ref().and_then(|failure| failure.error_type.as_deref()),
        "last_status_at": run.last_failure.as_ref().and_then(|failure| {
            chrono::DateTime::from_timestamp_millis(failure.at_ms)
                .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        }),
    })
}

fn get_run(server: &Server, run_id: &str, revoke: bool) -> (u16, Value) {
    let store = &server.state.backend.store;
    let now = (server.state.now_ms)();
    if revoke {
        server.budgets.revoke(run_id);
        if store.revoke_run(run_id, now).is_err() {
            return (
                503,
                error("The router could not revoke the run.", "router_error"),
            );
        }
    }
    match store.run(run_id) {
        Ok(Some(run)) => (200, usage_body(&run, server.budgets.get(run_id))),
        Ok(None) => (404, error("The router knows no such run.", "not_found")),
        Err(_) => (
            503,
            error("The router could not read its run records.", "router_error"),
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    run_id: String,
    gate: String,
    passed: bool,
}

/// Records a gate outcome and counts it toward the success rate of every
/// model the run used, each weighted by its share of the run's turns.
fn outcome(server: &Server, body: Value) -> (u16, Value) {
    let Ok(outcome) = serde_json::from_value::<Outcome>(body) else {
        return (
            400,
            error(
                "The outcome needs run_id, gate and passed.",
                "invalid_request",
            ),
        );
    };
    if outcome.gate.trim().is_empty() || outcome.gate.len() > 128 {
        return (400, error("The outcome names no gate.", "invalid_request"));
    }
    let store = &server.state.backend.store;
    let now = (server.state.now_ms)();
    let run = match store.run(&outcome.run_id) {
        Ok(Some(run)) => run,
        Ok(None) => return (404, error("The router knows no such run.", "not_found")),
        Err(_) => {
            return (
                503,
                error("The router could not read its run records.", "router_error"),
            )
        }
    };
    let weights = attribution(&run);
    let saved = store
        .record_outcome(&run.run_id, &outcome.gate, outcome.passed, now)
        .and_then(|()| {
            for (model, weight) in &weights {
                for (role, repo) in store::success_scopes(&run.role, &run.repo) {
                    store.observe_success(
                        (model, role, repo),
                        outcome.passed,
                        *weight,
                        now,
                        server.options.success.half_life_ms,
                    )?;
                }
            }
            Ok(())
        });
    if saved.is_err() {
        return (
            503,
            error("The router could not save the outcome.", "router_error"),
        );
    }
    (200, json!({"recorded": true, "models": weights}))
}

/// Each model's share of the turns a run sent.
pub fn attribution(run: &RunRecord) -> BTreeMap<String, f64> {
    let total: u64 = run.usage.models.values().sum();
    if total == 0 {
        return BTreeMap::new();
    }
    run.usage
        .models
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(model, count)| (model.clone(), *count as f64 / total as f64))
        .collect()
}

/// The hooks for one run-token turn: budget, success rates and metrics.
struct RunHooks<'a> {
    server: &'a Server,
    run: &'a RunRecord,
    /// What the attempt in flight holds of the budget.
    held: Mutex<f64>,
    /// Every upstream attempt of the turn, in order.
    attempts: Mutex<Vec<Attempt>>,
}

impl Hooks for RunHooks<'_> {
    fn success_rates(&self) -> BTreeMap<String, f64> {
        let now = (self.server.state.now_ms)();
        self.server
            .state
            .backend
            .store
            .success_stats(&self.run.role, &self.run.repo)
            .map(|stats| {
                store::success_rates(
                    &stats,
                    &self.run.role,
                    &self.run.repo,
                    now,
                    self.server.options.success,
                )
            })
            .unwrap_or_default()
    }

    fn budget(&self) -> Result<Option<f64>, (u16, Value)> {
        let budget = self
            .server
            .budgets
            .get(&self.run.run_id)
            .unwrap_or_default();
        let Some(left) = budget.remaining() else {
            return Ok(None);
        };
        if left > 0.0 {
            return Ok(Some(left));
        }
        self.server.metrics.add(
            "muniment_router_budget_rejections_total",
            &[("role", &self.run.role)],
            1.0,
        );
        Err((402, exhausted(self.run, budget)))
    }

    fn decided(&self, route: &Route, reason: &str) {
        self.server.metrics.add(
            "muniment_router_routing_decisions_total",
            &[
                ("model", &format!("{}/{}", route.family, route.model)),
                ("role", &self.run.role),
                ("reason", reason),
            ],
            1.0,
        );
    }

    fn admit(
        &self,
        _route: &Route,
        _account: &Account,
        estimate_usd: f64,
    ) -> Result<(), (u16, Value)> {
        match self.server.budgets.reserve(&self.run.run_id, estimate_usd) {
            Some(held) => {
                *self.held.lock().unwrap_or_else(|e| e.into_inner()) = held;
                Ok(())
            }
            None => {
                self.server.metrics.add(
                    "muniment_router_budget_rejections_total",
                    &[("role", &self.run.role)],
                    1.0,
                );
                let budget = self
                    .server
                    .budgets
                    .get(&self.run.run_id)
                    .unwrap_or_default();
                Err((402, exhausted(self.run, budget)))
            }
        }
    }

    fn settle(&self, attempt: &Attempt) {
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(attempt.clone());
        let held = std::mem::take(&mut *self.held.lock().unwrap_or_else(|e| e.into_inner()));
        self.server
            .budgets
            .settle(&self.run.run_id, held, attempt.cost_usd);
        let model = format!("{}/{}", attempt.route.family, attempt.route.model);
        let charge = RunCharge {
            cost_usd: attempt.cost_usd,
            tokens: attempt.tokens.unwrap_or_default(),
            model: attempt.served.then(|| model.clone()),
        };
        if charge.cost_usd > 0.0 || charge.model.is_some() {
            if let Err(error) = self
                .server
                .state
                .backend
                .store
                .add_run_usage(&self.run.run_id, &charge)
            {
                eprintln!(
                    "muniment-router: run {} usage not saved: {error}",
                    self.run.run_id
                );
            }
        }
        let metrics = &self.server.metrics;
        let outcome = match (attempt.served, attempt.status) {
            (true, _) => "served".to_owned(),
            (false, Some(status)) => status.to_string(),
            (false, None) => "failed".to_owned(),
        };
        metrics.add(
            "muniment_router_upstream_requests_total",
            &[
                ("model", &model),
                ("account", &attempt.account),
                ("outcome", &outcome),
            ],
            1.0,
        );
        metrics.observe(
            "muniment_router_upstream_duration_seconds",
            &[("model", &model)],
            attempt.elapsed_ms as f64 / 1000.0,
        );
        if let Some(tokens) = attempt.tokens {
            for (kind, count) in [
                ("input", tokens.input),
                ("output", tokens.output),
                ("cache_read", tokens.cache_read),
                ("cache_write", tokens.cache_write),
            ] {
                metrics.add(
                    "muniment_router_tokens_total",
                    &[("model", &model), ("kind", kind)],
                    count as f64,
                );
            }
        }
        if attempt.cost_usd > 0.0 {
            metrics.add(
                "muniment_router_cost_usd_total",
                &[("model", &model)],
                attempt.cost_usd,
            );
        }
        if attempt.status.is_some_and(usage::status_cools) {
            metrics.add(
                "muniment_router_cooldowns_total",
                &[("account", &attempt.account)],
                1.0,
            );
        }
    }
}

fn render_metrics(server: &Server) -> String {
    let now = (server.state.now_ms)();
    let mut gauges: Vec<metrics::Gauge> = Vec::new();
    let ledger = server.state.ledger();
    let config = server.state.backend.store.load_config().unwrap_or_default();
    for account in &config.accounts {
        let until = ledger
            .account(&account.id)
            .and_then(|usage| usage.cooldown_until_ms)
            .filter(|until| *until > now);
        gauges.push((
            "muniment_router_account_cooling",
            vec![("account", account.id.clone())],
            f64::from(u8::from(until.is_some())),
        ));
        gauges.push((
            "muniment_router_account_cooldown_seconds",
            vec![("account", account.id.clone())],
            until
                .map(|until| (until - now) as f64 / 1000.0)
                .unwrap_or(0.0),
        ));
    }
    for (account, count) in server
        .state
        .active
        .lock()
        .map(|a| a.clone())
        .unwrap_or_default()
    {
        gauges.push((
            "muniment_router_account_in_flight",
            vec![("account", account)],
            f64::from(count),
        ));
    }
    for (account, quota) in server.state.backend.store.load_quotas().accounts {
        for window in &quota.windows {
            gauges.push((
                "muniment_router_quota_used_percent",
                vec![
                    ("account", account.clone()),
                    ("window", format!("{:?}", window.kind).to_ascii_lowercase()),
                    ("scope", window.scope.clone()),
                ],
                window.used_percent,
            ));
        }
    }
    let active = server
        .budgets
        .lock()
        .values()
        .filter(|budget| !budget.revoked && budget.expires_ms > now)
        .count();
    gauges.push(("muniment_router_runs_active", Vec::new(), active as f64));
    gauges.push((
        "muniment_router_draining",
        Vec::new(),
        f64::from(u8::from(server.draining.load(Ordering::SeqCst))),
    ));
    server.metrics.render(&gauges)
}

/// Probes every subscription's quota once and saves what each answers. A
/// token inside a minute of expiry is refreshed first.
pub fn probe_quotas(
    backend: &Backend,
    only: Option<&str>,
) -> Vec<(String, Result<quota::Quota, String>)> {
    let Ok(config) = backend.config() else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for account in &config.accounts {
        if only.is_some_and(|id| id != account.id) {
            continue;
        }
        let Some(provider) = account.credential.pi_provider() else {
            continue;
        };
        if !quota::has_reader(provider) {
            continue;
        }
        let now = now_ms();
        let result = native_auth::refresh_account_in(backend, &account.id, now, REFRESH_TIMEOUT)
            .and_then(|account| {
                quota::probe(&account, now, quota::TIMEOUT)
                    .ok_or_else(|| "The provider did not answer.".to_owned())
            })
            .and_then(|quota| {
                backend
                    .store
                    .save_quota(&account.id, &quota)
                    .map(|()| quota)
                    .map_err(|error| error.to_string())
            });
        results.push((account.id.clone(), result));
    }
    results
}

#[cfg(test)]
mod tests;
