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
//! the next account of the pool takes the turn, up to [`ATTEMPTS`] times.

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
use super::native_auth;
use super::usage::{self, Ledger};
use super::{balance, plan, served_models, wire, ResolveError};

/// Where the router writes the port and token Pi needs.
pub const ENDPOINT_FILE: &str = "muniment-router-endpoint.json";
/// How many accounts one turn may try before it gives up.
pub const ATTEMPTS: usize = 3;
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

impl InFlight {
    fn start(active: &Active, account: &str) -> Self {
        if let Ok(mut held) = active.lock() {
            *held.entry(account.to_owned()).or_insert(0) += 1;
        }
        Self {
            active: Arc::clone(active),
            account: account.to_owned(),
        }
    }
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

impl State {
    /// The configuration as it stands right now. It is read per turn, so a
    /// change in Settings takes the next turn with no restart.
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
        ledger: Mutex::new(usage::load(&agent)),
        agent,
        active: Arc::clone(&active),
        now_ms: clock,
    });
    let stop = Arc::new(AtomicBool::new(false));
    let accept_stop = Arc::clone(&stop);
    let accept_token = endpoint.token.clone();
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
            complete(&mut stream, state, &request);
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

/// One chat turn: plan it once, send it, and fail over to the next account
/// when the upstream refuses the account rather than the request.
fn complete(stream: &mut TcpStream, state: &State, request: &Value) {
    let mut config = state.config();
    let requested = wire::requested_model(request).unwrap_or(config::AUTO_MODEL);
    let text = wire::classifier_state(request);
    // The turn classifies once. A failover picks another account against the
    // same plan, so one turn never spends the classifier twice.
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
    let mut refusals: Vec<String> = Vec::new();
    for _ in 0..ATTEMPTS {
        let picked = balance::pick(
            &config,
            &state.ledger(),
            &plan.family,
            &plan.model,
            (state.now_ms)(),
        );
        let account = match picked {
            Ok(account) => account,
            Err(error) => {
                let message = if refusals.is_empty() {
                    error.message()
                } else {
                    format!("{} {}", error.message(), refusals.join(" "))
                };
                respond(
                    stream,
                    503,
                    "Router",
                    &wire::error_body(&message, "router_error"),
                );
                return;
            }
        };
        // A token inside a minute of dying is traded for a fresh one first, and
        // the pool keeps the fresh one, so this turn and the ones behind it go
        // out on a live token. A refused refresh is the account refused.
        let account = match native_auth::refresh_if_expiring(
            &account.credential,
            (state.now_ms)(),
            REFRESH_TIMEOUT,
        ) {
            None => account.clone(),
            Some(Ok(credential)) => {
                let mut fresh = account.clone();
                fresh.credential = credential;
                let mut saved = config.clone();
                if let Some(entry) = saved.accounts.iter_mut().find(|entry| entry.id == fresh.id) {
                    entry.credential = fresh.credential.clone();
                }
                let _ = config::save(&state.agent, &saved);
                config = saved;
                fresh
            }
            Some(Err(message)) => {
                state.record_error(&account.id, &message, true);
                refusals.push(message);
                continue;
            }
        };
        let Some(upstream) = account.upstream() else {
            state.record_error(&account.id, "The account names no provider.", false);
            respond(
                stream,
                503,
                "Router",
                &wire::error_body("The picked account names no provider.", "router_error"),
            );
            return;
        };
        let url = format!("{upstream}/chat/completions");
        let body = wire::upstream_request(request, &plan.model);
        let _in_flight = InFlight::start(&state.active, &account.id);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(READ_TIMEOUT)
            .build();
        let call = agent
            .post(&url)
            .set("content-type", "application/json")
            .set(
                "authorization",
                &format!("Bearer {}", account.credential.bearer()),
            )
            .send_json(&body);
        match call {
            Ok(response) => {
                let response_id = wire::classified_response_id(
                    &plan.family,
                    &plan.model,
                    plan.classifier.as_ref(),
                );
                if wire::streams(request) {
                    relay_stream(
                        stream,
                        state,
                        &account.id,
                        response,
                        wire::wants_usage(request),
                        &response_id,
                    );
                } else {
                    relay_once(stream, state, &account.id, response, &response_id);
                }
                return;
            }
            Err(ureq::Error::Status(status, response)) => {
                let detail = response
                    .into_string()
                    .unwrap_or_else(|_| format!("The provider answered {status}."));
                let cools = usage::status_cools(status);
                state.record_error(&account.id, &detail, cools);
                if !cools {
                    // The request is wrong, not the account. Another account
                    // would refuse it the same way.
                    respond(
                        stream,
                        status,
                        "Provider",
                        &wire::error_body(&detail, "provider_error"),
                    );
                    return;
                }
                refusals.push(format!("{} answered {status}.", account.label));
            }
            Err(ureq::Error::Transport(error)) => {
                state.record_error(&account.id, &error.to_string(), true);
                refusals.push(format!("{} did not answer.", account.label));
            }
        }
    }
    respond(
        stream,
        503,
        "Router",
        &wire::error_body(
            &format!("No account served this turn. {}", refusals.join(" ")),
            "router_error",
        ),
    );
}

/// One whole answer: forward the body and count what it says it spent.
fn relay_once(
    stream: &mut TcpStream,
    state: &State,
    account: &str,
    response: ureq::Response,
    response_id: &str,
) {
    let Ok(mut value) = response.into_json::<Value>() else {
        state.record_error(
            account,
            "The provider answered with something that is not JSON.",
            false,
        );
        respond(
            stream,
            502,
            "Router",
            &wire::error_body(
                "The provider answered with something that is not JSON.",
                "provider_error",
            ),
        );
        return;
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("id".into(), Value::String(response_id.into()));
    }
    state.record_success(account, wire::tokens(&value).unwrap_or_default());
    respond(stream, 200, "OK", &value);
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
) {
    let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\nconnection: close\r\n\r\n";
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    let _ = stream.flush();
    let mut reader = BufReader::new(response.into_reader());
    let mut tokens = wire::Tokens::default();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        if let Some(payload) = line.trim_end().strip_prefix("data: ") {
            if payload != "[DONE]" {
                if let Ok(mut chunk) = serde_json::from_str::<Value>(payload) {
                    if let Some(counted) = wire::tokens(&chunk) {
                        tokens = counted;
                    }
                    if !keep_usage && wire::usage_only_chunk(&chunk) {
                        // The router asked for this frame. The client did not.
                        continue;
                    }
                    if let Some(object) = chunk.as_object_mut() {
                        object.insert("id".into(), Value::String(response_id.into()));
                    }
                    line = format!("data: {chunk}\n");
                }
            }
        }
        if stream.write_all(line.as_bytes()).is_err() {
            break;
        }
        let _ = stream.flush();
    }
    state.record_success(account, tokens);
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
