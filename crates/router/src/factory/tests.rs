use super::*;
use crate::config::{Credential, RouterConfig};
use crate::store::{FileSecrets, FileStore, RouterStore, SecretSource};
use std::io::{BufRead, Read};
use std::sync::mpsc;

const ADMIN: &str = "admin-token-for-tests";

/// One answer of the stand-in provider.
enum Answer {
    /// A whole JSON body with this status.
    Json(u16, String),
    /// An event stream sent piece by piece, each after its delay.
    Stream(Vec<(u64, String)>),
}

/// A stand-in OpenAI-compatible provider. Each connection takes the next
/// answer, and the request body it read goes to the receiver.
fn upstream(answers: Vec<Answer>) -> (String, mpsc::Receiver<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, seen) = mpsc::channel();
    std::thread::spawn(move || {
        for answer in answers {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_ascii_lowercase();
                if line.is_empty() {
                    break;
                }
                if let Some(value) = line.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            let _ = sender.send(serde_json::from_slice(&body).unwrap_or(Value::Null));
            match answer {
                Answer::Json(status, payload) => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                }
                Answer::Stream(pieces) => {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n"
                    );
                    for (delay, piece) in pieces {
                        std::thread::sleep(Duration::from_millis(delay));
                        if stream.write_all(piece.as_bytes()).is_err() {
                            break;
                        }
                        let _ = stream.flush();
                    }
                }
            }
        }
    });
    (format!("http://127.0.0.1:{port}/v1"), seen)
}

fn completion(text: &str, input: u64, output: u64) -> Answer {
    Answer::Json(
        200,
        json!({
            "id": "c1",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": input, "completion_tokens": output}
        })
        .to_string(),
    )
}

fn account(id: &str, url: &str, models: &[&str]) -> Account {
    Account {
        id: id.into(),
        family: "openai".into(),
        label: id.into(),
        credential: Credential::ApiKey {
            key: format!("sk-{id}"),
        },
        base_url: Some(url.into()),
        models: models.iter().map(|m| m.to_string()).collect(),
        enabled: true,
        weight: 1,
    }
}

struct Fixture {
    dir: PathBuf,
    handle: Handle,
}

use std::path::PathBuf;

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn options(min_samples: f64) -> Options {
    Options {
        admin_token: ADMIN.into(),
        signing_key: SigningKey::parse(&"5a".repeat(32)).unwrap(),
        success: SuccessWindow {
            half_life_ms: 86_400_000,
            min_samples,
        },
        metrics: true,
    }
}

/// A server on a file store holding `accounts`.
fn fixture(accounts: Vec<Account>, min_samples: f64) -> Fixture {
    let dir = std::env::temp_dir().join(format!("muniment-factory-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    crate::config::save(
        &dir,
        &RouterConfig {
            enabled: true,
            accounts,
            ..RouterConfig::default()
        },
    )
    .unwrap();
    let handle = start("127.0.0.1:0", Backend::files(&dir), options(min_samples)).unwrap();
    Fixture { dir, handle }
}

/// One request, answered whole: the status and the body.
fn call(
    address: SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&Value>,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut stream = TcpStream::connect(address).unwrap();
    let payload = body.map(Value::to_string).unwrap_or_default();
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nhost: router\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n{payload}",
        payload.len()
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let status = answer
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (
        status,
        answer
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default(),
    )
}

fn create_run(address: SocketAddr, run_id: &str, role: &str, budget: f64) -> String {
    let (status, body) = call(
        address,
        "POST",
        "/v1/runs",
        ADMIN,
        Some(
            &json!({"run_id": run_id, "task_id": "task-1", "repo": "factory/app", "role": role, "budget_usd": budget, "expires_in_s": 3600}),
        ),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    serde_json::from_str::<Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn turn(model: &str, stream: bool) -> Value {
    json!({"model": model, "stream": stream, "messages": [{"role": "user", "content": "Fix the failing test"}]})
}

fn run_usage(address: SocketAddr, run_id: &str) -> Value {
    let (status, body) = call(
        address,
        "GET",
        &format!("/v1/runs/{run_id}"),
        ADMIN,
        None,
        &[],
    );
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[test]
fn run_tokens_are_issued_bound_and_revoked() {
    let fixture = fixture(
        vec![account("a1", "http://127.0.0.1:9/v1", &["gpt-5.6-luna"])],
        5.0,
    );
    let address = fixture.handle.address();
    let new_run = json!({"run_id": "r1", "task_id": "t1", "repo": "factory/app", "role": "planner", "budget_usd": 1.0, "expires_in_s": 600});
    assert_eq!(
        call(address, "POST", "/v1/runs", "wrong", Some(&new_run), &[]).0,
        401
    );
    let (status, body) = call(address, "POST", "/v1/runs", ADMIN, Some(&new_run), &[]);
    assert_eq!(status, 200, "{body}");
    let token = serde_json::from_str::<Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, models) = call(address, "GET", "/v1/models", &token, None, &[]);
    assert_eq!(status, 200);
    assert!(models.contains("\"auto\""));
    assert_eq!(
        call(address, "GET", "/v1/models", "mrt1.forged.token", None, &[]).0,
        401
    );
    // An admin token does not route turns.
    assert_eq!(
        call(
            address,
            "POST",
            "/v1/chat/completions",
            ADMIN,
            Some(&turn("auto", false)),
            &[]
        )
        .0,
        401
    );
    // A retried create gets a token for the same run; a different run under
    // the same id is refused.
    let (status, again) = call(address, "POST", "/v1/runs", ADMIN, Some(&new_run), &[]);
    assert_eq!(status, 200);
    assert_ne!(again, body);
    let mut other = new_run.clone();
    other["budget_usd"] = json!(5.0);
    assert_eq!(
        call(address, "POST", "/v1/runs", ADMIN, Some(&other), &[]).0,
        409
    );
    let mut bad = new_run.clone();
    bad["expires_in_s"] = json!(0);
    assert_eq!(
        call(address, "POST", "/v1/runs", ADMIN, Some(&bad), &[]).0,
        400
    );
    // A token signed with another key is refused.
    let foreign = SigningKey::parse(&"7b".repeat(32)).unwrap().sign(&Claims {
        run_id: "r1".into(),
        task_id: "t1".into(),
        repo: "factory/app".into(),
        role: "planner".into(),
        budget_usd: 1.0,
        expires_ms: i64::MAX,
        nonce: token::nonce(),
    });
    assert_eq!(
        call(address, "GET", "/v1/models", &foreign, None, &[]).0,
        401
    );
    // Revoking ends every token of the run and answers its final usage.
    let (status, closed) = call(address, "DELETE", "/v1/runs/r1", ADMIN, None, &[]);
    assert_eq!(status, 200);
    let closed: Value = serde_json::from_str(&closed).unwrap();
    assert_eq!(closed["revoked"], true);
    assert_eq!(closed["spent_usd"], 0.0);
    assert_eq!(call(address, "GET", "/v1/models", &token, None, &[]).0, 401);
    assert_eq!(
        call(address, "POST", "/v1/runs", ADMIN, Some(&new_run), &[]).0,
        409
    );
    assert_eq!(
        call(address, "GET", "/v1/runs/nope", ADMIN, None, &[]).0,
        404
    );
    // A run token stops serving at its expiry.
    let short = json!({"run_id": "r2", "task_id": "t1", "repo": "factory/app", "role": "planner", "budget_usd": 1.0, "expires_in_s": 1});
    let (_, body) = call(address, "POST", "/v1/runs", ADMIN, Some(&short), &[]);
    let token = serde_json::from_str::<Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(call(address, "GET", "/v1/models", &token, None, &[]).0, 200);
    std::thread::sleep(Duration::from_millis(1_100));
    let (status, body) = call(address, "GET", "/v1/models", &token, None, &[]);
    assert_eq!(status, 401);
    assert!(body.contains("expired"));
}

#[test]
fn a_budget_is_reserved_settled_and_then_refused_with_402() {
    // gpt-5.6-luna costs $0.20 per million in and $1.20 out, so each answer
    // below costs $0.20 + $0.12.
    let (url, seen) = upstream(vec![
        completion("one", 1_000_000, 100_000),
        completion("two", 1_000_000, 100_000),
    ]);
    let fixture = fixture(vec![account("a1", &url, &["gpt-5.6-luna"])], 5.0);
    let address = fixture.handle.address();
    let token = create_run(address, "r1", "implementer", 0.5);
    let (status, body) = call(
        address,
        "POST",
        "/v1/chat/completions",
        &token,
        Some(&turn("auto", false)),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    let usage = run_usage(address, "r1");
    assert!((usage["spent_usd"].as_f64().unwrap() - 0.32).abs() < 1e-9);
    assert_eq!(usage["requests"], 1);
    assert_eq!(usage["input_tokens"], 1_000_000);
    assert_eq!(usage["models"]["openai/gpt-5.6-luna"], 1);
    assert_eq!(usage["reserved_usd"], 0.0);
    // The second turn starts under budget and ends over it.
    let (status, _) = call(
        address,
        "POST",
        "/v1/chat/completions",
        &token,
        Some(&turn("auto", false)),
        &[],
    );
    assert_eq!(status, 200);
    let (status, body) = call(
        address,
        "POST",
        "/v1/chat/completions",
        &token,
        Some(&turn("auto", false)),
        &[],
    );
    assert_eq!(status, 402, "{body}");
    let refusal: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(refusal["error"]["type"], "budget_exhausted");
    assert!((refusal["error"]["spent_usd"].as_f64().unwrap() - 0.64).abs() < 1e-9);
    assert_eq!(seen.try_iter().count(), 2);
    let (_, metrics) = call(address, "GET", "/metrics", "", None, &[]);
    assert!(metrics.contains("muniment_router_budget_rejections_total{role=\"implementer\"} 1"));
}

#[test]
fn a_reservation_holds_at_most_what_remains() {
    let budgets = Budgets::default();
    budgets.seed(&RunRecord {
        run_id: "r".into(),
        task_id: "t".into(),
        repo: "p".into(),
        role: "planner".into(),
        budget_usd: 1.0,
        created_ms: 0,
        expires_ms: i64::MAX,
        revoked_ms: None,
        usage: store::RunUsage {
            spent_usd: 0.25,
            ..store::RunUsage::default()
        },
    });
    assert_eq!(budgets.reserve("r", 0.5), Some(0.5));
    // Two turns in flight: the second holds only what the first left.
    assert_eq!(budgets.reserve("r", 0.5), Some(0.25));
    assert_eq!(budgets.reserve("r", 0.1), None);
    budgets.settle("r", 0.5, 0.1);
    assert_eq!(budgets.reserve("r", 0.1), Some(0.1));
    budgets.settle("r", 0.25, 0.25);
    budgets.settle("r", 0.1, 0.0);
    let budget = budgets.get("r").unwrap();
    assert!((budget.spent - 0.6).abs() < 1e-9);
    assert_eq!(budget.reserved, 0.0);
    assert_eq!(budgets.reserve("unknown", 1.0), None);
}

#[test]
fn outcomes_feed_measured_success_into_the_next_task() {
    let (url, seen) = upstream(vec![
        completion("first", 10, 2),
        completion("second", 10, 2),
    ]);
    let fixture = fixture(
        vec![account("a1", &url, &["gpt-5.6-luna", "gpt-5.6-sol"])],
        2.0,
    );
    let address = fixture.handle.address();
    let token = create_run(address, "r1", "implementer", 5.0);
    assert_eq!(
        call(
            address,
            "POST",
            "/v1/chat/completions",
            &token,
            Some(&turn("auto", false)),
            &[]
        )
        .0,
        200
    );
    // With nothing measured the cheapest capable model takes the task.
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).unwrap()["model"],
        "gpt-5.6-luna"
    );
    for gate in ["build", "unit_tests", "lint"] {
        let (status, body) = call(
            address,
            "POST",
            "/v1/outcomes",
            ADMIN,
            Some(&json!({"run_id": "r1", "gate": gate, "passed": false})),
            &[],
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["models"]["openai/gpt-5.6-luna"],
            1.0
        );
    }
    assert_eq!(
        call(
            address,
            "POST",
            "/v1/outcomes",
            "wrong",
            Some(&json!({"run_id": "r1", "gate": "x", "passed": true})),
            &[]
        )
        .0,
        401
    );
    assert_eq!(
        call(
            address,
            "POST",
            "/v1/outcomes",
            ADMIN,
            Some(&json!({"run_id": "nope", "gate": "x", "passed": true})),
            &[]
        )
        .0,
        404
    );
    let stats = fixture
        .handle
        .server
        .state
        .backend
        .store
        .success_stats("implementer", "factory/app")
        .unwrap();
    let global = stats[&(
        "openai/gpt-5.6-luna".to_owned(),
        "*".to_owned(),
        "*".to_owned(),
    )];
    assert!((global.trials - 3.0).abs() < 1e-3);
    assert_eq!(global.successes, 0.0);
    // The next task of the same role and repository finds luna under the
    // success floor and takes the next capable model.
    let next = create_run(address, "r2", "implementer", 5.0);
    let (status, body) = call(
        address,
        "POST",
        "/v1/chat/completions",
        &next,
        Some(&turn("auto", false)),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).unwrap()["model"],
        "gpt-5.6-sol"
    );
}

#[test]
fn task_and_validation_failure_headers_reach_policy() {
    let (url, seen) = upstream(vec![
        completion("first", 10, 2),
        completion("second", 10, 2),
        completion("third", 10, 2),
    ]);
    let fixture = fixture(
        vec![account("a1", &url, &["gpt-5.6-luna", "gpt-5.6-sol"])],
        5.0,
    );
    let address = fixture.handle.address();
    let token = create_run(address, "r1", "implementer", 5.0);
    let send = |headers: &[(&str, &str)]| {
        let (status, body) = call(
            address,
            "POST",
            "/v1/chat/completions",
            &token,
            Some(&turn("auto", false)),
            headers,
        );
        assert_eq!(status, 200, "{body}");
        seen.recv_timeout(Duration::from_secs(5)).unwrap()["model"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        send(&[
            ("x-muniment-task", "task-1"),
            ("x-muniment-validation-failures", "0")
        ]),
        "gpt-5.6-luna"
    );
    // Repeated validation failures escalate past the current capability.
    assert_eq!(
        send(&[
            ("x-muniment-task", "task-1"),
            ("x-muniment-validation-failures", "2")
        ]),
        "gpt-5.6-sol"
    );
    // A new task is a boundary: the cost path picks the cheapest again.
    assert_eq!(
        send(&[
            ("x-muniment-task", "task-2"),
            ("x-muniment-validation-failures", "0")
        ]),
        "gpt-5.6-luna"
    );
}

#[test]
fn metrics_expose_requests_tokens_cost_decisions_and_accounts() {
    let (url, _) = upstream(vec![completion("one", 1_000, 100)]);
    let fixture = fixture(
        vec![
            account("a1", &url, &["gpt-5.6-luna"]),
            account("a2", &url, &["gpt-5.6-luna"]),
        ],
        5.0,
    );
    let address = fixture.handle.address();
    let token = create_run(address, "r1", "reviewer", 1.0);
    assert_eq!(
        call(
            address,
            "POST",
            "/v1/chat/completions",
            &token,
            Some(&turn("auto", false)),
            &[]
        )
        .0,
        200
    );
    let (status, text) = call(address, "GET", "/metrics", "", None, &[]);
    assert_eq!(status, 200);
    for expected in [
        "muniment_router_http_requests_total{route=\"chat_completions\",status=\"200\"} 1",
        "muniment_router_http_requests_total{route=\"create_run\",status=\"200\"} 1",
        "muniment_router_upstream_requests_total{model=\"openai/gpt-5.6-luna\",account=\"a1\",outcome=\"served\"} 1",
        "muniment_router_tokens_total{model=\"openai/gpt-5.6-luna\",kind=\"input\"} 1000",
        "muniment_router_tokens_total{model=\"openai/gpt-5.6-luna\",kind=\"output\"} 100",
        "muniment_router_cost_usd_total{model=\"openai/gpt-5.6-luna\"}",
        "muniment_router_upstream_duration_seconds_count{model=\"openai/gpt-5.6-luna\"} 1",
        "role=\"reviewer\"",
        "# TYPE muniment_router_routing_decisions_total counter",
        "muniment_router_account_cooling{account=\"a2\"} 0",
        "muniment_router_runs_active 1",
        "muniment_router_draining 0",
    ] {
        assert!(text.contains(expected), "{expected} missing from:\n{text}");
    }
    let (status, health) = call(address, "GET", "/healthz", "", None, &[]);
    assert_eq!(status, 200);
    assert!(health.contains("true"));
}

#[test]
fn draining_refuses_new_connections_and_finishes_open_streams() {
    let chunk = |text: &str| {
        format!(
            "data: {}\n\n",
            json!({"choices": [{"delta": {"content": text}}]})
        )
    };
    let (url, seen) = upstream(vec![Answer::Stream(vec![
        (0, chunk("be")),
        (600, chunk("cause")),
        (0, "data: [DONE]\n\n".into()),
    ])]);
    let mut fixture = fixture(vec![account("a1", &url, &["gpt-5.6-luna"])], 5.0);
    let address = fixture.handle.address();
    let token = create_run(address, "r1", "implementer", 1.0);
    let client = std::thread::spawn(move || {
        call(
            address,
            "POST",
            "/v1/chat/completions",
            &token,
            Some(&turn("auto", true)),
            &[],
        )
    });
    seen.recv_timeout(Duration::from_secs(5)).unwrap();
    let started = Instant::now();
    assert!(fixture.handle.drain(Duration::from_secs(10)));
    // The open stream finished before the drain did.
    assert!(started.elapsed() >= Duration::from_millis(400));
    let (status, body) = client.join().unwrap();
    assert_eq!(status, 200);
    assert!(body.contains("cause") && body.contains("[DONE]"));
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn a_drain_gives_up_at_its_deadline() {
    let (url, seen) = upstream(vec![Answer::Stream(vec![
        (
            0,
            format!(
                "data: {}\n\n",
                json!({"choices": [{"delta": {"content": "slow"}}]})
            ),
        ),
        (3_000, "data: [DONE]\n\n".into()),
    ])]);
    let mut fixture = fixture(vec![account("a1", &url, &["gpt-5.6-luna"])], 5.0);
    let address = fixture.handle.address();
    let token = create_run(address, "r1", "implementer", 1.0);
    let _client = std::thread::spawn(move || {
        call(
            address,
            "POST",
            "/v1/chat/completions",
            &token,
            Some(&turn("auto", true)),
            &[],
        )
    });
    seen.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!fixture.handle.drain(Duration::from_millis(200)));
    assert_eq!(fixture.handle.connections(), 1);
}

/// The whole factory path on Postgres and OpenBao: an account added through
/// the account commands, a run, a routed turn and its usage.
#[test]
fn end_to_end_on_postgres_and_openbao() {
    let Some(scratch) = postgres::tests::scratch() else {
        return;
    };
    let mock = openbao::tests::mock(3600);
    let secrets = Arc::new(openbao::OpenBao::new(openbao::tests::settings(
        &mock.address,
        openbao::Auth::Token("static".into()),
        Duration::from_secs(60),
    )));
    let store = Arc::new(postgres::PgStore::connect(&scratch.url).unwrap());
    let backend = Backend::new(store.clone(), secrets);
    let (url, seen) = upstream(vec![completion("done", 1_000, 10)]);
    let id = accounts::add_key(
        &backend,
        "openai",
        "sk-live",
        None,
        Some(url),
        vec!["gpt-5.6-luna".into()],
        1,
    )
    .unwrap();
    assert_eq!(
        mock.secrets.lock().unwrap()[&format!("router/accounts/{id}")].0["key"],
        "sk-live"
    );
    let handle = start("127.0.0.1:0", backend, options(5.0)).unwrap();
    let address = handle.address();
    let token = create_run(address, "r1", "implementer", 1.0);
    let (status, body) = call(
        address,
        "POST",
        "/v1/chat/completions",
        &token,
        Some(&turn("auto", false)),
        &[],
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("done"));
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).unwrap()["model"],
        "gpt-5.6-luna"
    );
    let usage = run_usage(address, "r1");
    assert_eq!(usage["requests"], 1);
    assert_eq!(usage["input_tokens"], 1_000);
    assert_eq!(store.load_ledger().account(&id).unwrap().requests, 1);
    assert_eq!(store.load_sessions().entries.len(), 1);
    assert_eq!(
        call(
            address,
            "POST",
            "/v1/outcomes",
            ADMIN,
            Some(&json!({"run_id": "r1", "gate": "build", "passed": true})),
            &[]
        )
        .0,
        200
    );
    assert_eq!(
        store
            .success_stats("implementer", "factory/app")
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn a_server_without_secrets_serves_no_account() {
    let dir = std::env::temp_dir().join(format!("muniment-factory-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = FileStore::new(&dir);
    store
        .upsert_account(&account("a1", "http://127.0.0.1:9/v1", &["gpt-5.6-luna"]))
        .unwrap();
    let backend = Backend::new(Arc::new(store), Arc::new(NoSecrets));
    assert!(backend.config().unwrap().accounts.is_empty());
    assert!(NoSecrets
        .write("a1", &Credential::ApiKey { key: "k".into() })
        .is_err());
    let files = Backend::new(
        Arc::new(FileStore::new(&dir)),
        Arc::new(FileSecrets::new(&dir)),
    );
    assert_eq!(files.config().unwrap().accounts.len(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}
