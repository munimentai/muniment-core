use muniment_core::model_router::{classify, headless::*, policy};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Barrier},
};

const FIXTURE: &str =
    include_str!("../../../protocol-fixtures/muniment-routing-shadow/1/reserve.json");

struct State(PathBuf);
impl State {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("muniment-shadow-{}.sqlite", uuid::Uuid::new_v4())))
    }
    fn open(&self) -> Router {
        Router::open(&self.0).unwrap()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn request(index: usize) -> Request {
    let mut value: Value = serde_json::from_str(FIXTURE).unwrap();
    value["job"]["job_id"] = json!(format!("job-{index}"));
    value["job"]["session_id"] = json!(format!("session-{index}"));
    value["job"]["trace_id"] = json!(format!("trace-{index}"));
    serde_json::from_value(value).unwrap()
}
fn parts(request: &mut Request) -> (&mut Job, &mut Snapshot, &mut Option<Observation>) {
    match &mut request.operation {
        Operation::Reserve {
            job,
            snapshot,
            observation,
        } => (job, snapshot, observation),
        _ => panic!("The fixture must reserve a job."),
    }
}
fn release(index: usize, outcome: Outcome) -> Request {
    Request {
        version: VERSION.into(),
        operation: Operation::Release {
            job_id: format!("job-{index}"),
            session_id: format!("session-{index}"),
            trace_id: format!("trace-{index}"),
            outcome,
        },
    }
}
fn inspect(router: &mut Router, request: &Request) -> Response {
    let mut request = request.clone();
    let (job, snapshot, _) = parts(&mut request);
    router
        .handle(Request {
            version: VERSION.into(),
            operation: Operation::Inspect {
                job: job.clone(),
                snapshot: snapshot.clone(),
            },
        })
        .unwrap()
}
fn observe(router: &mut Router, request: &mut Request, answer: Value) {
    let response = inspect(router, request);
    let (job, _, o) = parts(request);
    *o = Some(Observation {
        revision: "kev-4b-test-1".into(),
        trace_id: job.trace_id.clone(),
        eligible_digest: response.eligible_digest,
        request_digest: response.request_digest,
        elapsed_ms: 10,
        status: ObservationStatus::Answer,
        answer: Some(answer),
    });
}

#[test]
fn fixture_uses_shared_policy_without_changing_the_baseline() {
    let state = State::new();
    let response = state.open().handle(request(1)).unwrap();
    assert_eq!(response.version, VERSION);
    assert_eq!(response.policy_version, policy::VERSION);
    assert_eq!(response.mode, "shadow");
    assert_eq!(response.selected.unwrap().account, "a");
    assert_eq!(response.baseline.account, "claude-isolated");
    assert_eq!(response.eligible.len(), 2);
    assert_eq!(response.eligible_digest.len(), 64);
}

#[test]
fn concurrent_process_connections_share_weighted_reservations() {
    let state = State::new();
    drop(state.open());
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let path = state.0.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut router = Router::open(&path).unwrap();
                barrier.wait();
                router
                    .handle(request(index))
                    .unwrap()
                    .selected
                    .unwrap()
                    .account
            })
        })
        .collect();
    let accounts: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(accounts.iter().filter(|a| *a == "a").count(), 6);
    assert_eq!(accounts.iter().filter(|a| *a == "b").count(), 2);
    let db = rusqlite::Connection::open(&state.0).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM jobs WHERE outcome IS NULL", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        8
    );
}

#[test]
fn concurrent_retries_and_restart_keep_one_reservation() {
    let state = State::new();
    drop(state.open());
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let path = state.0.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut router = Router::open(&path).unwrap();
                barrier.wait();
                router.handle(request(1)).unwrap()
            })
        })
        .collect();
    let responses: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(responses.iter().filter(|r| !r.reused).count(), 1);
    assert!(responses
        .iter()
        .all(|r| r.selected.as_ref().unwrap().account == "a"));
    let mut resumed = request(1);
    parts(&mut resumed).0.task_context = "Pi compacted the session.".into();
    assert!(state.open().handle(resumed).unwrap().reused);
    assert_eq!(
        state
            .open()
            .handle(request(2))
            .unwrap()
            .selected
            .unwrap()
            .account,
        "b"
    );
}

#[test]
fn release_is_idempotent_and_completed_sessions_cannot_reserve_again() {
    let state = State::new();
    state.open().handle(request(1)).unwrap();
    let first = state.open().handle(release(1, Outcome::Success)).unwrap();
    assert_eq!(first.outcome, Some(Outcome::Success));
    assert!(!first.reused);
    assert!(
        state
            .open()
            .handle(release(1, Outcome::Success))
            .unwrap()
            .reused
    );
    assert_eq!(
        state
            .open()
            .handle(release(1, Outcome::Failed))
            .unwrap_err(),
        Error::IdentityConflict
    );
    assert_eq!(
        state.open().handle(request(1)).unwrap_err(),
        Error::Completed
    );
    assert_eq!(
        state
            .open()
            .handle(release(2, Outcome::Success))
            .unwrap_err(),
        Error::UnknownJob
    );
    let db = rusqlite::Connection::open(&state.0).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM jobs WHERE outcome IS NULL", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
}

#[test]
fn conflicting_job_session_trace_and_constraints_do_not_reattach() {
    let state = State::new();
    state.open().handle(request(1)).unwrap();
    for field in ["job_id", "session_id", "trace_id", "budget_usd", "baseline"] {
        let mut value = serde_json::to_value(request(1)).unwrap();
        value["job"][field] = match field {
            "budget_usd" => json!(100),
            "baseline" => {
                json!({"account":"other","family":"anthropic","model":"claude-sonnet-4-6"})
            }
            _ => json!("different"),
        };
        assert_eq!(
            state
                .open()
                .handle(serde_json::from_value(value).unwrap())
                .unwrap_err(),
            Error::IdentityConflict,
            "{field}"
        );
    }
    let mut wrong = release(1, Outcome::Success);
    if let Operation::Release { trace_id, .. } = &mut wrong.operation {
        *trace_id = "different".into();
    }
    assert_eq!(
        state.open().handle(wrong).unwrap_err(),
        Error::IdentityConflict
    );
}

#[test]
fn cooling_or_removed_affinity_blocks_instead_of_switching_accounts() {
    for removed in [false, true] {
        let state = State::new();
        state.open().handle(request(1)).unwrap();
        let mut retry = request(1);
        let (_, snapshot, _) = parts(&mut retry);
        snapshot.revision = 2;
        if removed {
            snapshot.accounts.remove(0);
        } else {
            snapshot.accounts[0].cooldown_until_ms = 4102444800000;
        }
        assert_eq!(
            state.open().handle(retry).unwrap_err(),
            Error::AffinityUnavailable
        );
        assert_eq!(
            state.open().handle(request(2)).unwrap_err(),
            Error::StaleSnapshot
        );
    }
}

#[test]
fn refusal_cools_the_account_for_other_jobs_and_duplicate_release_does_not_extend_it() {
    let state = State::new();
    let mut first = request(1);
    parts(&mut first).0.baseline.account = "a".into();
    state.open().handle(first).unwrap();
    state.open().handle(release(1, Outcome::Refused)).unwrap();
    let db = rusqlite::Connection::open(&state.0).unwrap();
    let until: i64 = db
        .query_row("SELECT until_ms FROM refusals WHERE account='a'", [], |r| {
            r.get(0)
        })
        .unwrap();
    state.open().handle(release(1, Outcome::Refused)).unwrap();
    assert_eq!(
        db.query_row("SELECT until_ms FROM refusals WHERE account='a'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        until
    );
    let mut second = request(2);
    parts(&mut second).0.baseline.account = "a".into();
    assert_eq!(
        state
            .open()
            .handle(second)
            .unwrap()
            .selected
            .unwrap()
            .account,
        "b"
    );
    state.open().handle(release(2, Outcome::Success)).unwrap();
    assert!(inspect(&mut state.open(), &request(3))
        .eligible
        .iter()
        .any(|s| s.account == "a"));
}

#[test]
fn baseline_failure_does_not_cool_an_account_that_only_ran_in_shadow() {
    let state = State::new();
    state.open().handle(request(1)).unwrap();
    state.open().handle(release(1, Outcome::Refused)).unwrap();
    let mut router = state.open();
    let evidence = inspect(&mut router, &request(2));
    assert!(evidence.eligible.iter().any(|s| s.account == "a"));
    let db = rusqlite::Connection::open(&state.0).unwrap();
    assert_eq!(
        db.query_row("SELECT account FROM refusals", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "claude-isolated"
    );
}

#[test]
fn model_caps_survive_release_and_reset_requires_a_new_epoch() {
    let state = State::new();
    let mut first = request(1);
    let (_, snapshot, _) = parts(&mut first);
    snapshot.accounts.truncate(1);
    snapshot.accounts[0]
        .models
        .values_mut()
        .next()
        .unwrap()
        .limit = 1;
    state.open().handle(first.clone()).unwrap();
    assert!(state.open().handle(first.clone()).unwrap().reused);
    state.open().handle(release(1, Outcome::Cancelled)).unwrap();
    let mut next = first.clone();
    let (job, _, _) = parts(&mut next);
    job.job_id = "next".into();
    job.session_id = "next".into();
    assert_eq!(
        state.open().handle(next.clone()).unwrap_err(),
        Error::NoEligibleChoice
    );
    let (_, snapshot, _) = parts(&mut next);
    snapshot.revision = 2;
    snapshot.accounts[0]
        .models
        .values_mut()
        .next()
        .unwrap()
        .limit = 2;
    assert_eq!(
        state.open().handle(next.clone()).unwrap_err(),
        Error::StaleSnapshot
    );
    parts(&mut next).1.accounts[0]
        .models
        .values_mut()
        .next()
        .unwrap()
        .epoch = 2;
    state.open().handle(next).unwrap();
    assert_eq!(
        state.open().handle(first).unwrap_err(),
        Error::StaleSnapshot
    );
}

#[test]
fn capabilities_budget_and_account_constraints_filter_before_classification() {
    for constraint in [
        "budget",
        "context",
        "output",
        "tools",
        "images",
        "capability",
        "disabled",
        "weight",
        "cap",
        "expired",
        "cooldown",
        "empty",
    ] {
        let state = State::new();
        let mut request = request(1);
        let (job, snapshot, _) = parts(&mut request);
        match constraint {
            "budget" => job.budget_usd = 0.017,
            "context" => snapshot.models[0].context = 8192,
            "output" => job.output_tokens = 8193,
            "tools" => snapshot.models[0].tools = false,
            "images" => {
                snapshot.models[0].images = false;
                job.images = true;
            }
            "capability" => job.minimum_capability = 3,
            "disabled" => snapshot.accounts.iter_mut().for_each(|a| a.enabled = false),
            "weight" => snapshot.accounts.iter_mut().for_each(|a| a.weight = 0),
            "cap" => snapshot
                .accounts
                .iter_mut()
                .for_each(|a| a.models.values_mut().for_each(|c| c.limit = 0)),
            "expired" => snapshot
                .accounts
                .iter_mut()
                .for_each(|a| a.models.values_mut().for_each(|c| c.resets_at_ms = 1)),
            "cooldown" => snapshot
                .accounts
                .iter_mut()
                .for_each(|a| a.cooldown_until_ms = 4102444800000),
            "empty" => snapshot.accounts.clear(),
            _ => unreachable!(),
        }
        if constraint == "context" {
            job.input_tokens = 8192;
        }
        assert_eq!(
            state.open().handle(request).unwrap_err(),
            Error::NoEligibleChoice,
            "{constraint}"
        );
    }
    let state = State::new();
    let mut boundary = request(1);
    parts(&mut boundary).0.budget_usd = 0.018;
    state.open().handle(boundary).unwrap();
}

#[test]
fn classifier_failure_and_invalid_authority_use_shared_fallback() {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../protocol-fixtures/muniment-routing-shadow/1/observations.json"
    ))
    .unwrap();
    for case in cases {
        let state = State::new();
        let mut router = state.open();
        let mut request = request(1);
        observe(&mut router, &mut request, case["answer"].clone());
        let o = parts(&mut request).2.as_mut().unwrap();
        o.status = serde_json::from_value(case["status"].clone()).unwrap();
        o.elapsed_ms = case["elapsed_ms"].as_u64().unwrap();
        let response = router.handle(request).unwrap();
        assert_eq!(
            serde_json::to_value(response.fallback).unwrap(),
            case["fallback"]
        );
        assert_eq!(response.baseline.account, "claude-isolated");
        assert_eq!(response.selected.unwrap().account, "a");
        assert_eq!(
            response.classifier_revision.as_deref(),
            Some("kev-4b-test-1")
        );
    }
}

#[test]
fn multiple_models_use_the_desktop_capability_floor_and_cost_policy() {
    for classified in [false, true] {
        let state = State::new();
        let mut router = state.open();
        let mut request = request(1);
        let (_, snapshot, _) = parts(&mut request);
        let mut cheap = snapshot.models[0].clone();
        cheap.model = "small".into();
        cheap.capability = 1;
        cheap.input_price = 0.0;
        cheap.output_price = 0.0;
        snapshot.models.push(cheap);
        for account in &mut snapshot.accounts {
            let cap = account.models.values().next().unwrap().clone();
            account.models.insert("small".into(), cap);
        }
        if classified {
            observe(
                &mut router,
                &mut request,
                json!({"answers":{"route":{"choice":"anthropic/claude-sonnet-4-6","confidence":0.9}}}),
            );
        }
        let response = router.handle(request).unwrap();
        assert_eq!(
            response.selected.unwrap().model,
            if classified {
                "claude-sonnet-4-6"
            } else {
                "small"
            }
        );
        assert_eq!(response.baseline.model, "claude-sonnet-4-6");
    }
}

#[test]
fn classifier_cannot_use_a_stale_set_context_or_trace() {
    for field in ["digest", "context", "trace"] {
        let state = State::new();
        let mut router = state.open();
        let mut request = request(1);
        observe(&mut router, &mut request, json!({}));
        let (job, _, o) = parts(&mut request);
        match field {
            "digest" => o.as_mut().unwrap().eligible_digest = "0".repeat(64),
            "context" => job.task_context = "A different task.".into(),
            _ => o.as_mut().unwrap().trace_id = "other".into(),
        }
        assert_eq!(
            serde_json::to_value(router.handle(request).unwrap().fallback).unwrap(),
            "stale_observation"
        );
    }
}

#[test]
fn invalid_metadata_and_versions_fail_closed() {
    for case in [
        "price",
        "budget",
        "overflow",
        "zero",
        "duplicate",
        "missing_model",
        "revision",
        "context",
        "identity",
        "version",
    ] {
        let state = State::new();
        let mut request = request(1);
        let (job, snapshot, _) = parts(&mut request);
        match case {
            "price" => snapshot.models[0].input_price = f64::NAN,
            "budget" => job.budget_usd = f64::INFINITY,
            "overflow" => job.input_tokens = u64::MAX,
            "zero" => job.output_tokens = 0,
            "duplicate" => snapshot.accounts.push(snapshot.accounts[0].clone()),
            "missing_model" => snapshot.models.clear(),
            "revision" => snapshot.revision = u64::MAX,
            "context" => job.task_context = "a".repeat(classify::STATE_LIMIT + 1),
            "identity" => job.job_id = " ".into(),
            "version" => request.version = "future".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            state.open().handle(request).unwrap_err(),
            if case == "version" {
                Error::UnsupportedVersion
            } else {
                Error::InvalidRequest
            },
            "{case}"
        );
    }
}

#[test]
fn snapshot_order_is_canonical_and_conflicting_revisions_fail() {
    let state = State::new();
    let mut router = state.open();
    let mut request = request(1);
    let first = inspect(&mut router, &request);
    let mut other = request.clone();
    parts(&mut other).0.task_context = "Another classifier context.".into();
    let other = inspect(&mut router, &other);
    assert_eq!(first.eligible_digest, other.eligible_digest);
    assert_ne!(first.request_digest, other.request_digest);
    parts(&mut request).1.accounts.reverse();
    assert_eq!(
        first.eligible_digest,
        inspect(&mut router, &request).eligible_digest
    );
    parts(&mut request).1.accounts[0].weight += 1;
    assert_eq!(router.handle(request).unwrap_err(), Error::StaleSnapshot);
}

fn cli(state: &State, input: &[u8]) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_muniment-router-shadow"))
        .arg("--state")
        .arg(&state.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn executable_contract_survives_process_restart_and_never_echoes_context() {
    let state = State::new();
    let first = cli(&state, FIXTURE.as_bytes());
    assert_eq!(first["selected"]["account"], "a");
    assert!(!first.to_string().contains("parser boundary"));
    let retry = cli(&state, FIXTURE.as_bytes());
    assert_eq!(retry["selected"], first["selected"]);
    assert_eq!(retry["reused"], true);
    assert_eq!(cli(&state, b"not json")["error"], "invalid_request");
    assert_eq!(
        cli(&state, &vec![b' '; MAX_REQUEST_BYTES + 1])["error"],
        "invalid_request"
    );
    let mut secret: Value = serde_json::from_str(FIXTURE).unwrap();
    secret["snapshot"]["accounts"][0]["token"] = json!("secret-must-not-appear");
    let result = cli(&state, &serde_json::to_vec(&secret).unwrap());
    assert_eq!(result["error"], "invalid_request");
    assert!(!result.to_string().contains("secret-must-not-appear"));
}

#[test]
fn failed_persistence_rolls_back_the_reservation_and_snapshot() {
    let state = State::new();
    let mut router = state.open();
    let db = rusqlite::Connection::open(&state.0).unwrap();
    db.execute_batch("CREATE TRIGGER fail_reservation BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT, 'Storage failed.'); END;").unwrap();
    assert_eq!(router.handle(request(1)).unwrap_err(), Error::Storage);
    for table in ["jobs", "caps", "snapshot"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
    db.execute_batch("DROP TRIGGER fail_reservation").unwrap();
    assert!(!router.handle(request(1)).unwrap().reused);
    assert!(router.handle(request(1)).unwrap().reused);
}

#[test]
fn damaged_or_newer_storage_never_resets_affinity() {
    let state = State::new();
    std::fs::write(&state.0, b"broken database").unwrap();
    assert!(matches!(Router::open(&state.0), Err(Error::Storage)));
    std::fs::remove_file(&state.0).unwrap();
    let db = rusqlite::Connection::open(&state.0).unwrap();
    db.execute_batch("PRAGMA user_version=2").unwrap();
    assert!(matches!(
        Router::open(&state.0),
        Err(Error::UnsupportedVersion)
    ));
}
