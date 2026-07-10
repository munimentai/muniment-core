use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::sidecar::{
    JsonRpcId, JsonRpcTransport, JsonRpcTransportError, RestartPolicy, SidecarConfig, SidecarError,
    SidecarEvent, SidecarEventCause, SidecarStatus, SidecarSupervisor,
};
use serde_json::{json, Value};

fn config(args: &[&str]) -> SidecarConfig {
    let mut cfg = SidecarConfig::new(env!("CARGO_BIN_EXE_sidecar-test-stub"));
    cfg.args = args.iter().map(|s| s.to_string()).collect();
    cfg.restart = RestartPolicy {
        max_restarts: 3,
        window: Duration::from_secs(2),
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(40),
    };
    cfg.health_interval = Duration::from_secs(60);
    cfg.shutdown_timeout = Duration::from_millis(200);
    cfg.poll_interval = Duration::from_millis(5);
    cfg
}

fn temp_marker(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("muniment-sidecar-{name}-{}", std::process::id()))
}

fn wait_for(supervisor: &SidecarSupervisor, wanted: SidecarStatus) {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if supervisor.status() == wanted {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "timed out waiting for {wanted:?}; current status is {:?}",
        supervisor.status()
    );
}

fn next_event(events: &std::sync::mpsc::Receiver<SidecarEvent>) -> SidecarEvent {
    events.recv_timeout(Duration::from_secs(5)).unwrap()
}

#[test]
fn subscribers_receive_the_full_ordered_lifecycle() {
    let mut supervisor = SidecarSupervisor::spawn(config(&["echo"]), |_| Ok(())).unwrap();
    let first = supervisor.subscribe();
    let second = supervisor.subscribe();

    for events in [&first, &second] {
        assert_eq!(next_event(events).status, SidecarStatus::Starting);
        let healthy = next_event(events);
        assert_eq!(healthy.status, SidecarStatus::Healthy);
        assert_eq!(healthy.generation, Some(1));
    }

    drop(first);
    supervisor.shutdown().unwrap();
    assert_eq!(next_event(&second).status, SidecarStatus::Stopped);
    assert!(second.recv_timeout(Duration::from_millis(50)).is_err());
}

#[test]
fn restart_events_include_exit_attempt_and_backoff() {
    let marker = temp_marker("restart-events");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["once", &marker_arg]), |_| Ok(())).unwrap();
    let events = supervisor.subscribe();
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    assert_eq!(next_event(&events).status, SidecarStatus::Healthy);
    let restarting = next_event(&events);
    assert_eq!(restarting.status, SidecarStatus::Restarting);
    assert!(matches!(
        restarting.cause,
        Some(SidecarEventCause::ProcessExit { .. })
    ));
    assert_eq!(restarting.restart_attempt, Some(1));
    assert_eq!(restarting.backoff_delay, Some(Duration::from_millis(10)));
    assert_eq!(next_event(&events).status, SidecarStatus::Healthy);
    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

#[test]
fn failed_event_preserves_the_last_error() {
    let mut cfg = config(&["crash"]);
    cfg.restart.max_restarts = 1;
    let supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(())).unwrap();
    let events = supervisor.subscribe();
    let failed = loop {
        let event = next_event(&events);
        if event.status == SidecarStatus::Failed {
            break event;
        }
    };
    assert!(matches!(
        failed.cause,
        Some(SidecarEventCause::ProcessExit { .. })
    ));
    assert!(events.recv_timeout(Duration::from_millis(50)).is_err());
}

#[test]
fn spawn_and_line_round_trip() {
    let mut supervisor = SidecarSupervisor::spawn(config(&["echo"]), |_| Ok(())).unwrap();
    wait_for(&supervisor, SidecarStatus::Healthy);
    let io = supervisor.io();
    io.stdin.write_line("hello sidecar").unwrap();
    assert_eq!(
        io.stdout
            .read_line_timeout(Duration::from_secs(2))
            .unwrap()
            .as_deref(),
        Some("hello sidecar")
    );
    supervisor.shutdown().unwrap();
    assert_eq!(supervisor.status(), SidecarStatus::Stopped);
}

#[test]
fn stderr_is_bounded_and_reader_starts_at_oldest_retained_line() {
    let mut cfg = config(&["stderr-spam", "100000"]);
    cfg.stderr_capacity = 37;
    let mut supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(())).unwrap();
    assert_eq!(
        supervisor
            .io()
            .stdout
            .read_line_timeout(Duration::from_secs(10))
            .unwrap()
            .as_deref(),
        Some("stderr-done")
    );
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let retained = supervisor.recent_stderr();
        if retained.last().map(String::as_str) == Some("stderr-99999") {
            assert_eq!(retained.len(), 37);
            assert_eq!(retained.first().map(String::as_str), Some("stderr-99963"));
            break;
        }
        assert!(Instant::now() < until, "stderr forwarding did not complete");
        thread::yield_now();
    }
    assert_eq!(supervisor.io().stderr.read_line().unwrap(), "stderr-99963");
    supervisor.shutdown().unwrap();
}

#[test]
fn stderr_ring_is_cleared_when_a_replacement_starts() {
    let marker = temp_marker("stderr-generation");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["stderr-generation", &marker_arg]), |_| Ok(())).unwrap();
    let events = supervisor.subscribe();
    loop {
        let event = next_event(&events);
        if event.status == SidecarStatus::Healthy && event.generation == Some(2) {
            break;
        }
    }
    assert_eq!(
        supervisor
            .io()
            .stderr
            .read_line_timeout(Duration::from_secs(2))
            .unwrap()
            .as_deref(),
        Some("new-generation")
    );
    assert_eq!(supervisor.recent_stderr(), vec!["new-generation"]);
    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

#[test]
fn health_restart_cause_includes_recent_stderr() {
    let mut cfg = config(&["stderr-hang"]);
    cfg.health_interval = Duration::from_millis(20);
    let mut supervisor = SidecarSupervisor::spawn(cfg, |_| Err("unhealthy".into())).unwrap();
    let events = supervisor.subscribe();
    let restarting = loop {
        let event = next_event(&events);
        if event.status == SidecarStatus::Restarting {
            break event;
        }
    };
    assert!(matches!(
        restarting.cause,
        Some(SidecarEventCause::HealthProbeFailure { message, stderr_tail })
            if message == "unhealthy" && stderr_tail == ["health failure detail"]
    ));
    supervisor.shutdown().unwrap();
}

#[test]
fn crash_restarts_after_backoff() {
    let marker = temp_marker("restart");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["once", &marker_arg]), |_| Ok(())).unwrap();
    let io = supervisor.io();
    let started = Instant::now();
    loop {
        if supervisor.status() == SidecarStatus::Healthy
            && io.stdin.write_line("after restart").is_ok()
            && io
                .stdout
                .read_line_timeout(Duration::from_millis(100))
                .unwrap()
                .as_deref()
                == Some("after restart")
        {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    assert!(started.elapsed() >= Duration::from_millis(10));
    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

#[test]
fn restart_cap_exhaustion_becomes_failed() {
    let mut cfg = config(&["crash"]);
    cfg.restart.max_restarts = 2;
    let supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(())).unwrap();
    wait_for(&supervisor, SidecarStatus::Failed);
}

#[test]
fn failed_health_probe_restarts_the_child() {
    let marker = temp_marker("probe");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut cfg = config(&["probe-once", &marker_arg]);
    cfg.health_interval = Duration::from_millis(20);
    let successful_probes = Arc::new(AtomicUsize::new(0));
    let probe_count = successful_probes.clone();
    let mut supervisor = SidecarSupervisor::spawn(cfg, move |io| {
        io.stdin.write_line("ping").map_err(|e| e.to_string())?;
        match io
            .stdout
            .read_line_timeout(Duration::from_millis(100))
            .map_err(|e| e.to_string())?
        {
            Some(line) if line == "pong" => {
                probe_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            _ => Err("probe timed out".into()),
        }
    })
    .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while successful_probes.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < until,
            "healthy replacement was not started"
        );
        thread::sleep(Duration::from_millis(5));
    }
    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

fn spawn_with_json_rpc_probe(
    cfg: SidecarConfig,
) -> (SidecarSupervisor, Arc<OnceLock<Arc<JsonRpcTransport>>>) {
    let transport = Arc::new(OnceLock::new());
    let probe_transport = Arc::clone(&transport);
    let supervisor = SidecarSupervisor::spawn(cfg, move |io| {
        let transport = probe_transport.get_or_init(|| Arc::new(JsonRpcTransport::new(io.clone())));
        transport.health_probe("ping", Duration::from_millis(100))(io)
    })
    .unwrap();
    (supervisor, transport)
}

#[test]
fn json_rpc_probe_keeps_supervisor_healthy_across_intervals() {
    let mut cfg = config(&["json-rpc"]);
    cfg.health_interval = Duration::from_millis(20);
    let (mut supervisor, _) = spawn_with_json_rpc_probe(cfg);
    wait_for(&supervisor, SidecarStatus::Healthy);
    let stderr = supervisor.io().stderr;
    for _ in 0..3 {
        assert_eq!(
            stderr
                .read_line_timeout(Duration::from_secs(1))
                .unwrap()
                .as_deref(),
            Some("ping")
        );
    }
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    supervisor.shutdown().unwrap();
}

#[test]
fn failed_json_rpc_probe_restarts_child_and_recovers() {
    let marker = temp_marker("json-rpc-probe");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut cfg = config(&["json-rpc", &marker_arg]);
    cfg.health_interval = Duration::from_millis(20);
    let (mut supervisor, _) = spawn_with_json_rpc_probe(cfg);
    let stderr = supervisor.io().stderr;
    // The first child answers once, then times out. The replacement answers
    // repeatedly because the marker directory already exists.
    for _ in 0..3 {
        assert_eq!(
            stderr
                .read_line_timeout(Duration::from_secs(2))
                .unwrap()
                .as_deref(),
            Some("ping")
        );
    }
    wait_for(&supervisor, SidecarStatus::Healthy);
    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

#[test]
fn graceful_shutdown_leaves_no_child() {
    let pid_file = temp_marker("pid");
    let _ = std::fs::remove_file(&pid_file);
    let pid_arg = pid_file.to_string_lossy().into_owned();
    let mut supervisor = SidecarSupervisor::spawn(config(&["pid", &pid_arg]), |_| Ok(())).unwrap();
    wait_for(&supervisor, SidecarStatus::Healthy);
    let until = Instant::now() + Duration::from_secs(2);
    while !pid_file.exists() && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    supervisor.shutdown().unwrap();
    assert_eq!(supervisor.status(), SidecarStatus::Stopped);
    #[cfg(target_os = "linux")]
    assert!(
        !PathBuf::from(format!("/proc/{pid}")).exists(),
        "child {pid} was orphaned"
    );
    let _ = std::fs::remove_file(pid_file);
}

#[test]
fn shutdown_forces_and_reaps_an_uncooperative_child() {
    let pid_file = temp_marker("hung-pid");
    let _ = std::fs::remove_file(&pid_file);
    let pid_arg = pid_file.to_string_lossy().into_owned();
    let mut cfg = config(&["hang", &pid_arg]);
    cfg.shutdown_timeout = Duration::from_millis(30);
    let mut supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(())).unwrap();
    wait_for(&supervisor, SidecarStatus::Healthy);
    let until = Instant::now() + Duration::from_secs(2);
    while !pid_file.exists() && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    let pid = std::fs::read_to_string(&pid_file).unwrap();
    supervisor.shutdown().unwrap();
    #[cfg(target_os = "linux")]
    assert!(
        !PathBuf::from(format!("/proc/{pid}")).exists(),
        "uncooperative child {pid} was orphaned"
    );
    let _ = std::fs::remove_file(pid_file);
}

fn rpc_supervisor() -> SidecarSupervisor {
    let supervisor = SidecarSupervisor::spawn(config(&["json-rpc"]), |_| Ok(())).unwrap();
    wait_for(&supervisor, SidecarStatus::Healthy);
    supervisor
}

#[test]
fn json_rpc_params_and_result_round_trip() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    let result: Value = transport
        .call(
            "round_trip",
            Some(json!({"prompt": "hello", "count": 2})),
            Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(result, json!({"prompt": "hello", "count": 2}));
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_probe_serializes_with_in_flight_call() {
    let mut supervisor = rpc_supervisor();
    let io = supervisor.io();
    let transport = Arc::new(JsonRpcTransport::new(io.clone()));
    let call_transport = Arc::clone(&transport);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let call = thread::spawn(move || {
        let result: String = call_transport
            .call_with_notifications(
                "delayed",
                None::<Value>,
                JsonRpcId::String("application".into()),
                Duration::from_secs(1),
                |notification| {
                    assert_eq!(notification.method, "delayed.started");
                    started_tx.send(()).unwrap();
                },
            )
            .unwrap();
        assert_eq!(result, "delayed");
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let probe = transport.health_probe("ping", Duration::from_secs(1));
    let probe_io = io.clone();
    let probe = thread::spawn(move || probe(&probe_io));
    call.join().unwrap();
    probe.join().unwrap().unwrap();
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_delivers_notifications_in_order_before_result() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    let mut values = Vec::new();
    let result: u64 = transport
        .call_with_notifications(
            "count",
            Some(json!({"count": 3})),
            JsonRpcId::String("stream".into()),
            Duration::from_secs(2),
            |notification| {
                assert_eq!(notification.method, "count.progress");
                values.push(notification.params.unwrap()["value"].as_u64().unwrap());
            },
        )
        .unwrap();
    assert_eq!(values, vec![0, 1, 2]);
    assert_eq!(result, 3);
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_plain_call_skips_notifications() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    let result: u64 = transport
        .call("count", Some(json!({"count": 2})), Duration::from_secs(2))
        .unwrap();
    assert_eq!(result, 2);
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_reader_drops_blank_lines_and_normalizes_crlf() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    let result: String = transport
        .call::<Value, String>("normalized", None, Duration::from_secs(2))
        .unwrap();
    assert_eq!(result, "ok");
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_error_response_is_inspectable() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    let error = transport
        .call::<Value, Value>("fail", None, Duration::from_secs(2))
        .unwrap_err();
    match error {
        JsonRpcTransportError::ErrorResponse(error) => {
            assert_eq!(error.code, -32001);
            assert_eq!(error.message, "stub failure");
            assert_eq!(error.data, Some(json!({"retry": false})));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_rejects_malformed_response() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    assert!(matches!(
        transport.call::<Value, Value>("malformed", None, Duration::from_secs(2)),
        Err(JsonRpcTransportError::MalformedJson(_))
    ));
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_rejects_invalid_version_and_envelope_shape() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    for method in ["invalid_version", "invalid_shape"] {
        assert!(matches!(
            transport.call::<Value, Value>(method, None, Duration::from_secs(2)),
            Err(JsonRpcTransportError::InvalidEnvelope(_))
        ));
    }
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_rejects_mismatched_id() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    let error = transport
        .call_with_id::<Value, Value>(
            "mismatch",
            None,
            JsonRpcId::String("wanted".into()),
            Duration::from_secs(2),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        JsonRpcTransportError::MismatchedId {
            expected: JsonRpcId::String(expected),
            received: JsonRpcId::String(received),
        } if expected == "wanted" && received == "wrong"
    ));
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_call_obeys_timeout() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    assert!(matches!(
        transport.call::<Value, Value>("timeout", None, Duration::from_millis(30)),
        Err(JsonRpcTransportError::Timeout)
    ));
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_restart_discards_previous_generation_frames() {
    let marker = temp_marker("json-rpc-stale");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["json-rpc-stale-once", &marker_arg]), |_| Ok(()))
            .unwrap();
    let io = supervisor.io();
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match io.stderr.read_line_timeout(Duration::from_millis(100)) {
            Ok(Some(line)) if line == "replacement-ready" => break,
            Ok(_) | Err(SidecarError::Disconnected) => {}
            Err(error) => panic!("could not read replacement readiness: {error}"),
        }
        assert!(Instant::now() < until, "replacement did not become ready");
    }

    let transport = JsonRpcTransport::new(io);
    let mut notifications = Vec::new();
    let result: u64 = transport
        .call_with_notifications(
            "count",
            Some(json!({"count": 1})),
            JsonRpcId::String("current".into()),
            Duration::from_secs(2),
            |notification| notifications.push(notification.method),
        )
        .unwrap();
    assert_eq!(result, 1);
    assert_eq!(notifications, vec!["count.progress"]);

    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

#[test]
fn json_rpc_call_interrupted_by_restart_returns_bounded_error() {
    let marker = temp_marker("json-rpc-crash-call");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["json-rpc-crash-call-once", &marker_arg]), |_| {
            Ok(())
        })
        .unwrap();
    wait_for(&supervisor, SidecarStatus::Healthy);
    let transport = JsonRpcTransport::new(supervisor.io());
    let started = Instant::now();
    let error = transport
        .call::<Value, Value>("round_trip", None, Duration::from_secs(2))
        .unwrap_err();
    assert!(matches!(
        error,
        JsonRpcTransportError::Timeout | JsonRpcTransportError::Disconnected
    ));
    assert!(started.elapsed() < Duration::from_secs(3));

    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}
