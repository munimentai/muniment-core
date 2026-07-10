use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::sidecar::{
    JsonRpcId, JsonRpcTransport, JsonRpcTransportError, RestartPolicy, SidecarConfig,
    SidecarStatus, SidecarSupervisor,
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
        {
            if io
                .stdout
                .read_line_timeout(Duration::from_millis(100))
                .unwrap()
                .as_deref()
                == Some("after restart")
            {
                break;
            }
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
