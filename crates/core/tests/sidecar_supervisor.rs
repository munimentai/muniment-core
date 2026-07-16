use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use muniment_core::sidecar::{
    JsonRpcCancellationToken, JsonRpcId, JsonRpcTransport, JsonRpcTransportError, PiRpcWiring,
    ProbeOutcome, RestartPolicy, SidecarConfig, SidecarError, SidecarEvent, SidecarEventCause,
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
    cfg.startup_timeout = Duration::from_secs(2);
    cfg.shutdown_timeout = Duration::from_millis(200);
    cfg.poll_interval = Duration::from_millis(5);
    cfg
}

fn temp_marker(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("muniment-sidecar-{name}-{}", std::process::id()))
}

struct FileMarker(PathBuf);

impl FileMarker {
    fn new(name: &str) -> Self {
        let path = temp_marker(name);
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for FileMarker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct ProbeRelease(Option<std::sync::mpsc::Sender<()>>);

impl Drop for ProbeRelease {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    start_time: String,
}

#[cfg(target_os = "linux")]
impl ProcessIdentity {
    fn read(pid: u32) -> std::io::Result<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let fields = stat
            .rsplit_once(") ")
            .map(|(_, fields)| fields)
            .ok_or_else(|| std::io::Error::other("invalid /proc stat"))?;
        let start_time = fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| std::io::Error::other("missing process start time"))?;
        Ok(Self {
            pid,
            start_time: start_time.to_owned(),
        })
    }

    fn still_exists(&self) -> bool {
        Self::read(self.pid).is_ok_and(|current| current == *self)
    }
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
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["echo"]), |_| Ok(ProbeOutcome::Ready)).unwrap();
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
        SidecarSupervisor::spawn(config(&["once", &marker_arg]), |_| Ok(ProbeOutcome::Ready))
            .unwrap();
    let events = supervisor.subscribe();
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    let restarting = loop {
        let event = next_event(&events);
        if event.status == SidecarStatus::Restarting {
            break event;
        }
        assert_eq!(event.status, SidecarStatus::Healthy);
        assert_eq!(event.generation, Some(1));
    };
    assert_eq!(restarting.status, SidecarStatus::Restarting);
    assert!(matches!(
        restarting.cause,
        Some(SidecarEventCause::ProcessExit { .. })
    ));
    assert_eq!(restarting.restart_attempt, Some(1));
    assert_eq!(restarting.backoff_delay, Some(Duration::from_millis(10)));
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    assert_eq!(next_event(&events).status, SidecarStatus::Healthy);
    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
}

#[test]
fn failed_event_preserves_the_last_error() {
    let mut cfg = config(&["crash"]);
    cfg.restart.max_restarts = 1;
    let supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(ProbeOutcome::Ready)).unwrap();
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
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["echo"]), |_| Ok(ProbeOutcome::Ready)).unwrap();
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
    let mut supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(ProbeOutcome::Ready)).unwrap();
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
        SidecarSupervisor::spawn(config(&["stderr-generation", &marker_arg]), |_| {
            Ok(ProbeOutcome::Ready)
        })
        .unwrap();
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
fn loading_generation_becomes_healthy_once_when_ready() {
    let mut cfg = config(&["echo"]);
    cfg.health_interval = Duration::from_millis(10);
    let probes = Arc::new(AtomicUsize::new(0));
    let probe_count = Arc::clone(&probes);
    let mut supervisor = SidecarSupervisor::spawn(cfg, move |_| {
        if probe_count.fetch_add(1, Ordering::SeqCst) < 2 {
            Ok(ProbeOutcome::Loading)
        } else {
            Ok(ProbeOutcome::Ready)
        }
    })
    .unwrap();
    let events = supervisor.subscribe();
    let starting = next_event(&events);
    assert_eq!(starting.status, SidecarStatus::Starting);
    assert_eq!(starting.generation, Some(1));
    let healthy = next_event(&events);
    assert_eq!(healthy.status, SidecarStatus::Healthy);
    assert_eq!(healthy.generation, starting.generation);
    assert!(events.recv_timeout(Duration::from_millis(25)).is_err());
    supervisor.shutdown().unwrap();
}

#[test]
fn loading_timeout_exhausts_restart_budget_with_stderr_diagnostics() {
    let mut cfg = config(&["stderr-hang"]);
    cfg.startup_timeout = Duration::from_millis(25);
    cfg.restart.max_restarts = 1;
    let supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(ProbeOutcome::Loading)).unwrap();
    let events = supervisor.subscribe();
    let mut saw_restart = false;
    let failed = loop {
        let event = next_event(&events);
        saw_restart |= event.status == SidecarStatus::Restarting;
        if event.status == SidecarStatus::Failed {
            break event;
        }
    };
    assert!(saw_restart);
    assert!(matches!(failed.cause,
        Some(SidecarEventCause::StartupTimeout { timeout, stderr_tail })
            if timeout == Duration::from_millis(25) && stderr_tail == ["health failure detail"]));
}

#[test]
fn blocked_probe_cannot_delay_startup_timeout_or_become_healthy() {
    let mut cfg = config(&["echo"]);
    cfg.startup_timeout = Duration::from_millis(10);
    cfg.restart.max_restarts = 0;
    let (release_probe, blocked_probe) = std::sync::mpsc::channel();
    let blocked_probe = Arc::new(std::sync::Mutex::new(blocked_probe));
    let probe_started = Arc::new(AtomicUsize::new(0));
    let started = Arc::clone(&probe_started);
    let supervisor = SidecarSupervisor::spawn(cfg, move |_| {
        started.store(1, Ordering::SeqCst);
        blocked_probe.lock().unwrap().recv().unwrap();
        Ok(ProbeOutcome::Ready)
    })
    .unwrap();
    let events = supervisor.subscribe();
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    let deadline = Instant::now() + Duration::from_secs(1);
    while probe_started.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "probe did not start");
        thread::yield_now();
    }
    let timeout_started = Instant::now();
    let failed = next_event(&events);
    assert!(timeout_started.elapsed() < Duration::from_millis(200));
    assert_eq!(failed.status, SidecarStatus::Failed);
    assert!(matches!(
        failed.cause,
        Some(SidecarEventCause::StartupTimeout { timeout, .. })
            if timeout == Duration::from_millis(10)
    ));
    assert!(events.recv_timeout(Duration::from_millis(25)).is_err());
    release_probe.send(()).unwrap();
}

#[test]
fn restarted_generation_probes_independently_of_stale_blocked_probe() {
    let mut cfg = config(&["echo"]);
    cfg.startup_timeout = Duration::from_millis(100);
    cfg.health_interval = Duration::from_millis(5);
    cfg.restart.max_restarts = 1;
    let (release_first, blocked_first) = std::sync::mpsc::channel();
    let blocked_first = Arc::new(std::sync::Mutex::new(blocked_first));
    let (release_second, blocked_second) = std::sync::mpsc::channel();
    let blocked_second = Arc::new(std::sync::Mutex::new(blocked_second));
    let probe_count = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&probe_count);
    let supervisor = SidecarSupervisor::spawn(cfg, move |_| {
        match count.fetch_add(1, Ordering::SeqCst) {
            0 => blocked_first.lock().unwrap().recv().unwrap(),
            1 => blocked_second.lock().unwrap().recv().unwrap(),
            call => panic!("overlapping probe call {call} for replacement generation"),
        }
        Ok(ProbeOutcome::Ready)
    })
    .unwrap();
    let events = supervisor.subscribe();
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    let restarting = next_event(&events);
    assert_eq!(restarting.status, SidecarStatus::Restarting);
    assert!(matches!(
        restarting.cause,
        Some(SidecarEventCause::StartupTimeout { .. })
    ));
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);

    let until = Instant::now() + Duration::from_secs(1);
    while probe_count.load(Ordering::SeqCst) < 2 {
        assert!(Instant::now() < until, "replacement probe did not start");
        thread::yield_now();
    }
    release_first.send(()).unwrap();
    thread::sleep(Duration::from_millis(20));
    assert_eq!(probe_count.load(Ordering::SeqCst), 2);
    release_second.send(()).unwrap();

    let healthy = next_event(&events);
    assert_eq!(healthy.status, SidecarStatus::Healthy);
    assert_eq!(healthy.generation, Some(2));
}

#[test]
fn hard_startup_probe_failure_uses_health_failure_path() {
    let mut cfg = config(&["stderr-hang"]);
    cfg.restart.max_restarts = 0;
    let supervisor = SidecarSupervisor::spawn(cfg, |_| Err("startup probe failed".into())).unwrap();
    let events = supervisor.subscribe();
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    let failed = next_event(&events);
    assert_eq!(failed.status, SidecarStatus::Failed);
    assert!(matches!(failed.cause,
        Some(SidecarEventCause::HealthProbeFailure { message, .. })
            if message == "startup probe failed"));
}

#[test]
fn shutdown_during_loading_is_prompt_and_reaps_child() {
    let pid_file = FileMarker::new("loading-pid");
    let pid_arg = pid_file.0.to_string_lossy().into_owned();
    let mut cfg = config(&["pid", &pid_arg]);
    cfg.startup_timeout = Duration::from_secs(30);
    let (release_probe, blocked_probe) = std::sync::mpsc::channel();
    let _release_probe = ProbeRelease(Some(release_probe));
    let blocked_probe = Arc::new(std::sync::Mutex::new(blocked_probe));
    let probe_started = Arc::new(AtomicUsize::new(0));
    let started_probe = Arc::clone(&probe_started);
    let mut supervisor = SidecarSupervisor::spawn(cfg, move |_| {
        started_probe.store(1, Ordering::SeqCst);
        blocked_probe.lock().unwrap().recv().unwrap();
        Ok(ProbeOutcome::Loading)
    })
    .unwrap();
    let events = supervisor.subscribe();
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    let until = Instant::now() + Duration::from_secs(2);
    let pid = loop {
        if let Ok(pid) = std::fs::read_to_string(&pid_file.0)
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .parse::<u32>()
        {
            break pid;
        }
        assert!(Instant::now() < until, "stub did not write its pid");
        thread::yield_now();
    };
    while probe_started.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < until, "probe did not start");
        thread::yield_now();
    }
    #[cfg(target_os = "linux")]
    let child_identity = ProcessIdentity::read(pid).unwrap();
    let started = Instant::now();
    supervisor.shutdown().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(next_event(&events).status, SidecarStatus::Stopped);
    #[cfg(target_os = "linux")]
    assert!(
        !child_identity.still_exists(),
        "exact child {child_identity:?} still exists after shutdown returned"
    );
}

#[test]
fn crash_restarts_after_backoff() {
    let marker = temp_marker("restart");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["once", &marker_arg]), |_| Ok(ProbeOutcome::Ready))
            .unwrap();
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
    let supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(ProbeOutcome::Ready)).unwrap();
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
                Ok(ProbeOutcome::Ready)
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
fn pi_probe_routes_interleaved_frames_before_its_response() {
    let mut cfg = config(&["pi-rpc-interleaved"]);
    cfg.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(cfg, wiring.readiness_probe(Duration::from_millis(100))).unwrap();

    wait_for(&supervisor, SidecarStatus::Healthy);
    let transport = wiring.transport().expect("probe initialized dispatcher");
    let routed = transport.subscribe();

    // Run a second probe after subscribing so both unrelated frames are
    // deterministically observable and the correlated response remains last.
    transport.health_probe(Duration::from_millis(100))(&supervisor.io()).unwrap();
    assert_eq!(
        routed.recv_timeout(Duration::from_secs(1)).unwrap(),
        json!({"type": "agent_start", "requestId": "unrelated"})
    );
    assert_eq!(
        routed.recv_timeout(Duration::from_secs(1)).unwrap(),
        json!({
            "type": "response",
            "command": "get_state",
            "success": true,
            "id": "another-call"
        })
    );
    assert!(routed.recv_timeout(Duration::from_millis(20)).is_err());
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    supervisor.shutdown().unwrap();
}

#[test]
fn pi_dispatcher_delivers_event_after_response_without_another_call() {
    let mut cfg = config(&["pi-rpc-interleaved"]);
    cfg.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(cfg, wiring.readiness_probe(Duration::from_millis(100))).unwrap();
    wait_for(&supervisor, SidecarStatus::Healthy);
    let transport = wiring.transport().expect("probe initialized dispatcher");
    let routed = transport.subscribe();

    let response = transport
        .call(json!({"type": "prompt"}), Duration::from_millis(100))
        .unwrap();
    assert_eq!(response["command"], "prompt");
    assert_eq!(
        routed.recv_timeout(Duration::from_secs(1)).unwrap(),
        json!({"type": "agent_start", "requestId": "unrelated"})
    );
    assert_eq!(
        routed.recv_timeout(Duration::from_secs(1)).unwrap()["id"],
        "another-call"
    );
    assert_eq!(
        routed.recv_timeout(Duration::from_secs(1)).unwrap(),
        json!({"type": "message_update", "requestId": "after-response"})
    );
    supervisor.shutdown().unwrap();
}

#[test]
fn pi_wiring_replaces_dispatcher_after_child_restart() {
    let marker = temp_marker("pi-rpc-restart");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut cfg = config(&["pi-rpc-restart-once", &marker_arg]);
    cfg.health_interval = Duration::from_secs(60);
    let wiring = PiRpcWiring::new();
    let mut supervisor =
        SidecarSupervisor::spawn(cfg, wiring.readiness_probe(Duration::from_millis(100))).unwrap();

    wait_for(&supervisor, SidecarStatus::Healthy);
    let stale = wiring.transport().expect("first dispatcher installed");
    assert!(stale
        .call(json!({"type": "prompt"}), Duration::from_secs(1))
        .is_err());

    let events = supervisor.subscribe();
    loop {
        let event = events.recv_timeout(Duration::from_secs(2)).unwrap();
        if event.status == SidecarStatus::Healthy && event.generation == Some(2) {
            break;
        }
    }

    let transport = wiring
        .transport()
        .expect("replacement dispatcher installed");
    assert!(stale
        .call(json!({"type": "get_state"}), Duration::from_millis(100))
        .unwrap_err()
        .contains("replaced child generation"));
    let routed = transport.subscribe();
    let response = transport
        .call(json!({"type": "prompt"}), Duration::from_millis(100))
        .unwrap();
    assert_eq!(response["command"], "prompt");
    assert_eq!(
        routed.recv_timeout(Duration::from_secs(1)).unwrap(),
        json!({"type": "agent_start", "requestId": "unrelated"})
    );

    supervisor.shutdown().unwrap();
    let _ = std::fs::remove_dir(marker);
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
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["pid", &pid_arg]), |_| Ok(ProbeOutcome::Ready)).unwrap();
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
    let mut supervisor = SidecarSupervisor::spawn(cfg, |_| Ok(ProbeOutcome::Ready)).unwrap();
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
    let supervisor =
        SidecarSupervisor::spawn(config(&["json-rpc"]), |_| Ok(ProbeOutcome::Ready)).unwrap();
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
fn json_rpc_probe_skips_in_flight_call_without_stealing_frames() {
    let mut cfg = config(&["json-rpc"]);
    cfg.health_interval = Duration::from_millis(20);
    let (mut supervisor, transport) = spawn_with_json_rpc_probe(cfg);
    let events = supervisor.subscribe();
    wait_for(&supervisor, SidecarStatus::Healthy);
    assert_eq!(
        supervisor
            .io()
            .stderr
            .read_line_timeout(Duration::from_secs(1))
            .unwrap()
            .as_deref(),
        Some("ping")
    );
    assert_eq!(next_event(&events).status, SidecarStatus::Starting);
    assert_eq!(next_event(&events).status, SidecarStatus::Healthy);
    let transport = Arc::clone(transport.get().unwrap());
    let call_transport = Arc::clone(&transport);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let call = thread::spawn(move || {
        let result: String = call_transport
            .call_with_notifications(
                "delayed",
                Some(json!({"delay_ms": 250})),
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
    call.join().unwrap();
    assert_eq!(supervisor.status(), SidecarStatus::Healthy);
    assert!(
        events.try_recv().is_err(),
        "sidecar restarted during the call"
    );
    supervisor.shutdown().unwrap();
}

#[test]
fn shutdown_is_not_stalled_by_in_flight_json_rpc_call() {
    let mut cfg = config(&["json-rpc"]);
    cfg.health_interval = Duration::from_millis(20);
    cfg.shutdown_timeout = Duration::from_millis(50);
    let (mut supervisor, transport) = spawn_with_json_rpc_probe(cfg);
    wait_for(&supervisor, SidecarStatus::Healthy);
    assert_eq!(
        supervisor
            .io()
            .stderr
            .read_line_timeout(Duration::from_secs(1))
            .unwrap()
            .as_deref(),
        Some("ping")
    );
    let transport = Arc::clone(transport.get().unwrap());
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let call = thread::spawn(move || {
        transport.call_with_notifications::<_, String, _>(
            "delayed",
            Some(json!({"delay_ms": 500})),
            JsonRpcId::String("application".into()),
            Duration::from_secs(1),
            |_| {
                started_tx.send(()).unwrap();
            },
        )
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let started = Instant::now();
    supervisor.shutdown().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "shutdown waited for the application call"
    );
    assert!(call.join().unwrap().is_err());
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
fn json_rpc_discards_late_response_after_timeout() {
    let mut supervisor = rpc_supervisor();
    let transport = JsonRpcTransport::new(supervisor.io());
    assert!(matches!(
        transport.call::<Value, Value>("late_success", None, Duration::from_millis(20)),
        Err(JsonRpcTransportError::Timeout)
    ));
    thread::sleep(Duration::from_millis(120));
    let result: Value = transport
        .call(
            "round_trip",
            Some(json!({"after": "timeout"})),
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(result, json!({"after": "timeout"}));
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_cancellation_notifies_and_discards_late_error() {
    let mut supervisor = rpc_supervisor();
    let io = supervisor.io();
    let transport =
        Arc::new(JsonRpcTransport::new(io.clone()).with_cancel_method("muniment/cancelGeneration"));
    let cancellation = JsonRpcCancellationToken::new();
    let call_transport = Arc::clone(&transport);
    let call_cancellation = cancellation.clone();
    let call = thread::spawn(move || {
        call_transport.call_with_id_and_cancellation::<Value, Value>(
            "late_error",
            None,
            JsonRpcId::String("cancel-me".into()),
            Duration::from_secs(1),
            &call_cancellation,
        )
    });
    thread::sleep(Duration::from_millis(20));
    cancellation.cancel();
    assert!(matches!(
        call.join().unwrap(),
        Err(JsonRpcTransportError::Cancelled)
    ));
    let cancel: Value = serde_json::from_str(
        &io.stderr
            .read_line_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(cancel["method"], "muniment/cancelGeneration");
    assert_eq!(cancel["params"]["id"], "cancel-me");
    thread::sleep(Duration::from_millis(120));
    let result: Value = transport
        .call::<Value, Value>("round_trip", None, Duration::from_secs(1))
        .unwrap();
    assert_eq!(result, Value::Null);
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_cancel_response_race_does_not_corrupt_follow_up() {
    let mut supervisor = rpc_supervisor();
    let transport = Arc::new(JsonRpcTransport::new(supervisor.io()).with_cancel_method("cancel"));
    let cancellation = JsonRpcCancellationToken::new();
    let call_transport = Arc::clone(&transport);
    let call_cancellation = cancellation.clone();
    let call = thread::spawn(move || {
        call_transport.call_with_cancellation::<Value, String>(
            "cancel_race",
            None,
            Duration::from_secs(1),
            &call_cancellation,
        )
    });
    cancellation.cancel();
    match call.join().unwrap() {
        Ok(result) => assert_eq!(result, "raced"),
        Err(JsonRpcTransportError::Cancelled) => {}
        Err(other) => panic!("unexpected race outcome: {other:?}"),
    }
    let result: Value = transport
        .call(
            "round_trip",
            Some(json!({"after": "race"})),
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(result, json!({"after": "race"}));
    supervisor.shutdown().unwrap();
}

#[test]
fn json_rpc_restart_discards_previous_generation_frames() {
    let marker = temp_marker("json-rpc-stale");
    let _ = std::fs::remove_dir(&marker);
    let marker_arg = marker.to_string_lossy().into_owned();
    let mut supervisor =
        SidecarSupervisor::spawn(config(&["json-rpc-stale-once", &marker_arg]), |_| {
            Ok(ProbeOutcome::Ready)
        })
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
            Ok(ProbeOutcome::Ready)
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
