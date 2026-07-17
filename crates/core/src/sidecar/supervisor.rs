use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, BufWriter};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::io::{LineReaderInner, LineReceiver};
use super::io::{StderrRing, StderrState, WriterState};
use super::{LineReader, LineWriter, SidecarError, SidecarIo};

const DEFAULT_STDERR_CAPACITY: usize = 256;
const STDERR_DIAGNOSTIC_LINES: usize = 20;

type HealthProbe = dyn Fn(&SidecarIo) -> Result<ProbeOutcome, String> + Send + Sync + 'static;

struct ProbeResult {
    generation: u64,
    completed_at: Instant,
    outcome: Result<ProbeOutcome, String>,
}

/// A successful probe result, distinguishing startup progress from readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ready,
    Loading,
}

#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// Number of restarts allowed during `window` (the initial start is free).
    pub max_restarts: usize,
    pub window: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 5,
            window: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub program: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub restart: RestartPolicy,
    pub health_interval: Duration,
    /// Maximum time a spawned generation may report `Loading` before restart.
    pub startup_timeout: Duration,
    pub shutdown_timeout: Duration,
    /// Maximum number of recent stderr lines retained for reading and diagnostics.
    pub stderr_capacity: usize,
    /// Frequency of exit and shutdown checks. Kept configurable for bounded tests.
    pub poll_interval: Duration,
}

impl SidecarConfig {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: HashMap::new(),
            restart: RestartPolicy::default(),
            health_interval: Duration::from_secs(5),
            startup_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(2),
            stderr_capacity: DEFAULT_STDERR_CAPACITY,
            poll_interval: Duration::from_millis(20),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarStatus {
    Starting,
    Healthy,
    Restarting,
    Stopped,
    Failed,
}

/// Why a sidecar lifecycle transition occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarEventCause {
    ProcessExit {
        code: Option<i32>,
        signal: Option<i32>,
        stderr_tail: Vec<String>,
    },
    ProcessWaitError {
        message: String,
        stderr_tail: Vec<String>,
    },
    SpawnError(String),
    HealthProbeFailure {
        message: String,
        stderr_tail: Vec<String>,
    },
    StartupTimeout {
        timeout: Duration,
        stderr_tail: Vec<String>,
    },
    Shutdown,
}

/// An ordered sidecar status transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarEvent {
    pub status: SidecarStatus,
    pub cause: Option<SidecarEventCause>,
    pub restart_attempt: Option<usize>,
    pub backoff_delay: Option<Duration>,
    pub generation: Option<u64>,
}

pub struct SidecarSupervisor {
    state: Arc<Mutex<SupervisorState>>,
    io: SidecarIo,
    command: mpsc::Sender<SupervisorCommand>,
    worker: Option<JoinHandle<()>>,
}

struct SupervisorState {
    status: SidecarStatus,
    events: Vec<SidecarEvent>,
    subscribers: Vec<mpsc::Sender<SidecarEvent>>,
    closed: bool,
}

enum SupervisorCommand {
    Shutdown(mpsc::Sender<()>),
}

impl SidecarSupervisor {
    pub fn spawn(
        config: SidecarConfig,
        health_probe: impl Fn(&SidecarIo) -> Result<ProbeOutcome, String> + Send + Sync + 'static,
    ) -> Result<Self, SidecarError> {
        if config.program.is_empty() {
            return Err(SidecarError::Spawn(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "program is empty",
            )));
        }
        let (stdout_tx, stdout_rx) = mpsc::channel();
        let stderr = Arc::new(StderrRing {
            state: Mutex::new(StderrState {
                lines: VecDeque::new(),
                first_sequence: 0,
                next_sequence: 0,
                read_sequence: 0,
                generation: 0,
            }),
            available: Condvar::new(),
            capacity: config.stderr_capacity,
        });
        let generation = Arc::new(AtomicU64::new(0));
        let stdin = LineWriter(Arc::new(Mutex::new(WriterState {
            generation: 0,
            writer: None,
        })));
        let io = SidecarIo {
            stdin: stdin.clone(),
            stdout: LineReader(LineReaderInner::Channel(Arc::new(Mutex::new(
                LineReceiver {
                    receiver: stdout_rx,
                    pending: VecDeque::new(),
                    generation: generation.clone(),
                },
            )))),
            stderr: LineReader(LineReaderInner::Stderr(stderr.clone())),
        };
        let state = Arc::new(Mutex::new(SupervisorState {
            status: SidecarStatus::Starting,
            events: Vec::new(),
            subscribers: Vec::new(),
            closed: false,
        }));
        let (command, commands) = mpsc::channel();
        let worker_state = state.clone();
        let worker_io = io.clone();
        let probe: Arc<HealthProbe> = Arc::new(health_probe);
        let worker = thread::spawn(move || {
            supervise(
                config,
                worker_state,
                worker_io,
                stdout_tx,
                stderr,
                generation,
                commands,
                probe,
            )
        });
        Ok(Self {
            state,
            io,
            command,
            worker: Some(worker),
        })
    }

    pub fn status(&self) -> SidecarStatus {
        self.state.lock().unwrap().status
    }

    /// Subscribes to lifecycle transitions, replaying transitions already emitted.
    pub fn subscribe(&self) -> mpsc::Receiver<SidecarEvent> {
        let (sender, receiver) = mpsc::channel();
        let mut state = self.state.lock().unwrap();
        for event in &state.events {
            let _ = sender.send(event.clone());
        }
        if !state.closed {
            state.subscribers.push(sender);
        }
        receiver
    }

    pub fn io(&self) -> SidecarIo {
        self.io.clone()
    }

    /// Returns the retained stderr lines for the active child, oldest first.
    pub fn recent_stderr(&self) -> Vec<String> {
        let LineReaderInner::Stderr(ring) = &self.io.stderr.0 else {
            unreachable!()
        };
        ring.snapshot()
    }

    pub fn shutdown(&mut self) -> Result<(), SidecarError> {
        let Some(worker) = self.worker.take() else {
            return Err(SidecarError::AlreadyStopped);
        };
        let (done_tx, done_rx) = mpsc::channel();
        self.command
            .send(SupervisorCommand::Shutdown(done_tx))
            .map_err(|_| SidecarError::AlreadyStopped)?;
        let _ = done_rx.recv();
        let _ = worker.join();
        Ok(())
    }
}

impl Drop for SidecarSupervisor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// These independent handles make the supervisor's shared state and I/O dependencies explicit.
#[allow(clippy::too_many_arguments)]
fn supervise(
    config: SidecarConfig,
    state: Arc<Mutex<SupervisorState>>,
    io: SidecarIo,
    stdout_tx: mpsc::Sender<(u64, String)>,
    stderr: Arc<StderrRing>,
    generation: Arc<AtomicU64>,
    commands: mpsc::Receiver<SupervisorCommand>,
    probe: Arc<HealthProbe>,
) {
    let (probe_results_tx, probe_results) = mpsc::channel::<ProbeResult>();
    let mut probe_in_flight_generation = None;
    let mut restarts = VecDeque::new();
    let mut consecutive_failures = 0u32;
    let mut restart_cause = None;
    let mut restart_attempt = None;
    loop {
        if consecutive_failures > 0 {
            let shift = consecutive_failures.saturating_sub(1).min(31);
            let delay = config
                .restart
                .initial_backoff
                .saturating_mul(1u32 << shift)
                .min(config.restart.max_backoff);
            emit_event(
                &state,
                SidecarEvent {
                    status: SidecarStatus::Restarting,
                    cause: restart_cause.clone(),
                    restart_attempt,
                    backoff_delay: Some(delay),
                    generation: None,
                },
            );
            if wait_or_shutdown(delay, &commands, &io, None, &config, &state) {
                return;
            }
        }
        let child_generation = generation.fetch_add(1, Ordering::AcqRel) + 1;
        let (mut child, stderr_reader) = match spawn_child(
            &config,
            &io,
            stdout_tx.clone(),
            stderr.clone(),
            child_generation,
        ) {
            Ok(child) => child,
            Err(error) => {
                let cause = SidecarEventCause::SpawnError(error.to_string());
                if let Some(attempt) = allow_restart(&config.restart, &mut restarts) {
                    restart_attempt = Some(attempt);
                    restart_cause = Some(cause);
                } else {
                    emit_terminal(&state, SidecarStatus::Failed, Some(cause));
                    return;
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
                continue;
            }
        };
        emit_event(
            &state,
            SidecarEvent {
                status: SidecarStatus::Starting,
                cause: None,
                restart_attempt: None,
                backoff_delay: None,
                generation: Some(child_generation),
            },
        );
        let startup_deadline = Instant::now() + config.startup_timeout;
        let mut ready = false;
        let mut next_probe = Instant::now();
        let cause = loop {
            let wait = if ready {
                config.poll_interval
            } else {
                config
                    .poll_interval
                    .min(startup_deadline.saturating_duration_since(Instant::now()))
            };
            match commands.recv_timeout(wait) {
                Ok(SupervisorCommand::Shutdown(done)) => {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    emit_terminal(
                        &state,
                        SidecarStatus::Stopped,
                        Some(SidecarEventCause::Shutdown),
                    );
                    let _ = done.send(());
                    return;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    emit_terminal(
                        &state,
                        SidecarStatus::Stopped,
                        Some(SidecarEventCause::Shutdown),
                    );
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            match child.try_wait() {
                Ok(Some(exit)) => {
                    let _ = stderr_reader.join();
                    break process_exit_cause(exit, &stderr);
                }
                Err(error) => {
                    break SidecarEventCause::ProcessWaitError {
                        message: error.to_string(),
                        stderr_tail: stderr_tail(&stderr),
                    }
                }
                Ok(None) => {}
            }

            let mut probe_result = None;
            while let Ok(result) = probe_results.try_recv() {
                if probe_in_flight_generation == Some(result.generation) {
                    probe_in_flight_generation = None;
                }
                if result.generation == child_generation {
                    probe_result = Some(result);
                }
            }

            if let Some(result) = probe_result {
                if !ready && result.completed_at >= startup_deadline {
                    stop_child(
                        &mut child,
                        &io,
                        config.shutdown_timeout,
                        config.poll_interval,
                    );
                    let _ = stderr_reader.join();
                    break SidecarEventCause::StartupTimeout {
                        timeout: config.startup_timeout,
                        stderr_tail: stderr_tail(&stderr),
                    };
                }
                match result.outcome {
                    Ok(ProbeOutcome::Ready) => {
                        if !ready {
                            ready = true;
                            consecutive_failures = 0;
                            emit_event(
                                &state,
                                SidecarEvent {
                                    status: SidecarStatus::Healthy,
                                    cause: None,
                                    restart_attempt: None,
                                    backoff_delay: None,
                                    generation: Some(child_generation),
                                },
                            );
                        }
                    }
                    Ok(ProbeOutcome::Loading) if !ready => {}
                    Ok(ProbeOutcome::Loading) => {
                        stop_child(
                            &mut child,
                            &io,
                            config.shutdown_timeout,
                            config.poll_interval,
                        );
                        let _ = stderr_reader.join();
                        break SidecarEventCause::HealthProbeFailure {
                            message: "probe reported loading after readiness".into(),
                            stderr_tail: stderr_tail(&stderr),
                        };
                    }
                    Err(message) => {
                        stop_child(
                            &mut child,
                            &io,
                            config.shutdown_timeout,
                            config.poll_interval,
                        );
                        let _ = stderr_reader.join();
                        break SidecarEventCause::HealthProbeFailure {
                            message,
                            stderr_tail: stderr_tail(&stderr),
                        };
                    }
                }
            }

            if !ready && Instant::now() >= startup_deadline {
                stop_child(
                    &mut child,
                    &io,
                    config.shutdown_timeout,
                    config.poll_interval,
                );
                let _ = stderr_reader.join();
                break SidecarEventCause::StartupTimeout {
                    timeout: config.startup_timeout,
                    stderr_tail: stderr_tail(&stderr),
                };
            }
            if probe_in_flight_generation != Some(child_generation) && Instant::now() >= next_probe
            {
                next_probe = Instant::now() + config.health_interval;
                probe_in_flight_generation = Some(child_generation);
                let probe = Arc::clone(&probe);
                let probe_io = io.clone();
                let results = probe_results_tx.clone();
                thread::spawn(move || {
                    let outcome = probe(&probe_io);
                    let _ = results.send(ProbeResult {
                        generation: child_generation,
                        completed_at: Instant::now(),
                        outcome,
                    });
                });
            }
        };
        io.stdin.0.lock().unwrap().writer = None;
        if let Some(attempt) = allow_restart(&config.restart, &mut restarts) {
            restart_attempt = Some(attempt);
            restart_cause = Some(cause);
        } else {
            emit_terminal(&state, SidecarStatus::Failed, Some(cause));
            return;
        }
        consecutive_failures = consecutive_failures.saturating_add(1);
    }
}

fn process_exit_cause(exit: std::process::ExitStatus, stderr: &StderrRing) -> SidecarEventCause {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    SidecarEventCause::ProcessExit {
        code: exit.code(),
        #[cfg(unix)]
        signal: exit.signal(),
        #[cfg(not(unix))]
        signal: None,
        stderr_tail: stderr_tail(stderr),
    }
}

fn stderr_tail(stderr: &StderrRing) -> Vec<String> {
    let lines = stderr.snapshot();
    lines[lines.len().saturating_sub(STDERR_DIAGNOSTIC_LINES)..].to_vec()
}

fn spawn_child(
    config: &SidecarConfig,
    io: &SidecarIo,
    out: mpsc::Sender<(u64, String)>,
    err: Arc<StderrRing>,
    generation: u64,
) -> Result<(Child, JoinHandle<()>), std::io::Error> {
    let mut child = Command::new(&config.program)
        .args(&config.args)
        .envs(&config.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    err.begin_generation(generation);
    {
        let mut stdin = io.stdin.0.lock().unwrap();
        stdin.generation = generation;
        stdin.writer = child.stdin.take().map(BufWriter::new);
    }
    pipe_lines(child.stdout.take().unwrap(), out, generation);
    let stderr_reader = pipe_error_lines(child.stderr.take().unwrap(), err, generation);
    Ok((child, stderr_reader))
}

fn pipe_lines(pipe: ChildStdout, tx: mpsc::Sender<(u64, String)>, generation: u64) {
    thread::spawn(move || forward_lines(pipe, tx, generation));
}
fn pipe_error_lines(pipe: ChildStderr, ring: Arc<StderrRing>, generation: u64) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            match line {
                Ok(line) => {
                    let line = line.strip_suffix('\r').unwrap_or(&line);
                    if !line.is_empty() {
                        ring.push(generation, line.to_owned());
                    }
                }
                Err(_) => break,
            }
        }
    })
}
fn forward_lines(pipe: impl std::io::Read, tx: mpsc::Sender<(u64, String)>, generation: u64) {
    for line in BufReader::new(pipe).lines() {
        match line {
            Ok(line) => {
                let line = line.strip_suffix('\r').unwrap_or(&line);
                if line.is_empty() {
                    continue;
                }
                if tx.send((generation, line.to_owned())).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn allow_restart(policy: &RestartPolicy, history: &mut VecDeque<Instant>) -> Option<usize> {
    let now = Instant::now();
    while history
        .front()
        .is_some_and(|at| now.duration_since(*at) > policy.window)
    {
        history.pop_front();
    }
    if history.len() >= policy.max_restarts {
        return None;
    }
    history.push_back(now);
    Some(history.len())
}

fn stop_child(child: &mut Child, io: &SidecarIo, deadline: Duration, poll: Duration) {
    io.stdin.0.lock().unwrap().writer = None;
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(poll.min(until.saturating_duration_since(Instant::now())));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_or_shutdown(
    delay: Duration,
    commands: &mpsc::Receiver<SupervisorCommand>,
    io: &SidecarIo,
    child: Option<&mut Child>,
    config: &SidecarConfig,
    state: &Arc<Mutex<SupervisorState>>,
) -> bool {
    match commands.recv_timeout(delay) {
        Ok(SupervisorCommand::Shutdown(done)) => {
            if let Some(child) = child {
                stop_child(child, io, config.shutdown_timeout, config.poll_interval);
            }
            emit_terminal(
                state,
                SidecarStatus::Stopped,
                Some(SidecarEventCause::Shutdown),
            );
            let _ = done.send(());
            true
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            emit_terminal(
                state,
                SidecarStatus::Stopped,
                Some(SidecarEventCause::Shutdown),
            );
            true
        }
        Err(mpsc::RecvTimeoutError::Timeout) => false,
    }
}

fn emit_event(state: &Arc<Mutex<SupervisorState>>, event: SidecarEvent) {
    let mut state = state.lock().unwrap();
    state.status = event.status;
    state.events.push(event.clone());
    state
        .subscribers
        .retain(|sender| sender.send(event.clone()).is_ok());
}

fn emit_terminal(
    state: &Arc<Mutex<SupervisorState>>,
    status: SidecarStatus,
    cause: Option<SidecarEventCause>,
) {
    emit_event(
        state,
        SidecarEvent {
            status,
            cause,
            restart_attempt: None,
            backoff_delay: None,
            generation: None,
        },
    );
    let mut state = state.lock().unwrap();
    state.closed = true;
    state.subscribers.clear();
}
