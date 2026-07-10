use std::collections::VecDeque;
use std::fmt;
use std::io::{BufWriter, Write};
use std::process::ChildStdin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SidecarError {
    Spawn(std::io::Error),
    Io(std::io::Error),
    Disconnected,
    AlreadyStopped,
}

impl fmt::Display for SidecarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start sidecar: {e}"),
            Self::Io(e) => write!(f, "sidecar I/O failed: {e}"),
            Self::Disconnected => write!(f, "sidecar output disconnected"),
            Self::AlreadyStopped => write!(f, "sidecar supervisor is already stopped"),
        }
    }
}

impl std::error::Error for SidecarError {}

pub(super) struct WriterState {
    pub(super) generation: u64,
    pub(super) writer: Option<BufWriter<ChildStdin>>,
}

#[derive(Clone)]
pub struct LineWriter(pub(super) Arc<Mutex<WriterState>>);

impl LineWriter {
    pub fn write_line(&self, line: &str) -> Result<(), SidecarError> {
        self.write_line_in_generation(line).map(|_| ())
    }

    pub(super) fn write_line_in_generation(&self, line: &str) -> Result<u64, SidecarError> {
        let mut guard = self.0.lock().unwrap();
        let generation = guard.generation;
        let writer = guard.writer.as_mut().ok_or(SidecarError::Disconnected)?;
        writer
            .write_all(line.as_bytes())
            .map_err(SidecarError::Io)?;
        writer.write_all(b"\n").map_err(SidecarError::Io)?;
        writer.flush().map_err(SidecarError::Io)?;
        Ok(generation)
    }
}

pub(super) struct LineReceiver {
    pub(super) receiver: mpsc::Receiver<(u64, String)>,
    pub(super) pending: VecDeque<(u64, String)>,
    pub(super) generation: Arc<AtomicU64>,
}

pub(super) struct StderrState {
    pub(super) lines: VecDeque<String>,
    pub(super) first_sequence: u64,
    pub(super) next_sequence: u64,
    pub(super) read_sequence: u64,
    pub(super) generation: u64,
}

pub(super) struct StderrRing {
    pub(super) state: Mutex<StderrState>,
    pub(super) available: Condvar,
    pub(super) capacity: usize,
}

impl StderrRing {
    pub(super) fn begin_generation(&self, generation: u64) {
        let mut state = self.state.lock().unwrap();
        state.lines.clear();
        state.first_sequence = state.next_sequence;
        state.read_sequence = state.next_sequence;
        state.generation = generation;
    }

    pub(super) fn push(&self, generation: u64, line: String) {
        let mut state = self.state.lock().unwrap();
        if self.capacity == 0 || state.generation != generation {
            return;
        }
        if state.lines.len() == self.capacity {
            state.lines.pop_front();
            state.first_sequence += 1;
        }
        state.lines.push_back(line);
        state.next_sequence += 1;
        self.available.notify_all();
    }

    pub(super) fn snapshot(&self) -> Vec<String> {
        self.state.lock().unwrap().lines.iter().cloned().collect()
    }

    fn read(&self, timeout: Option<Duration>) -> Result<Option<String>, SidecarError> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.state.lock().unwrap();
        loop {
            state.read_sequence = state.read_sequence.max(state.first_sequence);
            if state.read_sequence < state.next_sequence {
                let index = (state.read_sequence - state.first_sequence) as usize;
                state.read_sequence += 1;
                return Ok(state.lines.get(index).cloned());
            }
            state = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    let (state, result) = self.available.wait_timeout(state, remaining).unwrap();
                    if result.timed_out() {
                        return Ok(None);
                    }
                    state
                }
                None => self.available.wait(state).unwrap(),
            };
        }
    }
}

#[derive(Clone)]
pub struct LineReader(pub(super) LineReaderInner);

#[derive(Clone)]
pub(super) enum LineReaderInner {
    Channel(Arc<Mutex<LineReceiver>>),
    Stderr(Arc<StderrRing>),
}

impl LineReader {
    pub fn read_line(&self) -> Result<String, SidecarError> {
        if let LineReaderInner::Stderr(ring) = &self.0 {
            return ring.read(None)?.ok_or(SidecarError::Disconnected);
        }
        let LineReaderInner::Channel(receiver) = &self.0 else {
            unreachable!()
        };
        let mut guard = receiver.lock().unwrap();
        if let Some((_, line)) = guard.pending.pop_front() {
            return Ok(line);
        }
        guard
            .receiver
            .recv()
            .map(|(_, line)| line)
            .map_err(|_| SidecarError::Disconnected)
    }

    pub fn read_line_timeout(&self, timeout: Duration) -> Result<Option<String>, SidecarError> {
        if let LineReaderInner::Stderr(ring) = &self.0 {
            return ring.read(Some(timeout));
        }
        let LineReaderInner::Channel(receiver) = &self.0 else {
            unreachable!()
        };
        let mut guard = receiver.lock().unwrap();
        if let Some((_, line)) = guard.pending.pop_front() {
            return Ok(Some(line));
        }
        match guard.receiver.recv_timeout(timeout) {
            Ok((_, line)) => Ok(Some(line)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SidecarError::Disconnected),
        }
    }

    pub(super) fn read_line_timeout_for_generation(
        &self,
        generation: u64,
        timeout: Duration,
    ) -> Result<Option<String>, SidecarError> {
        self.read_for_generation(generation, Some(timeout))
    }

    fn read_for_generation(
        &self,
        generation: u64,
        timeout: Option<Duration>,
    ) -> Result<Option<String>, SidecarError> {
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let LineReaderInner::Channel(receiver) = &self.0 else {
            return Err(SidecarError::Disconnected);
        };
        let mut guard = receiver.lock().unwrap();
        loop {
            if guard.generation.load(Ordering::Acquire) != generation {
                return Err(SidecarError::Disconnected);
            }
            guard.pending.retain(|(seen, _)| *seen >= generation);
            if let Some(index) = guard
                .pending
                .iter()
                .position(|(seen, _)| *seen == generation)
            {
                return Ok(guard.pending.remove(index).map(|(_, line)| line));
            }
            let received = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    match guard.receiver.recv_timeout(remaining) {
                        Ok(line) => line,
                        Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(SidecarError::Disconnected)
                        }
                    }
                }
                None => guard
                    .receiver
                    .recv()
                    .map_err(|_| SidecarError::Disconnected)?,
            };
            match received {
                (seen, line) if seen == generation => return Ok(Some(line)),
                (seen, _) if seen < generation => continue,
                future => guard.pending.push_back(future),
            }
        }
    }
}

#[derive(Clone)]
pub struct SidecarIo {
    pub stdin: LineWriter,
    pub stdout: LineReader,
    pub stderr: LineReader,
}
