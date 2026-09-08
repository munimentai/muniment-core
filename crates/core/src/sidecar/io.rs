use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::process::ChildStdin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, TryLockError};
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
    // Keep pipe ownership separate from its write lock so shutdown can kill a blocked child.
    pub(super) writer: Option<Arc<Mutex<ChildStdin>>>,
}

#[derive(Clone)]
pub struct LineWriter(pub(super) Arc<Mutex<WriterState>>);

impl LineWriter {
    pub(super) fn generation(&self) -> u64 {
        self.0.lock().unwrap().generation
    }

    pub fn write_line(&self, line: &str) -> Result<(), SidecarError> {
        self.write_line_in_generation(line).map(|_| ())
    }

    pub(super) fn write_line_in_generation(&self, line: &str) -> Result<u64, SidecarError> {
        let (generation, writer) = {
            let guard = self.0.lock().unwrap();
            let writer = guard.writer.clone().ok_or(SidecarError::Disconnected)?;
            (guard.generation, writer)
        };
        let mut writer = writer.lock().unwrap();
        writer
            .write_all(format!("{line}\n").as_bytes())
            .map_err(SidecarError::Io)?;
        Ok(generation)
    }

    /// Bounds the writer lock and pipe write without blocking supervisor cleanup.
    pub(super) fn write_line_until(
        &self,
        line: String,
        generation: u64,
        deadline: Instant,
    ) -> Result<(), SidecarError> {
        let writer = {
            let guard = self.0.lock().unwrap();
            if guard.generation != generation {
                return Err(SidecarError::Disconnected);
            }
            guard.writer.clone().ok_or(SidecarError::Disconnected)?
        };
        const PENDING: u8 = 0;
        const WRITING: u8 = 1;
        const CANCELLED: u8 = 2;
        let attempt = Arc::new(AtomicU8::new(PENDING));
        let worker_attempt = Arc::clone(&attempt);
        let state = Arc::clone(&self.0);
        let (sender, receiver) = mpsc::channel();
        // The supervisor kills the child to release a pipe write that outlives the deadline.
        std::thread::Builder::new()
            .name("pi-rpc-writer".into())
            .spawn(move || {
                let result = (|| {
                    let mut writer = loop {
                        if Instant::now() >= deadline {
                            return Err(write_timeout());
                        }
                        match writer.try_lock() {
                            Ok(writer) => break writer,
                            Err(TryLockError::Poisoned(error)) => break error.into_inner(),
                            Err(TryLockError::WouldBlock) => std::thread::sleep(
                                deadline
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_millis(1)),
                            ),
                        }
                    };
                    if Instant::now() >= deadline {
                        return Err(write_timeout());
                    }
                    {
                        let state = state.lock().unwrap();
                        if state.generation != generation || state.writer.is_none() {
                            return Err(SidecarError::Disconnected);
                        }
                    }
                    // The caller can cancel a queued write without closing an untouched pipe.
                    if worker_attempt
                        .compare_exchange(PENDING, WRITING, Ordering::SeqCst, Ordering::SeqCst)
                        .is_err()
                    {
                        return Err(write_timeout());
                    }
                    writer
                        .write_all(format!("{line}\n").as_bytes())
                        .map_err(SidecarError::Io)
                })();
                let _ = sender.send(result);
            })
            .map_err(SidecarError::Io)?;
        let result = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(write_timeout()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SidecarError::Disconnected),
        };
        if result.is_err() && attempt.swap(CANCELLED, Ordering::SeqCst) == WRITING {
            // A partial frame makes this pipe unusable. Keep cleanup off the writer lock.
            let mut guard = self.0.lock().unwrap();
            if guard.generation == generation {
                guard.writer = None;
            }
        }
        result
    }
}

fn write_timeout() -> SidecarError {
    SidecarError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out writing Pi RPC stdin",
    ))
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
    pub(crate) fn stderr_tail(&self) -> Vec<String> {
        match &self.0 {
            LineReaderInner::Stderr(ring) => {
                let lines = ring.snapshot();
                lines
                    .into_iter()
                    .rev()
                    .take(20)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            }
            LineReaderInner::Channel(_) => Vec::new(),
        }
    }

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

    pub(super) fn read_line_for_generation(&self, generation: u64) -> Result<String, SidecarError> {
        self.read_for_generation(generation, None)?
            .ok_or(SidecarError::Disconnected)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_tail_keeps_the_last_twenty_lines_without_consuming_stderr() {
        let ring = Arc::new(StderrRing {
            state: Mutex::new(StderrState {
                lines: VecDeque::new(),
                first_sequence: 0,
                next_sequence: 0,
                read_sequence: 0,
                generation: 1,
            }),
            available: Condvar::new(),
            capacity: 25,
        });
        let reader = LineReader(LineReaderInner::Stderr(Arc::clone(&ring)));
        assert!(reader.stderr_tail().is_empty());
        for index in 0..30 {
            ring.push(1, format!("Pi stderr {index}"));
        }
        let expected: Vec<_> = (10..30).map(|index| format!("Pi stderr {index}")).collect();
        assert_eq!(reader.stderr_tail(), expected);
        assert_eq!(reader.read_line().unwrap(), "Pi stderr 5");
        assert_eq!(reader.stderr_tail(), expected);
        ring.begin_generation(2);
        ring.push(1, "stale stderr".into());
        assert!(reader.stderr_tail().is_empty());
    }
}
