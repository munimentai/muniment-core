//! Langfuse generations through the public ingestion API.
//!
//! A request thread hands each event to a bounded queue and never waits. One
//! sender thread posts the queue in batches to `<host>/api/public/ingestion`
//! with the project's public and secret keys as basic auth. A full queue drops
//! the event and counts it, so a slow or missing Langfuse never slows a turn.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const QUEUE: usize = 10_000;
const BATCH: usize = 100;
const INTERVAL: Duration = Duration::from_secs(2);
const TIMEOUT: Duration = Duration::from_secs(10);
/// The longest trace id a request header may name.
const TRACE_ID_LIMIT: usize = 128;

/// Where the generations go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub host: String,
    pub public_key: String,
    pub secret_key: String,
}

enum Message {
    Event(Value),
    Flush(mpsc::Sender<()>),
}

/// The ingestion queue. Cloning shares the queue and its sender thread.
#[derive(Clone)]
pub struct Langfuse {
    queue: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

impl Langfuse {
    /// Starts the sender thread.
    pub fn start(settings: Settings) -> Self {
        let (queue, receiver) = mpsc::sync_channel(QUEUE);
        let failed = Arc::new(AtomicU64::new(0));
        let sender_failed = Arc::clone(&failed);
        std::thread::spawn(move || send_loop(&settings, &receiver, &sender_failed));
        Self {
            queue,
            dropped: Arc::new(AtomicU64::new(0)),
            failed,
        }
    }

    /// Queues one ingestion event without waiting.
    pub fn send(&self, event: Value) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.queue.try_send(Message::Event(event))
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Posts every queued event, waiting at most `deadline`. Answers whether
    /// the queue emptied in time.
    pub fn flush(&self, deadline: Duration) -> bool {
        let (done, wait) = mpsc::channel();
        let until = Instant::now() + deadline;
        loop {
            match self.queue.try_send(Message::Flush(done.clone())) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(_)) if Instant::now() >= until => return false,
                Err(TrySendError::Full(_)) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        wait.recv_timeout(until.saturating_duration_since(Instant::now()))
            .is_ok()
    }

    /// Events the full queue dropped.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Events whose batch Langfuse did not accept.
    pub fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

fn send_loop(settings: &Settings, receiver: &Receiver<Message>, failed: &AtomicU64) {
    let agent = crate::http::agent_builder().timeout(TIMEOUT).build();
    let url = format!(
        "{}/api/public/ingestion",
        settings.host.trim_end_matches('/')
    );
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", settings.public_key, settings.secret_key))
    );
    let mut batch: Vec<Value> = Vec::new();
    let mut due = Instant::now() + INTERVAL;
    loop {
        let message = receiver.recv_timeout(due.saturating_duration_since(Instant::now()));
        let mut flushed = None;
        match message {
            Ok(Message::Event(event)) => batch.push(event),
            Ok(Message::Flush(done)) => flushed = Some(done),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                post(&agent, &url, &auth, &mut batch, failed);
                return;
            }
        }
        if flushed.is_some() || batch.len() >= BATCH || Instant::now() >= due {
            post(&agent, &url, &auth, &mut batch, failed);
            due = Instant::now() + INTERVAL;
        }
        if let Some(done) = flushed {
            let _ = done.send(());
        }
    }
}

fn post(agent: &ureq::Agent, url: &str, auth: &str, batch: &mut Vec<Value>, failed: &AtomicU64) {
    if batch.is_empty() {
        return;
    }
    let events = std::mem::take(batch);
    let count = events.len() as u64;
    let result = agent
        .post(url)
        .set("authorization", auth)
        .send_json(json!({ "batch": events }));
    match result {
        // Langfuse answers 207 with a per-event result. A rejected event is
        // logged once and not sent again.
        Ok(response) => {
            let answer: Value = response.into_json().unwrap_or(Value::Null);
            let errors = answer["errors"].as_array().map(Vec::len).unwrap_or(0);
            if errors > 0 {
                failed.fetch_add(errors as u64, Ordering::Relaxed);
                eprintln!(
                    "muniment-router: Langfuse rejected {errors} of {count} events: {}",
                    answer["errors"][0]
                );
            }
        }
        Err(error) => {
            failed.fetch_add(count, Ordering::Relaxed);
            eprintln!("muniment-router: Langfuse ingestion failed for {count} events: {error}");
        }
    }
}

/// The trace a request names in `x-muniment-trace`, when it is a usable id.
pub fn trace_header(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    let usable = !value.is_empty()
        && value.len() <= TRACE_ID_LIMIT
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    usable.then(|| value.to_owned())
}

/// The trace id for a task with no trace header: the first 16 bytes of the
/// SHA-256 of the task id, in hex, which is the id the Langfuse SDKs derive
/// from the same seed.
pub fn task_trace_id(task_id: &str) -> String {
    Sha256::digest(task_id.as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One ingestion event of `kind` around `body`.
pub fn event(kind: &str, body: Value) -> Value {
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "type": kind,
        "body": body,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A stand-in Langfuse that answers every POST with `status` and sends
    /// each request's authorization and body to the receiver.
    pub(crate) fn ingestion(status: u16) -> (String, mpsc::Receiver<(String, Value)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, seen) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut length, mut auth) = (0, String::new());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = line.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap_or((line, ""));
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap_or(0),
                        "authorization" => auth = value.trim().to_owned(),
                        _ => {}
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let _ = sender.send((auth, serde_json::from_slice(&body).unwrap_or(Value::Null)));
                let answer = r#"{"successes":[],"errors":[]}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                    answer.len()
                );
            }
        });
        (format!("http://127.0.0.1:{port}"), seen)
    }

    #[test]
    fn events_post_in_one_batch_with_basic_auth_on_flush() {
        let (host, seen) = ingestion(207);
        let langfuse = Langfuse::start(Settings {
            host: format!("{host}/"),
            public_key: "pk-lf-1".into(),
            secret_key: "sk-lf-1".into(),
        });
        langfuse.send(event("generation-create", json!({"id": "g1"})));
        langfuse.send(event("generation-create", json!({"id": "g2"})));
        assert!(langfuse.flush(Duration::from_secs(5)));
        let (auth, body) = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(auth, "Basic cGstbGYtMTpzay1sZi0x");
        let batch = body["batch"].as_array().unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0]["type"], "generation-create");
        assert_eq!(batch[1]["body"]["id"], "g2");
        assert_eq!(langfuse.failed(), 0);
    }

    #[test]
    fn a_failing_langfuse_never_blocks_a_send() {
        let langfuse = Langfuse::start(Settings {
            host: "http://127.0.0.1:9".into(),
            public_key: "pk".into(),
            secret_key: "sk".into(),
        });
        let started = Instant::now();
        for index in 0..(QUEUE + 50) {
            langfuse.send(json!({ "index": index }));
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(langfuse.flush(Duration::from_secs(30)));
        assert!(langfuse.failed() > 0);
    }

    #[test]
    fn trace_ids_come_from_the_header_or_the_task() {
        assert_eq!(trace_header(Some(" abc-123_X ")), Some("abc-123_X".into()));
        assert_eq!(trace_header(Some("")), None);
        assert_eq!(trace_header(Some("a b")), None);
        assert_eq!(trace_header(Some(&"a".repeat(129))), None);
        assert_eq!(trace_header(None), None);
        // The Langfuse SDKs' create_trace_id(seed="task-1").
        assert_eq!(task_trace_id("task-1"), "7afaa346b4bf92bf9dc21e9ae8098874");
    }
}
