//! The loopback search endpoint.
//!
//! The server answers `GET /search?q=…&format=json` in the SearXNG JSON format
//! on `127.0.0.1` at an ephemeral port, behind a bearer token it writes with
//! the port to an endpoint file. Nothing off the machine reaches the port, and
//! the token keeps other processes on the machine from using the engine.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engines::TimeRange;
use crate::metasearch::{EngineStatus, Metasearch, Query, MAX_COUNT};

/// The endpoint file's name inside an agent directory.
pub const ENDPOINT_FILE: &str = "muniment-search-endpoint.json";
/// The longest a request head may be.
const HEAD_LIMIT: usize = 64 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// The port and token a client reaches the engine on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub port: u16,
    pub token: String,
}

impl Endpoint {
    /// The base URL a SearXNG client stores.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The `Authorization` header value a client sends.
    pub fn authorization(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

/// The endpoint file inside an agent directory.
pub fn endpoint_path(agent: &Path) -> PathBuf {
    agent.join(ENDPOINT_FILE)
}

/// The endpoint a running server wrote to `path`.
pub fn read_endpoint(path: &Path) -> Option<Endpoint> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Writes the endpoint file readable by its owner only, replacing it atomically.
fn write_endpoint(path: &Path, endpoint: &Endpoint) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(&serde_json::to_vec_pretty(endpoint)?)?;
            file.sync_all()
        })
        .and_then(|()| muniment_atomic_file::replace(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// A random 32-byte token in hex.
fn token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("the platform's random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A started server. Dropping the handle stops the listener.
pub struct Handle {
    endpoint: Endpoint,
    stop: Arc<AtomicBool>,
}

impl Handle {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Stops the accept loop. Searches already in flight finish.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Binds the loopback listener, writes the endpoint file to `endpoint_file`,
/// and serves searches through `search` until the handle stops or drops.
pub fn start(endpoint_file: &Path, search: Arc<Metasearch>) -> io::Result<Handle> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let endpoint = Endpoint {
        port,
        token: token(),
    };
    write_endpoint(endpoint_file, &endpoint)?;
    let stop = Arc::new(AtomicBool::new(false));
    let accept_stop = Arc::clone(&stop);
    let accept_token = endpoint.token.clone();
    std::thread::spawn(move || {
        while !accept_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let search = Arc::clone(&search);
                    let token = accept_token.clone();
                    std::thread::spawn(move || {
                        let _ = stream.set_nonblocking(false);
                        serve(stream, &search, &token);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL);
                }
                Err(_) => break,
            }
        }
    });
    Ok(Handle { endpoint, stop })
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

    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    fn params(&self) -> Vec<(String, String)> {
        let query = self.target.split_once('?').map_or("", |(_, query)| query);
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect()
    }
}

fn read_head(reader: &mut BufReader<TcpStream>) -> Option<Head> {
    let mut reader = reader.take(HEAD_LIMIT as u64);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
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

fn respond(stream: &mut dyn Write, status: u16, reason: &str, body: &Value) {
    let payload = body.to_string();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(payload.as_bytes());
    let _ = stream.flush();
}

fn error(message: &str) -> Value {
    json!({ "error": message })
}

fn serve(stream: TcpStream, search: &Metasearch, token: &str) {
    let Ok(peer) = stream.peer_addr() else {
        return;
    };
    // Belt on top of the loopback bind: nothing off the machine is served.
    if !peer.ip().is_loopback() {
        return;
    }
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
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
            &error("The request head is unreadable."),
        );
        return;
    };
    if head.path() == "/healthz" {
        respond(&mut stream, 200, "OK", &json!({ "ok": true }));
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
            &error("The token is missing or wrong."),
        );
        return;
    }
    match (head.method.as_str(), head.path()) {
        ("GET", "/search") => {
            let (status, reason, body) = answer(search, &head.params());
            respond(&mut stream, status, reason, &body);
        }
        _ => respond(&mut stream, 404, "Not Found", &error("No such route.")),
    }
}

/// Answers one `/search` request from its query parameters.
fn answer(search: &Metasearch, params: &[(String, String)]) -> (u16, &'static str, Value) {
    let param = |name: &str| {
        params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if param("format") != Some("json") {
        return (400, "Bad Request", error("Only format=json is served."));
    }
    let Some(text) = param("q").map(str::trim).filter(|text| !text.is_empty()) else {
        return (400, "Bad Request", error("The q parameter is missing."));
    };
    let time_range = match param("time_range").filter(|range| !range.is_empty()) {
        None => None,
        Some(name) => match TimeRange::from_name(name) {
            Some(range) => Some(range),
            None => {
                return (
                    400,
                    "Bad Request",
                    error("time_range must be day, week, month or year."),
                )
            }
        },
    };
    let query = Query {
        text: text.to_owned(),
        time_range,
        count: MAX_COUNT,
    };
    let outcome = search.search(&query);
    let unresponsive: Vec<Value> = outcome
        .engines
        .iter()
        .filter_map(|report| {
            let reason = match &report.status {
                EngineStatus::Answered(_) | EngineStatus::Skipped => return None,
                EngineStatus::Blocked(reason) => format!("blocked: {reason}"),
                EngineStatus::CoolingDown(seconds) => format!("cooling down for {seconds}s"),
                EngineStatus::Failed(reason) => reason.clone(),
            };
            Some(json!([report.engine.name(), reason]))
        })
        .collect();
    let results: Vec<Value> = outcome
        .results
        .iter()
        .map(|merged| {
            let engines: Vec<&str> = merged.engines.iter().map(|engine| engine.name()).collect();
            json!({
                "url": merged.result.url,
                "title": merged.result.title,
                "content": merged.result.snippet,
                "engine": engines.first().copied().unwrap_or_default(),
                "engines": engines,
            })
        })
        .collect();
    let body = json!({
        "query": text,
        "number_of_results": results.len(),
        "results": results,
        "answers": [],
        "unresponsive_engines": unresponsive,
    });
    // No engine answered, so the client moves on to its next provider.
    if !outcome.answered() && !unresponsive.is_empty() {
        return (503, "Service Unavailable", body);
    }
    (200, "OK", body)
}

/// Compares two secrets without leaking where they differ through timing.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |seen, (a, b)| seen | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_compare_whole() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert_eq!(token().len(), 64);
    }
}
