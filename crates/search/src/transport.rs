//! How a session sends one GET.
//!
//! Each engine session owns one transport, and the transport owns that
//! engine's cookie jar. The default is `ureq` with rustls and the OS
//! certificate verifier. Brave goes through the system `curl` program when
//! one is on `PATH`, because Brave lets curl's TLS handshake through when it
//! flags rustls.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::engines::EngineId;

/// How long one request may take.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// How many redirects one request follows.
pub const REDIRECTS: u32 = 10;

/// The user agent and request headers of a desktop Chrome navigation.
pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
pub const ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
pub const ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

/// A finished response: its status, the URL after redirects, and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub final_url: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The peer reset or aborted the connection. The session retries once.
    ConnectionReset(String),
    Other(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::ConnectionReset(message) => write!(f, "connection reset: {message}"),
            TransportError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TransportError {}

/// Sends GET requests for one engine and keeps its cookies between them.
pub trait Transport: Send {
    /// Fetches `url`, sending `referer` when the session has a same-origin one.
    /// Any HTTP status is a response, not an error.
    fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError>;

    /// A short name for the transport in engine reports.
    fn name(&self) -> &'static str {
        "custom"
    }
}

/// Builds the transport a fresh engine session uses.
pub type TransportFactory = Arc<dyn Fn(EngineId) -> Box<dyn Transport> + Send + Sync>;

/// The default transport for `engine`: the system curl for Brave when one
/// runs, and `ureq` otherwise.
pub fn default_transport(engine: EngineId) -> Box<dyn Transport> {
    if engine == EngineId::Brave {
        if let Some(curl) = system_curl().and_then(|program| SystemCurl::new(program).ok()) {
            return Box::new(curl);
        }
    }
    Box::new(UreqTransport::new())
}

/// The default transport factory.
pub fn default_factory() -> TransportFactory {
    Arc::new(default_transport)
}

/// `ureq` over rustls with its own cookie store.
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .tls_config(tls_config())
            .try_proxy_from_env(true)
            .timeout(TIMEOUT)
            .redirects(REDIRECTS)
            .user_agent(USER_AGENT)
            .build();
        UreqTransport { agent }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UreqTransport {
    fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError> {
        let mut request = self
            .agent
            .get(url)
            .set("accept", ACCEPT)
            .set("accept-language", ACCEPT_LANGUAGE);
        if let Some(referer) = referer {
            request = request.set("referer", referer);
        }
        let response = match request.call() {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => return Err(ureq_error(error)),
        };
        let status = response.status();
        let final_url = response.get_url().to_owned();
        let body = response.into_string().map_err(|error| io_error(&error))?;
        Ok(Response {
            status,
            final_url,
            body,
        })
    }

    fn name(&self) -> &'static str {
        "ureq"
    }
}

fn ureq_error(error: ureq::Transport) -> TransportError {
    use std::error::Error as _;
    let reset = error
        .source()
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .map(io_error);
    match reset {
        Some(TransportError::ConnectionReset(_)) => {
            TransportError::ConnectionReset(error.to_string())
        }
        _ => TransportError::Other(error.to_string()),
    }
}

fn io_error(error: &std::io::Error) -> TransportError {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => {
            TransportError::ConnectionReset(error.to_string())
        }
        _ => TransportError::Other(error.to_string()),
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    use rustls_platform_verifier::BuilderVerifierExt;

    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // Select ring explicitly even when another dependency enables a second crypto provider.
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("The TLS protocol versions are invalid.")
            .with_platform_verifier()
            .expect("The OS certificate verifier could not start.")
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// The program name the system curl has on `PATH`.
#[cfg(windows)]
const CURL_PROGRAM: &str = "curl.exe";
#[cfg(not(windows))]
const CURL_PROGRAM: &str = "curl";

/// What `curl -w` prints after a transfer: the status, then the final URL.
const WRITE_OUT: &str = "%{http_code}\\n%{url_effective}";

/// The system `curl` program: the first one on `PATH` that answers
/// `curl --version`. The search runs once per process.
pub fn system_curl() -> Option<&'static Path> {
    static FOUND: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            let path = std::env::var_os("PATH")?;
            find_curl(&path).and_then(check_curl)
        })
        .as_deref()
}

/// The first absolute `PATH` entry that holds a curl program file.
fn find_curl(path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(CURL_PROGRAM))
        .find(|program| program.is_file())
}

/// `program` when it runs and reports itself as curl.
fn check_curl(program: PathBuf) -> Option<PathBuf> {
    let output = curl_command(&program).arg("--version").output().ok()?;
    let version = String::from_utf8_lossy(&output.stdout);
    (output.status.success() && version.starts_with("curl ")).then_some(program)
}

fn curl_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // A console program started from a GUI process opens no console window.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// The system `curl` program, run once per request with no shell. Its cookie
/// jar and the response body live in a private directory that the transport
/// removes when it drops.
pub struct SystemCurl {
    program: PathBuf,
    directory: PathBuf,
    protocols: &'static str,
}

impl SystemCurl {
    /// A transport over `program` with a fresh, empty cookie jar.
    pub fn new(program: &Path) -> std::io::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "muniment-search-curl-{}",
            uuid::Uuid::now_v7().simple()
        ));
        create_private_directory(&directory)?;
        Ok(SystemCurl {
            program: program.to_owned(),
            directory,
            protocols: "=https",
        })
    }

    fn jar(&self) -> PathBuf {
        self.directory.join("cookies.txt")
    }

    fn body(&self) -> PathBuf {
        self.directory.join("body")
    }
}

/// Creates `path` readable by its owner only. On Windows the user's temporary
/// directory is already private to that user.
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(path)
    }
}

impl Drop for SystemCurl {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Transport for SystemCurl {
    fn get(&mut self, url: &str, referer: Option<&str>) -> Result<Response, TransportError> {
        let body_path = self.body();
        let _ = std::fs::remove_file(&body_path);
        let arguments = curl_arguments(&self.jar(), &body_path, self.protocols, url, referer);
        let output = curl_command(&self.program)
            .args(&arguments)
            .output()
            .map_err(|error| TransportError::Other(format!("curl did not start: {error}")))?;
        if !output.status.success() {
            return Err(curl_error(
                output.status.code(),
                &String::from_utf8_lossy(&output.stderr),
            ));
        }
        let written = String::from_utf8_lossy(&output.stdout);
        let (status, final_url) = parse_written(&written).ok_or_else(|| {
            TransportError::Other(format!("curl wrote no status: {}", written.trim()))
        })?;
        // curl writes no file for an empty body.
        let body = match std::fs::read(&body_path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(io_error(&error)),
        };
        let _ = std::fs::remove_file(&body_path);
        Ok(Response {
            status,
            final_url,
            body,
        })
    }

    fn name(&self) -> &'static str {
        "curl"
    }
}

/// The curl arguments for one GET. `-q` keeps a user's `.curlrc` out, and the
/// user agent goes through `-A` so the headers keep the curl command line's
/// order.
fn curl_arguments(
    jar: &Path,
    body: &Path,
    protocols: &str,
    url: &str,
    referer: Option<&str>,
) -> Vec<OsString> {
    let redirects = REDIRECTS.to_string();
    let seconds = TIMEOUT.as_secs().to_string();
    let accept = format!("accept: {ACCEPT}");
    let accept_language = format!("accept-language: {ACCEPT_LANGUAGE}");
    let mut arguments: Vec<OsString> = [
        "-q",
        "-sS",
        "--compressed",
        "-L",
        "--max-redirs",
        &redirects,
        "--max-time",
        &seconds,
        "--proto",
        protocols,
        "--proto-redir",
        protocols,
        "-A",
        USER_AGENT,
        "-H",
        &accept,
        "-H",
        &accept_language,
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    // A control character in a header value would start a new header line.
    if let Some(referer) = referer.filter(|referer| !referer.chars().any(char::is_control)) {
        arguments.push("-H".into());
        arguments.push(format!("referer: {referer}").into());
    }
    arguments.push("-b".into());
    arguments.push(jar.into());
    arguments.push("-c".into());
    arguments.push(jar.into());
    arguments.push("-o".into());
    arguments.push(body.into());
    arguments.push("-w".into());
    arguments.push(WRITE_OUT.into());
    arguments.push("--url".into());
    arguments.push(url.into());
    arguments
}

/// The status and final URL that [`WRITE_OUT`] prints. Status 0 means curl
/// got no response.
fn parse_written(written: &str) -> Option<(u16, String)> {
    let (status, final_url) = written.split_once('\n')?;
    let status = status.trim().parse().ok().filter(|&status| status != 0)?;
    let final_url = final_url.trim();
    (!final_url.is_empty()).then(|| (status, final_url.to_owned()))
}

/// Maps a curl exit code to an error. Codes 55 and 56 are a failed send and a
/// failed receive, which a reset connection causes.
fn curl_error(code: Option<i32>, stderr: &str) -> TransportError {
    let message = match stderr.trim() {
        "" => match code {
            Some(code) => format!("curl exited with code {code}"),
            None => "curl was stopped by a signal".to_owned(),
        },
        message => message.to_owned(),
    };
    match code {
        Some(55 | 56) => TransportError::ConnectionReset(message),
        _ => TransportError::Other(message),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn ureq_keeps_cookies_and_reports_error_statuses_as_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for answer in [
                "HTTP/1.1 200 OK\r\nSet-Cookie: id=7; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let read = socket.read(&mut request).unwrap();
                seen.push(String::from_utf8_lossy(&request[..read]).to_lowercase());
                socket.write_all(answer.as_bytes()).unwrap();
            }
            seen
        });
        let mut transport = UreqTransport::new();
        let first = transport.get(&format!("http://{address}/"), None).unwrap();
        assert_eq!((first.status, first.body.as_str()), (200, "ok"));
        let second = transport
            .get(&format!("http://{address}/search"), Some(&first.final_url))
            .unwrap();
        assert_eq!((second.status, second.body.as_str()), (429, "slow"));
        let seen = server.join().unwrap();
        assert!(seen[0].contains("user-agent: mozilla/5.0"));
        assert!(seen[0].contains("accept-language: en-us"));
        assert!(seen[1].contains("cookie: id=7"));
        assert!(seen[1].contains(&format!("referer: http://{address}/")));
    }

    fn texts(arguments: &[OsString]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn curl_arguments_send_the_chrome_headers_and_the_url_as_one_argument() {
        let url = "https://search.brave.com/search?q=a+b%26c&source=web";
        let arguments = texts(&curl_arguments(
            Path::new("/jar"),
            Path::new("/body"),
            "=https",
            url,
            Some("https://search.brave.com/"),
        ));
        assert_eq!(arguments[0], "-q");
        let after = |flag: &str| -> Vec<&str> {
            arguments
                .windows(2)
                .filter(|pair| pair[0] == flag)
                .map(|pair| pair[1].as_str())
                .collect()
        };
        assert_eq!(after("-A"), [USER_AGENT]);
        assert_eq!(
            after("-H"),
            [
                format!("accept: {ACCEPT}").as_str(),
                &format!("accept-language: {ACCEPT_LANGUAGE}"),
                "referer: https://search.brave.com/",
            ]
        );
        assert_eq!(after("--proto"), ["=https"]);
        assert_eq!(after("--proto-redir"), ["=https"]);
        assert_eq!(after("--max-redirs"), ["10"]);
        assert_eq!(after("--max-time"), ["15"]);
        assert_eq!((after("-b"), after("-c")), (vec!["/jar"], vec!["/jar"]));
        assert_eq!(after("-o"), ["/body"]);
        assert_eq!(after("-w"), [WRITE_OUT]);
        assert_eq!(arguments[arguments.len() - 2..], ["--url", url]);
        assert!(arguments.contains(&"--compressed".to_owned()));
    }

    #[test]
    fn curl_arguments_drop_a_referer_with_a_line_break() {
        let arguments = texts(&curl_arguments(
            Path::new("/jar"),
            Path::new("/body"),
            "=https",
            "https://example.com/",
            Some("https://example.com/\r\nx-injected: 1"),
        ));
        assert!(!arguments
            .iter()
            .any(|argument| argument.contains("x-injected")));
    }

    #[test]
    fn curl_output_splits_into_status_and_final_url() {
        assert_eq!(
            parse_written("200\nhttps://search.brave.com/search?q=x"),
            Some((200, "https://search.brave.com/search?q=x".to_owned()))
        );
        assert_eq!(
            parse_written("429\r\nhttps://example.com/\r\n"),
            Some((429, "https://example.com/".to_owned()))
        );
        assert_eq!(parse_written("000\nhttps://example.com/"), None);
        assert_eq!(parse_written("200"), None);
        assert_eq!(parse_written("200\n"), None);
    }

    #[test]
    fn curl_exit_codes_for_send_and_receive_failures_are_resets() {
        assert!(matches!(
            curl_error(Some(56), "curl: (56) Recv failure: Connection reset by peer"),
            TransportError::ConnectionReset(message) if message.contains("Recv failure")
        ));
        assert!(matches!(
            curl_error(Some(55), ""),
            TransportError::ConnectionReset(_)
        ));
        assert_eq!(
            curl_error(Some(28), ""),
            TransportError::Other("curl exited with code 28".into())
        );
    }

    #[test]
    fn discovery_finds_no_curl_where_none_is() {
        let missing = std::env::temp_dir().join(format!(
            "muniment-search-missing-{}",
            uuid::Uuid::now_v7().simple()
        ));
        assert_eq!(check_curl(missing.join(CURL_PROGRAM)), None);
        assert_eq!(find_curl(missing.as_os_str()), None);
        assert_eq!(find_curl(OsStr::new("relative/bin")), None);
    }

    #[test]
    fn a_curl_transport_removes_its_directory_when_dropped() {
        let transport = SystemCurl::new(Path::new(CURL_PROGRAM)).unwrap();
        let directory = transport.directory.clone();
        assert!(directory.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&directory).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        drop(transport);
        assert!(!directory.exists());
    }

    /// Writes an executable script that stands in for curl.
    #[cfg(unix)]
    fn fake_curl(directory: &Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let program = directory.join(CURL_PROGRAM);
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        program
    }

    #[cfg(unix)]
    #[test]
    fn a_fake_curl_answers_through_the_body_file_and_write_out() {
        let directory = std::env::temp_dir().join(format!(
            "muniment-search-fake-{}",
            uuid::Uuid::now_v7().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let answering = fake_curl(
            &directory,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "curl 8.0.0 (fake)"; exit 0; fi
out=""; previous=""
for argument in "$@"; do
  if [ "$previous" = "-o" ]; then out="$argument"; fi
  previous="$argument"
done
printf 'page body' > "$out"
printf '201\nhttps://example.com/final'
"#,
        );
        assert_eq!(find_curl(directory.as_os_str()), Some(answering.clone()));
        assert_eq!(check_curl(answering.clone()), Some(answering.clone()));
        let mut transport = SystemCurl::new(&answering).unwrap();
        assert_eq!(
            transport.get("https://example.com/", None).unwrap(),
            Response {
                status: 201,
                final_url: "https://example.com/final".into(),
                body: "page body".into(),
            }
        );
        drop(transport);
        let resetting = fake_curl(
            &directory,
            "#!/bin/sh\necho 'curl: (56) Recv failure: Connection reset by peer' >&2\nexit 56\n",
        );
        assert_eq!(check_curl(resetting.clone()), None);
        let mut transport = SystemCurl::new(&resetting).unwrap();
        assert!(matches!(
            transport.get("https://example.com/", None),
            Err(TransportError::ConnectionReset(_))
        ));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn the_system_curl_keeps_cookies_and_reports_error_statuses_as_responses() {
        let Some(program) = system_curl() else {
            return;
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for answer in [
                "HTTP/1.1 200 OK\r\nSet-Cookie: id=7; Path=/\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0; 4096];
                let read = socket.read(&mut request).unwrap();
                seen.push(String::from_utf8_lossy(&request[..read]).to_lowercase());
                socket.write_all(answer.as_bytes()).unwrap();
            }
            seen
        });
        let mut transport = SystemCurl::new(program).unwrap();
        // The loopback server speaks plain HTTP.
        transport.protocols = "=http";
        let first = transport.get(&format!("http://{address}/"), None).unwrap();
        assert_eq!((first.status, first.body.as_str()), (200, "ok"));
        assert_eq!(first.final_url, format!("http://{address}/"));
        let second = transport
            .get(&format!("http://{address}/search"), Some(&first.final_url))
            .unwrap();
        assert_eq!((second.status, second.body.as_str()), (429, "slow"));
        let seen = server.join().unwrap();
        assert!(seen[0].contains("user-agent: mozilla/5.0"));
        assert!(seen[0].contains("accept-language: en-us"));
        assert!(seen[1].contains("cookie: id=7"));
        assert!(seen[1].contains(&format!("referer: http://{address}/")));
    }
}
