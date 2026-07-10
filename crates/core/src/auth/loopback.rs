//! Loopback redirect listener for the native-app flow (RFC 8252 §7.3).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use super::urlenc;
use super::AuthError;

pub struct RedirectCatcher {
    listener: TcpListener,
    port: u16,
}

impl RedirectCatcher {
    /// Bind an ephemeral port on 127.0.0.1 only — nothing off-machine can
    /// reach the callback.
    pub fn bind() -> Result<Self, AuthError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| AuthError::Redirect(format!("cannot bind loopback listener: {e}")))?;
        let port = listener
            .local_addr()
            .map_err(|e| AuthError::Redirect(format!("loopback listener address: {e}")))?
            .port();
        // Non-blocking accept so the wait below can honor its deadline.
        listener
            .set_nonblocking(true)
            .map_err(|e| AuthError::Redirect(format!("loopback listener mode: {e}")))?;
        Ok(RedirectCatcher { listener, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    /// Block until the browser is redirected to `/callback`, answer it with
    /// a small "return to the app" page, and hand back the authorization
    /// code. The callback is accepted only when its `state` matches
    /// `expected_state`; other paths (favicon probes etc.) get a 404 and the
    /// wait continues. The listener shuts down when this returns.
    pub fn wait_for_callback(
        self,
        expected_state: &str,
        timeout: Duration,
    ) -> Result<String, AuthError> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut stream = match self.listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(AuthError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(e) => return Err(AuthError::Redirect(format!("accept failed: {e}"))),
            };
            // Windows accepted sockets inherit the listener's non-blocking
            // mode; the request read below wants a plain blocking socket.
            let _ = stream.set_nonblocking(false);

            let Some(target) = read_request_target(&mut stream) else {
                continue;
            };
            let (path, query) = match target.split_once('?') {
                Some((p, q)) => (p, q),
                None => (target.as_str(), ""),
            };
            if path != "/callback" {
                respond_plain(&mut stream, "404 Not Found", "not found");
                continue;
            }

            let params = urlenc::parse_query(query);
            let param = |k: &str| {
                params
                    .iter()
                    .find(|(pk, _)| pk == k)
                    .map(|(_, v)| v.clone())
            };

            if let Some(error) = param("error") {
                respond_page(
                    &mut stream,
                    "Sign-in was not completed",
                    "You can close this tab and try again from the app.",
                );
                let desc = param("error_description").unwrap_or_default();
                return Err(AuthError::Denied(if desc.is_empty() {
                    error
                } else {
                    format!("{error}: {desc}")
                }));
            }
            if param("state").as_deref() != Some(expected_state) {
                respond_page(
                    &mut stream,
                    "Sign-in rejected",
                    "This sign-in attempt could not be verified. Close this tab and try again from the app.",
                );
                return Err(AuthError::StateMismatch);
            }
            return match param("code") {
                Some(code) => {
                    respond_page(
                        &mut stream,
                        "Signed in",
                        "You can close this tab and return to muniment.",
                    );
                    Ok(code)
                }
                None => {
                    respond_page(
                        &mut stream,
                        "Sign-in failed",
                        "The identity provider did not return an authorization code. Close this tab and try again from the app.",
                    );
                    Err(AuthError::Redirect(
                        "callback carried no authorization code".into(),
                    ))
                }
            };
        }
    }
}

/// First line of the HTTP request → request target (e.g. `/callback?x=y`);
/// `None` for anything unreadable (connection probes, non-GET methods).
fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next()?.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    (method == "GET").then(|| target.to_string())
}

fn respond_plain(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn respond_page(stream: &mut TcpStream, heading: &str, detail: &str) {
    // Static page, so the app's design tokens (§1.3) are inlined here.
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>muniment</title>\
         <style>:root{{color-scheme:light dark}}\
         body{{font-family:system-ui,sans-serif;display:grid;place-content:center;min-height:100vh;margin:0;background:#F6F7F6;color:#1A1D1C}}\
         main{{text-align:center}}h1{{font-size:20px;font-weight:600;margin:0 0 8px}}p{{color:#5C6461;font-size:14px;margin:0}}\
         @media (prefers-color-scheme:dark){{body{{background:#141716;color:#E8EBE9}}p{{color:#8A928E}}}}</style></head>\
         <body><main><h1>{heading}</h1><p>{detail}</p></main></body></html>"
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn ignores_stray_requests_then_returns_the_code() {
        let catcher = RedirectCatcher::bind().unwrap();
        let port = catcher.port();
        assert_eq!(
            catcher.redirect_uri(),
            format!("http://127.0.0.1:{port}/callback")
        );
        let browser = std::thread::spawn(move || {
            let favicon = get(port, "/favicon.ico");
            let callback = get(port, "/callback?code=abc%2F1&state=xyz");
            (favicon, callback)
        });
        let code = catcher
            .wait_for_callback("xyz", Duration::from_secs(5))
            .unwrap();
        assert_eq!(code, "abc/1"); // percent-decoded
        let (favicon, callback) = browser.join().unwrap();
        assert!(favicon.starts_with("HTTP/1.1 404"));
        assert!(callback.contains("return to muniment"));
    }

    #[test]
    fn times_out_when_no_browser_comes_back() {
        let catcher = RedirectCatcher::bind().unwrap();
        let err = catcher
            .wait_for_callback("xyz", Duration::from_millis(80))
            .unwrap_err();
        assert_eq!(err, AuthError::Timeout);
    }
}
