//! The subscription sign-ins the router runs itself, for the providers Pi
//! has no sign-in for: Kimi by device code, Antigravity and Devin through the
//! browser with a loopback redirect. Every step reaches clients as the same
//! `models.login` event Pi's own sign-ins send, and the credential lands in
//! the router's pool as one more account of the provider's family.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use muniment_core::chrono;
use muniment_core::model_router::config::Credential;
use muniment_core::model_router::native_auth::{self, Poll};
use muniment_core::serde_json::{self, json};

use super::sign_in::write_response;
use super::{router, ModelService};

/// How long a sign-in may take before the router gives up on it.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How long one network call may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const START_ERROR: &str = "The sign-in could not start. Try again.";

/// The one sign-in in flight, as the flag that stops it.
#[derive(Default)]
pub(super) struct PoolSignIns(Mutex<Option<Arc<AtomicBool>>>);

impl PoolSignIns {
    /// Stops the sign-in in flight, when there is one.
    pub(super) fn stop(&self) {
        if let Some(flag) = self.0.lock().unwrap_or_else(|e| e.into_inner()).take() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    fn arm(&self) -> Arc<AtomicBool> {
        self.stop();
        let flag = Arc::new(AtomicBool::new(false));
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(flag.clone());
        flag
    }

    /// Forgets the sign-in `flag` stops, when it is still the one in flight.
    fn finish(&self, flag: &Arc<AtomicBool>) {
        let mut active = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if active.as_ref().is_some_and(|held| Arc::ptr_eq(held, flag)) {
            *active = None;
        }
    }
}

fn emit(service: &ModelService, provider: &str, mut payload: serde_json::Value) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("provider".into(), provider.into());
    }
    service.emit(payload);
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Starts the router's own sign-in for one of its native providers.
pub(super) fn start(service: &Arc<ModelService>, provider: &str) -> Result<(), String> {
    if !muniment_core::model_router::family::native_sign_in(provider) {
        return Err("This provider has no subscription the router can pool.".into());
    }
    let flag = service.pool_sign_ins.arm();
    let app = Arc::clone(service);
    let provider = provider.to_owned();
    emit(&app, &provider, json!({ "stage": "start" }));
    std::thread::Builder::new()
        .name(format!("pool-login-{provider}"))
        .spawn(move || {
            let outcome = match provider.as_str() {
                "kimi" => kimi(&app, &flag),
                "meta" => muse(&app, &flag),
                "antigravity" => antigravity(&app, &flag),
                "devin" => devin(&app, &flag),
                _ => Err("This provider has no subscription the router can pool.".into()),
            };
            if flag.load(Ordering::SeqCst) {
                // A cancel already told the shell. Nothing more to say.
                return;
            }
            match outcome {
                Ok((credential, name)) => {
                    match router::import_credential(
                        &app.agent,
                        &app.router,
                        &provider,
                        credential,
                        name,
                    ) {
                        Ok(account) => emit(
                            &app,
                            &provider,
                            json!({ "stage": "done", "type": "oauth", "pool": true, "account": account }),
                        ),
                        Err(message) => emit(
                            &app,
                            &provider,
                            json!({ "stage": "failed", "message": message, "pool": true }),
                        ),
                    }
                }
                Err(message) => emit(&app, &provider, json!({ "stage": "failed", "message": message })),
            }
            app.pool_sign_ins.finish(&flag);
            emit(&app, &provider, json!({ "stage": "exit", "answered": true }));
        })
        .map_err(|_| START_ERROR.to_string())?;
    Ok(())
}

/// Waits `interval` while watching the stop flag. Answers whether to go on.
fn wait(flag: &AtomicBool, interval: Duration) -> bool {
    let until = Instant::now() + interval;
    while Instant::now() < until {
        if flag.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    !flag.load(Ordering::SeqCst)
}

/// Kimi's device flow: show the code, poll the token endpoint until the user
/// has typed it on the page.
fn kimi(app: &ModelService, flag: &AtomicBool) -> Result<(Credential, Option<String>), String> {
    let device_id = uuid::Uuid::new_v4().to_string();
    let code = native_auth::kimi_device_code(native_auth::KIMI_AUTH_URL, &device_id, CALL_TIMEOUT)?;
    emit(
        app,
        "kimi",
        json!({ "stage": "event", "event": {
            "type": "device_code",
            "userCode": code.user_code,
            "verificationUri": code.verification_uri,
            "verificationUriComplete": code.verification_uri_complete,
        } }),
    );
    let deadline =
        Instant::now() + SIGN_IN_TIMEOUT.min(Duration::from_secs(code.expires_in.max(60)));
    let interval = Duration::from_secs(code.interval);
    while Instant::now() < deadline {
        if !wait(flag, interval) {
            return Err("The sign-in was cancelled.".into());
        }
        match native_auth::kimi_poll(
            native_auth::KIMI_AUTH_URL,
            &device_id,
            &code.device_code,
            now_ms(),
            CALL_TIMEOUT,
        )? {
            Poll::Pending => continue,
            Poll::Granted(credential) => return Ok((credential, None)),
            Poll::Refused(message) => return Err(message),
        }
    }
    Err("The Kimi code expired before the sign-in finished. Start again.".into())
}

fn muse(app: &ModelService, flag: &AtomicBool) -> Result<(Credential, Option<String>), String> {
    let code = native_auth::muse_device_code(native_auth::MUSE_DEVICE_URL, CALL_TIMEOUT)?;
    emit(
        app,
        "meta",
        json!({"stage":"event", "event": {
            "type":"device_code", "userCode":code.user_code,
            "verificationUri":code.verification_uri,
            "verificationUriComplete":code.verification_uri_complete,
        }}),
    );
    let deadline = Instant::now() + SIGN_IN_TIMEOUT.min(Duration::from_secs(code.expires_in));
    let mut interval = Duration::from_secs(code.interval);
    while Instant::now() < deadline {
        if !wait(flag, interval) {
            return Err("The sign-in was cancelled.".into());
        }
        match native_auth::muse_poll(
            native_auth::MUSE_TOKEN_URL,
            native_auth::MUSE_MINT_URL,
            &code.device_code,
            CALL_TIMEOUT,
        )? {
            native_auth::MusePoll::Pending => {}
            native_auth::MusePoll::SlowDown => interval += Duration::from_secs(5),
            native_auth::MusePoll::Granted(credential) => return Ok((credential, None)),
        }
    }
    Err("The Muse Code sign-in code expired. Start again.".into())
}

/// The code a browser redirect carried, once it lands on the listener with
/// the state the sign-in issued. The page the browser shows is muniment's.
fn await_code(
    service: &ModelService,
    listener: &TcpListener,
    path: &str,
    state: &str,
    provider_name: &str,
    flag: &AtomicBool,
) -> Result<String, String> {
    let _ = listener.set_nonblocking(true);
    let deadline = Instant::now() + SIGN_IN_TIMEOUT;
    while Instant::now() < deadline {
        if flag.load(Ordering::SeqCst) {
            return Err("The sign-in was cancelled.".into());
        }
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(_) => return Err("The sign-in page could not listen for the browser.".into()),
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        match redirect_code(&mut stream, path, state) {
            Some(Ok(code)) => {
                write_response(
                    &mut stream,
                    "200 OK",
                    &service.sign_in_page(Some(provider_name)),
                );
                return Ok(code);
            }
            Some(Err(message)) => {
                write_response(&mut stream, "400 Bad Request", &service.sign_in_page(None));
                return Err(message);
            }
            None => write_response(&mut stream, "404 Not Found", &service.sign_in_page(None)),
        }
    }
    Err("The browser did not come back before the sign-in timed out.".into())
}

/// The code in a redirect request, when the request line hits the callback
/// path. A wrong state or a provider error is a refusal, another path is
/// nothing.
fn redirect_code(
    stream: &mut TcpStream,
    path: &str,
    state: &str,
) -> Option<Result<String, String>> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while request.len() < 16 * 1024 {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&request);
    let line = text.lines().next()?;
    parse_redirect(line, path, state)
}

/// The code in one request line, checked against the callback path and state.
fn parse_redirect(request_line: &str, path: &str, state: &str) -> Option<Result<String, String>> {
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    let (target_path, query) = target.split_once('?').unwrap_or((target, ""));
    if target_path != path {
        return None;
    }
    let url = url::Url::parse(&format!("http://localhost{target_path}?{query}")).ok()?;
    let mut code = None;
    let mut got_state = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => got_state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    if let Some(error) = error {
        return Some(Err(format!("The sign-in page answered {error}.")));
    }
    if got_state.as_deref() != Some(state) {
        return Some(Err(
            "The sign-in came back with another state. Start again.".into(),
        ));
    }
    match code.filter(|code| !code.is_empty()) {
        Some(code) => Some(Ok(code)),
        None => Some(Err("The sign-in came back without a code.".into())),
    }
}

/// Antigravity: a Google sign-in on the client's fixed loopback port.
fn antigravity(
    app: &ModelService,
    flag: &AtomicBool,
) -> Result<(Credential, Option<String>), String> {
    let listener = TcpListener::bind(("127.0.0.1", native_auth::ANTIGRAVITY_CALLBACK_PORT))
        .map_err(|_| {
            format!(
                "Port {} is in use, and Google sends the sign-in back there. Close what holds it, then retry.",
                native_auth::ANTIGRAVITY_CALLBACK_PORT
            )
        })?;
    let state = native_auth::state();
    let redirect = native_auth::antigravity_redirect_uri();
    let url = native_auth::antigravity_auth_url(&state, &redirect)?;
    emit(
        app,
        "antigravity",
        json!({ "stage": "event", "event": { "type": "auth_url", "url": url, "instructions": "Sign in with the Google account Antigravity uses. The browser comes back to muniment." } }),
    );
    let code = await_code(
        app,
        &listener,
        native_auth::ANTIGRAVITY_CALLBACK_PATH,
        &state,
        "Antigravity",
        flag,
    )?;
    let mut credential = native_auth::antigravity_exchange(
        native_auth::GOOGLE_TOKEN_URL,
        &code,
        &redirect,
        now_ms(),
        CALL_TIMEOUT,
    )?;
    let access = credential.bearer().to_owned();
    let email = native_auth::google_email(native_auth::GOOGLE_USERINFO_URL, &access, CALL_TIMEOUT);
    let project =
        native_auth::antigravity_project(native_auth::ANTIGRAVITY_LOAD_URL, &access, CALL_TIMEOUT);
    if let Credential::Subscription {
        account_id,
        email: held,
        ..
    } = &mut credential
    {
        *account_id = project;
        *held = email.clone();
    }
    Ok((credential, email))
}

/// Devin: PKCE through its web app, on a loopback port picked for the run.
fn devin(app: &ModelService, flag: &AtomicBool) -> Result<(Credential, Option<String>), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| START_ERROR.to_string())?;
    let port = listener
        .local_addr()
        .map_err(|_| START_ERROR.to_string())?
        .port();
    let redirect = format!(
        "http://127.0.0.1:{port}{}",
        native_auth::DEVIN_CALLBACK_PATH
    );
    let pkce = native_auth::pkce();
    let state = native_auth::state();
    let url = native_auth::devin_auth_url(
        native_auth::DEVIN_APP_URL,
        &redirect,
        &pkce.challenge,
        &state,
    );
    emit(
        app,
        "devin",
        json!({ "stage": "event", "event": { "type": "auth_url", "url": url, "instructions": "Sign in to Devin. The browser comes back to muniment." } }),
    );
    let code = await_code(
        app,
        &listener,
        native_auth::DEVIN_CALLBACK_PATH,
        &state,
        "Devin",
        flag,
    )?;
    let mut credential = native_auth::devin_exchange(
        native_auth::DEVIN_API_URL,
        &code,
        &pkce.verifier,
        CALL_TIMEOUT,
    )?;
    let access = credential.bearer().to_owned();
    let (name, org) = native_auth::devin_profile(native_auth::DEVIN_API_URL, &access, CALL_TIMEOUT)
        .unwrap_or((None, None));
    if let Credential::Subscription { account_id, .. } = &mut credential {
        *account_id = org;
    }
    Ok((credential, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redirect_yields_its_code_only_on_the_callback_path_with_the_state_it_was_given() {
        assert_eq!(
            parse_redirect(
                "GET /callback?code=abc&state=s1 HTTP/1.1",
                "/callback",
                "s1"
            ),
            Some(Ok("abc".into()))
        );
        assert_eq!(
            parse_redirect("GET /favicon.ico HTTP/1.1", "/callback", "s1"),
            None
        );
        assert_eq!(
            parse_redirect(
                "POST /callback?code=abc&state=s1 HTTP/1.1",
                "/callback",
                "s1"
            ),
            None
        );
        assert!(matches!(
            parse_redirect("GET /callback?code=abc&state=other HTTP/1.1", "/callback", "s1"),
            Some(Err(message)) if message.contains("another state")
        ));
        assert!(matches!(
            parse_redirect("GET /callback?error=access_denied&state=s1 HTTP/1.1", "/callback", "s1"),
            Some(Err(message)) if message.contains("access_denied")
        ));
        assert!(matches!(
            parse_redirect("GET /callback?state=s1 HTTP/1.1", "/callback", "s1"),
            Some(Err(message)) if message.contains("without a code")
        ));
        assert_eq!(
            parse_redirect(
                "GET /oauth-callback?state=s1&code=4%2F0A HTTP/1.1",
                "/oauth-callback",
                "s1"
            ),
            Some(Ok("4/0A".into()))
        );
    }

    #[test]
    fn a_stop_flag_ends_the_wait_and_arms_a_new_flag() {
        let sign_ins = PoolSignIns::default();
        let first = sign_ins.arm();
        let second = sign_ins.arm();
        assert!(first.load(Ordering::SeqCst));
        assert!(!second.load(Ordering::SeqCst));
        assert!(!wait(&first, Duration::from_millis(10)));
        assert!(wait(&second, Duration::from_millis(10)));
        sign_ins.stop();
        assert!(second.load(Ordering::SeqCst));
    }
}
