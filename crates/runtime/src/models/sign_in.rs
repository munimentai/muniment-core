//! Account sign-in for a Pi provider: Pi's own OAuth flow runs inside an RPC
//! process the runtime owns, through the engine adapter, and every step
//! reaches clients as a `models.login` event.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use muniment_core::engine::{is_paste_prompt, PiSignIn, SignInPages, SignInStep};
use muniment_core::serde_json::{json, Value};

use super::{providers, router, ModelService};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const ACCOUNT_PROVIDERS: [&str; 5] = [
    "openai-codex",
    "xai",
    "openrouter",
    "github-copilot",
    "anthropic",
];
pub(super) const START_ERROR: &str = "The sign-in could not start. Try again.";
/// The provider whose OAuth redirect lands on a fixed local port, and that port.
/// The runtime holds the port first, so the browser lands on its own page and
/// the code reaches Pi through its paste prompt.
const CALLBACK_PROVIDER: &str = "openai-codex";
const CALLBACK_PORT: u16 = 1455;
const CALLBACK_PATH: &str = "/auth/callback";

struct ActiveLogin {
    sign_in: PiSignIn,
    generation: u64,
    callback: Option<Arc<Callback>>,
    /// The callback servers, one per loopback address the port is held on.
    servers: Vec<JoinHandle<()>>,
}

/// The redirect the runtime's callback page received and the paste prompt Pi
/// opened for it. Whichever arrives second sends the redirect to Pi.
#[derive(Default)]
struct Callback {
    stop: AtomicBool,
    state: Mutex<CallbackState>,
}

#[derive(Default)]
struct CallbackState {
    redirect: Option<String>,
    prompt_id: Option<String>,
    answered: bool,
}

impl Callback {
    /// Records one side and returns the prompt answer once both sides are known.
    fn take_answer(
        &self,
        redirect: Option<String>,
        prompt_id: Option<String>,
    ) -> Option<(String, String)> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if redirect.is_some() {
            state.redirect = redirect;
        }
        if prompt_id.is_some() {
            state.prompt_id = prompt_id;
        }
        if state.answered {
            return None;
        }
        let answer = match (&state.prompt_id, &state.redirect) {
            (Some(id), Some(url)) => Some((id.clone(), url.clone())),
            _ => None,
        };
        state.answered = answer.is_some();
        answer
    }
}

pub(super) fn provider_display_name(provider: &str) -> &str {
    match provider {
        "openai-codex" => "OpenAI",
        "xai" => "xAI",
        "openrouter" => "OpenRouter",
        "github-copilot" => "GitHub Copilot",
        "anthropic" => "Anthropic",
        other => other,
    }
}

/// The redirect URL for a request line that hits the callback path with a code, else nothing.
fn callback_redirect(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    let (path, query) = target.split_once('?')?;
    if path != CALLBACK_PATH
        || !query
            .split('&')
            .any(|pair| pair.starts_with("code=") && pair.len() > "code=".len())
    {
        return None;
    }
    Some(format!("http://localhost:{CALLBACK_PORT}{target}"))
}

pub(super) fn write_response(stream: &mut TcpStream, status: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

/// The sign-ins in flight: Pi's, with its prompt answers, and the generation
/// that tells a finished sign-in from the one that replaced it.
#[derive(Default)]
pub(super) struct SignInState {
    active: Mutex<Option<ActiveLogin>>,
    generation: Mutex<u64>,
}

impl SignInState {
    pub(super) fn stop(&self) {
        let login = self.active.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(login) = login {
            close(login);
        }
    }

    /// Answers Pi's paste prompt with the redirect once both are known.
    fn deliver_callback(&self, generation: u64, answer: Option<(String, String)>) {
        let Some((id, url)) = answer else {
            return;
        };
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(login) = active
            .as_mut()
            .filter(|login| login.generation == generation)
        {
            let _ = login.sign_in.answer(&id, Some(url), None);
        }
    }

    /// Takes the sign-in of `generation` when it is still the active one.
    fn take(&self, generation: u64) -> Option<ActiveLogin> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active
            .as_ref()
            .is_some_and(|login| login.generation == generation)
        {
            active.take()
        } else {
            None
        }
    }
}

fn serve_callback(
    listener: TcpListener,
    callback: Arc<Callback>,
    service: Arc<ModelService>,
    provider: String,
    generation: u64,
) {
    let _ = listener.set_nonblocking(true);
    while !callback.stop.load(Ordering::SeqCst) {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(_) => break,
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
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
        let redirect = text.lines().next().and_then(callback_redirect);
        match redirect {
            Some(url) => {
                write_response(
                    &mut stream,
                    "200 OK",
                    &service.sign_in_page(Some(provider_display_name(&provider))),
                );
                service
                    .sign_ins
                    .deliver_callback(generation, callback.take_answer(Some(url), None));
            }
            None => write_response(&mut stream, "404 Not Found", &service.sign_in_page(None)),
        }
    }
}

/// Ends one sign-in: the callback servers stop, Pi exits, and the listeners
/// close with their threads, so the next sign-in binds the port at once. It
/// runs outside the state lock, because a server mid-redirect takes that lock.
fn close(mut login: ActiveLogin) {
    if let Some(callback) = &login.callback {
        callback.stop.store(true, Ordering::SeqCst);
    }
    login.sign_in.stop();
    for server in login.servers.drain(..) {
        let _ = server.join();
    }
}

/// Holds the callback port on both loopback addresses, so the browser's
/// `localhost` redirect lands here whichever one it resolves first. A wildcard
/// listener of another program yields to the specific bind, a program on the
/// loopback itself is named, and a host without an IPv6 loopback keeps the
/// IPv4 one alone.
fn bind_callback(port: u16) -> Result<Vec<TcpListener>, String> {
    let mut listeners = Vec::new();
    for address in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        match TcpListener::bind((address, port)) {
            Ok(listener) => listeners.push(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(port_error(port));
            }
            Err(_) => {}
        }
    }
    if listeners.is_empty() {
        return Err(port_error(port));
    }
    Ok(listeners)
}

fn port_error(port: u16) -> String {
    format!("Port {port} is in use by another program. Stop it and try again, or use an API key.")
}

/// Where a sign-in lands. Pi's own slot holds one account per provider; the
/// router's pool holds many, so a pool sign-in runs Pi in a directory of its
/// own and the credential is lifted from there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// Pi's `auth.json`, as one provider's single account.
    Pi,
    /// The router's pool, as one more account of the provider's family.
    Pool,
}

/// Starts the Connect list's sign-in.
pub(super) fn start(service: &Arc<ModelService>, provider: &str) -> Result<(), String> {
    if target_for(provider) == Target::Pool {
        start_into_pool(service, provider)
    } else {
        start_with(service, provider, Target::Pi)
    }
}

/// Where the Connect list's sign-in lands: the pool for a family the router
/// pools, so the account gets its card with what it has served, and Pi's own
/// slot for a provider the router does not pool.
fn target_for(provider: &str) -> Target {
    if muniment_core::model_router::family::family_for_pi_provider(provider).is_some() {
        Target::Pool
    } else {
        Target::Pi
    }
}

/// A sign-in whose credential joins the router's pool.
pub(super) fn start_into_pool(service: &Arc<ModelService>, provider: &str) -> Result<(), String> {
    if muniment_core::model_router::family::family_for_pi_provider(provider).is_none() {
        return Err("This provider has no subscription the router can pool.".into());
    }
    // Kimi, Antigravity and Devin have no Pi sign-in. The router runs its own.
    if muniment_core::model_router::family::native_sign_in(provider) {
        service.sign_ins.stop();
        return super::pool_sign_in::start(service, provider);
    }
    start_with(service, provider, Target::Pool)
}

fn start_with(service: &Arc<ModelService>, provider: &str, target: Target) -> Result<(), String> {
    if !ACCOUNT_PROVIDERS.contains(&provider) {
        return Err("This provider has no account sign-in.".into());
    }
    let state = &service.sign_ins;
    state.stop();
    // A pool sign-in runs Pi in a directory of its own, so the credential
    // never lands in Pi's one slot for the provider.
    let agent = match target {
        Target::Pi => service.agent.clone(),
        Target::Pool => {
            let scratch = service
                .agent
                .join(format!("pool-login-{}", uuid::Uuid::now_v7()));
            std::fs::create_dir_all(&scratch).map_err(|_| START_ERROR.to_string())?;
            scratch
        }
    };
    // The port is held before Pi starts, so Pi's own callback server yields and
    // its paste prompt carries the redirect the runtime's page received. A
    // port another program holds stops the sign-in here with its number, never
    // with a wait on a redirect that lands elsewhere.
    let listeners = if provider == CALLBACK_PROVIDER {
        bind_callback(CALLBACK_PORT)?
    } else {
        Vec::new()
    };
    let callback = (!listeners.is_empty()).then(|| Arc::new(Callback::default()));
    let (sign_in, steps) = service.engine.start_sign_in(
        &agent,
        provider,
        SignInPages {
            success: service.sign_in_page(Some(provider_display_name(provider))),
            failure: service.sign_in_page(None),
        },
    )?;
    let generation = {
        let mut counter = state.generation.lock().unwrap_or_else(|e| e.into_inner());
        *counter += 1;
        *counter
    };
    *state.active.lock().unwrap_or_else(|e| e.into_inner()) = Some(ActiveLogin {
        sign_in,
        generation,
        callback: callback.clone(),
        servers: Vec::new(),
    });
    if let Some(callback) = callback.clone() {
        let servers: Vec<JoinHandle<()>> = listeners
            .into_iter()
            .map(|listener| {
                let callback = Arc::clone(&callback);
                let server_service = Arc::clone(service);
                let server_provider = provider.to_owned();
                std::thread::spawn(move || {
                    serve_callback(
                        listener,
                        callback,
                        server_service,
                        server_provider,
                        generation,
                    )
                })
            })
            .collect();
        let mut active = state.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(login) = active
            .as_mut()
            .filter(|login| login.generation == generation)
        {
            login.servers = servers;
        }
    }
    let provider = provider.to_owned();
    let reader = Arc::clone(service);
    std::thread::spawn(move || {
        let mut answered = false;
        for step in steps {
            let mut event = match step {
                SignInStep::Event(event) => event,
                SignInStep::Finished => {
                    answered = true;
                    break;
                }
                SignInStep::Other => continue,
            };
            let stage = event
                .get("stage")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let is_paste = event.get("kind").and_then(Value::as_str) == Some("input")
                && event
                    .get("title")
                    .and_then(Value::as_str)
                    .is_some_and(is_paste_prompt);
            if let (Some(callback), true) = (&callback, is_paste) {
                // The runtime's page answers this prompt. The client never sees it.
                let id = event.get("id").and_then(Value::as_str).map(str::to_owned);
                reader
                    .sign_ins
                    .deliver_callback(generation, callback.take_answer(None, id));
                continue;
            }
            if stage == "done" {
                match target {
                    Target::Pi => {
                        let _ = providers::adopt_provider_default(
                            &agent,
                            &reader.engine,
                            &provider,
                            true,
                        );
                    }
                    Target::Pool => {
                        match router::import_pi_sign_in(
                            &reader.agent,
                            &reader.router,
                            &agent,
                            &provider,
                        ) {
                            Ok(account) => {
                                if let Some(object) = event.as_object_mut() {
                                    object.insert("pool".into(), true.into());
                                    object.insert("account".into(), account.into());
                                }
                            }
                            Err(message) => {
                                event =
                                    json!({ "stage": "failed", "message": message, "pool": true });
                            }
                        }
                    }
                }
            }
            if let Some(object) = event.as_object_mut() {
                object.insert("provider".into(), provider.clone().into());
            }
            reader.emit(event);
        }
        if let Some(login) = reader.sign_ins.take(generation) {
            close(login);
            reader.emit(json!({ "stage": "exit", "provider": provider, "answered": answered }));
        }
        if target == Target::Pool {
            // The scratch directory held one credential for one sign-in, and
            // the pool holds it now.
            let _ = std::fs::remove_dir_all(&agent);
        }
    });
    let watchdog = Arc::clone(service);
    std::thread::spawn(move || {
        std::thread::sleep(LOGIN_TIMEOUT);
        if let Some(login) = watchdog.sign_ins.take(generation) {
            close(login);
        }
    });
    Ok(())
}

pub(super) fn answer(
    state: &SignInState,
    id: &str,
    value: Option<String>,
    confirmed: Option<bool>,
) -> Result<(), String> {
    let mut active = state.active.lock().unwrap_or_else(|e| e.into_inner());
    let login = active
        .as_mut()
        .ok_or("No sign-in is waiting for an answer.")?;
    login
        .sign_in
        .answer(id, value, confirmed)
        .map_err(|_| "The sign-in stopped. Start it again.".to_string())
}

pub(super) fn cancel(service: &ModelService) {
    service.sign_ins.stop();
    service.pool_sign_ins.stop();
    service.emit(json!({ "stage": "cancelled" }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_redirect_parses_only_on_the_callback_path_with_a_code() {
        assert_eq!(
            callback_redirect("GET /auth/callback?code=ac_1&state=s HTTP/1.1"),
            Some("http://localhost:1455/auth/callback?code=ac_1&state=s".to_owned())
        );
        assert_eq!(
            callback_redirect("GET /auth/callback?state=s HTTP/1.1"),
            None
        );
        assert_eq!(callback_redirect("GET /favicon.ico HTTP/1.1"), None);
        assert_eq!(
            callback_redirect("POST /auth/callback?code=x HTTP/1.1"),
            None
        );
    }

    #[test]
    fn the_paste_prompt_answers_once_both_sides_are_known() {
        let callback = Callback::default();
        assert_eq!(callback.take_answer(None, Some("i1".into())), None);
        assert_eq!(
            callback.take_answer(
                Some("http://localhost:1455/auth/callback?code=c".into()),
                None
            ),
            Some((
                "i1".into(),
                "http://localhost:1455/auth/callback?code=c".into()
            ))
        );
        assert_eq!(callback.take_answer(None, Some("i1".into())), None);
    }

    #[test]
    fn the_callback_port_is_held_on_both_loopbacks_and_a_holder_is_named() {
        let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let listeners = bind_callback(port).unwrap();
        let addresses: Vec<IpAddr> = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap().ip())
            .collect();
        assert_eq!(addresses[0], IpAddr::V4(Ipv4Addr::LOCALHOST));
        if let Some(second) = addresses.get(1) {
            assert_eq!(*second, IpAddr::V6(Ipv6Addr::LOCALHOST));
        }
        assert!(listeners
            .iter()
            .all(|listener| listener.local_addr().unwrap().port() == port));
        drop(listeners);
        let holder = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let error = bind_callback(port).unwrap_err();
        assert!(error.contains(&port.to_string()), "{error}");
        drop(holder);
    }

    #[test]
    fn a_pooled_family_signs_in_to_the_pool_and_the_rest_to_the_one_slot() {
        assert_eq!(target_for("xai"), Target::Pool);
        assert_eq!(target_for("openai-codex"), Target::Pool);
        assert_eq!(target_for("openrouter"), Target::Pi);
        assert_eq!(target_for("github-copilot"), Target::Pi);
    }

    #[test]
    fn only_account_providers_start_a_sign_in() {
        assert!(ACCOUNT_PROVIDERS.contains(&"openai-codex"));
        assert!(ACCOUNT_PROVIDERS.contains(&"xai"));
        assert!(!ACCOUNT_PROVIDERS.contains(&"google"));
    }

    #[test]
    fn an_answer_without_a_sign_in_names_the_missing_sign_in() {
        let state = SignInState::default();
        assert_eq!(
            answer(&state, "i1", Some("x".into()), None).unwrap_err(),
            "No sign-in is waiting for an answer."
        );
    }
}
