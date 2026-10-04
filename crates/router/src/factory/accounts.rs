//! `muniment-router accounts …`: the account pool from a terminal.
//!
//! Every command writes to the configured store and secret source, the same
//! ones the server reads, so a running server sees a change on its next turn.

use std::io::{BufRead, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::config::{Account, Credential};
use crate::family;
use crate::native_auth::{self, MusePoll, Poll};
use crate::store::Backend;

const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

pub const USAGE: &str = "\
muniment-router accounts list
muniment-router accounts add-key <family> [--label L] [--base-url URL] [--models a,b] [--weight N]
    The key is read from MUNIMENT_ROUTER_ACCOUNT_KEY, or else from the first line of stdin.
muniment-router accounts login <family> [--label L]
    openai, anthropic and xai sign in through Pi; kimi and meta by device code;
    google (Antigravity) and devin through a browser on this machine.
muniment-router accounts import-pi-auth <auth.json> [--provider P] [--label L]
muniment-router accounts set-weight <id> <weight>
muniment-router accounts disable <id>
muniment-router accounts enable <id>
muniment-router accounts remove <id>
muniment-router accounts probe [<id>]";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Splits `--name value` options from positional arguments.
fn options(
    args: &[String],
) -> Result<(Vec<String>, std::collections::BTreeMap<String, String>), String> {
    let mut positional = Vec::new();
    let mut named = std::collections::BTreeMap::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            let value = iter
                .next()
                .ok_or_else(|| format!("--{name} needs a value."))?;
            named.insert(name.to_owned(), value.clone());
        } else {
            positional.push(arg.clone());
        }
    }
    Ok((positional, named))
}

/// Runs one `accounts` command.
pub fn run(backend: &Backend, args: &[String], out: &mut dyn Write) -> Result<(), String> {
    let (positional, named) = options(args)?;
    let word = |index: usize| positional.get(index).map(String::as_str);
    let label = named.get("label").cloned();
    match (word(0), word(1)) {
        (Some("list"), None) => list(backend, out),
        (Some("add-key"), Some(family)) => {
            let key = match std::env::var("MUNIMENT_ROUTER_ACCOUNT_KEY") {
                Ok(key) => key,
                Err(_) => {
                    let mut line = String::new();
                    std::io::stdin()
                        .lock()
                        .read_line(&mut line)
                        .map_err(|e| e.to_string())?;
                    line
                }
            };
            let weight = named
                .get("weight")
                .map(|weight| {
                    weight
                        .parse::<u32>()
                        .map_err(|_| "--weight is not a whole number.")
                })
                .transpose()?;
            let id = add_key(
                backend,
                family,
                key.trim(),
                label,
                named.get("base-url").cloned(),
                named
                    .get("models")
                    .map(|models| {
                        models
                            .split(',')
                            .map(str::trim)
                            .filter(|m| !m.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                weight.unwrap_or(1),
            )?;
            writeln!(out, "Added {id}.").map_err(|e| e.to_string())
        }
        (Some("login"), Some(family)) => {
            let id = login(backend, family, label, out)?;
            writeln!(out, "Signed in as {id}.").map_err(|e| e.to_string())
        }
        (Some("import-pi-auth"), Some(path)) => {
            let ids = import_pi_auth(
                backend,
                Path::new(path),
                named.get("provider").map(String::as_str),
                label,
            )?;
            if ids.is_empty() {
                return Err("The file holds no sign-in the router can pool.".into());
            }
            writeln!(out, "Imported {}.", ids.join(", ")).map_err(|e| e.to_string())
        }
        (Some("set-weight"), Some(id)) => {
            let weight: u32 = word(2)
                .ok_or("set-weight needs a weight.")?
                .parse()
                .map_err(|_| "The weight is not a whole number.")?;
            update(backend, id, |account| account.weight = weight)?;
            writeln!(out, "{id} now has weight {weight}.").map_err(|e| e.to_string())
        }
        (Some("disable"), Some(id)) => {
            update(backend, id, |account| account.enabled = false)?;
            writeln!(out, "{id} is off.").map_err(|e| e.to_string())
        }
        (Some("enable"), Some(id)) => {
            update(backend, id, |account| account.enabled = true)?;
            writeln!(out, "{id} is on.").map_err(|e| e.to_string())
        }
        (Some("remove"), Some(id)) => {
            find(backend, id)?;
            backend.remove_account(id).map_err(|e| e.to_string())?;
            writeln!(out, "Removed {id}.").map_err(|e| e.to_string())
        }
        (Some("probe"), only) => {
            for (id, result) in super::probe_quotas(backend, only) {
                match result {
                    Ok(quota) => {
                        let headline = quota
                            .headline()
                            .map(|window| {
                                format!(
                                    "{} {:.0}% left",
                                    window.kind.label(),
                                    window.remaining_percent()
                                )
                            })
                            .unwrap_or_else(|| "no window".into());
                        writeln!(out, "{id}: {headline}").map_err(|e| e.to_string())?;
                    }
                    Err(error) => writeln!(out, "{id}: {error}").map_err(|e| e.to_string())?,
                }
            }
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

/// The accounts as the store holds them, without their credentials.
fn find(backend: &Backend, id: &str) -> Result<Account, String> {
    backend
        .store
        .load_config()
        .map_err(|e| e.to_string())?
        .accounts
        .into_iter()
        .find(|account| account.id == id)
        .ok_or_else(|| format!("No account has the id {id}."))
}

fn update(backend: &Backend, id: &str, change: impl FnOnce(&mut Account)) -> Result<(), String> {
    let mut account = find(backend, id)?;
    change(&mut account);
    backend
        .store
        .upsert_account(&account)
        .map_err(|e| e.to_string())
}

fn list(backend: &Backend, out: &mut dyn Write) -> Result<(), String> {
    let config = backend.store.load_config().map_err(|e| e.to_string())?;
    let ledger = backend.store.load_ledger();
    let quotas = backend.store.load_quotas();
    let now = now_ms();
    let mut write = |line: String| writeln!(out, "{line}").map_err(|e| e.to_string());
    write(format!(
        "{:<38} {:<10} {:<20} {:<14} {:<4} {:>6} {:<8} {:>9} {}",
        "ID", "FAMILY", "LABEL", "SOURCE", "ON", "WEIGHT", "SECRET", "REQUESTS", "STATE"
    ))?;
    for account in &config.accounts {
        let source = account.credential.pi_provider().unwrap_or("api key");
        let secret = match backend.secrets.read(&account.id) {
            Ok(Some(_)) => "ok",
            Ok(None) => "missing",
            Err(_) => "error",
        };
        let usage = ledger.account(&account.id);
        let state = match usage
            .and_then(|usage| usage.cooldown_until_ms)
            .filter(|until| *until > now)
        {
            Some(until) => format!("cooling {}s", (until - now) / 1000),
            None => quotas
                .accounts
                .get(&account.id)
                .and_then(|quota| quota.headline())
                .map(|window| format!("{:.0}% left", window.remaining_percent()))
                .unwrap_or_else(|| "ready".into()),
        };
        write(format!(
            "{:<38} {:<10} {:<20} {:<14} {:<4} {:>6} {:<8} {:>9} {}",
            account.id,
            account.family,
            account.label.chars().take(20).collect::<String>(),
            source,
            if account.enabled { "yes" } else { "no" },
            account.weight,
            secret,
            usage.map(|usage| usage.requests).unwrap_or(0),
            state
        ))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn add_key(
    backend: &Backend,
    family_id: &str,
    key: &str,
    label: Option<String>,
    base_url: Option<String>,
    models: Vec<String>,
    weight: u32,
) -> Result<String, String> {
    let family =
        family::family(family_id).ok_or_else(|| format!("{family_id} is not a pooled family."))?;
    if key.is_empty() {
        return Err("The key is empty.".into());
    }
    let account = Account {
        id: uuid::Uuid::now_v7().to_string(),
        family: family.id.into(),
        label: label.unwrap_or_else(|| format!("{} key", family.name)),
        credential: Credential::ApiKey { key: key.into() },
        base_url,
        models,
        enabled: true,
        weight,
    };
    backend.save_account(&account).map_err(|e| e.to_string())?;
    Ok(account.id)
}

/// Adds a subscription, or refreshes the credential of the account that
/// already holds the same subscription and keeps its id and settings.
pub fn import(
    backend: &Backend,
    family_id: &str,
    credential: Credential,
    label: Option<String>,
) -> Result<String, String> {
    let config = backend.store.load_config().map_err(|e| e.to_string())?;
    if let Some(existing) = config
        .accounts
        .iter()
        .find(|account| account.credential.same_subscription(&credential))
    {
        let mut account = existing.clone();
        account.credential = credential;
        if let Some(label) = label {
            account.label = label;
        }
        backend.save_account(&account).map_err(|e| e.to_string())?;
        return Ok(account.id);
    }
    let family =
        family::family(family_id).ok_or_else(|| format!("{family_id} is not a pooled family."))?;
    let label = label
        .or_else(|| match &credential {
            Credential::Subscription {
                email: Some(email), ..
            } => Some(email.clone()),
            _ => None,
        })
        .unwrap_or_else(|| format!("{} account", family.name));
    let account = Account {
        id: uuid::Uuid::now_v7().to_string(),
        family: family.id.into(),
        label,
        credential,
        base_url: None,
        models: Vec::new(),
        enabled: true,
        weight: 1,
    };
    backend.save_account(&account).map_err(|e| e.to_string())?;
    Ok(account.id)
}

/// Imports every sign-in from a Pi `auth.json` whose provider the router
/// pools, or only `provider`'s.
pub fn import_pi_auth(
    backend: &Backend,
    path: &Path,
    provider: Option<&str>,
    label: Option<String>,
) -> Result<Vec<String>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let entries: serde_json::Map<String, Value> = serde_json::from_str(&text)
        .map_err(|_| format!("{} is not a Pi auth.json.", path.display()))?;
    let mut ids = Vec::new();
    for (pi, entry) in &entries {
        if provider.is_some_and(|wanted| wanted != pi) {
            continue;
        }
        if let Some(family) = family::family_for_pi_provider(pi) {
            if let Some(credential) = Credential::from_pi_auth(pi, entry) {
                ids.push(import(backend, family.id, credential, label.clone())?);
                continue;
            }
        }
        // A pasted key under a family's own id joins that family's pool.
        if entry["type"] == "api_key" {
            if let (Some(family), Some(key)) = (family::family(pi), entry["key"].as_str()) {
                ids.push(add_key(
                    backend,
                    family.id,
                    key,
                    label.clone(),
                    None,
                    Vec::new(),
                    1,
                )?);
            }
        }
    }
    Ok(ids)
}

/// The Pi provider or native flow a `login` argument names.
fn sign_in(name: &str) -> Option<&'static str> {
    Some(match name {
        "openai" | "openai-codex" => "openai-codex",
        "anthropic" => "anthropic",
        "xai" => "xai",
        "kimi" => "kimi",
        "google" | "antigravity" => "antigravity",
        "devin" => "devin",
        "meta" | "muse" => "meta",
        _ => return None,
    })
}

fn login(
    backend: &Backend,
    name: &str,
    label: Option<String>,
    out: &mut dyn Write,
) -> Result<String, String> {
    let provider =
        sign_in(name).ok_or_else(|| format!("{name} has no sign-in the router can pool."))?;
    let family =
        family::family_for_pi_provider(provider).ok_or("This provider pools into no family.")?;
    let say =
        |out: &mut dyn Write, text: String| writeln!(out, "{text}").map_err(|e| e.to_string());
    let (credential, name) = match provider {
        "kimi" => {
            let device = uuid::Uuid::new_v4().to_string();
            let code =
                native_auth::kimi_device_code(native_auth::KIMI_AUTH_URL, &device, CALL_TIMEOUT)?;
            say(
                out,
                format!(
                    "Open {} and enter {}.",
                    code.verification_uri_complete, code.user_code
                ),
            )?;
            let deadline =
                Instant::now() + SIGN_IN_TIMEOUT.min(Duration::from_secs(code.expires_in.max(60)));
            loop {
                if Instant::now() >= deadline {
                    return Err("The Kimi code expired before the sign-in finished.".into());
                }
                std::thread::sleep(Duration::from_secs(code.interval));
                match native_auth::kimi_poll(
                    native_auth::KIMI_AUTH_URL,
                    &device,
                    &code.device_code,
                    now_ms(),
                    CALL_TIMEOUT,
                )? {
                    Poll::Pending => continue,
                    Poll::Granted(credential) => break (credential, None),
                    Poll::Refused(message) => return Err(message),
                }
            }
        }
        "meta" => {
            let code = native_auth::muse_device_code(native_auth::MUSE_DEVICE_URL, CALL_TIMEOUT)?;
            say(
                out,
                format!(
                    "Open {} and enter {}.",
                    code.verification_uri_complete, code.user_code
                ),
            )?;
            let deadline =
                Instant::now() + SIGN_IN_TIMEOUT.min(Duration::from_secs(code.expires_in));
            let mut interval = Duration::from_secs(code.interval);
            loop {
                if Instant::now() >= deadline {
                    return Err("The Muse Code sign-in code expired.".into());
                }
                std::thread::sleep(interval);
                match native_auth::muse_poll(
                    native_auth::MUSE_TOKEN_URL,
                    native_auth::MUSE_MINT_URL,
                    &code.device_code,
                    CALL_TIMEOUT,
                )? {
                    MusePoll::Pending => {}
                    MusePoll::SlowDown => interval += Duration::from_secs(5),
                    MusePoll::Granted(credential) => break (credential, None),
                }
            }
        }
        "antigravity" => {
            let port = native_auth::ANTIGRAVITY_CALLBACK_PORT;
            let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|_| {
                format!("Port {port} is in use, and Google sends the sign-in back there.")
            })?;
            let state = native_auth::state();
            let redirect = native_auth::antigravity_redirect_uri();
            let url = native_auth::antigravity_auth_url(&state, &redirect)?;
            say(out, format!("Open this page in a browser on this machine, or forward port {port} first (ssh -L {port}:127.0.0.1:{port} <host>):\n{url}"))?;
            let code = await_code(&listener, native_auth::ANTIGRAVITY_CALLBACK_PATH, &state)?;
            let mut credential = native_auth::antigravity_exchange(
                native_auth::GOOGLE_TOKEN_URL,
                &code,
                &redirect,
                now_ms(),
                CALL_TIMEOUT,
            )?;
            let access = credential.bearer().to_owned();
            let email =
                native_auth::google_email(native_auth::GOOGLE_USERINFO_URL, &access, CALL_TIMEOUT);
            let project = native_auth::antigravity_project(
                native_auth::ANTIGRAVITY_LOAD_URL,
                &access,
                CALL_TIMEOUT,
            );
            if let Credential::Subscription {
                account_id,
                email: held,
                ..
            } = &mut credential
            {
                *account_id = project;
                *held = email.clone();
            }
            (credential, email)
        }
        "devin" => {
            let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
            let port = listener.local_addr().map_err(|e| e.to_string())?.port();
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
            say(out, format!("Open this page in a browser on this machine, or forward port {port} first (ssh -L {port}:127.0.0.1:{port} <host>):\n{url}"))?;
            let code = await_code(&listener, native_auth::DEVIN_CALLBACK_PATH, &state)?;
            let mut credential = native_auth::devin_exchange(
                native_auth::DEVIN_API_URL,
                &code,
                &pkce.verifier,
                CALL_TIMEOUT,
            )?;
            let access = credential.bearer().to_owned();
            let (name, org) =
                native_auth::devin_profile(native_auth::DEVIN_API_URL, &access, CALL_TIMEOUT)
                    .unwrap_or((None, None));
            if let Credential::Subscription { account_id, .. } = &mut credential {
                *account_id = org;
            }
            (credential, name)
        }
        _ => return pi_login(backend, provider, label, out),
    };
    import(backend, family.id, credential, label.or(name))
}

/// Pi's own sign-in, run interactively in a scratch agent directory. The
/// credential Pi writes to that directory's `auth.json` joins the pool and the
/// directory is removed.
fn pi_login(
    backend: &Backend,
    provider: &str,
    label: Option<String>,
    out: &mut dyn Write,
) -> Result<String, String> {
    let scratch =
        std::env::temp_dir().join(format!("muniment-router-login-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700));
    }
    let pi = std::env::var("MUNIMENT_ROUTER_PI").unwrap_or_else(|_| "pi".into());
    writeln!(
        out,
        "Pi starts now. Run /login, choose {provider}, finish the sign-in, then quit Pi."
    )
    .map_err(|e| e.to_string())?;
    let status = std::process::Command::new(&pi)
        .env("PI_CODING_AGENT_DIR", &scratch)
        .current_dir(&scratch)
        .status()
        .map_err(|error| format!("{pi} could not start: {error}"));
    let imported = status.and_then(|_| {
        let written = scratch.join("auth.json");
        if !written.exists() {
            return Err("Pi wrote no sign-in.".into());
        }
        import_pi_auth(backend, &written, Some(provider), label)
    });
    let _ = std::fs::remove_dir_all(&scratch);
    imported?
        .into_iter()
        .next()
        .ok_or_else(|| format!("Pi wrote no {provider} sign-in."))
}

/// Waits for the browser to land on `path` with `state`, and answers its code.
fn await_code(listener: &TcpListener, path: &str, state: &str) -> Result<String, String> {
    let deadline = Instant::now() + SIGN_IN_TIMEOUT;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    while Instant::now() < deadline {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut request = vec![0_u8; 16 * 1024];
        let read = stream.read(&mut request).unwrap_or(0);
        let line = String::from_utf8_lossy(&request[..read])
            .lines()
            .next()
            .unwrap_or("")
            .to_owned();
        let answer = redirect_code(&line, path, state);
        let page = match &answer {
            Some(Ok(_)) => "Signed in. This window can close.",
            Some(Err(_)) => "The sign-in did not finish. Return to the terminal.",
            None => "Not found.",
        };
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}",
            page.len()
        );
        if let Some(answer) = answer {
            return answer;
        }
    }
    Err("The browser did not come back before the sign-in timed out.".into())
}

/// The code in one redirect request line, checked against the path and state.
fn redirect_code(line: &str, path: &str, state: &str) -> Option<Result<String, String>> {
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    let url = url::Url::parse(&format!("http://localhost{target}")).ok()?;
    if url.path() != path {
        return None;
    }
    let pair = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if let Some(error) = pair("error") {
        return Some(Err(format!("The sign-in page answered {error}.")));
    }
    if pair("state").as_deref() != Some(state) {
        return Some(Err("The sign-in came back with another state.".into()));
    }
    Some(
        pair("code")
            .filter(|code| !code.is_empty())
            .ok_or_else(|| "The sign-in came back without a code.".to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> (Backend, std::path::PathBuf) {
        let agent =
            std::env::temp_dir().join(format!("muniment-accounts-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&agent).unwrap();
        (Backend::files(&agent), agent)
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn keys_weights_switches_and_removal_reach_the_store() {
        let (backend, agent) = backend();
        let id = add_key(
            &backend,
            "openai",
            "sk-1",
            None,
            None,
            vec!["gpt-5.6-sol".into()],
            2,
        )
        .unwrap();
        assert!(add_key(&backend, "nobody", "sk", None, None, Vec::new(), 1).is_err());
        let mut out = Vec::new();
        run(&backend, &args(&format!("set-weight {id} 5")), &mut out).unwrap();
        run(&backend, &args(&format!("disable {id}")), &mut out).unwrap();
        let account = find(&backend, &id).unwrap();
        assert_eq!(account.weight, 5);
        assert!(!account.enabled);
        assert_eq!(
            account.credential,
            Credential::ApiKey { key: "sk-1".into() }
        );
        run(&backend, &args(&format!("enable {id}")), &mut out).unwrap();
        assert!(find(&backend, &id).unwrap().enabled);
        let mut listing = Vec::new();
        run(&backend, &args("list"), &mut listing).unwrap();
        let listing = String::from_utf8(listing).unwrap();
        assert!(listing.contains(&id));
        assert!(listing.contains("api key"));
        assert!(!listing.contains("sk-1"));
        run(&backend, &args(&format!("remove {id}")), &mut out).unwrap();
        assert!(find(&backend, &id).is_err());
        assert!(run(&backend, &args("remove nope"), &mut out).is_err());
        assert!(run(&backend, &args("frobnicate"), &mut out)
            .unwrap_err()
            .contains("accounts list"));
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_pi_auth_file_imports_once_per_subscription() {
        let (backend, agent) = backend();
        let path = agent.join("auth.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "anthropic": {"type": "oauth", "access": "a1", "refresh": "r1", "expires": 5, "email": "x@example.com"},
                "openai-codex": {"type": "oauth", "access": "c1", "accountId": "acct-1"},
                "openai": {"type": "api_key", "key": "sk-2"},
                "github-copilot": {"type": "oauth", "access": "g"}
            })
            .to_string(),
        )
        .unwrap();
        let ids = import_pi_auth(&backend, &path, None, None).unwrap();
        assert_eq!(ids.len(), 3);
        // A second sign-in to the same subscription refreshes its account.
        std::fs::write(
            &path,
            serde_json::json!({"openai-codex": {"type": "oauth", "access": "c2", "accountId": "acct-1"}}).to_string(),
        )
        .unwrap();
        let again = import_pi_auth(&backend, &path, Some("openai-codex"), None).unwrap();
        let config = backend.config().unwrap();
        assert_eq!(config.accounts.len(), 3);
        let codex = config.account(&again[0]).unwrap();
        assert_eq!(codex.credential.bearer(), "c2");
        assert!(ids.contains(&again[0]));
        assert_eq!(
            config
                .accounts
                .iter()
                .find(|a| a.family == "anthropic")
                .unwrap()
                .label,
            "x@example.com"
        );
        std::fs::remove_dir_all(agent).unwrap();
    }

    #[test]
    fn a_redirect_yields_its_code_only_with_the_right_path_and_state() {
        assert_eq!(
            redirect_code(
                "GET /callback?code=abc&state=s1 HTTP/1.1",
                "/callback",
                "s1"
            ),
            Some(Ok("abc".into()))
        );
        assert_eq!(
            redirect_code("GET /favicon.ico HTTP/1.1", "/callback", "s1"),
            None
        );
        assert!(redirect_code(
            "GET /callback?code=abc&state=s2 HTTP/1.1",
            "/callback",
            "s1"
        )
        .unwrap()
        .is_err());
        assert!(redirect_code(
            "GET /callback?error=denied&state=s1 HTTP/1.1",
            "/callback",
            "s1"
        )
        .unwrap()
        .is_err());
        assert_eq!(
            redirect_code(
                "GET /oauth-callback?state=s1&code=4%2F0A HTTP/1.1",
                "/oauth-callback",
                "s1"
            ),
            Some(Ok("4/0A".into()))
        );
        assert_eq!(sign_in("google"), Some("antigravity"));
        assert_eq!(sign_in("openai"), Some("openai-codex"));
        assert_eq!(sign_in("nobody"), None);
    }
}
