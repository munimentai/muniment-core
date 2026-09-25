//! The sign-ins the router runs itself, for the subscriptions Pi has no
//! sign-in for: Kimi by device code, Antigravity and Devin by browser OAuth.
//! Each flow ends in one `Credential::Subscription` the pool holds. This
//! module speaks the wire and parses the answers. The desktop owns the
//! browser, the loopback listener and the events the screen shows.

use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::config::Credential;

/// Kimi Code's OAuth client, the one its own CLI presents.
pub const KIMI_CLIENT_ID: &str = "17e5f671-d194-4dfb-9706-5516cb48c098";
pub const KIMI_AUTH_URL: &str = "https://auth.kimi.com";
pub const KIMI_DEVICE_CODE_PATH: &str = "/api/oauth/device_authorization";
pub const KIMI_TOKEN_PATH: &str = "/api/oauth/token";

/// xAI signs in through the client its Grok CLI presents. Pi runs that
/// sign-in, and the router refreshes the token it leaves.
pub const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
pub const XAI_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
/// How long an xAI token lives when the answer does not say.
const XAI_TOKEN_LIFETIME_SECONDS: f64 = 3600.0;

/// Antigravity signs in with a Google account through the client its IDE
/// presents, and its redirect lands on this fixed loopback port.
pub const ANTIGRAVITY_CLIENT_ID: &str =
    "***REMOVED***";
pub const ANTIGRAVITY_CLIENT_SECRET: &str = "***REMOVED***";
pub const ANTIGRAVITY_CALLBACK_PORT: u16 = 51121;
pub const ANTIGRAVITY_CALLBACK_PATH: &str = "/oauth-callback";
pub const ANTIGRAVITY_SCOPES: [&str; 5] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];
pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json";
pub const ANTIGRAVITY_LOAD_URL: &str =
    "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
pub const ANTIGRAVITY_USER_AGENT: &str =
    "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)";

/// Devin signs in through its web app with PKCE and hands back a session
/// token its API and its reasoning backend both take.
pub const DEVIN_APP_URL: &str = "https://app.devin.ai";
pub const DEVIN_API_URL: &str = "https://api.devin.ai";
pub const DEVIN_CALLBACK_PATH: &str = "/callback";
const DEVIN_TOKEN_PREFIX: &str = "devin-session-token$";

/// The device code Kimi hands out: what the user types, where, and how to poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    /// Seconds until the code dies.
    pub expires_in: u64,
    /// Seconds between polls, at least five.
    pub interval: u64,
}

/// One poll of the token endpoint during a device flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// The user has not finished yet. Poll again after the interval.
    Pending,
    Granted(Credential),
    /// The code expired or the user said no. The sentence names which.
    Refused(String),
}

/// A PKCE pair: the verifier the exchange sends, the challenge the URL carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A fresh PKCE pair from 64 random bytes, S256.
pub fn pkce() -> Pkce {
    let seed: Vec<u8> = (0..4)
        .flat_map(|_| uuid::Uuid::new_v4().into_bytes())
        .collect();
    pkce_from(&seed)
}

/// The pair a fixed seed makes, so a test can check the challenge.
pub fn pkce_from(seed: &[u8]) -> Pkce {
    let verifier = base64url(seed);
    let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

/// A one-time state value for a browser redirect.
pub fn state() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// The instant a token issued now dies, from the seconds the upstream gave.
fn expires_ms(expires_in: Option<f64>, now_ms: i64) -> Option<i64> {
    expires_in
        .filter(|seconds| *seconds > 0.0)
        .map(|seconds| now_ms + (seconds * 1000.0) as i64)
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(timeout).build()
}

/// The status and body of a response, whatever the status.
fn read(result: Result<ureq::Response, ureq::Error>) -> Result<(u16, Value), String> {
    match result {
        Ok(response) => {
            let status = response.status();
            let body = response.into_json::<Value>().unwrap_or(Value::Null);
            Ok((status, body))
        }
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_json::<Value>().unwrap_or(Value::Null);
            Ok((status, body))
        }
        Err(ureq::Error::Transport(_)) => Err("The sign-in service did not answer.".into()),
    }
}

// Muse Code uses a device token to mint the subscription request credential.
pub const MUSE_DEVICE_URL: &str = "https://auth.meta.com/oidc/device/authorization/";
pub const MUSE_TOKEN_URL: &str = "https://auth.meta.com/oidc/device/token/";
pub const MUSE_MINT_URL: &str = "https://api.meta.ai/muse-code/key";
const MUSE_CLIENT_ID: &str = "1031625952748946";

pub fn muse_device_code(url: &str, timeout: Duration) -> Result<DeviceCode, String> {
    let (status, body) = read(
        agent(timeout)
            .post(url)
            .set("user-agent", "muse-code/1.0.2")
            .send_form(&[("client_id", MUSE_CLIENT_ID)]),
    )?;
    if status != 200 {
        return Err(format!(
            "Muse Code answered {status} to the sign-in request."
        ));
    }
    let code = parse_kimi_device_code(&body).ok_or("Muse Code answered without a device code.")?;
    if !code.verification_uri_complete.starts_with("https://") {
        return Err("Muse Code returned an invalid sign-in URL.".into());
    }
    Ok(code)
}

pub enum MusePoll {
    Pending,
    SlowDown,
    Granted(Credential),
}

pub fn muse_poll(
    token_url: &str,
    mint_url: &str,
    code: &str,
    timeout: Duration,
) -> Result<MusePoll, String> {
    let (status, body) = read(
        agent(timeout)
            .post(token_url)
            .set("user-agent", "muse-code/1.0.2")
            .send_form(&[
                ("client_id", MUSE_CLIENT_ID),
                ("device_code", code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ]),
    )?;
    match body["error"].as_str() {
        Some("authorization_pending") => return Ok(MusePoll::Pending),
        Some("slow_down") => return Ok(MusePoll::SlowDown),
        Some("access_denied") => return Err("The Muse Code sign-in was denied.".into()),
        Some("expired_token") => return Err("The Muse Code sign-in code expired.".into()),
        Some(_) => return Err("Muse Code refused the sign-in. Start again.".into()),
        None => {}
    }
    if status != 200 {
        return Err(format!("Muse Code answered {status} to the sign-in poll."));
    }
    let dca = text(body.get("access_token")).ok_or("Muse Code returned no device token.")?;
    let (status, minted) = read(
        agent(timeout)
            .post(mint_url)
            .set("user-agent", "muse-code/1.0.2")
            .set("authorization", &format!("Bearer {dca}"))
            .send_json(json!({"dca_token":dca})),
    )?;
    if status != 200 {
        return Err(format!(
            "Muse Code answered {status} to the credential request."
        ));
    }
    muse_credential(&minted).map(MusePoll::Granted)
}

fn muse_credential(minted: &Value) -> Result<Credential, String> {
    // Do not send the minted credential to an unrecognized destination.
    if text(minted.get("base_url"))
        .is_some_and(|url| url.trim_end_matches('/') != "https://api.meta.ai/v1")
    {
        return Err("Muse Code returned an unsupported API address.".into());
    }
    let access = text(minted.get("api_key"))
        .ok_or("Muse Code did not grant a request credential. Check your subscription.")?;
    Ok(Credential::Subscription {
        provider: "meta".into(),
        access,
        refresh: None,
        expires_ms: None,
        account_id: None,
        email: text(minted.get("user_email")),
        plan: text(minted.get("subs_tier_name")),
        renews_at_ms: None,
    })
}

// Kimi.

/// The headers Kimi's device flow gates on, naming this machine as the device.
pub fn kimi_headers(device_id: &str) -> Vec<(&'static str, String)> {
    vec![
        ("X-Msh-Platform", "muniment".to_owned()),
        ("X-Msh-Version", env!("CARGO_PKG_VERSION").to_owned()),
        (
            "X-Msh-Device-Name",
            std::env::var("HOSTNAME")
                .ok()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "muniment".to_owned()),
        ),
        (
            "X-Msh-Device-Model",
            format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        ),
        ("X-Msh-Device-Id", device_id.to_owned()),
    ]
}

fn kimi_post(
    base_url: &str,
    path: &str,
    device_id: &str,
    form: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, Value), String> {
    let mut request = agent(timeout)
        .post(&format!("{}{path}", base_url.trim_end_matches('/')))
        .set("Accept", "application/json");
    for (name, value) in kimi_headers(device_id) {
        request = request.set(name, &value);
    }
    read(request.send_form(form))
}

/// Asks Kimi for a device code.
pub fn kimi_device_code(
    base_url: &str,
    device_id: &str,
    timeout: Duration,
) -> Result<DeviceCode, String> {
    let (status, body) = kimi_post(
        base_url,
        KIMI_DEVICE_CODE_PATH,
        device_id,
        &[("client_id", KIMI_CLIENT_ID)],
        timeout,
    )?;
    if status != 200 {
        return Err(format!(
            "Kimi answered {status} to the device code request."
        ));
    }
    parse_kimi_device_code(&body).ok_or_else(|| "Kimi answered without a device code.".into())
}

/// The device code in Kimi's answer.
pub fn parse_kimi_device_code(body: &Value) -> Option<DeviceCode> {
    let complete = text(body.get("verification_uri_complete"));
    let verification_uri = text(body.get("verification_uri")).or_else(|| complete.clone())?;
    Some(DeviceCode {
        device_code: text(body.get("device_code"))?,
        user_code: text(body.get("user_code")).unwrap_or_default(),
        verification_uri_complete: complete.unwrap_or_else(|| verification_uri.clone()),
        verification_uri,
        expires_in: number(body.get("expires_in")).unwrap_or(900.0) as u64,
        interval: (number(body.get("interval")).unwrap_or(5.0) as u64).max(5),
    })
}

/// One poll of Kimi's token endpoint.
pub fn kimi_poll(
    base_url: &str,
    device_id: &str,
    device_code: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<Poll, String> {
    let (_, body) = kimi_post(
        base_url,
        KIMI_TOKEN_PATH,
        device_id,
        &[
            ("client_id", KIMI_CLIENT_ID),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ],
        timeout,
    )?;
    Ok(parse_kimi_poll(&body, device_id, now_ms))
}

/// Kimi answers 200 to a pending poll and to a grant alike, and names the
/// state in `error` while it is pending.
pub fn parse_kimi_poll(body: &Value, device_id: &str, now_ms: i64) -> Poll {
    match text(body.get("error")).as_deref() {
        Some("authorization_pending") | Some("slow_down") => Poll::Pending,
        Some("expired_token") => Poll::Refused("The Kimi code expired. Start again.".into()),
        Some("access_denied") => Poll::Refused("Kimi said the sign-in was refused.".into()),
        Some(other) => Poll::Refused(format!(
            "Kimi answered {other}: {}",
            text(body.get("error_description")).unwrap_or_default()
        )),
        None => match kimi_credential(body, device_id, now_ms) {
            Some(credential) => Poll::Granted(credential),
            None => Poll::Refused("Kimi answered without an access token.".into()),
        },
    }
}

fn kimi_credential(body: &Value, device_id: &str, now_ms: i64) -> Option<Credential> {
    let access = text(body.get("access_token"))?;
    Some(Credential::Subscription {
        provider: "kimi".into(),
        access,
        refresh: text(body.get("refresh_token")),
        expires_ms: expires_ms(number(body.get("expires_in")), now_ms),
        account_id: Some(device_id.to_owned()),
        email: None,
        plan: None,
        renews_at_ms: None,
    })
}

/// Trades a Kimi refresh token for a new access token.
pub fn kimi_refresh(
    base_url: &str,
    device_id: &str,
    refresh: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<Credential, String> {
    let (status, body) = kimi_post(
        base_url,
        KIMI_TOKEN_PATH,
        device_id,
        &[
            ("client_id", KIMI_CLIENT_ID),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
        ],
        timeout,
    )?;
    if status == 401 || status == 403 {
        return Err("Kimi refused the refresh token. Sign in again.".into());
    }
    if status != 200 {
        return Err(format!("Kimi answered {status} to the refresh."));
    }
    let mut credential = kimi_credential(&body, device_id, now_ms)
        .ok_or_else(|| "Kimi answered without an access token.".to_string())?;
    // A refresh that names no new refresh token keeps the one it used.
    if let Credential::Subscription { refresh: next, .. } = &mut credential {
        if next.is_none() {
            *next = Some(refresh.to_owned());
        }
    }
    Ok(credential)
}

// Antigravity.

/// The Google sign-in page for Antigravity, with the loopback redirect.
pub fn antigravity_auth_url(state: &str, redirect_uri: &str) -> String {
    let mut url = url::Url::parse(GOOGLE_AUTH_URL).expect("a fixed URL parses");
    url.query_pairs_mut()
        .append_pair("access_type", "offline")
        .append_pair("client_id", ANTIGRAVITY_CLIENT_ID)
        .append_pair("prompt", "consent")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &ANTIGRAVITY_SCOPES.join(" "))
        .append_pair("state", state);
    url.to_string()
}

/// The redirect Antigravity's client registers.
pub fn antigravity_redirect_uri() -> String {
    format!("http://localhost:{ANTIGRAVITY_CALLBACK_PORT}{ANTIGRAVITY_CALLBACK_PATH}")
}

fn google_credential(body: &Value, now_ms: i64) -> Option<Credential> {
    let access = text(body.get("access_token"))?;
    Some(Credential::Subscription {
        provider: "antigravity".into(),
        access,
        refresh: text(body.get("refresh_token")),
        expires_ms: expires_ms(number(body.get("expires_in")), now_ms),
        account_id: None,
        email: None,
        plan: None,
        renews_at_ms: None,
    })
}

/// Trades the code the redirect carried for Google tokens.
pub fn antigravity_exchange(
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<Credential, String> {
    let (status, body) = read(agent(timeout).post(token_url).send_form(&[
        ("code", code),
        ("client_id", ANTIGRAVITY_CLIENT_ID),
        ("client_secret", ANTIGRAVITY_CLIENT_SECRET),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ]))?;
    if status != 200 {
        return Err(format!("Google answered {status} to the token exchange."));
    }
    google_credential(&body, now_ms)
        .ok_or_else(|| "Google answered without an access token.".into())
}

/// Trades a Google refresh token for a new access token.
pub fn antigravity_refresh(
    token_url: &str,
    refresh: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<Credential, String> {
    let (status, body) = read(agent(timeout).post(token_url).send_form(&[
        ("client_id", ANTIGRAVITY_CLIENT_ID),
        ("client_secret", ANTIGRAVITY_CLIENT_SECRET),
        ("refresh_token", refresh),
        ("grant_type", "refresh_token"),
    ]))?;
    if status == 400 || status == 401 {
        return Err("Google refused the refresh token. Sign in again.".into());
    }
    if status != 200 {
        return Err(format!("Google answered {status} to the refresh."));
    }
    let mut credential = google_credential(&body, now_ms)
        .ok_or_else(|| "Google answered without an access token.".to_string())?;
    if let Credential::Subscription { refresh: next, .. } = &mut credential {
        if next.is_none() {
            *next = Some(refresh.to_owned());
        }
    }
    Ok(credential)
}

// xAI.

/// The credential an xAI token answer describes. An answer that names no new
/// refresh token keeps the one it was asked with.
pub fn xai_credential(body: &Value, previous_refresh: &str, now_ms: i64) -> Option<Credential> {
    let access = text(body.get("access_token"))?;
    let refresh = text(body.get("refresh_token")).unwrap_or_else(|| previous_refresh.to_owned());
    let expires_in = number(body.get("expires_in")).unwrap_or(XAI_TOKEN_LIFETIME_SECONDS);
    Some(Credential::Subscription {
        provider: "xai".into(),
        access,
        refresh: Some(refresh),
        expires_ms: expires_ms(Some(expires_in), now_ms),
        account_id: None,
        email: None,
        plan: None,
        renews_at_ms: None,
    })
}

/// Trades the refresh token for a fresh access token at xAI.
pub fn xai_refresh(
    token_url: &str,
    refresh: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<Credential, String> {
    let (status, body) = read(
        agent(timeout)
            .post(token_url)
            .set("accept", "application/json")
            .send_form(&[
                ("grant_type", "refresh_token"),
                ("client_id", XAI_CLIENT_ID),
                ("refresh_token", refresh),
            ]),
    )?;
    if status == 400 || status == 401 {
        return Err("xAI refused the refresh token. Sign in again.".into());
    }
    if status != 200 {
        return Err(format!("xAI answered {status} to the refresh."));
    }
    xai_credential(&body, refresh, now_ms)
        .ok_or_else(|| "xAI answered without an access token.".to_string())
}

/// The email of the Google account behind a token.
pub fn google_email(userinfo_url: &str, access: &str, timeout: Duration) -> Option<String> {
    let (status, body) = read(
        agent(timeout)
            .get(userinfo_url)
            .set("Authorization", &format!("Bearer {access}"))
            .set("User-Agent", ANTIGRAVITY_USER_AGENT)
            .call(),
    )
    .ok()?;
    (status == 200).then(|| text(body.get("email"))).flatten()
}

/// The Cloud Code project the account holds, which the quota route wants.
pub fn antigravity_project(load_url: &str, access: &str, timeout: Duration) -> Option<String> {
    let (status, body) = read(
        agent(timeout)
            .post(load_url)
            .set("Authorization", &format!("Bearer {access}"))
            .set("User-Agent", ANTIGRAVITY_USER_AGENT)
            .send_json(serde_json::json!({"metadata": {"ideType": "ANTIGRAVITY"}})),
    )
    .ok()?;
    if status != 200 {
        return None;
    }
    parse_antigravity_project(&body)
}

/// The project id in a `loadCodeAssist` answer, under whichever key it sits.
pub fn parse_antigravity_project(body: &Value) -> Option<String> {
    for key in ["cloudaicompanionProject", "projectId", "project"] {
        match body.get(key) {
            Some(Value::String(id)) if !id.trim().is_empty() => return Some(id.trim().to_owned()),
            Some(Value::Object(object)) => {
                if let Some(id) = text(object.get("id")) {
                    return Some(id);
                }
            }
            _ => {}
        }
    }
    None
}

// Devin.

/// Devin's sign-in page, with the PKCE challenge and the loopback redirect.
pub fn devin_auth_url(app_url: &str, redirect_uri: &str, challenge: &str, state: &str) -> String {
    let mut url = url::Url::parse(&format!(
        "{}/auth/cli/continue",
        app_url.trim_end_matches('/')
    ))
    .expect("a fixed URL parses");
    url.query_pairs_mut()
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("prompt", "select_account")
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    url.to_string()
}

/// A Devin session token with the prefix its backends want.
pub fn devin_session_token(raw: &str) -> String {
    let token = raw.trim();
    if token.starts_with(DEVIN_TOKEN_PREFIX) || !token.starts_with("eyJ") {
        return token.to_owned();
    }
    format!("{DEVIN_TOKEN_PREFIX}{token}")
}

/// Trades the code the redirect carried for a Devin session token.
pub fn devin_exchange(
    api_url: &str,
    code: &str,
    verifier: &str,
    timeout: Duration,
) -> Result<Credential, String> {
    let (status, body) = read(
        agent(timeout)
            .post(&format!("{}/auth/cli/token", api_url.trim_end_matches('/')))
            .set("Accept", "application/json")
            .send_json(serde_json::json!({"code": code, "code_verifier": verifier})),
    )?;
    if !(200..300).contains(&status) {
        return Err(format!("Devin answered {status} to the token exchange."));
    }
    let token =
        text(body.get("token")).ok_or_else(|| "Devin answered without a token.".to_string())?;
    Ok(Credential::Subscription {
        provider: "devin".into(),
        access: devin_session_token(&token),
        refresh: None,
        expires_ms: None,
        account_id: None,
        email: None,
        plan: None,
        renews_at_ms: None,
    })
}

/// The Devin account's own name and organization, when the API says.
pub fn devin_profile(
    api_url: &str,
    access: &str,
    timeout: Duration,
) -> Option<(Option<String>, Option<String>)> {
    let (status, body) = read(
        agent(timeout)
            .get(&format!("{}/v3/self", api_url.trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {access}"))
            .set("Accept", "application/json")
            .call(),
    )
    .ok()?;
    if status != 200 {
        return None;
    }
    Some((text(body.get("user_name")), text(body.get("org_id"))))
}

/// Refreshes the OAuth credentials used by the native Codex and Claude wires.
fn inference_refresh(
    provider: &str,
    refresh: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<Credential, String> {
    let client = agent(timeout);
    let call = if provider == "openai-codex" {
        client
            .post("https://auth.openai.com/oauth/token")
            .send_form(&[
                ("client_id", "app_EMoamEEZ73f0CkXaXp7hrann"),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
            ])
    } else {
        client
            .post("https://platform.claude.com/v1/oauth/token")
            .send_json(serde_json::json!({
                "client_id":"9d1c250a-e61b-44d9-88ed-5944d1962f5e",
                "grant_type":"refresh_token", "refresh_token":refresh,
            }))
    };
    let (status, body) = read(call)?;
    if status != 200 {
        return Err(format!(
            "The account refused token refresh ({status}). Reconnect the account."
        ));
    }
    let access =
        text(body.get("access_token")).ok_or("The refresh response has no access token.")?;
    Ok(Credential::Subscription {
        provider: provider.into(),
        access,
        refresh: Some(text(body.get("refresh_token")).unwrap_or_else(|| refresh.into())),
        expires_ms: expires_ms(number(body.get("expires_in")), now_ms),
        account_id: None,
        email: None,
        plan: None,
        renews_at_ms: None,
    })
}

struct RefreshWriteLock(std::path::PathBuf);
impl Drop for RefreshWriteLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}
fn refresh_write_lock(agent: &std::path::Path) -> Result<RefreshWriteLock, String> {
    let path = agent.join(format!("{}.lock", super::config::CONFIG_FILE));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(RefreshWriteLock(path)),
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(_) => return Err("Cannot lock account settings for token refresh.".into()),
        }
    }
}

/// Serializes token rotation across concurrent turns and merges only that credential.
/// Always reload after the network call so unrelated settings survive a refresh.
pub fn refresh_account(
    agent: &std::path::Path,
    id: &str,
    now_ms: i64,
    timeout: Duration,
) -> Result<super::config::Account, String> {
    static REFRESH: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = REFRESH.lock().unwrap_or_else(|error| error.into_inner());
    let mut config = super::config::load(agent).map_err(|_| "Cannot read account settings.")?;
    let mut account = config
        .accounts
        .iter()
        .find(|account| account.id == id)
        .cloned()
        .ok_or("The account was removed.")?;
    if let Some(result) = refresh_if_expiring(&account.credential, now_ms, timeout) {
        let original = account.credential.clone();
        account.credential = result?;
        let _file_lock = refresh_write_lock(agent)?;
        config = super::config::load(agent).map_err(|_| "Cannot read account settings.")?;
        let entry = config
            .accounts
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or("The account was removed.")?;
        if entry.credential != original {
            return Ok(entry.clone());
        }
        entry.credential = account.credential.clone();
        super::config::save(agent, &config).map_err(|_| "Cannot save the refreshed account.")?;
    }
    Ok(account)
}

/// Refreshes a subscription whose upstream hands out refresh tokens, when
/// its access token is inside a minute of dying. Answers the new credential,
/// or none when nothing needed doing or the upstream refused.
pub fn refresh_if_expiring(
    credential: &Credential,
    now_ms: i64,
    timeout: Duration,
) -> Option<Result<Credential, String>> {
    let Credential::Subscription {
        provider,
        refresh: Some(refresh),
        account_id,
        email,
        plan,
        renews_at_ms,
        ..
    } = credential
    else {
        return None;
    };
    if !credential.expired(now_ms) {
        return None;
    }
    let refreshed = match provider.as_str() {
        "kimi" => kimi_refresh(
            KIMI_AUTH_URL,
            account_id.as_deref().unwrap_or_default(),
            refresh,
            now_ms,
            timeout,
        ),
        "antigravity" => antigravity_refresh(GOOGLE_TOKEN_URL, refresh, now_ms, timeout),
        "xai" => xai_refresh(XAI_TOKEN_URL, refresh, now_ms, timeout),
        "openai-codex" | "anthropic" => inference_refresh(provider, refresh, now_ms, timeout),
        _ => return None,
    };
    Some(refreshed.map(|mut fresh| {
        // The refresh answers tokens alone. Everything the account knows stays.
        if let Credential::Subscription {
            account_id: next_account,
            email: next_email,
            plan: next_plan,
            renews_at_ms: next_renews,
            ..
        } = &mut fresh
        {
            if next_account.is_none() {
                *next_account = account_id.clone();
            }
            *next_email = email.clone();
            *next_plan = plan.clone();
            *next_renews = *renews_at_ms;
        }
        fresh
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn muse_requires_a_minted_key_and_keeps_subscription_identity() {
        let credential = muse_credential(&json!({"api_key":"fixture-key",
            "user_email":"fixture@example.com", "subs_tier_name":"Pro",
            "base_url":"https://api.meta.ai/v1/"}))
        .unwrap();
        assert_eq!(credential.pi_provider(), Some("meta"));
        assert!(credential.servable());
        assert_eq!(credential.bearer(), "fixture-key");
        assert_eq!(
            credential.clone().into_email().as_deref(),
            Some("fixture@example.com")
        );
        assert!(muse_credential(&json!({"access_token":"dca:device"})).is_err());
        assert!(muse_credential(
            &json!({"api_key":"fixture-key","base_url":"https://untrusted.example/v1"})
        )
        .is_err());
    }

    #[test]
    fn pkce_is_the_s256_challenge_of_a_url_safe_verifier() {
        let pair = pkce_from(b"0123456789abcdef0123456789abcdef");
        assert_eq!(pair.verifier, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY");
        assert_eq!(
            pair.challenge,
            base64url(&Sha256::digest(pair.verifier.as_bytes()))
        );
        assert!(!pair.challenge.contains('=') && !pair.challenge.contains('+'));
        assert_ne!(pkce().verifier, pkce().verifier);
        assert_eq!(state().len(), 32);
    }

    #[test]
    fn a_kimi_device_code_reads_its_urls_and_keeps_the_poll_interval_at_five() {
        let code = parse_kimi_device_code(&json!({
            "device_code": "dc", "user_code": "ABCD-1234",
            "verification_uri": "https://auth.kimi.com/device",
            "verification_uri_complete": "https://auth.kimi.com/device?user_code=ABCD-1234",
            "expires_in": 600, "interval": 2
        }))
        .unwrap();
        assert_eq!(code.user_code, "ABCD-1234");
        assert_eq!(code.interval, 5);
        assert_eq!(code.expires_in, 600);
        assert!(code.verification_uri_complete.ends_with("ABCD-1234"));
        assert!(parse_kimi_device_code(&json!({"user_code": "x"})).is_none());
    }

    #[test]
    fn a_kimi_poll_is_pending_then_granted_and_a_refusal_names_itself() {
        assert_eq!(
            parse_kimi_poll(&json!({"error": "authorization_pending"}), "dev", 0),
            Poll::Pending
        );
        assert_eq!(
            parse_kimi_poll(&json!({"error": "slow_down"}), "dev", 0),
            Poll::Pending
        );
        assert!(matches!(
            parse_kimi_poll(&json!({"error": "expired_token"}), "dev", 0),
            Poll::Refused(message) if message.contains("expired")
        ));
        let granted = parse_kimi_poll(
            &json!({"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "token_type": "Bearer"}),
            "device-1",
            1_000,
        );
        match granted {
            Poll::Granted(Credential::Subscription {
                provider,
                access,
                refresh,
                expires_ms,
                account_id,
                ..
            }) => {
                assert_eq!(provider, "kimi");
                assert_eq!(access, "at");
                assert_eq!(refresh.as_deref(), Some("rt"));
                assert_eq!(expires_ms, Some(3_601_000));
                assert_eq!(account_id.as_deref(), Some("device-1"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_kimi_poll(&json!({"token_type": "Bearer"}), "dev", 0),
            Poll::Refused(_)
        ));
        let headers = kimi_headers("device-1");
        assert!(headers
            .iter()
            .any(|(name, value)| *name == "X-Msh-Device-Id" && value == "device-1"));
    }

    #[test]
    fn the_antigravity_url_carries_its_client_scopes_and_loopback_redirect() {
        let url = antigravity_auth_url("st4te", &antigravity_redirect_uri());
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("state=st4te"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A51121%2Foauth-callback"));
        assert!(url.contains("cclog"));
        assert_eq!(
            parse_antigravity_project(&json!({"cloudaicompanionProject": " proj-1 "})).as_deref(),
            Some("proj-1")
        );
        assert_eq!(
            parse_antigravity_project(&json!({"project": {"id": "proj-2"}})).as_deref(),
            Some("proj-2")
        );
        assert_eq!(parse_antigravity_project(&json!({})), None);
        let credential = google_credential(
            &json!({"access_token": "ya29", "refresh_token": "1//r", "expires_in": 3599}),
            10,
        )
        .unwrap();
        assert!(
            matches!(credential, Credential::Subscription { ref provider, .. } if provider == "antigravity")
        );
        assert_eq!(credential.bearer(), "ya29");
    }

    #[test]
    fn the_devin_url_carries_pkce_and_the_session_token_takes_its_prefix() {
        let url = devin_auth_url(
            DEVIN_APP_URL,
            "http://127.0.0.1:4321/callback",
            "ch4ll",
            "st",
        );
        assert!(url.starts_with("https://app.devin.ai/auth/cli/continue?"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A4321%2Fcallback"));
        assert!(url.contains("code_challenge=ch4ll"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("prompt=select_account"));
        assert_eq!(devin_session_token("eyJabc"), "devin-session-token$eyJabc");
        assert_eq!(
            devin_session_token("devin-session-token$eyJabc"),
            "devin-session-token$eyJabc"
        );
        assert_eq!(devin_session_token("plain"), "plain");
    }

    #[test]
    fn an_xai_answer_reads_its_tokens_and_keeps_the_refresh_it_was_asked_with() {
        let body = serde_json::json!({ "access_token": "at2", "refresh_token": "rt2", "expires_in": 3600 });
        let Some(Credential::Subscription {
            provider,
            access,
            refresh,
            expires_ms,
            ..
        }) = xai_credential(&body, "rt1", 1_000)
        else {
            panic!("no credential");
        };
        assert_eq!(provider, "xai");
        assert_eq!(access, "at2");
        assert_eq!(refresh.as_deref(), Some("rt2"));
        assert_eq!(expires_ms, Some(3_601_000));
        let kept = serde_json::json!({ "access_token": "at3" });
        let Some(Credential::Subscription {
            refresh,
            expires_ms,
            ..
        }) = xai_credential(&kept, "rt1", 0)
        else {
            panic!("no credential");
        };
        assert_eq!(refresh.as_deref(), Some("rt1"));
        assert_eq!(expires_ms, Some(3_600_000));
        assert!(xai_credential(&serde_json::json!({}), "rt1", 0).is_none());
    }

    #[test]
    fn only_an_expiring_token_with_a_refresh_asks_the_upstream() {
        let fresh = Credential::Subscription {
            provider: "kimi".into(),
            access: "at".into(),
            refresh: Some("rt".into()),
            expires_ms: Some(10_000_000),
            account_id: Some("dev".into()),
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        assert!(refresh_if_expiring(&fresh, 1_000, Duration::from_millis(10)).is_none());
        let devin = Credential::Subscription {
            provider: "devin".into(),
            access: "st".into(),
            refresh: None,
            expires_ms: None,
            account_id: None,
            email: None,
            plan: None,
            renews_at_ms: None,
        };
        assert!(refresh_if_expiring(&devin, 1_000, Duration::from_millis(10)).is_none());
        let key = Credential::ApiKey { key: "sk".into() };
        assert!(refresh_if_expiring(&key, 1_000, Duration::from_millis(10)).is_none());
    }
}
