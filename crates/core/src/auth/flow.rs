//! Authorization-code + PKCE flow orchestration (RFC 6749/7636/8252).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use super::discovery::{discover, ProviderMetadata};
use super::loopback::RedirectCatcher;
use super::pkce::{random_state, PkcePair};
use super::store::{status, AuthStatus, TokenSet, TokenStore};
use super::urlenc;
use super::AuthError;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the client is registered and as what. One instance of this is the
/// whole configuration surface of the auth flow; the desktop app builds it
/// in `src-tauri/src/auth/mod.rs`.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// e.g. `https://api.muniment.ai`
    pub issuer: String,
    /// Public-client id registered on the control plane. This native app has
    /// no secret, so PKCE supplies the proof.
    pub client_id: String,
    /// Space-separated; `offline_access` requests a refresh token.
    pub scopes: String,
}

/// Wire shape of a token-endpoint success response (RFC 6749 §5.1).
/// Deliberately no `Debug` derive: it holds raw tokens.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    id_token: Option<String>,
}

/// Full interactive sign-in: discovery → loopback listener → browser →
/// callback (state-checked) → code exchange. `open_browser` receives the
/// authorization URL; the app hands it to the OS, tests drive it
/// programmatically. Returns the tokens. Persisting them is the caller's
/// job, via a [`TokenStore`].
pub fn run_sign_in(
    cfg: &OidcConfig,
    open_browser: impl FnOnce(&str) -> Result<(), AuthError>,
    timeout: Duration,
) -> Result<TokenSet, AuthError> {
    let meta = discover(&cfg.issuer)?;
    let catcher = RedirectCatcher::bind()?;
    let redirect_uri = catcher.redirect_uri();
    let pkce = PkcePair::generate()?;
    let state = random_state()?;
    let url = build_authorization_url(&meta, cfg, &redirect_uri, &pkce, &state);
    open_browser(&url)?;
    let code = catcher.wait_for_callback(&state, timeout)?;
    exchange_code(
        &meta.token_endpoint,
        &cfg.client_id,
        &redirect_uri,
        &code,
        &pkce.verifier,
    )
}

pub fn build_authorization_url(
    meta: &ProviderMetadata,
    cfg: &OidcConfig,
    redirect_uri: &str,
    pkce: &PkcePair,
    state: &str,
) -> String {
    let params = [
        ("response_type", "code"),
        ("client_id", cfg.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("scope", cfg.scopes.as_str()),
        ("state", state),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", urlenc::encode(v)))
        .collect();
    let sep = if meta.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{sep}{}", meta.authorization_endpoint, query.join("&"))
}

/// Exchange an authorization code for tokens (RFC 6749 §4.1.3 + PKCE proof).
pub fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenSet, AuthError> {
    let resp = post_token_form(
        token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier),
        ],
    )?;
    Ok(token_set_from(resp, None, None, now_unix()))
}

/// Refresh grant (RFC 6749 §6). Carries the current refresh token and
/// subject forward when the provider omits them from the response.
pub fn refresh_tokens(
    token_endpoint: &str,
    client_id: &str,
    current: &TokenSet,
) -> Result<TokenSet, AuthError> {
    refresh_tokens_at(token_endpoint, client_id, current, now_unix())
}

fn refresh_tokens_at(
    token_endpoint: &str,
    client_id: &str,
    current: &TokenSet,
    now_unix: u64,
) -> Result<TokenSet, AuthError> {
    let refresh_token = current
        .refresh_token
        .as_deref()
        .ok_or_else(|| AuthError::Token("no refresh token stored".into()))?;
    let resp = post_token_form(
        token_endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ],
    )?;
    Ok(token_set_from(
        resp,
        current.refresh_token.clone(),
        current.subject.clone(),
        now_unix,
    ))
}

/// Return the current session status, renewing tokens when expiry is near.
/// `now_unix` is supplied by the caller so expiry decisions are deterministic.
pub fn ensure_fresh(
    store: &dyn TokenStore,
    cfg: &OidcConfig,
    now_unix: u64,
    skew: Duration,
) -> Result<AuthStatus, AuthError> {
    let Some(tokens) = store.load()? else {
        return status(store);
    };

    let refresh_needed = tokens
        .expires_at
        .is_some_and(|expires_at| expires_at <= now_unix.saturating_add(skew.as_secs()));
    if !refresh_needed {
        return status(store);
    }
    if tokens.refresh_token.is_none() {
        store.clear()?;
        return status(store);
    }

    let metadata = discover(&cfg.issuer)?;
    match refresh_tokens_at(&metadata.token_endpoint, &cfg.client_id, &tokens, now_unix) {
        Ok(refreshed) => {
            store.save(&refreshed)?;
            status(store)
        }
        Err(AuthError::Token(_)) => {
            store.clear()?;
            status(store)
        }
        Err(error) => Err(error),
    }
}

/// RFC 7009 revocation. Callers treat failures as best-effort by design.
pub fn revoke_token(
    revocation_endpoint: &str,
    client_id: &str,
    token: &str,
    token_type_hint: &str,
) -> Result<(), AuthError> {
    revoke_token_with_timeout(
        revocation_endpoint,
        client_id,
        token,
        token_type_hint,
        HTTP_TIMEOUT,
    )
}

#[doc(hidden)]
pub fn revoke_token_with_timeout(
    revocation_endpoint: &str,
    client_id: &str,
    token: &str,
    token_type_hint: &str,
    timeout: Duration,
) -> Result<(), AuthError> {
    match ureq::post(revocation_endpoint)
        .timeout(timeout)
        .send_form(&[
            ("token", token),
            ("token_type_hint", token_type_hint),
            ("client_id", client_id),
        ]) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code, _)) => Err(AuthError::Http(format!(
            "revocation endpoint returned {code}"
        ))),
        Err(e) => Err(AuthError::Http(format!("revocation request failed: {e}"))),
    }
}

/// Sign out: best-effort server-side revocation (when discovery advertises
/// an endpoint), then clear the store. Only the store clear can fail.
pub fn sign_out(store: &dyn TokenStore, cfg: &OidcConfig) -> Result<(), AuthError> {
    if let Ok(Some(tokens)) = store.load() {
        if let Ok(meta) = discover(&cfg.issuer) {
            if let Some(endpoint) = meta.revocation_endpoint.as_deref() {
                let (token, hint) = match tokens.refresh_token.as_deref() {
                    Some(rt) => (rt, "refresh_token"),
                    None => (tokens.access_token.as_str(), "access_token"),
                };
                let _ = revoke_token(endpoint, &cfg.client_id, token, hint);
            }
        }
    }
    store.clear()
}

fn post_token_form(endpoint: &str, form: &[(&str, &str)]) -> Result<TokenResponse, AuthError> {
    match ureq::post(endpoint).timeout(HTTP_TIMEOUT).send_form(form) {
        Ok(resp) => resp
            .into_json::<TokenResponse>()
            .map_err(|e| AuthError::Token(format!("malformed token response: {e}"))),
        Err(ureq::Error::Status(code, resp)) => {
            // OAuth error responses are JSON {error, error_description};
            // surface those fields rather than echoing the raw body.
            let body: serde_json::Value = resp.into_json().unwrap_or(serde_json::Value::Null);
            let error = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown_error");
            let mut msg = format!("token endpoint returned {code}: {error}");
            if let Some(desc) = body.get("error_description").and_then(|v| v.as_str()) {
                msg.push_str(&format!(" ({desc})"));
            }
            Err(AuthError::Token(msg))
        }
        Err(e) => Err(AuthError::Http(format!("token request failed: {e}"))),
    }
}

fn token_set_from(
    resp: TokenResponse,
    prev_refresh: Option<String>,
    prev_subject: Option<String>,
    now_unix: u64,
) -> TokenSet {
    let expires_at = resp.expires_in.map(|s| now_unix.saturating_add(s));
    let subject = resp
        .id_token
        .as_deref()
        .and_then(id_token_subject)
        .or(prev_subject);
    TokenSet {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token.or(prev_refresh),
        expires_at,
        subject,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `sub` claim of an id_token. The token arrives over TLS directly from the
/// token endpoint, so per OIDC Core §3.1.3.7 (6) the client may rely on it
/// without checking the signature; here it is display metadata only, never
/// an authorization input.
fn id_token_subject(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes()).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(auth_endpoint: &str) -> ProviderMetadata {
        ProviderMetadata {
            issuer: "https://idp.example".into(),
            authorization_endpoint: auth_endpoint.into(),
            token_endpoint: "https://idp.example/token".into(),
            revocation_endpoint: None,
        }
    }

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example".into(),
            client_id: "muniment-desktop".into(),
            scopes: "openid profile".into(),
        }
    }

    #[test]
    fn authorization_url_carries_all_pkce_flow_params_encoded() {
        let pkce = PkcePair::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into());
        let url = build_authorization_url(
            &meta("https://idp.example/authorize"),
            &cfg(),
            "http://127.0.0.1:49152/callback",
            &pkce,
            "st4te",
        );
        assert!(url.starts_with("https://idp.example/authorize?response_type=code&"));
        assert!(url.contains("client_id=muniment-desktop"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback"));
        assert!(url.contains("scope=openid%20profile"));
        assert!(url.contains("state=st4te"));
        assert!(url.contains("code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn authorization_url_appends_to_an_existing_query() {
        let pkce = PkcePair::from_verifier("v".repeat(43));
        let url = build_authorization_url(
            &meta("https://idp.example/authorize?tenant=t1"),
            &cfg(),
            "http://127.0.0.1:1/callback",
            &pkce,
            "s",
        );
        assert!(url.starts_with("https://idp.example/authorize?tenant=t1&response_type=code&"));
    }

    #[test]
    fn id_token_subject_reads_the_sub_claim() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user-123","aud":"x"}"#);
        let jwt = format!("eyJhbGciOiJub25lIn0.{payload}.sig");
        assert_eq!(id_token_subject(&jwt).as_deref(), Some("user-123"));
        assert_eq!(id_token_subject("not-a-jwt"), None);
    }
}
