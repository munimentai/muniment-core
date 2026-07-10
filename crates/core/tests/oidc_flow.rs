//! End-to-end auth-flow tests against an in-process mock IdP: a canned
//! discovery document plus token/revocation endpoints that enforce PKCE the
//! way a real provider would. The test itself plays the browser — it parses
//! the authorization URL and performs the loopback redirect. No network
//! beyond 127.0.0.1.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use muniment_core::auth::{
    discover, ensure_fresh, refresh_tokens, run_sign_in, sign_out, status, urlenc, AuthError,
    InMemoryTokenStore, OidcConfig, PkcePair, TokenSet, TokenStore,
};

const CLIENT_ID: &str = "muniment-desktop";
const AUTH_CODE: &str = "mock-code-1";

#[derive(Default)]
struct MockState {
    /// S256 challenge from the authorization request; the token endpoint
    /// verifies the later `code_verifier` against it, like a real IdP.
    expected_challenge: Mutex<Option<String>>,
    token_endpoint_hit: AtomicBool,
    revoked: Mutex<Vec<String>>,
}

struct MockIdp {
    issuer: String,
    state: Arc<MockState>,
}

impl MockIdp {
    fn spawn() -> Self {
        Self::spawn_advertising(None)
    }

    /// `advertised_issuer` lets a test serve a discovery document that
    /// claims a different issuer than the one it lives at.
    fn spawn_advertising(advertised_issuer: Option<String>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let advertised = advertised_issuer.unwrap_or_else(|| issuer.clone());
        let state = Arc::new(MockState::default());
        let st = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                handle(&mut stream, &advertised, &st);
            }
        });
        MockIdp { issuer, state }
    }

    fn config(&self) -> OidcConfig {
        OidcConfig {
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.into(),
            scopes: "openid profile email offline_access".into(),
        }
    }

    /// A "browser": parses the authorization URL like the IdP would, records
    /// the PKCE challenge, then performs the loopback redirect from another
    /// thread (a real browser tab is not the caller's thread either).
    /// `mutate` tampers with the callback parameters before the redirect.
    fn browser(
        &self,
        mutate: impl FnOnce(&mut HashMap<String, String>) + Send + 'static,
    ) -> impl FnOnce(&str) -> Result<(), AuthError> {
        let st = self.state.clone();
        let issuer = self.issuer.clone();
        move |auth_url: &str| {
            let (endpoint, query) = auth_url.split_once('?').expect("authorization URL query");
            assert_eq!(endpoint, format!("{issuer}/authorize"));
            let params: HashMap<String, String> = urlenc::parse_query(query).into_iter().collect();
            assert_eq!(
                params.get("response_type").map(String::as_str),
                Some("code")
            );
            assert_eq!(params.get("client_id").map(String::as_str), Some(CLIENT_ID));
            assert_eq!(
                params.get("code_challenge_method").map(String::as_str),
                Some("S256")
            );
            *st.expected_challenge.lock().unwrap() = params.get("code_challenge").cloned();

            let redirect_uri = params.get("redirect_uri").expect("redirect_uri").clone();
            assert!(redirect_uri.starts_with("http://127.0.0.1:"));
            assert!(redirect_uri.ends_with("/callback"));

            let mut cb = HashMap::new();
            cb.insert("code".to_string(), AUTH_CODE.to_string());
            cb.insert(
                "state".to_string(),
                params.get("state").expect("state").clone(),
            );
            mutate(&mut cb);
            std::thread::spawn(move || {
                let qs = cb
                    .iter()
                    .map(|(k, v)| format!("{k}={}", urlenc::encode(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                http_get(&format!("{redirect_uri}?{qs}"));
            });
            Ok(())
        }
    }
}

#[test]
fn full_sign_in_exchanges_the_code_for_tokens() {
    let idp = MockIdp::spawn();
    let tokens = run_sign_in(&idp.config(), idp.browser(|_| {}), Duration::from_secs(10)).unwrap();

    assert_eq!(tokens.access_token, "at-1");
    assert_eq!(tokens.refresh_token.as_deref(), Some("rt-1"));
    assert_eq!(tokens.subject.as_deref(), Some("user-123"));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = tokens.expires_at.unwrap();
    assert!((now + 3590..=now + 3610).contains(&expires_at));

    // Store round-trip drives auth_status without any network.
    let store = InMemoryTokenStore::new();
    store.save(&tokens).unwrap();
    let st = status(&store).unwrap();
    assert!(st.signed_in);
    assert_eq!(st.subject.as_deref(), Some("user-123"));
    assert_eq!(st.expires_at, Some(expires_at));
}

#[test]
fn tampered_state_is_rejected_before_any_token_request() {
    let idp = MockIdp::spawn();
    let err = run_sign_in(
        &idp.config(),
        idp.browser(|cb| {
            cb.insert("state".to_string(), "forged-by-attacker".to_string());
        }),
        Duration::from_secs(10),
    )
    .unwrap_err();
    assert_eq!(err, AuthError::StateMismatch);
    assert!(!idp.state.token_endpoint_hit.load(Ordering::SeqCst));
}

#[test]
fn provider_error_redirect_surfaces_as_denied() {
    let idp = MockIdp::spawn();
    let err = run_sign_in(
        &idp.config(),
        idp.browser(|cb| {
            cb.remove("code");
            cb.insert("error".to_string(), "access_denied".to_string());
        }),
        Duration::from_secs(10),
    )
    .unwrap_err();
    assert!(matches!(err, AuthError::Denied(ref m) if m.contains("access_denied")));
    assert!(!idp.state.token_endpoint_hit.load(Ordering::SeqCst));
}

#[test]
fn token_endpoint_enforces_the_pkce_proof() {
    let idp = MockIdp::spawn();
    let meta = discover(&idp.issuer).unwrap();
    let right = PkcePair::from_verifier("right-verifier-right-verifier-right-verifier".into());
    *idp.state.expected_challenge.lock().unwrap() = Some(right.challenge.clone());

    let err = muniment_core::auth::exchange_code(
        &meta.token_endpoint,
        CLIENT_ID,
        "http://127.0.0.1:1/callback",
        AUTH_CODE,
        "wrong-verifier-wrong-verifier-wrong-verifier",
    )
    .unwrap_err();
    assert!(matches!(err, AuthError::Token(ref m) if m.contains("invalid_grant")));

    let tokens = muniment_core::auth::exchange_code(
        &meta.token_endpoint,
        CLIENT_ID,
        "http://127.0.0.1:1/callback",
        AUTH_CODE,
        &right.verifier,
    )
    .unwrap();
    assert_eq!(tokens.access_token, "at-1");
}

#[test]
fn refresh_rotates_tokens_and_keeps_the_subject() {
    let idp = MockIdp::spawn();
    let tokens = run_sign_in(&idp.config(), idp.browser(|_| {}), Duration::from_secs(10)).unwrap();
    let meta = discover(&idp.issuer).unwrap();

    let refreshed = refresh_tokens(&meta.token_endpoint, CLIENT_ID, &tokens).unwrap();
    assert_eq!(refreshed.access_token, "at-2");
    assert_eq!(refreshed.refresh_token.as_deref(), Some("rt-2"));
    // The refresh response has no id_token; the subject carries forward.
    assert_eq!(refreshed.subject.as_deref(), Some("user-123"));
}

#[test]
fn refresh_without_a_stored_refresh_token_fails_cleanly() {
    let tokens = TokenSet {
        access_token: "at-1".into(),
        refresh_token: None,
        expires_at: None,
        subject: None,
    };
    let err = refresh_tokens("http://127.0.0.1:1/token", CLIENT_ID, &tokens).unwrap_err();
    assert!(matches!(err, AuthError::Token(_)));
}

#[test]
fn ensure_fresh_does_not_contact_the_provider_for_fresh_tokens() {
    let idp = MockIdp::spawn();
    let store = InMemoryTokenStore::new();
    store
        .save(&TokenSet {
            access_token: "at-current".into(),
            refresh_token: Some("rt-1".into()),
            expires_at: Some(2_000),
            subject: Some("user-123".into()),
        })
        .unwrap();

    let result = ensure_fresh(&store, &idp.config(), 1_000, Duration::from_secs(60)).unwrap();
    assert!(result.signed_in);
    assert!(!idp.state.token_endpoint_hit.load(Ordering::SeqCst));
}

#[test]
fn ensure_fresh_refreshes_and_persists_expired_tokens() {
    let idp = MockIdp::spawn();
    let store = InMemoryTokenStore::new();
    store
        .save(&TokenSet {
            access_token: "at-expired".into(),
            refresh_token: Some("rt-1".into()),
            expires_at: Some(999),
            subject: Some("user-123".into()),
        })
        .unwrap();

    let result = ensure_fresh(&store, &idp.config(), 1_000, Duration::ZERO).unwrap();
    assert!(result.signed_in);
    let persisted = store.load().unwrap().unwrap();
    assert_eq!(persisted.access_token, "at-2");
    assert_eq!(persisted.refresh_token.as_deref(), Some("rt-2"));
    assert_eq!(persisted.subject.as_deref(), Some("user-123"));
    assert_eq!(persisted.expires_at, Some(4_600));
}

#[test]
fn ensure_fresh_clears_a_session_when_refresh_is_rejected() {
    let idp = MockIdp::spawn();
    let store = InMemoryTokenStore::new();
    store
        .save(&TokenSet {
            access_token: "at-expired".into(),
            refresh_token: Some("rt-dead".into()),
            expires_at: Some(999),
            subject: Some("user-123".into()),
        })
        .unwrap();

    let result = ensure_fresh(&store, &idp.config(), 1_000, Duration::ZERO).unwrap();
    assert!(!result.signed_in);
    assert!(store.load().unwrap().is_none());
}

#[test]
fn ensure_fresh_preserves_tokens_on_a_network_failure() {
    let store = InMemoryTokenStore::new();
    store
        .save(&TokenSet {
            access_token: "at-expired".into(),
            refresh_token: Some("rt-1".into()),
            expires_at: Some(999),
            subject: Some("user-123".into()),
        })
        .unwrap();
    let cfg = OidcConfig {
        issuer: "http://127.0.0.1:1".into(),
        client_id: CLIENT_ID.into(),
        scopes: String::new(),
    };

    let error = ensure_fresh(&store, &cfg, 1_000, Duration::ZERO).unwrap_err();
    assert!(matches!(error, AuthError::Discovery(_)));
    assert_eq!(store.load().unwrap().unwrap().access_token, "at-expired");
}

#[test]
fn sign_out_revokes_the_refresh_token_and_clears_the_store() {
    let idp = MockIdp::spawn();
    let store = InMemoryTokenStore::new();
    let tokens = run_sign_in(&idp.config(), idp.browser(|_| {}), Duration::from_secs(10)).unwrap();
    store.save(&tokens).unwrap();

    sign_out(&store, &idp.config()).unwrap();
    assert!(store.load().unwrap().is_none());
    assert_eq!(*idp.state.revoked.lock().unwrap(), vec!["rt-1".to_string()]);
}

#[test]
fn discovery_rejects_an_issuer_mismatch() {
    let idp = MockIdp::spawn_advertising(Some("https://evil.example".into()));
    let err = discover(&idp.issuer).unwrap_err();
    assert!(matches!(err, AuthError::Discovery(ref m) if m.contains("issuer mismatch")));
}

// ---- minimal HTTP plumbing (std only) ----------------------------------

struct Request {
    method: String,
    path: String,
    body: String,
}

fn handle(stream: &mut TcpStream, issuer: &str, st: &MockState) {
    let Some(req) = read_request(stream) else {
        return;
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/.well-known/openid-configuration") => {
            let body = format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","revocation_endpoint":"{issuer}/revoke"}}"#
            );
            respond(stream, 200, &body);
        }
        ("POST", "/token") => {
            st.token_endpoint_hit.store(true, Ordering::SeqCst);
            let form: HashMap<String, String> =
                urlenc::parse_query(&req.body).into_iter().collect();
            match form.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                    let proof_ok = st.expected_challenge.lock().unwrap().as_deref()
                        == Some(PkcePair::from_verifier(verifier).challenge.as_str());
                    if form.get("code").map(String::as_str) != Some(AUTH_CODE)
                        || !form.contains_key("redirect_uri")
                        || form.get("client_id").map(String::as_str) != Some(CLIENT_ID)
                        || !proof_ok
                    {
                        respond(
                            stream,
                            400,
                            r#"{"error":"invalid_grant","error_description":"code or PKCE verification failed"}"#,
                        );
                        return;
                    }
                    let id_token = fake_id_token();
                    respond(
                        stream,
                        200,
                        &format!(
                            r#"{{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-1","id_token":"{id_token}"}}"#
                        ),
                    );
                }
                Some("refresh_token") => {
                    if form.get("refresh_token").map(String::as_str) != Some("rt-1") {
                        respond(stream, 400, r#"{"error":"invalid_grant"}"#);
                        return;
                    }
                    respond(
                        stream,
                        200,
                        r#"{"access_token":"at-2","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2"}"#,
                    );
                }
                _ => respond(stream, 400, r#"{"error":"unsupported_grant_type"}"#),
            }
        }
        ("POST", "/revoke") => {
            let form: HashMap<String, String> =
                urlenc::parse_query(&req.body).into_iter().collect();
            st.revoked
                .lock()
                .unwrap()
                .push(form.get("token").cloned().unwrap_or_default());
            respond(stream, 200, "{}");
        }
        _ => respond(stream, 404, r#"{"error":"not_found"}"#),
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 65536 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut first = head.lines().next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let path = target.split('?').next().unwrap_or("").to_string();

    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some(Request {
        method,
        path,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn respond(stream: &mut TcpStream, code: u16, body: &str) {
    let reason = if code == 200 { "OK" } else { "Bad Request" };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

/// Bare GET, ignoring the response — the loopback redirect leg.
fn http_get(url: &str) {
    let rest = url.strip_prefix("http://").expect("http url");
    let (hostport, path_query) = rest.split_once('/').expect("path");
    if let Ok(mut s) = TcpStream::connect(hostport) {
        let _ = write!(
            s,
            "GET /{path_query} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n"
        );
        let mut sink = String::new();
        let _ = s.read_to_string(&mut sink);
    }
}

/// Unsigned id_token with the shape the client parses (it never validates
/// the signature of tokens received directly from the token endpoint).
fn fake_id_token() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user-123","iss":"mock"}"#);
    format!("{header}.{payload}.sig")
}
