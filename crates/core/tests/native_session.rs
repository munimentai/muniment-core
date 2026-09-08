use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_core::auth::{
    ensure_fresh_native_session, ensure_native_session, inspect_native_session, native_status,
    InstallationRecord, NativeCredentialStore, NativeCredentials, NativeSession,
    NativeSessionError, NativeSessionRequest, NativeTokenError, NativeTokenRequest,
    NativeTokenResponse, SessionTransport, TokenSet, TokenTransport, UreqSessionTransport,
};
use uuid::Uuid;

const DEVICE_ID: &str = "10000000-0000-4000-8000-000000000001";

#[derive(Default)]
struct MemoryStore(Mutex<Option<NativeCredentials>>);

impl NativeCredentialStore for MemoryStore {
    fn load_installation(
        &self,
    ) -> Result<Option<InstallationRecord>, muniment_core::auth::NativeTokenError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .as_ref()
            .map(|c| c.installation.clone()))
    }
    fn save_credentials(
        &self,
        value: &NativeCredentials,
    ) -> Result<(), muniment_core::auth::NativeTokenError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }
    fn load_credentials(
        &self,
    ) -> Result<Option<NativeCredentials>, muniment_core::auth::NativeTokenError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn clear_session(&self) -> Result<(), muniment_core::auth::NativeTokenError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

fn store() -> MemoryStore {
    MemoryStore(Mutex::new(Some(NativeCredentials {
        installation: InstallationRecord {
            private_key: [1; 32],
            device_id: Uuid::parse_str(DEVICE_ID).unwrap(),
            registration_token: "registration-secret".into(),
            device_challenge: "challenge-secret".into(),
            registration_expires_at: 600,
        },
        tokens: TokenSet {
            access_token: "access-secret".into(),
            refresh_token: Some("refresh-secret".into()),
            expires_at: Some(1_900),
            subject: Some("user".into()),
        },
        refresh_expires_at: 86_400,
    })))
}

fn success() -> String {
    // Section 2.2 uses an opaque example device ID. Registration stores a UUID.
    CONTRACT_EXAMPLE.replace("dev_desktop_1", DEVICE_ID)
}

const CONTRACT_EXAMPLE: &str = r#"{
  "session": {
    "org_id": "org_acme",
    "user_id": "usr_7",
    "role": "user",
    "device_id": "dev_desktop_1",
    "client_role": "desktop",
    "expires_at": "2026-07-11T12:15:00.000Z"
  },
  "user": {
    "id": "usr_7",
    "email": "ada@example.test",
    "status": "active",
    "role": "user",
    "entitlement_version": 42
  },
  "org": { "id": "org_acme", "display_name": "Acme" },
  "entitlement_snapshot": {
    "payload": {
      "org_id": "org_acme",
      "user_id": "usr_7",
      "entitlement_version": 42,
      "issued_at": "2026-07-11T12:00:00.000Z",
      "capabilities": ["mcp.local_stdio"],
      "grants": [{
        "id": "grt_stub",
        "principal_type": "org",
        "principal_id": "org_acme",
        "resource_type": "model",
        "resource_id": "muniment-stub-chat",
        "action": "use",
        "effect": "allow",
        "expires_at": null
      }]
    },
    "signature": "base64url-signature-redacted",
    "algorithm": "hmac-sha256"
  }
}"#;

#[test]
fn canonical_example_decodes_with_opaque_identifiers() {
    let session: NativeSession = serde_json::from_str(CONTRACT_EXAMPLE).unwrap();
    assert_eq!(session.session.device_id, "dev_desktop_1");
    assert_eq!(session.session.user_id, "usr_7");
}

struct Server {
    base_url: String,
    request: Arc<Mutex<Option<String>>>,
}

impl Server {
    fn spawn(status: u16, body: String) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let request = Arc::new(Mutex::new(None));
        let captured = request.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            *captured.lock().unwrap() = Some(read_request(&mut stream));
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        Self { base_url, request }
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream.read(&mut buffer).unwrap();
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn exact_authenticated_get_decodes_typed_contract() {
    let server = Server::spawn(200, success());
    let result = inspect_native_session(
        &store(),
        &UreqSessionTransport::new(Duration::from_secs(2)),
        &server.base_url,
    )
    .unwrap();
    assert_eq!(result.session.user_id, "usr_7");
    assert_eq!(result.entitlement_snapshot.payload.entitlement_version, 42);
    assert_eq!(result.entitlement_snapshot.payload.grants[0].id, "grt_stub");
    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with("GET /v1/auth/native/session HTTP/1.1\r\n"));
    assert_eq!(
        request
            .to_ascii_lowercase()
            .matches("authorization:")
            .count(),
        1
    );
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer access-secret\r\n"));
}

#[test]
fn composed_native_session_uses_the_local_server() {
    let server = Server::spawn(200, success());
    let result =
        ensure_native_session(&orchestration_store(2_000, 4_000), &server.base_url, 1_000).unwrap();

    assert!(result.status.signed_in);
    assert_eq!(result.status.expires_at, Some(2_000));
    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with("GET /v1/auth/native/session HTTP/1.1\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer access-secret\r\n"));
}

#[test]
fn contract_and_compatible_fields_return_the_same_signed_in_projection() {
    let body: serde_json::Value = serde_json::from_str(&success()).unwrap();
    let mut extended = body.clone();
    for pointer in [
        "",
        "/session",
        "/user",
        "/org",
        "/entitlement_snapshot",
        "/entitlement_snapshot/payload",
        "/entitlement_snapshot/payload/grants/0",
    ] {
        extended
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "future_field".into(),
                serde_json::json!({"secret": "not-for-webview"}),
            );
    }
    let mut projections = Vec::new();
    for body in [body, extended] {
        let server = Server::spawn(200, body.to_string());
        let result =
            ensure_native_session(&orchestration_store(2_000, 4_000), &server.base_url, 1_000)
                .unwrap();
        assert!(result.status.signed_in);
        assert_eq!(result.status.subject.as_deref(), Some("usr_7"));
        let view = result.entitlement_snapshot.unwrap();
        assert_eq!(view.organization_display_name.as_deref(), Some("Acme"));
        assert_eq!(view.user_display_name.as_deref(), Some("ada@example.test"));
        assert_eq!(view.role, muniment_core::auth::NativeSessionRole::User);
        assert_eq!(view.snapshot_version, 42);
        assert_eq!(view.org_id, "org_acme");
        assert_eq!(view.user_id, "usr_7");
        assert_eq!(view.capabilities, ["mcp.local_stdio"]);
        assert_eq!(
            view.grants,
            session_result().entitlement_snapshot.payload.grants
        );
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("not-for-webview"));
        assert!(!json.contains("signature"));
        projections.push(view);
    }
    assert_eq!(projections[0], projections[1]);
}

#[test]
fn rejects_inconsistent_identity_and_invalid_versions_without_changing_credentials() {
    for (pointer, value) in [
        ("/session/device_id", serde_json::json!("")),
        ("/session/client_role", serde_json::json!("")),
        ("/session/org_id", serde_json::json!("")),
        ("/user/id", serde_json::json!("other-user")),
        ("/org/id", serde_json::json!("other-org")),
        ("/user/role", serde_json::json!("owner")),
        ("/user/status", serde_json::json!("inactive")),
        ("/user/entitlement_version", serde_json::json!(43)),
        (
            "/entitlement_snapshot/payload/org_id",
            serde_json::json!("other-org"),
        ),
        (
            "/entitlement_snapshot/payload/user_id",
            serde_json::json!("other-user"),
        ),
        (
            "/entitlement_snapshot/payload/entitlement_version",
            serde_json::json!(-1),
        ),
        (
            "/entitlement_snapshot/payload/entitlement_version",
            serde_json::json!(1.5),
        ),
        (
            "/entitlement_snapshot/payload/entitlement_version",
            serde_json::json!(9_007_199_254_740_992_u64),
        ),
        ("/session/expires_at", serde_json::json!("not-a-time")),
        (
            "/entitlement_snapshot/payload/issued_at",
            serde_json::json!(null),
        ),
        ("/entitlement_snapshot/signature", serde_json::json!("")),
    ] {
        let mut body: serde_json::Value = serde_json::from_str(&success()).unwrap();
        *body.pointer_mut(pointer).unwrap() = value;
        let server = Server::spawn(200, body.to_string());
        let store = orchestration_store(2_000, 4_000);
        let before = store.load_credentials().unwrap().unwrap();
        assert_eq!(
            ensure_native_session(&store, &server.base_url, 1_000).unwrap_err(),
            muniment_core::auth::FreshNativeSessionError::SessionInspection,
            "{pointer}"
        );
        let after = store.load_credentials().unwrap().unwrap();
        assert_eq!(after.tokens.access_token, before.tokens.access_token);
        assert_eq!(after.tokens.refresh_token, before.tokens.refresh_token);
        assert_eq!(after.tokens.expires_at, before.tokens.expires_at);
        assert_eq!(after.installation.device_id, before.installation.device_id);
        assert_eq!(
            after.installation.device_challenge,
            before.installation.device_challenge
        );
        assert_eq!(after.refresh_expires_at, before.refresh_expires_at);
    }
}

#[test]
fn zero_and_max_versions_empty_grants_and_deny_records_remain_display_hints() {
    for version in [0, 9_007_199_254_740_991_u64] {
        for empty in [true, false] {
            let mut body: serde_json::Value = serde_json::from_str(&success()).unwrap();
            body["user"]["entitlement_version"] = version.into();
            let payload = &mut body["entitlement_snapshot"]["payload"];
            payload["entitlement_version"] = version.into();
            payload["capabilities"] = serde_json::json!([]);
            if empty {
                payload["grants"] = serde_json::json!([]);
            } else {
                let mut deny = payload["grants"][0].clone();
                deny["id"] = "grt_deny".into();
                deny["effect"] = "deny".into();
                deny["expires_at"] = "2000-01-01T00:00:00Z".into();
                deny["resource_id"] = serde_json::Value::Null;
                deny["principal_id"] = serde_json::Value::Null;
                payload["grants"].as_array_mut().unwrap().push(deny);
            }
            let expected: NativeSession = serde_json::from_value(body.clone()).unwrap();
            let server = Server::spawn(200, body.to_string());
            let result =
                ensure_native_session(&orchestration_store(2_000, 4_000), &server.base_url, 1_000)
                    .unwrap();
            assert!(result.status.signed_in);
            let view = result.entitlement_snapshot.unwrap();
            assert_eq!(view.snapshot_version, version);
            assert!(view.capabilities.is_empty());
            assert_eq!(view.grants, expected.entitlement_snapshot.payload.grants);
        }
    }
}

#[test]
fn signed_out_and_bad_configuration_make_no_request() {
    let server = Server::spawn(200, success());
    assert_eq!(
        inspect_native_session(
            &MemoryStore::default(),
            &UreqSessionTransport::new(Duration::from_secs(1)),
            &server.base_url
        )
        .unwrap_err(),
        NativeSessionError::CredentialsMissing
    );
    assert!(server.request.lock().unwrap().is_none());
    assert!(matches!(
        inspect_native_session(
            &store(),
            &UreqSessionTransport::new(Duration::from_secs(1)),
            "http://example.com"
        ),
        Err(NativeSessionError::Config(_))
    ));
}

#[test]
fn rejects_wrong_device_role_algorithm_and_schema_without_mutation() {
    let cases = [
        success().replace(DEVICE_ID, "10000000-0000-4000-8000-000000000009"),
        success().replace(
            "\"client_role\": \"desktop\"",
            "\"client_role\": \"mobile\"",
        ),
        success().replace("\"role\": \"user\"", "\"role\": \"superuser\""),
        success().replace("hmac-sha256", "ed25519"),
        success().replace("\"client_role\": \"desktop\",", ""),
    ];
    for body in cases {
        let server = Server::spawn(200, body);
        let store = store();
        assert!(matches!(
            inspect_native_session(
                &store,
                &UreqSessionTransport::new(Duration::from_secs(2)),
                &server.base_url
            ),
            Err(NativeSessionError::MalformedResponse(_))
        ));
        assert_eq!(
            store
                .load_credentials()
                .unwrap()
                .unwrap()
                .tokens
                .access_token,
            "access-secret"
        );
    }
}

#[test]
fn rejects_malformed_required_entitlement_fields() {
    for body in [
        success().replace(
            "\"entitlement_version\": 42",
            "\"entitlement_version\": \"seven\"",
        ),
        success().replace("\"grants\": [{", "\"grants\": [null, {"),
        success().replace(
            "\"capabilities\": [\"mcp.local_stdio\"]",
            "\"capabilities\": [4]",
        ),
    ] {
        let server = Server::spawn(200, body);
        assert!(matches!(
            inspect_native_session(
                &store(),
                &UreqSessionTransport::new(Duration::from_secs(2)),
                &server.base_url
            ),
            Err(NativeSessionError::MalformedResponse(_))
        ));
    }
}

#[test]
fn failures_and_debug_output_redact_all_secrets() {
    for (status, body) in [
        (401, "response-secret".into()),
        (200, "signature-secret invalid".into()),
    ] {
        let server = Server::spawn(status, body);
        let error = inspect_native_session(
            &store(),
            &UreqSessionTransport::new(Duration::from_secs(2)),
            &server.base_url,
        )
        .unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("response-secret"));
        assert!(!rendered.contains("signature-secret"));
    }
    let session: muniment_core::auth::NativeSession = serde_json::from_str(&success()).unwrap();
    let rendered = format!("{session:?}");
    assert!(!rendered.contains("base64url-signature-redacted"));
    assert!(matches!(
        inspect_native_session(
            &store(),
            &UreqSessionTransport::new(Duration::from_millis(50)),
            "http://127.0.0.1:1"
        ),
        Err(NativeSessionError::Transport(_))
    ));
}

struct CountingTokenTransport {
    calls: AtomicUsize,
    response: Option<String>,
    error: Option<NativeTokenError>,
}

impl TokenTransport for CountingTokenTransport {
    fn exchange(
        &self,
        _: &str,
        _: &NativeTokenRequest,
    ) -> Result<NativeTokenResponse, NativeTokenError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        Ok(serde_json::from_str(self.response.as_deref().unwrap()).unwrap())
    }
}

struct CountingSessionTransport {
    calls: AtomicUsize,
    result: Result<NativeSession, NativeSessionError>,
}

impl SessionTransport for CountingSessionTransport {
    fn inspect(
        &self,
        _: &str,
        _: &NativeSessionRequest,
    ) -> Result<NativeSession, NativeSessionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

fn session_result() -> NativeSession {
    serde_json::from_str(&success()).unwrap()
}

fn token_response() -> String {
    let challenge =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [12; 32]);
    format!(
        r#"{{"access_token":"rotated-access-secret","token_type":"Bearer","expires_in":900,"refresh_token":"rotated-refresh-secret","refresh_expires_in":86400,"session":{{"org_id":"20000000-0000-4000-8000-000000000002","user_id":"30000000-0000-4000-8000-000000000003","role":"user","device_id":"{DEVICE_ID}","client_role":"desktop"}},"entitlement_snapshot":{{"payload":{{"version":8}},"signature":"rotated-signature-secret","algorithm":"hmac-sha256"}},"device_challenge":"{challenge}"}}"#
    )
}

fn orchestration_store(expires_at: u64, refresh_expires_at: u64) -> MemoryStore {
    let store = store();
    let mut credentials = store.load_credentials().unwrap().unwrap();
    credentials.tokens.expires_at = Some(expires_at);
    credentials.refresh_expires_at = refresh_expires_at;
    credentials.installation.device_challenge =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [11; 32]);
    store.save_credentials(&credentials).unwrap();
    store
}

#[test]
fn local_native_status_uses_only_the_coherent_record() {
    let empty = MemoryStore::default();
    assert!(!native_status(&empty, 1_000).unwrap().signed_in);

    let status = native_status(&orchestration_store(500, 4_000), 1_000).unwrap();
    assert!(status.signed_in);
    assert_eq!(status.subject.as_deref(), Some("user"));
    assert_eq!(status.expires_at, Some(500));

    let status = native_status(&orchestration_store(2_000, 1_000), 1_000).unwrap();
    assert!(!status.signed_in);
    assert_eq!(status.subject, None);
    assert_eq!(status.expires_at, None);
}

#[test]
fn fresh_credentials_skip_exchange_but_still_validate_the_session() {
    let tokens = CountingTokenTransport {
        calls: AtomicUsize::new(0),
        response: None,
        error: Some(NativeTokenError::Transport("token-secret".into())),
    };
    let sessions = CountingSessionTransport {
        calls: AtomicUsize::new(0),
        result: Ok(session_result()),
    };
    let result = ensure_fresh_native_session(
        &orchestration_store(1_061, 4_000),
        &tokens,
        &sessions,
        "http://localhost:3000",
        1_000,
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(result.status.signed_in);
    assert_eq!(result.status.subject.as_deref(), Some("usr_7"));
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sessions.calls.load(Ordering::SeqCst), 1);
    let projection = result.entitlement_snapshot.unwrap();
    assert_eq!(
        projection.role,
        muniment_core::auth::NativeSessionRole::User
    );
    assert_eq!(
        projection.grants[0].resource_id.as_deref(),
        Some("muniment-stub-chat")
    );
    assert_eq!(projection.capabilities, ["mcp.local_stdio"]);
    let json = serde_json::to_string(&projection).unwrap();
    for forbidden in [
        "signature",
        "algorithm",
        "access-secret",
        "refresh-secret",
        "challenge-secret",
        "private_key",
        "entitlement_snapshot",
    ] {
        assert!(!json.contains(forbidden), "projection leaked {forbidden}");
    }
}

#[test]
fn near_expiry_refreshes_persists_rotation_then_inspects() {
    let store = orchestration_store(1_060, 4_000);
    let tokens = CountingTokenTransport {
        calls: AtomicUsize::new(0),
        response: Some(token_response()),
        error: None,
    };
    let sessions = CountingSessionTransport {
        calls: AtomicUsize::new(0),
        result: Ok(session_result()),
    };
    let result = ensure_fresh_native_session(
        &store,
        &tokens,
        &sessions,
        "http://localhost:3000",
        1_000,
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sessions.calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.status.expires_at, Some(1_900));
    let persisted = store.load_credentials().unwrap().unwrap();
    assert_eq!(persisted.tokens.access_token, "rotated-access-secret");
    assert_eq!(
        persisted.tokens.refresh_token.as_deref(),
        Some("rotated-refresh-secret")
    );
    assert_eq!(persisted.refresh_expires_at, 87_400);
}

#[test]
fn signed_out_refresh_and_validation_failures_are_fail_closed_and_redacted() {
    let tokens = CountingTokenTransport {
        calls: AtomicUsize::new(0),
        response: None,
        error: Some(NativeTokenError::HttpStatus(401)),
    };
    let sessions = CountingSessionTransport {
        calls: AtomicUsize::new(0),
        result: Err(NativeSessionError::Transport("session-secret".into())),
    };
    for store in [MemoryStore::default(), orchestration_store(900, 1_000)] {
        let result = ensure_fresh_native_session(
            &store,
            &tokens,
            &sessions,
            "http://localhost:3000",
            1_000,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(!result.status.signed_in);
    }
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sessions.calls.load(Ordering::SeqCst), 0);

    let store = orchestration_store(1_060, 4_000);
    let old_access = store
        .load_credentials()
        .unwrap()
        .unwrap()
        .tokens
        .access_token;
    let error = ensure_fresh_native_session(
        &store,
        &tokens,
        &sessions,
        "http://localhost:3000",
        1_000,
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert_eq!(
        store
            .load_credentials()
            .unwrap()
            .unwrap()
            .tokens
            .access_token,
        old_access
    );
    assert!(!format!("{error:?} {error}").contains("secret"));

    let fresh = orchestration_store(2_000, 4_000);
    let error = ensure_fresh_native_session(
        &fresh,
        &tokens,
        &sessions,
        "http://localhost:3000",
        1_000,
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert_eq!(
        fresh
            .load_credentials()
            .unwrap()
            .unwrap()
            .tokens
            .access_token,
        "access-secret"
    );
    assert!(!format!("{error:?} {error}").contains("secret"));
}
