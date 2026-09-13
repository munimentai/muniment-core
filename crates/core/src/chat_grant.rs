//! Cloud chat grant and receipt contracts.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::sidecar::pi_chat::Receipt;

mod gateway;
mod recovery;

pub(crate) use gateway::{answer_grant_request, grant_error_message};
#[cfg(feature = "keyring")]
pub(crate) use recovery::inspect_native_chat_session;
#[cfg(test)]
pub(crate) use recovery::refresh_chat_credentials;

const SAFE_LIFE_SECONDS: u64 = 90;

const GRANT_PATH: &str = "/v1/chat/grants";
const PROTOCOL: &str = "muniment.desktop-access/1";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
// The grant contract does not supply a receipt URL.
const RECEIPT_PATH: &str = "/v1/chat/receipts";

// This launch value also serves local mode. Only GrantResponse reads cloud JSON.
pub struct ChatGrant {
    pub workspace: String,
    pub gateway_url: String,
    pub virtual_key: String,
    pub model: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub native_access_token: Option<String>,
    pub minimum_cacheable_prefix_characters: usize,
    pub receipt_url: String,
}

impl ChatGrant {
    pub fn local() -> Self {
        Self {
            workspace: "local".into(),
            gateway_url: String::new(),
            virtual_key: String::new(),
            model: None,
            expires_at: None,
            native_access_token: None,
            minimum_cacheable_prefix_characters: 8_192,
            receipt_url: String::new(),
        }
    }

    pub fn needs_renewal(&self) -> bool {
        // Safe life excludes the contract's 30-second clock-skew margin.
        self.expires_at.is_some_and(|expiry| {
            expiry <= Utc::now() + chrono::Duration::seconds(SAFE_LIFE_SECONDS as i64)
        })
    }

    pub fn is_local(&self) -> bool {
        self.workspace == "local"
            && self.gateway_url.is_empty()
            && self.virtual_key.is_empty()
            && self.receipt_url.is_empty()
    }
}

impl std::fmt::Debug for ChatGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatGrant")
            .field("workspace", &self.workspace)
            .field("model", &self.model)
            .field("expires_at", &self.expires_at)
            .field("virtual_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchGrantError {
    Unauthorized,
    NotEntitled { message: String },
    Unavailable,
    InvalidResponse,
}

impl FetchGrantError {
    pub fn into_message(self) -> String {
        match self {
            Self::Unauthorized => "The capability is not authorized.".into(),
            Self::NotEntitled { message } => format!("chat_not_entitled: {message}"),
            Self::Unavailable => "Chat configuration is temporarily unavailable.".into(),
            Self::InvalidResponse => "The chat configuration response was invalid.".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchReceiptError;

#[derive(Deserialize)]
struct GrantResponse {
    protocol: String,
    chat_grant: CloudGrant,
}

#[derive(Deserialize)]
struct CloudGrant {
    grant_id: String,
    gateway_url: String,
    virtual_key: String,
    allowed_models: Vec<String>,
    issued_at: DateTime<chrono::FixedOffset>,
    expires_at: DateTime<chrono::FixedOffset>,
    native_session_id: String,
    device_id: String,
    entitlement_version: u64,
}

/// Load the installation from the same credential record as the native bearer.
#[cfg(feature = "keyring")]
pub fn fetch_native_grant(
    issuer_base_url: &str,
    access_token: &str,
) -> Result<ChatGrant, FetchGrantError> {
    recovery::fetch_native(issuer_base_url, access_token)
}

#[cfg(feature = "keyring")]
pub(crate) fn renew_native_grant(access_token: &str) -> Result<ChatGrant, FetchGrantError> {
    fetch_native_grant(&crate::auth::api_base_url(), access_token)
}

pub fn fetch_grant(
    issuer_base_url: &str,
    access_token: &str,
    expected_device_id: &str,
) -> Result<ChatGrant, FetchGrantError> {
    if !is_control_plane_endpoint(issuer_base_url) {
        return Err(FetchGrantError::InvalidResponse);
    }
    if access_token.trim().is_empty() || expected_device_id.trim().is_empty() {
        return Err(FetchGrantError::Unauthorized);
    }
    // Each run requests a new key. Retry a stale issuance once, never reuse it.
    for attempt in 0..2 {
        let grant = issue_grant(issuer_base_url, access_token, expected_device_id)
            .map_err(|failure| failure.shell_error())?;
        if grant.needs_renewal() {
            if attempt == 0 {
                continue;
            }
            return Err(FetchGrantError::Unavailable);
        }
        return Ok(grant);
    }
    unreachable!()
}

pub(crate) fn issue_grant(
    issuer_base_url: &str,
    access_token: &str,
    expected_device_id: &str,
) -> Result<ChatGrant, recovery::GrantFailure> {
    use recovery::GrantFailure;
    if !is_control_plane_endpoint(issuer_base_url) {
        return Err(GrantFailure::Other(FetchGrantError::InvalidResponse));
    }
    if access_token.trim().is_empty() || expected_device_id.trim().is_empty() {
        return Err(GrantFailure::SessionInvalid);
    }
    let response = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .post(&format!(
            "{}{GRANT_PATH}",
            issuer_base_url.trim_end_matches('/')
        ))
        .set("Authorization", &format!("Bearer {access_token}"))
        .send_json(serde_json::json!({"protocol": PROTOCOL}))
        .map_err(|error| match error {
            ureq::Error::Status(status, response) => grant_status_error(status, response),
            ureq::Error::Transport(_) => GrantFailure::Other(FetchGrantError::Unavailable),
        })?;
    if response.status() != 201 {
        return Err(GrantFailure::Other(FetchGrantError::InvalidResponse));
    }
    let envelope: GrantResponse = response
        .into_json()
        .map_err(|_| GrantFailure::Other(FetchGrantError::InvalidResponse))?;
    parse_grant(envelope, issuer_base_url, expected_device_id).map_err(GrantFailure::Other)
}

fn parse_grant(
    envelope: GrantResponse,
    issuer_base_url: &str,
    expected_device_id: &str,
) -> Result<ChatGrant, FetchGrantError> {
    let wire = envelope.chat_grant;
    let lifetime = wire.expires_at - wire.issued_at;
    if envelope.protocol != PROTOCOL
        || wire.device_id != expected_device_id
        || wire.grant_id.trim().is_empty()
        || wire.native_session_id.trim().is_empty()
        || wire.entitlement_version > MAX_SAFE_INTEGER
        || wire.issued_at.offset().local_minus_utc() != 0
        || wire.expires_at.offset().local_minus_utc() != 0
        || lifetime <= chrono::Duration::zero()
        || lifetime > chrono::Duration::minutes(15)
        || wire.issued_at > Utc::now() + chrono::Duration::seconds(60)
        || wire.allowed_models.is_empty()
        || wire
            .allowed_models
            .iter()
            .any(|model| model.trim().is_empty())
        || wire
            .allowed_models
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !is_https_endpoint(&wire.gateway_url)
        || wire.virtual_key.trim().is_empty()
    {
        return Err(FetchGrantError::InvalidResponse);
    }
    Ok(ChatGrant {
        gateway_url: wire.gateway_url,
        virtual_key: wire.virtual_key,
        model: wire.allowed_models.into_iter().next(),
        expires_at: Some(wire.expires_at.with_timezone(&Utc)),
        receipt_url: format!("{}{RECEIPT_PATH}", issuer_base_url.trim_end_matches('/')),
        ..ChatGrant::local()
    })
}

fn is_control_plane_endpoint(value: &str) -> bool {
    is_https_endpoint(value)
        || url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "http"
                && url.host_str().is_some_and(|host| {
                    host == "localhost"
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                })
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

fn is_https_endpoint(value: &str) -> bool {
    value.trim() == value
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

pub fn renew_grant_if_needed(
    grant: &mut ChatGrant,
    renew: impl FnOnce() -> Result<ChatGrant, FetchGrantError>,
) -> Result<(), FetchGrantError> {
    if grant.needs_renewal() {
        // Drop the expired key even when renewal fails.
        grant.virtual_key.clear();
        let replacement = renew()?;
        validate_grant(&replacement)?;
        if replacement.workspace != grant.workspace || replacement.expires_at.is_none() {
            return Err(FetchGrantError::InvalidResponse);
        }
        *grant = replacement;
    }
    Ok(())
}

pub fn validate_grant(grant: &ChatGrant) -> Result<(), FetchGrantError> {
    if !is_https_endpoint(&grant.gateway_url)
        || !is_control_plane_endpoint(&grant.receipt_url)
        || grant
            .expires_at
            .is_some_and(|expiry| expiry <= Utc::now() + chrono::Duration::seconds(30))
        || grant.virtual_key.trim().is_empty()
        || grant.workspace.trim().is_empty()
        || grant.minimum_cacheable_prefix_characters == 0
    {
        return Err(FetchGrantError::InvalidResponse);
    }
    Ok(())
}

pub fn grant_authorizes_workspace(grant: &ChatGrant, requested_workspace: Option<&str>) -> bool {
    requested_workspace.is_none_or(|workspace| workspace == grant.workspace)
}

pub fn fetch_receipt(
    endpoint_url: &str,
    access_token: &str,
    run_id: &str,
) -> Result<Receipt, FetchReceiptError> {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .post(endpoint_url)
        .set("Authorization", &format!("Bearer {access_token}"))
        .send_json(serde_json::json!({"runId": run_id}))
        .map_err(|_| FetchReceiptError)?
        .into_json()
        .map_err(|_| FetchReceiptError)
}

fn grant_status_error(status: u16, response: ureq::Response) -> recovery::GrantFailure {
    use recovery::GrantFailure;
    let invalid = GrantFailure::Other(FetchGrantError::InvalidResponse);
    if status >= 500 && status != 503 {
        return GrantFailure::Other(FetchGrantError::Unavailable);
    }
    #[derive(Deserialize)]
    struct ErrorEnvelope {
        protocol: String,
        error: ErrorBody,
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        code: String,
        message: String,
        #[serde(default, deserialize_with = "present_seconds")]
        retry_after_seconds: Option<u64>,
    }
    fn present_seconds<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        u64::deserialize(deserializer).map(Some)
    }
    let Ok(envelope) = response.into_json::<ErrorEnvelope>() else {
        return invalid;
    };
    let error = envelope.error;
    if envelope.protocol != PROTOCOL
        || error.message.trim().is_empty()
        || error
            .retry_after_seconds
            .is_some_and(|seconds| seconds > MAX_SAFE_INTEGER)
        || (error.retry_after_seconds.is_some()
            && !matches!(
                error.code.as_str(),
                "rate_limited" | "temporarily_unavailable"
            ))
    {
        return invalid;
    }
    match (status, error.code.as_str()) {
        (401, "session_invalid") => GrantFailure::SessionInvalid,
        (403, "device_removed") => GrantFailure::DeviceRemoved,
        (403, "chat_not_entitled") => GrantFailure::NotEntitled(error.message),
        (409, "entitlement_changed") => GrantFailure::EntitlementChanged,
        (503, "temporarily_unavailable") => {
            GrantFailure::Wait(error.retry_after_seconds.unwrap_or(1))
        }
        (429, "rate_limited") if error.retry_after_seconds.is_some() => {
            GrantFailure::Wait(error.retry_after_seconds.unwrap())
        }
        _ => invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    const GRANT_RESPONSE: &str = r#"{
      "protocol": "muniment.desktop-access/1",
      "chat_grant": {
        "grant_id": "cgr_01JZQ8H4YH6F8B10D2A3",
        "gateway_url": "https://llm.internal.muniment.example/v1",
        "virtual_key": "sk-muniment-ephemeral-example",
        "allowed_models": ["muniment-stub-chat"],
        "issued_at": "2026-07-11T12:00:00.000Z",
        "expires_at": "2026-07-11T12:15:00.000Z",
        "native_session_id": "nas_01JZQ7ZKJ3E9Y5QH5T1R",
        "device_id": "dev_desktop_1",
        "entitlement_version": 42
      }
    }"#;

    fn current_response() -> Value {
        let mut body: Value = serde_json::from_str(GRANT_RESPONSE).unwrap();
        body["chat_grant"]["issued_at"] = json!(Utc::now());
        body["chat_grant"]["expires_at"] = json!(Utc::now() + chrono::Duration::minutes(14));
        body
    }

    fn valid_grant() -> ChatGrant {
        ChatGrant {
            workspace: "/work".into(),
            gateway_url: "https://gateway.example.com".into(),
            virtual_key: "key".into(),
            receipt_url: "https://receipts.example.com".into(),
            ..ChatGrant::local()
        }
    }

    #[test]
    fn accepts_valid_grant() {
        assert_eq!(validate_grant(&valid_grant()), Ok(()));
    }

    #[test]
    fn grant_workspace_authorizes_only_matching_and_missing_requests() {
        let grant = valid_grant();
        assert!(grant_authorizes_workspace(&grant, Some("/work")));
        assert!(!grant_authorizes_workspace(&grant, Some("/other")));
        assert!(grant_authorizes_workspace(&grant, None));
    }

    #[test]
    fn rejects_non_https_gateway_url() {
        let grant = ChatGrant {
            gateway_url: "http://gateway.example.com".into(),
            ..valid_grant()
        };
        assert_eq!(
            validate_grant(&grant),
            Err(FetchGrantError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_non_https_receipt_url() {
        let grant = ChatGrant {
            receipt_url: "http://receipts.example.com".into(),
            ..valid_grant()
        };
        assert_eq!(
            validate_grant(&grant),
            Err(FetchGrantError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_blank_virtual_key() {
        let grant = ChatGrant {
            virtual_key: " \t".into(),
            ..valid_grant()
        };
        assert_eq!(
            validate_grant(&grant),
            Err(FetchGrantError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_blank_workspace() {
        let grant = ChatGrant {
            workspace: " \t".into(),
            ..valid_grant()
        };
        assert_eq!(
            validate_grant(&grant),
            Err(FetchGrantError::InvalidResponse)
        );
    }

    #[test]
    fn rejects_zero_memory_character_budget() {
        let grant = ChatGrant {
            minimum_cacheable_prefix_characters: 0,
            ..valid_grant()
        };
        assert_eq!(
            validate_grant(&grant),
            Err(FetchGrantError::InvalidResponse)
        );
    }

    #[test]
    fn parses_canonical_envelope_and_compatible_fields() {
        let mut body: Value = serde_json::from_str(GRANT_RESPONSE).unwrap();
        body["compatible"] = json!(true);
        body["chat_grant"]["compatible"] = json!({"value": 1});
        let grant = parse_grant(
            serde_json::from_value(body).unwrap(),
            "https://api.example.com",
            "dev_desktop_1",
        )
        .unwrap();
        assert_eq!(
            grant.gateway_url,
            "https://llm.internal.muniment.example/v1"
        );
        assert_eq!(grant.virtual_key, "sk-muniment-ephemeral-example");
        assert_eq!(grant.model.as_deref(), Some("muniment-stub-chat"));
        assert_eq!(grant.workspace, "local");
        assert!(!grant.is_local());
        assert!(!format!("{grant:?}").contains(&grant.virtual_key));
    }

    #[test]
    fn rejects_invalid_envelopes() {
        for (field, value) in [
            ("device_id", json!("another-device")),
            ("grant_id", json!("")),
            ("native_session_id", json!(" ")),
            ("virtual_key", json!(" ")),
            ("allowed_models", json!([])),
            ("allowed_models", json!([""])),
            ("allowed_models", json!(["b", "a"])),
            ("allowed_models", json!(["a", "a"])),
            ("entitlement_version", json!(-1)),
            ("entitlement_version", json!(1.5)),
            ("entitlement_version", json!(MAX_SAFE_INTEGER + 1)),
            ("issued_at", json!("invalid")),
            ("expires_at", json!("2026-07-11T12:00:00.000Z")),
            ("expires_at", json!("2026-07-11T12:16:00.000Z")),
            ("gateway_url", json!("http://gateway.example.com")),
            (
                "gateway_url",
                json!("https://user:secret@gateway.example.com"),
            ),
            (
                "gateway_url",
                json!("https://gateway.example.com?key=secret"),
            ),
            (
                "gateway_url",
                json!("https://gateway.example.com/#fragment"),
            ),
            ("gateway_url", json!("https://")),
        ] {
            let mut body: Value = serde_json::from_str(GRANT_RESPONSE).unwrap();
            body["chat_grant"][field] = value;
            let parsed = serde_json::from_value(body)
                .map_err(|_| FetchGrantError::InvalidResponse)
                .and_then(|body| parse_grant(body, "https://api.example.com", "dev_desktop_1"));
            assert_eq!(
                parsed.unwrap_err(),
                FetchGrantError::InvalidResponse,
                "{field}"
            );
        }
        let body = GRANT_RESPONSE.replace(PROTOCOL, "muniment.desktop-access/2");
        assert_eq!(
            parse_grant(
                serde_json::from_str(&body).unwrap(),
                "https://api.example.com",
                "dev_desktop_1"
            )
            .unwrap_err(),
            FetchGrantError::InvalidResponse
        );
    }

    #[test]
    fn maps_authentication_statuses_to_unauthorized() {
        for (status, code) in [(401, "session_invalid"), (403, "device_removed")] {
            let body = json!({"protocol": PROTOCOL, "error": {"code": code, "message": "Denied."}});
            let response = ureq::Response::new(status, "Error", &body.to_string()).unwrap();
            assert_eq!(
                grant_status_error(status, response).shell_error(),
                FetchGrantError::Unauthorized
            );
        }
        let response = ureq::Response::new(500, "Error", "").unwrap();
        assert_eq!(
            grant_status_error(500, response).shell_error(),
            FetchGrantError::Unavailable
        );
    }

    struct RecoveryProbe {
        base: String,
        token: String,
        actions: Vec<String>,
        refresh_fails: bool,
        inspection_failures: std::collections::VecDeque<recovery::GrantFailure>,
        session_expires_at: Option<u64>,
    }

    impl recovery::GrantRecovery for RecoveryProbe {
        fn session_needs_renewal(&self) -> bool {
            recovery::session_needs_renewal(
                self.session_expires_at,
                Utc::now().timestamp().max(0) as u64,
            )
        }
        fn issue(&mut self) -> Result<ChatGrant, recovery::GrantFailure> {
            self.actions.push("issue".into());
            issue_grant(&self.base, &self.token, "dev_desktop_1")
        }
        fn refresh(&mut self) -> Result<(), FetchGrantError> {
            self.actions.push("refresh".into());
            if self.refresh_fails {
                return Err(FetchGrantError::Unauthorized);
            }
            self.session_expires_at = None;
            self.token = "refreshed-token".into();
            Ok(())
        }
        fn inspect(&mut self) -> Result<(), recovery::GrantFailure> {
            self.actions.push("inspect".into());
            self.inspection_failures.pop_front().map_or(Ok(()), Err)
        }
        fn clear(&mut self, installation: bool) -> Result<(), FetchGrantError> {
            self.actions.push(
                if installation {
                    "clear-installation"
                } else {
                    "clear-session"
                }
                .into(),
            );
            Ok(())
        }
        fn wait(&mut self, seconds: u64, retry: bool) -> Result<(), FetchGrantError> {
            self.actions.push(format!("wait:{seconds}:{retry}"));
            if retry && seconds <= 30 {
                Ok(())
            } else {
                Err(FetchGrantError::Unavailable)
            }
        }
    }

    fn issuance_failure(status: u16, code: &str, wait: Option<u64>) -> (u16, String) {
        let mut body = json!({"protocol": PROTOCOL, "error": {"code": code, "message": "The request failed."}});
        if let Some(wait) = wait {
            body["error"]["retry_after_seconds"] = json!(wait);
        }
        (status, body.to_string())
    }

    #[test]
    fn issuance_recovers_before_shell_mapping() {
        use recovery::recover_grant;
        for (status, code, wait, actions, succeeds) in [
            (400, "invalid_request", None, vec!["issue"], false),
            (
                401,
                "session_invalid",
                None,
                vec!["issue", "refresh", "issue"],
                true,
            ),
            (
                403,
                "device_removed",
                None,
                vec!["issue", "clear-installation"],
                false,
            ),
            (403, "chat_not_entitled", None, vec!["issue"], false),
            (
                409,
                "entitlement_changed",
                None,
                vec!["issue", "inspect", "issue"],
                true,
            ),
            (
                429,
                "rate_limited",
                Some(5),
                vec!["issue", "wait:5:true", "issue"],
                true,
            ),
            (
                503,
                "temporarily_unavailable",
                None,
                vec!["issue", "wait:1:true", "issue"],
                true,
            ),
            (
                503,
                "temporarily_unavailable",
                Some(7),
                vec!["issue", "wait:7:true", "issue"],
                true,
            ),
            (
                429,
                "rate_limited",
                Some(31),
                vec!["issue", "wait:31:true"],
                false,
            ),
        ] {
            let mut responses = vec![issuance_failure(status, code, wait)];
            if succeeds {
                responses.push((201, current_response().to_string()));
            }
            let (base, stub) = serve(responses);
            let mut probe = RecoveryProbe {
                base,
                token: "initial-token".into(),
                actions: Vec::new(),
                refresh_fails: false,
                inspection_failures: Default::default(),
                session_expires_at: None,
            };
            assert_eq!(recover_grant(&mut probe).is_ok(), succeeds, "{code}");
            assert_eq!(probe.actions, actions, "{code}");
            let requests = stub.join().unwrap();
            if code == "session_invalid" {
                assert!(requests[1].contains("Bearer refreshed-token"));
            }
            for request in requests {
                assert_eq!(
                    serde_json::from_str::<Value>(request_body(&request)).unwrap(),
                    json!({"protocol": PROTOCOL})
                );
            }
        }
    }

    #[test]
    fn near_expiry_session_refresh_shares_the_recovery_budget() {
        for denied in [false, true] {
            let response = if denied {
                issuance_failure(401, "session_invalid", None)
            } else {
                (201, current_response().to_string())
            };
            let (base, stub) = serve(vec![response]);
            let mut probe = RecoveryProbe {
                base,
                token: "near-expiry-token".into(),
                actions: Vec::new(),
                refresh_fails: false,
                inspection_failures: Default::default(),
                session_expires_at: Some(Utc::now().timestamp() as u64 + 80),
            };
            assert_eq!(recovery::recover_grant(&mut probe).is_ok(), !denied);
            if denied {
                assert_eq!(probe.actions, ["refresh", "issue", "clear-session"]);
            } else {
                assert_eq!(probe.actions, ["refresh", "issue"]);
            }
            let requests = stub.join().unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].contains("Bearer refreshed-token"));
        }
    }

    #[test]
    fn entitlement_refusal_keeps_the_cloud_message_without_recovery() {
        let message = "No chat model is currently available for this account.";
        let body = json!({"protocol": PROTOCOL, "error": {
            "code": "chat_not_entitled", "message": message
        }});
        let (base, stub) = serve(vec![(403, body.to_string())]);
        let mut probe = RecoveryProbe {
            base,
            token: "token".into(),
            actions: Vec::new(),
            refresh_fails: false,
            inspection_failures: Default::default(),
            session_expires_at: None,
        };
        let started = std::time::Instant::now();
        let error = recovery::recover_grant(&mut probe).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(30));
        assert_eq!(
            error,
            FetchGrantError::NotEntitled {
                message: message.into()
            }
        );
        assert_eq!(
            error.into_message(),
            format!("chat_not_entitled: {message}")
        );
        assert_eq!(probe.actions, ["issue"]);
        assert_eq!(stub.join().unwrap().len(), 1);
    }

    #[test]
    fn entitlement_refusal_rejects_invalid_and_contradictory_envelopes() {
        for (status, protocol, message, extra) in [
            (401, PROTOCOL, json!("Denied."), json!({})),
            (403, "v2", json!("Denied."), json!({})),
            (403, PROTOCOL, json!(" "), json!({})),
            (403, PROTOCOL, json!(null), json!({})),
            (
                403,
                PROTOCOL,
                json!("Denied."),
                json!({"retry_after_seconds": 0}),
            ),
        ] {
            let mut error = json!({"code": "chat_not_entitled", "message": message});
            error
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let body = json!({"protocol": protocol, "error": error});
            let response = ureq::Response::new(status, "Error", &body.to_string()).unwrap();
            assert_eq!(
                grant_status_error(status, response).shell_error(),
                FetchGrantError::InvalidResponse
            );
        }
    }

    #[test]
    fn issuance_limits_refresh_inspection_and_backoff() {
        use recovery::{recover_grant, GrantFailure};
        for (responses, refresh_fails, inspections, expected) in [
            (
                vec![issuance_failure(401, "session_invalid", None)],
                true,
                vec![],
                vec!["issue", "refresh", "clear-session"],
            ),
            (
                vec![issuance_failure(401, "session_invalid", None); 2],
                false,
                vec![],
                vec!["issue", "refresh", "issue", "clear-session"],
            ),
            (
                vec![issuance_failure(409, "entitlement_changed", None); 2],
                false,
                vec![],
                vec!["issue", "inspect", "issue"],
            ),
            (
                vec![
                    issuance_failure(429, "rate_limited", Some(5)),
                    issuance_failure(429, "rate_limited", Some(8)),
                ],
                false,
                vec![],
                vec!["issue", "wait:5:true", "issue", "wait:8:false"],
            ),
            (
                vec![issuance_failure(409, "entitlement_changed", None)],
                false,
                vec![GrantFailure::SessionInvalid; 2],
                vec!["issue", "inspect", "refresh", "inspect", "clear-session"],
            ),
            (
                vec![issuance_failure(409, "entitlement_changed", None)],
                false,
                vec![GrantFailure::DeviceRemoved],
                vec!["issue", "inspect", "clear-installation"],
            ),
        ] {
            let (base, stub) = serve(responses);
            let mut probe = RecoveryProbe {
                base,
                token: "token".into(),
                actions: Vec::new(),
                refresh_fails,
                inspection_failures: inspections.into(),
                session_expires_at: None,
            };
            assert!(recover_grant(&mut probe).is_err());
            assert_eq!(probe.actions, expected);
            stub.join().unwrap();
        }
    }

    #[test]
    fn maps_each_issuance_error() {
        for (status, code, expected) in [
            (400, "invalid_request", FetchGrantError::InvalidResponse),
            (401, "session_invalid", FetchGrantError::Unauthorized),
            (403, "device_removed", FetchGrantError::Unauthorized),
            (
                403,
                "chat_not_entitled",
                FetchGrantError::NotEntitled {
                    message: "Denied.".into(),
                },
            ),
            (409, "entitlement_changed", FetchGrantError::Unavailable),
            (429, "rate_limited", FetchGrantError::Unavailable),
            (503, "temporarily_unavailable", FetchGrantError::Unavailable),
        ] {
            let mut body =
                json!({"protocol": PROTOCOL, "error": {"code": code, "message": "Denied."}});
            if code == "rate_limited" {
                body["error"]["retry_after_seconds"] = json!(5);
            }
            let (base, stub) = serve(vec![(status, body.to_string())]);
            assert_eq!(
                fetch_grant(&base, "access-token", "dev_desktop_1").unwrap_err(),
                expected
            );
            assert_eq!(stub.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn rejects_invalid_error_envelopes() {
        for body in [
            json!({"protocol": "v2", "error": {"code": "session_invalid", "message": "Denied."}}),
            json!({"protocol": PROTOCOL, "error": {"code": "rate_limited", "message": "Denied."}}),
            json!({"protocol": PROTOCOL, "error": {"code": "rate_limited", "message": "Denied.", "retry_after_seconds": -1}}),
            json!({"protocol": PROTOCOL, "error": {"code": "rate_limited", "message": "Denied.", "retry_after_seconds": MAX_SAFE_INTEGER + 1}}),
            json!({"protocol": PROTOCOL, "error": {"code": "session_invalid", "message": "Denied."}}),
        ] {
            let response = ureq::Response::new(429, "Error", &body.to_string()).unwrap();
            assert_eq!(
                grant_status_error(429, response).shell_error(),
                FetchGrantError::InvalidResponse
            );
        }
    }

    #[test]
    fn renews_expired_grant_with_a_new_post_and_bounds_retries() {
        for renewed in [true, false] {
            let stale = {
                let mut body = current_response();
                body["chat_grant"]["issued_at"] = json!(Utc::now() - chrono::Duration::minutes(5));
                body["chat_grant"]["expires_at"] =
                    json!(Utc::now() + chrono::Duration::seconds(29));
                body.to_string()
            };
            let second = if renewed {
                current_response().to_string()
            } else {
                stale.clone()
            };
            let (base, stub) = serve(vec![(201, stale), (201, second)]);
            let result = fetch_grant(&base, "access-token", "dev_desktop_1");
            if renewed {
                assert!(!result.unwrap().needs_renewal());
            } else {
                assert_eq!(result.unwrap_err(), FetchGrantError::Unavailable);
            }
            let requests = stub.join().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(request_body(&requests[0]), request_body(&requests[1]));
        }
    }

    #[test]
    fn renews_before_launch_and_drops_a_key_on_failure() {
        let mut grant = valid_grant();
        grant.expires_at = Some(Utc::now() + chrono::Duration::seconds(89));
        assert!(grant.needs_renewal());
        renew_grant_if_needed(&mut grant, || {
            Ok(ChatGrant {
                virtual_key: "replacement".into(),
                expires_at: Some(Utc::now() + chrono::Duration::minutes(10)),
                ..valid_grant()
            })
        })
        .unwrap();
        assert_eq!(grant.virtual_key, "replacement");
        renew_grant_if_needed(&mut grant, || panic!("a current grant needs no renewal")).unwrap();
        grant.expires_at = Some(Utc::now());
        assert_eq!(
            renew_grant_if_needed(&mut grant, || Err(FetchGrantError::Unavailable)),
            Err(FetchGrantError::Unavailable)
        );
        assert!(grant.virtual_key.is_empty());
        let mut local = ChatGrant::local();
        renew_grant_if_needed(&mut local, || panic!("local mode requests no grant")).unwrap();
    }

    #[test]
    fn rejects_expired_grants_at_the_clock_skew_boundary() {
        let grant = ChatGrant {
            expires_at: Some(Utc::now() + chrono::Duration::seconds(30)),
            ..valid_grant()
        };
        assert_eq!(
            validate_grant(&grant),
            Err(FetchGrantError::InvalidResponse)
        );
        let grant = ChatGrant {
            expires_at: Some(Utc::now() + chrono::Duration::seconds(91)),
            ..valid_grant()
        };
        assert!(!grant.needs_renewal());
        assert_eq!(validate_grant(&grant), Ok(()));
    }

    #[test]
    fn the_grant_request_carries_no_client_classification() {
        let (base, stub) = serve(vec![(201, current_response().to_string())]);
        let grant = fetch_grant(&base, "access-token", "dev_desktop_1").unwrap();
        let request = stub.join().unwrap().remove(0);
        assert_eq!(grant.model.as_deref(), Some("muniment-stub-chat"));
        assert_eq!(grant.receipt_url, format!("{base}{RECEIPT_PATH}"));
        assert!(request.starts_with("POST /v1/chat/grants HTTP/1.1\r\n"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer access-token\r\n"));
        assert_eq!(
            serde_json::from_str::<Value>(request_body(&request)).unwrap(),
            json!({"protocol": PROTOCOL})
        );
        assert_carries_no_classification(&request);
    }

    #[test]
    fn rejects_wrong_status_and_redirects() {
        for status in [200, 202, 302] {
            let (base, stub) = serve(vec![(status, current_response().to_string())]);
            assert_eq!(
                fetch_grant(&base, "access-token", "dev_desktop_1").unwrap_err(),
                FetchGrantError::InvalidResponse
            );
            stub.join().unwrap();
        }
    }

    #[test]
    fn the_receipt_request_carries_only_the_run_id() {
        let (base, stub) = serve(vec![(
            200,
            r#"{"route":"policy 7","model":"model-a"}"#.into(),
        )]);
        let receipt = fetch_receipt(&format!("{base}/receipt"), "access-token", "run-1").unwrap();
        let request = stub.join().unwrap().remove(0);
        assert_eq!(receipt.route.as_deref(), Some("policy 7"));
        assert_eq!(
            serde_json::from_str::<Value>(request_body(&request)).unwrap(),
            json!({"runId": "run-1"})
        );
        assert_carries_no_classification(&request);
    }

    /// Answer requests on loopback and return the bytes the desktop sent.
    fn serve(responses: Vec<(u16, String)>) -> (String, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            responses.into_iter().map(|(status, body)| {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let request = read_request(&mut stream);
                write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                request
            }).collect()
        });
        (base, handle)
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        while !request_is_complete(&request) {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(request).unwrap()
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(head_length) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&request[..head_length]).to_ascii_lowercase();
        let body_length: usize = head
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse().ok())
            })
            .unwrap_or(0);
        request.len() >= head_length + 4 + body_length
    }

    fn request_body(request: &str) -> &str {
        request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    fn assert_carries_no_classification(request: &str) {
        let lowercase = request.to_ascii_lowercase();
        for field in [
            "classification",
            "routinglabel",
            "routing_label",
            "signals_version",
            "task_type",
            "tier",
            "confidence",
        ] {
            assert!(
                !lowercase.contains(field),
                "the desktop request names {field}"
            );
        }
    }
}
