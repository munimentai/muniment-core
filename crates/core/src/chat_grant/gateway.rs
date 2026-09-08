//! The core exchanges grants at each gateway request boundary.

use crate::chat_grant::{renew_grant_if_needed, ChatGrant, FetchGrantError};
use crate::pi_launch::PiLaunchBoundaries;
use crate::sidecar::pi_chat::{ExtensionUiAnswer, ExtensionUiDialog, ExtensionUiRequest};
use serde::Deserialize;
use serde_json::json;

pub fn grant_error_message(error: FetchGrantError) -> &'static str {
    match error {
        FetchGrantError::Unauthorized => "The capability is not authorized.",
        FetchGrantError::Unavailable => "Chat configuration is temporarily unavailable.",
        FetchGrantError::InvalidResponse => "The chat configuration response was invalid.",
    }
}

#[derive(Deserialize)]
struct Denial {
    status: u16,
    body: GatewayEnvelope,
    #[serde(default)]
    terminal: bool,
}

#[derive(Deserialize)]
struct GatewayEnvelope {
    protocol: String,
    error: GatewayError,
}

#[derive(Deserialize)]
struct GatewayError {
    code: String,
    message: String,
}

fn prepare(
    boundaries: &impl PiLaunchBoundaries,
    grant: &mut ChatGrant,
    access_token: &mut String,
    request: &str,
) -> Result<(), FetchGrantError> {
    if grant.is_local() {
        return Err(FetchGrantError::Unauthorized);
    }
    if let Some(token) = grant.native_access_token.take() {
        *access_token = token;
    }
    if request != "null" {
        // Any denial drops the key before inspection or renewal can fail.
        grant.virtual_key.clear();
        grant.expires_at = Some(chrono::Utc::now());
        let denial: Denial =
            serde_json::from_str(request).map_err(|_| FetchGrantError::InvalidResponse)?;
        if denial.body.protocol != "muniment.desktop-access/1"
            || denial.body.error.message.trim().is_empty()
        {
            return Err(FetchGrantError::InvalidResponse);
        }
        match (denial.status, denial.body.error.code.as_str()) {
            (409, "entitlement_changed") | (401, "grant_revoked") => {
                *access_token = boundaries.inspect_chat_session(access_token)?;
            }
            (401, "grant_expired" | "grant_replaced") => {}
            (429, "budget_exhausted") => {
                *access_token = boundaries.inspect_chat_session(access_token)?;
                return Err(FetchGrantError::Unauthorized);
            }
            (403, "model_not_allowed") => return Err(FetchGrantError::Unauthorized),
            _ => return Err(FetchGrantError::InvalidResponse),
        }
        if denial.terminal {
            return Err(FetchGrantError::Unavailable);
        }
    }
    renew_grant_if_needed(grant, || boundaries.renew_chat_grant(access_token))?;
    if let Some(token) = grant.native_access_token.take() {
        *access_token = token;
    }
    if grant.needs_renewal() || grant.virtual_key.is_empty() {
        return Err(FetchGrantError::Unavailable);
    }
    Ok(())
}

/// Consume this private exchange before permission projection or journal writes.
pub fn answer_grant_request(
    boundaries: &impl PiLaunchBoundaries,
    grant: &mut ChatGrant,
    access_token: &mut String,
    request: &ExtensionUiRequest,
) -> Option<(ExtensionUiAnswer, Option<FetchGrantError>)> {
    let ExtensionUiDialog::Editor { title, prefill } = &request.dialog else {
        return None;
    };
    if title != "muniment:chat-grant" {
        return None;
    }
    let result = prepare(
        boundaries,
        grant,
        access_token,
        prefill.as_deref().unwrap_or(""),
    );
    let failure = result.err();
    let answer = match result {
        Ok(()) => json!({"gateway_url": grant.gateway_url, "virtual_key": grant.virtual_key, "model": grant.model}).to_string(),
        Err(error) => json!({"error": grant_error_message(error)}).to_string(),
    };
    Some((ExtensionUiAnswer::Editor(answer), failure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pi_launch::PiLaunchError;
    use std::cell::RefCell;
    use std::path::PathBuf;

    struct Boundary {
        actions: RefCell<Vec<String>>,
        fail_renewal: bool,
        fail_inspection: bool,
    }

    impl PiLaunchBoundaries for Boundary {
        fn pi_session_root(&self) -> Result<PathBuf, PiLaunchError> {
            unreachable!()
        }
        fn memory_agent_extension_path(&self) -> Option<PathBuf> {
            None
        }
        fn renew_chat_grant(&self, token: &str) -> Result<ChatGrant, FetchGrantError> {
            self.actions.borrow_mut().push(format!("renew:{token}"));
            if self.fail_renewal {
                return Err(FetchGrantError::Unavailable);
            }
            let mut grant = current();
            grant.virtual_key = "replacement-key".into();
            grant.model = Some("replacement-model".into());
            grant.native_access_token = Some("refreshed-bearer".into());
            Ok(grant)
        }
        fn inspect_chat_session(&self, token: &str) -> Result<String, FetchGrantError> {
            self.actions.borrow_mut().push(format!("inspect:{token}"));
            if self.fail_inspection {
                Err(FetchGrantError::Unauthorized)
            } else {
                Ok("inspected-bearer".into())
            }
        }
    }

    fn boundary() -> Boundary {
        Boundary {
            actions: RefCell::new(Vec::new()),
            fail_renewal: false,
            fail_inspection: false,
        }
    }

    fn current() -> ChatGrant {
        ChatGrant {
            gateway_url: "https://gateway.example/v1".into(),
            virtual_key: "initial-key".into(),
            model: Some("initial-model".into()),
            receipt_url: "https://api.example/receipt".into(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(10)),
            ..ChatGrant::local()
        }
    }

    fn denial(status: u16, code: &str, terminal: bool) -> String {
        json!({"status": status, "terminal": terminal, "body": {"protocol": "muniment.desktop-access/1",
            "error": {"code": code, "message": "The request failed."}}}).to_string()
    }

    #[test]
    fn delayed_startup_checks_safe_life_at_the_first_gateway_request() {
        let mut grant = current();
        let boundary = boundary();
        assert!(!grant.needs_renewal());
        // Package preparation and Pi startup consume the grant's safe life.
        grant.expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(89));
        let mut token = "bearer".into();
        prepare(&boundary, &mut grant, &mut token, "null").unwrap();
        assert_eq!(*boundary.actions.borrow(), ["renew:bearer"]);
        assert_eq!(grant.virtual_key, "replacement-key");
        assert_eq!(token, "refreshed-bearer");
    }

    #[test]
    fn tool_wait_checks_safe_life_without_restarting_the_turn() {
        let boundary = boundary();
        let mut grant = current();
        let mut token = "bearer".into();
        prepare(&boundary, &mut grant, &mut token, "null").unwrap();
        assert!(boundary.actions.borrow().is_empty());
        // The next model request follows the completed tool and its permission wait.
        grant.expires_at = Some(chrono::Utc::now());
        prepare(&boundary, &mut grant, &mut token, "null").unwrap();
        assert_eq!(*boundary.actions.borrow(), ["renew:bearer"]);
    }

    #[test]
    fn every_gateway_denial_uses_its_recovery_action() {
        for (status, code, succeeds, actions) in [
            (401, "grant_expired", true, vec!["renew:bearer"]),
            (401, "grant_replaced", true, vec!["renew:bearer"]),
            (
                401,
                "grant_revoked",
                true,
                vec!["inspect:bearer", "renew:inspected-bearer"],
            ),
            (
                409,
                "entitlement_changed",
                true,
                vec!["inspect:bearer", "renew:inspected-bearer"],
            ),
            (429, "budget_exhausted", false, vec!["inspect:bearer"]),
            (403, "model_not_allowed", false, vec![]),
            (401, "model_not_allowed", false, vec![]),
            (500, "unknown", false, vec![]),
        ] {
            let boundary = boundary();
            let mut grant = current();
            let result = prepare(
                &boundary,
                &mut grant,
                &mut "bearer".into(),
                &denial(status, code, false),
            );
            assert_eq!(result.is_ok(), succeeds, "{code}");
            assert_eq!(*boundary.actions.borrow(), actions, "{code}");
            if succeeds {
                assert_eq!(grant.virtual_key, "replacement-key");
                assert_eq!(grant.model.as_deref(), Some("replacement-model"));
            } else {
                assert!(grant.virtual_key.is_empty());
            }
        }
    }

    #[test]
    fn terminal_denial_and_failed_recovery_never_reuse_a_key() {
        for (boundary, request) in [
            (boundary(), denial(401, "grant_expired", true)),
            (
                Boundary {
                    fail_renewal: true,
                    ..boundary()
                },
                denial(401, "grant_expired", false),
            ),
            (
                Boundary {
                    fail_inspection: true,
                    ..boundary()
                },
                denial(401, "grant_revoked", false),
            ),
            (
                boundary(),
                denial(401, "grant_expired", false).replace("desktop-access/1", "desktop-access/2"),
            ),
            (boundary(), "{}".into()),
        ] {
            let mut grant = current();
            assert!(prepare(&boundary, &mut grant, &mut "bearer".into(), &request).is_err());
            assert!(grant.virtual_key.is_empty());
        }
    }

    #[test]
    fn private_grant_exchange_returns_no_native_bearer() {
        let request = ExtensionUiRequest {
            id: "private".into(),
            timeout: None,
            dialog: ExtensionUiDialog::Editor {
                title: "muniment:chat-grant".into(),
                prefill: Some("null".into()),
            },
        };
        let mut grant = current();
        grant.native_access_token = Some("native-secret".into());
        let mut token = String::new();
        let (answer, failure) =
            answer_grant_request(&boundary(), &mut grant, &mut token, &request).unwrap();
        assert_eq!(failure, None);
        let ExtensionUiAnswer::Editor(answer) = answer else {
            panic!("The boundary requires an editor answer.")
        };
        assert!(!answer.contains("native-secret"));
        assert_eq!(token, "native-secret");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&answer).unwrap()["virtual_key"],
            "initial-key"
        );
        assert!(prepare(&boundary(), &mut ChatGrant::local(), &mut token, "null").is_err());
    }
}
