//! Cloud chat grant and receipt contracts.

use serde::Deserialize;

use crate::sidecar::pi_chat::Receipt;

const GRANT_PATH: &str = "/v1/desktop/chat/config";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatGrant {
    pub workspace: String,
    pub gateway_url: String,
    pub virtual_key: String,
    #[serde(default)]
    pub model: Option<String>,
    pub receipt_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchGrantError {
    Unauthorized,
    Unavailable,
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchReceiptError;

pub fn fetch_grant(
    issuer_base_url: &str,
    access_token: &str,
) -> Result<ChatGrant, FetchGrantError> {
    ureq::post(&format!(
        "{}{}",
        issuer_base_url.trim_end_matches('/'),
        GRANT_PATH
    ))
    .set("Authorization", &format!("Bearer {access_token}"))
    .call()
    .map_err(|error| match error {
        ureq::Error::Status(status, _) => grant_status_error(status),
        ureq::Error::Transport(_) => FetchGrantError::Unavailable,
    })?
    .into_json()
    .map_err(|_| FetchGrantError::InvalidResponse)
}

pub fn validate_grant(grant: &ChatGrant) -> Result<(), FetchGrantError> {
    if !grant.gateway_url.starts_with("https://")
        || !grant.receipt_url.starts_with("https://")
        || grant.virtual_key.trim().is_empty()
        || grant.workspace.trim().is_empty()
    {
        return Err(FetchGrantError::InvalidResponse);
    }
    Ok(())
}

pub fn fetch_receipt(
    endpoint_url: &str,
    access_token: &str,
    run_id: &str,
) -> Result<Receipt, FetchReceiptError> {
    ureq::post(endpoint_url)
        .set("Authorization", &format!("Bearer {access_token}"))
        .send_json(serde_json::json!({"runId": run_id}))
        .map_err(|_| FetchReceiptError)?
        .into_json()
        .map_err(|_| FetchReceiptError)
}

fn grant_status_error(status: u16) -> FetchGrantError {
    if matches!(status, 401 | 403) {
        FetchGrantError::Unauthorized
    } else {
        FetchGrantError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_grant() -> ChatGrant {
        ChatGrant {
            workspace: "/work".into(),
            gateway_url: "https://gateway.example.com".into(),
            virtual_key: "key".into(),
            model: None,
            receipt_url: "https://receipts.example.com".into(),
        }
    }

    #[test]
    fn accepts_valid_grant() {
        assert_eq!(validate_grant(&valid_grant()), Ok(()));
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
    fn maps_authentication_statuses_to_unauthorized() {
        assert_eq!(grant_status_error(401), FetchGrantError::Unauthorized);
        assert_eq!(grant_status_error(403), FetchGrantError::Unauthorized);
        assert_eq!(grant_status_error(500), FetchGrantError::Unavailable);
    }
}
