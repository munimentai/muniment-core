//! The chat launch value: the gateway, key and model a run starts Pi with.
//!
//! Local runs use [`ChatGrant::local`]. A host that issues cloud grants
//! supplies them through [`crate::pi_launch::PiLaunchBoundaries`], and the
//! core renews and answers them at each gateway request boundary.

use chrono::{DateTime, Utc};

mod gateway;

pub use gateway::{answer_grant_request, grant_error_message};

/// A grant closer than this to expiry is renewed before use.
pub const SAFE_LIFE_SECONDS: u64 = 90;

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

/// Whether a control-plane URL is HTTPS, or plain HTTP to a loopback host.
pub fn is_control_plane_endpoint(value: &str) -> bool {
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

/// Whether a URL is HTTPS with a host and no credentials, query or fragment.
pub fn is_https_endpoint(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
