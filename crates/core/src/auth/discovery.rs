//! OIDC discovery (`/.well-known/openid-configuration`).

use std::time::Duration;

use serde::Deserialize;

use super::AuthError;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The subset of the discovery document the flow needs.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

/// Fetch and validate provider metadata for `issuer`.
///
/// Plain-HTTP issuers are allowed only on loopback (the in-test mock IdP);
/// everything else must be HTTPS.
pub fn discover(issuer: &str) -> Result<ProviderMetadata, AuthError> {
    let issuer = issuer.trim_end_matches('/');
    if !issuer.starts_with("https://") && !is_loopback_http(issuer) {
        return Err(AuthError::Config(format!(
            "issuer must use https (got {issuer})"
        )));
    }
    let url = format!("{issuer}/.well-known/openid-configuration");
    let meta: ProviderMetadata = ureq::get(&url)
        .timeout(HTTP_TIMEOUT)
        .call()
        .map_err(|e| AuthError::Discovery(format!("fetching {url}: {e}")))?
        .into_json()
        .map_err(|e| AuthError::Discovery(format!("malformed discovery document: {e}")))?;
    // RFC 8414 §3.3: the document must claim the issuer we asked about.
    if meta.issuer.trim_end_matches('/') != issuer {
        return Err(AuthError::Discovery(format!(
            "issuer mismatch: requested {issuer}, document claims {}",
            meta.issuer
        )));
    }
    Ok(meta)
}

fn is_loopback_http(issuer: &str) -> bool {
    let Some(rest) = issuer.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority == "[::1]" || authority.starts_with("[::1]:") {
        return true;
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    matches!(host, "127.0.0.1" | "localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_loopback_only() {
        assert!(is_loopback_http("http://127.0.0.1:39114"));
        assert!(is_loopback_http("http://localhost"));
        assert!(is_loopback_http("http://[::1]:8000"));
        assert!(!is_loopback_http("http://api.muniment.ai"));
        assert!(!is_loopback_http("https://api.muniment.ai"));
    }

    #[test]
    fn discover_rejects_non_loopback_http_without_touching_the_network() {
        let err = discover("http://api.muniment.ai").unwrap_err();
        assert!(matches!(err, AuthError::Config(_)));
    }
}
