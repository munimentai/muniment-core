//! Bounded reads of public Grok Bot share pages. No account cookies or app activation.
use std::io::Read;
pub fn public_url(input: &str) -> Result<String, String> {
    let url = url::Url::parse(input.trim()).map_err(|_| "Paste a public x.ai/bot share link.")?;
    let parts: Vec<_> = url.path().trim_matches('/').split('/').collect();
    if url.scheme() != "https"
        || url.host_str() != Some("x.ai")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || parts.len() < 2
        || parts.len() > 3
        || parts[0] != "bot"
        || parts[1].len() != 21
        || !parts[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("Paste a public x.ai/bot share link.".into());
    }
    Ok(format!("https://x.ai/bot/{}", parts[1]))
}
pub fn fetch_public_template(input: &str) -> Result<serde_json::Value, String> {
    let url = public_url(input)?;
    let response = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .redirects(0)
        .build()
        .get(&url)
        .set("Accept", "text/html")
        .call()
        .map_err(|error| match error {
            ureq::Error::Status(404, _) => {
                "This template was not found. It may be private or deleted.".to_string()
            }
            ureq::Error::Status(401 | 403, _) => {
                "This template is not public. Export its configuration from Grok Bot instead."
                    .to_string()
            }
            _ => "The Grok template could not be loaded. Check the link and try again.".to_string(),
        })?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "The template response could not be read.")?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("The template page is too large.".into());
    }
    let html = String::from_utf8(bytes).map_err(|_| "The template page is not valid text.")?;
    Ok(serde_json::json!({ "url": url, "html": html }))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confines_reads_to_public_share_pages() {
        assert_eq!(
            public_url("https://x.ai/bot/rfAHsaFrz6xHBMtUpxDi5/dewey?tracking=1").unwrap(),
            "https://x.ai/bot/rfAHsaFrz6xHBMtUpxDi5"
        );
        for url in [
            "http://x.ai/bot/rfAHsaFrz6xHBMtUpxDi5",
            "https://x.ai.evil.test/bot/rfAHsaFrz6xHBMtUpxDi5",
            "https://user@x.ai/bot/rfAHsaFrz6xHBMtUpxDi5",
            "https://127.0.0.1/bot/rfAHsaFrz6xHBMtUpxDi5",
            "https://x.ai/bot/marketplace",
        ] {
            assert!(public_url(url).is_err(), "{url}");
        }
    }
}
