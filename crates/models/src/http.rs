//! The desktop and runtime share HTTP agent configuration.

/// Keep caller timeouts, redirects, and proxies while sharing the OS TLS verifier.
pub fn agent_builder() -> ureq::AgentBuilder {
    let builder = ureq::AgentBuilder::new();
    #[cfg(feature = "tls")]
    let builder = builder.tls_config(tls_config());
    builder
}

pub fn agent() -> ureq::Agent {
    agent_builder().build()
}

#[cfg(feature = "tls")]
fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    use rustls_platform_verifier::BuilderVerifierExt;
    use std::sync::{Arc, OnceLock};

    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // Select ring explicitly even when another dependency enables a second crypto provider.
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("The TLS protocol versions are invalid.")
            .with_platform_verifier()
            .expect("The OS certificate verifier could not start.")
            .with_no_client_auth();
            // Never fall back to bundled roots or bypass certificate validation.
            Arc::new(config)
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn shared_agent_preserves_http_and_redirect_controls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).unwrap() > 0);
            socket
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let response = agent_builder()
            .try_proxy_from_env(false)
            .timeout(Duration::from_secs(5))
            .redirects(0)
            .build()
            .get(&format!("http://{address}/"))
            .call()
            .unwrap();
        assert_eq!(response.status(), 302);
        server.join().unwrap();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_config_is_shared_across_threads() {
        let config = tls_config();
        let other = std::thread::spawn(tls_config).join().unwrap();
        assert!(std::sync::Arc::ptr_eq(&config, &other));
    }
}
