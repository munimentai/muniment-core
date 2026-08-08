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
    pub minimum_cacheable_prefix_characters: usize,
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
        || grant.minimum_cacheable_prefix_characters == 0
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

    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use serde_json::Value;

    fn valid_grant() -> ChatGrant {
        ChatGrant {
            workspace: "/work".into(),
            gateway_url: "https://gateway.example.com".into(),
            virtual_key: "key".into(),
            model: None,
            minimum_cacheable_prefix_characters: 8_192,
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
    fn maps_authentication_statuses_to_unauthorized() {
        assert_eq!(grant_status_error(401), FetchGrantError::Unauthorized);
        assert_eq!(grant_status_error(403), FetchGrantError::Unauthorized);
        assert_eq!(grant_status_error(500), FetchGrantError::Unavailable);
    }

    const GRANT_RESPONSE: &str = r#"{"workspace":"/work","gatewayUrl":"https://gateway.example.com","virtualKey":"key","minimumCacheablePrefixCharacters":8192,"receiptUrl":"https://receipts.example.com"}"#;
    const RECEIPT_RESPONSE: &str = r#"{"route":"policy 7","model":"model-a"}"#;
    /// This deadline bounds the stub read when no request arrives. It is a test
    /// deadline, never a production timeout.
    const STUB_READ_DEADLINE: Duration = Duration::from_secs(5);

    /// Answer one request on loopback and hand back the bytes the desktop sent.
    /// Both tests below read that wire copy, never a request builder.
    fn serve_one_request(listener: TcpListener, response_body: &'static str) -> JoinHandle<String> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("the desktop connects");
            stream
                .set_read_timeout(Some(STUB_READ_DEADLINE))
                .expect("the stub bounds its read");
            let request = read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .expect("the stub answers");
            request
        })
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        while !request_is_complete(&request) {
            let read = stream.read(&mut buffer).expect("the request reads");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(request).expect("the request is UTF-8")
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(head_length) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        request.len() >= head_length + 4 + declared_body_length(&request[..head_length])
    }

    fn declared_body_length(head: &[u8]) -> usize {
        let head = String::from_utf8_lossy(head).to_ascii_lowercase();
        head.lines()
            .find_map(|line| {
                line.strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse().ok())
            })
            .unwrap_or(0)
    }

    fn request_body(request: &str) -> &str {
        request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    /// The cloud classifies every request at ingress, so no desktop request may
    /// name a routing tier, a routing label, or a classification of its own.
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
                "the desktop request names {field}: {request}"
            );
        }
    }

    #[test]
    fn the_grant_request_carries_no_client_classification() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the stub binds loopback");
        let address = listener.local_addr().expect("the stub reports its address");
        let stub = serve_one_request(listener, GRANT_RESPONSE);

        let grant = fetch_grant(&format!("http://{address}"), "access-token")
            .expect("the stub answers a grant");
        let request = stub.join().expect("the stub finishes");

        assert_eq!(grant.workspace, "/work");
        assert!(
            request.starts_with(&format!("POST {GRANT_PATH} HTTP/1.1")),
            "unexpected request line: {request}"
        );
        assert_eq!(request_body(&request), "");
        assert_carries_no_classification(&request);
    }

    #[test]
    fn the_receipt_request_carries_only_the_run_id() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the stub binds loopback");
        let address = listener.local_addr().expect("the stub reports its address");
        let stub = serve_one_request(listener, RECEIPT_RESPONSE);

        let receipt = fetch_receipt(
            &format!("http://{address}/receipt"),
            "access-token",
            "run-1",
        )
        .expect("the stub answers a receipt");
        let request = stub.join().expect("the stub finishes");

        assert_eq!(receipt.route.as_deref(), Some("policy 7"));
        let body: Value = serde_json::from_str(request_body(&request)).expect("the body is JSON");
        let fields = body.as_object().expect("the body is a JSON object");
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            ["runId"]
        );
        assert_eq!(fields["runId"], "run-1");
        assert_carries_no_classification(&request);
    }
}
