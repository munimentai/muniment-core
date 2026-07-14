use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_core::auth::{
    list_native_devices, NativeDeviceListError, NativeDevicePlatform, UreqNativeDeviceListTransport,
};
use uuid::Uuid;

const TOKEN: &str = "native-access-secret";

fn success() -> String {
    r#"{"devices":[{"device_id":"10000000-0000-4000-8000-000000000001","client_id":"muniment-desktop","client_role":"desktop","platform":"desktop","created_at":"2026-06-01T10:00:00Z","revoked_at":null,"last_active_at":"2026-07-01T12:30:00Z","current":true},{"device_id":"20000000-0000-4000-8000-000000000002","client_id":"muniment-ios","client_role":"mobile","platform":"ios","created_at":"2026-01-01T10:00:00+01:00","revoked_at":"2026-06-02T11:00:00Z","last_active_at":"2026-06-01T09:00:00Z","current":false}]}"#.into()
}

struct Server {
    base_url: String,
    request: Arc<Mutex<Option<String>>>,
}

impl Server {
    fn spawn(status: u16, body: String) -> Self {
        Self::spawn_with_length(status, body.clone(), body.len())
    }

    fn spawn_with_length(status: u16, body: String, content_length: usize) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let request = Arc::new(Mutex::new(None));
        let captured = request.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            *captured.lock().unwrap() = Some(read_request(&mut stream));
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n{body}").unwrap();
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

fn list(server: &Server) -> Result<muniment_core::auth::NativeDeviceList, NativeDeviceListError> {
    list_native_devices(
        &UreqNativeDeviceListTransport::new(Duration::from_secs(2)),
        &server.base_url,
        TOKEN,
    )
}

#[test]
fn exact_authenticated_get_parses_active_revoked_and_current_devices() {
    let server = Server::spawn(200, success());
    let result = list(&server).unwrap();
    assert_eq!(result.devices.len(), 2);
    assert_eq!(result.devices[0].platform, NativeDevicePlatform::Desktop);
    assert!(result.devices[0].current);
    assert_eq!(result.devices[0].revoked_at, None);
    assert_eq!(result.devices[1].platform, NativeDevicePlatform::Ios);
    assert!(result.devices[1].revoked_at.is_some());
    assert!(!result.devices[1].current);
    assert_eq!(
        result.devices[1].device_id,
        Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap()
    );

    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with("GET /v1/auth/native/devices HTTP/1.1\r\n"));
    assert_eq!(
        request
            .to_ascii_lowercase()
            .matches("authorization:")
            .count(),
        1
    );
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer native-access-secret\r\n"));
}

#[test]
fn strict_schema_rejects_invalid_missing_unknown_and_trailing_data() {
    let cases = [
        success().replace("10000000-0000-4000-8000-000000000001", "not-a-uuid"),
        success().replace("\"platform\":\"desktop\"", "\"platform\":\"linux\""),
        success().replace("2026-06-01T10:00:00Z", "yesterday"),
        success().replace("\"current\":true", "\"current\":\"yes\""),
        success().replace(",\"current\":true", ""),
        success().replace("\"revoked_at\":null,", ""),
        success().replace(
            "\"current\":true",
            "\"current\":true,\"access_token\":\"response-secret\"",
        ),
        format!("{} trailing-secret", success()),
    ];
    for body in cases {
        let server = Server::spawn(200, body);
        assert!(matches!(
            list(&server),
            Err(NativeDeviceListError::MalformedResponse(_))
        ));
    }
}

#[test]
fn rejects_more_than_one_hundred_devices() {
    let item = r#"{"device_id":"10000000-0000-4000-8000-000000000001","client_id":"desktop","client_role":"desktop","platform":"desktop","created_at":"2026-01-01T00:00:00Z","revoked_at":null,"last_active_at":"2026-01-01T00:00:00Z","current":false}"#;
    let server = Server::spawn(
        200,
        format!(r#"{{"devices":[{}]}}"#, vec![item; 101].join(",")),
    );
    assert!(matches!(
        list(&server),
        Err(NativeDeviceListError::MalformedResponse(_))
    ));
}

#[test]
fn status_malformed_oversized_truncated_and_transport_errors_are_redacted() {
    let oversized = format!(r#"{{"devices":[],"padding":"{}"}}"#, "x".repeat(70_000));
    let truncated = Server::spawn_with_length(200, r#"{"devices":["#.into(), 100);
    let servers = [
        Server::spawn(401, "response-secret".into()),
        Server::spawn(200, "response-secret".into()),
        Server::spawn(200, oversized),
        truncated,
    ];
    for server in &servers {
        let error = list(server).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(TOKEN));
        assert!(!rendered.contains("response-secret"));
    }

    let error = list_native_devices(
        &UreqNativeDeviceListTransport::new(Duration::from_millis(50)),
        "http://127.0.0.1:1",
        TOKEN,
    )
    .unwrap_err();
    assert!(matches!(error, NativeDeviceListError::Transport(_)));
    assert!(!format!("{error:?} {error}").contains(TOKEN));
}

#[test]
fn invalid_bases_and_empty_credentials_fail_before_a_request() {
    for base in [
        "http://example.com",
        "https://api.muniment.ai/path",
        "not a URL",
    ] {
        assert!(matches!(
            list_native_devices(
                &UreqNativeDeviceListTransport::new(Duration::from_secs(1)),
                base,
                TOKEN
            ),
            Err(NativeDeviceListError::Config(_))
        ));
    }
    let server = Server::spawn(200, success());
    assert_eq!(
        list_native_devices(
            &UreqNativeDeviceListTransport::new(Duration::from_secs(1)),
            &server.base_url,
            ""
        )
        .unwrap_err(),
        NativeDeviceListError::CredentialsMissing
    );
    assert!(server.request.lock().unwrap().is_none());
}

#[test]
fn public_model_debug_contains_display_metadata_only() {
    let devices: muniment_core::auth::NativeDeviceList = serde_json::from_str(&success()).unwrap();
    let rendered = format!("{devices:?}");
    for forbidden in [
        "access_token",
        "refresh_token",
        "installation",
        "challenge",
        "authorization",
        TOKEN,
    ] {
        assert!(!rendered.contains(forbidden));
    }
}
