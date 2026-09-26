use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use muniment_core::auth::{
    challenge_expired, create_pairing_challenge, qr_json, read_pairing, revoke_pairing,
    PairingError, PairingQr, UreqPairingTransport, CHALLENGE_PATH, CONTRACT_VERSION, PAIRING_PATH,
    REPLACEMENT_INTERVAL,
};
use serde_json::Value;
use uuid::Uuid;

const TOKEN: &str = "native-access-secret";
const CHALLENGE_BODY: &str = r#"{"contract_version":"muniment.remote-control-pairing/1","expires_at":"2026-01-01T00:02:00.000Z","qr":{"contract_version":"muniment.remote-control-pairing/1","desktop_device_id":"11111111-1111-4111-8111-111111111111","desktop_public_key":"ERERERERERERERERERERERERERERERERERERERERERE","challenge":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"}}"#;
const PAIR_BODY: &str = r#"{"contract_version":"muniment.remote-control-pairing/1","pair":{"pair_id":"22222222-2222-4222-8222-222222222222","desktop_device_id":"11111111-1111-4111-8111-111111111111","mobile_device_id":"33333333-3333-4333-8333-333333333333","desktop_public_key":"ERERERERERERERERERERERERERERERERERERERERERE","mobile_public_key":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM","created_at":"2026-01-01T00:01:00.000Z"}}"#;
const EMPTY_PAIR_BODY: &str =
    r#"{"contract_version":"muniment.remote-control-pairing/1","pair":null}"#;
const REVOKE_BODY: &str =
    r#"{"contract_version":"muniment.remote-control-pairing/1","revoked":true}"#;

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
            let header = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap();
            let headers = String::from_utf8_lossy(&bytes[..header]);
            let length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.eq_ignore_ascii_case("content-length"))
                    .then(|| value.trim().parse::<usize>().ok())?
            });
            if let Some(length) = length {
                let body_start = header + 4;
                while bytes.len() < body_start + length {
                    let read = stream.read(&mut buffer).unwrap();
                    bytes.extend_from_slice(&buffer[..read]);
                }
            }
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}

fn transport() -> UreqPairingTransport {
    UreqPairingTransport::new(Duration::from_secs(2))
}

fn store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "muniment-pairing-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path.join("remote-control-pair.json")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/remote-control/pairing-v1.json")).unwrap()
}

#[test]
fn challenge_posts_the_contract_and_encodes_the_exact_qr_object() {
    let server = Server::spawn(201, CHALLENGE_BODY.into());
    let view = create_pairing_challenge(&transport(), &server.base_url, TOKEN).unwrap();
    let expected = fixture()["responses"][0]["qr"].clone();
    let qr: PairingQr = serde_json::from_value(expected).unwrap();
    let payload = qr_json(&qr).unwrap();
    assert_eq!(
        payload,
        r#"{"contract_version":"muniment.remote-control-pairing/1","desktop_device_id":"11111111-1111-4111-8111-111111111111","desktop_public_key":"ERERERERERERERERERERERERERERERERERERERERERE","challenge":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"}"#
    );
    assert_eq!(
        view.expires_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "2026-01-01T00:02:00.000Z"
    );
    assert!(view.qr_svg.contains("Pairing code"));
    assert!(!view
        .qr_svg
        .contains("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"));
    assert!(!view
        .qr_svg
        .contains("ERERERERERERERERERERERERERERERERERERERERERE"));
    assert!(!payload.contains("http://"));
    assert!(!payload.contains("https://"));
    assert!(!payload.contains("Bearer"));
    assert!(!payload.contains("access_token"));
    assert!(!payload.contains("private_key"));
    assert!(!format!("{qr:?}").contains("IiIi"));

    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with(&format!("POST {CHALLENGE_PATH} HTTP/1.1\r\n")));
    assert!(request
        .to_ascii_lowercase()
        .contains("authorization: bearer native-access-secret\r\n"));
    assert!(request.contains(&format!(r#""contract_version":"{CONTRACT_VERSION}""#)));
    assert!(!request.contains("expires_in"));
    assert!(!request.contains("owner_user_id"));
}

#[test]
fn rendered_qr_decodes_the_exact_server_object_in_both_themes() {
    let server = Server::spawn(201, CHALLENGE_BODY.into());
    let view = create_pairing_challenge(&transport(), &server.base_url, TOKEN).unwrap();
    let expected = fixture()["responses"][0]["qr"].clone();
    for (ink, surface) in [("#1A1D1C", "#FFFFFF"), ("#ECEFED", "#0E1110")] {
        let themed = view.qr_svg.replacen(
            "<svg ",
            &format!("<svg color=\"{ink}\" style=\"--surface:{surface}\" "),
            1,
        );
        let tree = resvg::usvg::Tree::from_str(&themed, &Default::default()).unwrap();
        let mut pixmap = resvg::tiny_skia::Pixmap::new(220, 220).unwrap();
        let scale = 220.0 / tree.size().width();
        resvg::render(
            &tree,
            resvg::tiny_skia::Transform::from_scale(scale, scale),
            &mut pixmap.as_mut(),
        );
        let pixels = pixmap.pixels();
        let gray: Vec<u8> = pixels.iter().map(|pixel| pixel.red()).collect();
        let quiet = (4.0 * scale).floor() as usize;
        for y in 0..220 {
            for x in 0..220 {
                if x < quiet || y < quiet || x >= 220 - quiet || y >= 220 - quiet {
                    let pixel = pixels[y * 220 + x];
                    assert_eq!(
                        (pixel.red(), pixel.green(), pixel.blue(), pixel.alpha()),
                        (255, 255, 255, 255)
                    );
                }
            }
        }
        let mut decoder = quircs::Quirc::default();
        let codes: Vec<_> = decoder.identify(220, 220, &gray).collect();
        assert_eq!(codes.len(), 1);
        let decoded = codes.into_iter().next().unwrap().unwrap().decode().unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&decoded.payload).unwrap(),
            expected
        );
    }
}

#[test]
fn challenge_rejects_unknown_fields_tokens_and_caller_origins() {
    let cases = [
        CHALLENGE_BODY.replace(
            "\"challenge\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI\"",
            "\"challenge\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI\",\"origin\":\"https://evil.example\"",
        ),
        CHALLENGE_BODY.replace(
            "\"challenge\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI\"",
            "\"challenge\":\"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI\",\"access_token\":\"secret\"",
        ),
        CHALLENGE_BODY.replace(CONTRACT_VERSION, "muniment.remote-control-pairing/2"),
        format!("{CHALLENGE_BODY} trailing-secret"),
        CHALLENGE_BODY.replace("\"qr\":{", "\"qr\":{\"private_key\":\"secret\","),
    ];
    for body in cases {
        let server = Server::spawn(201, body);
        let error = create_pairing_challenge(&transport(), &server.base_url, TOKEN).unwrap_err();
        assert!(matches!(error, PairingError::MalformedResponse(_)));
        assert!(!format!("{error:?} {error}").contains("secret"));
        assert!(!format!("{error:?}").contains(TOKEN));
    }
}

#[test]
fn replacement_within_ten_seconds_is_rate_limited() {
    assert_eq!(REPLACEMENT_INTERVAL, Duration::from_secs(10));
    let server = Server::spawn(
        429,
        r#"{"error":{"code":"pairing_rate_limited","message":"The pairing request failed."}}"#
            .into(),
    );
    let error = create_pairing_challenge(&transport(), &server.base_url, TOKEN).unwrap_err();
    assert_eq!(error, PairingError::HttpStatus(429));
    assert_eq!(
        error.to_string(),
        "Wait ten seconds before replacing the code."
    );
    assert!(!format!("{error:?}").contains("secret"));
}

#[test]
fn already_paired_desktop_cannot_create_a_challenge() {
    let server = Server::spawn(
        409,
        r#"{"error":{"code":"pairing_conflict","message":"The pairing request failed."}}"#.into(),
    );
    let error = create_pairing_challenge(&transport(), &server.base_url, TOKEN).unwrap_err();
    assert_eq!(error, PairingError::HttpStatus(409));
    assert_eq!(error.to_string(), "A phone is already paired.");
}

#[test]
fn status_stores_the_authorized_phone_and_clears_it_when_revoked() {
    let store = store_path("status");
    let server = Server::spawn(200, PAIR_BODY.into());
    let view = read_pairing(&transport(), &server.base_url, TOKEN, &store).unwrap();
    let phone = view.pair.unwrap();
    assert_eq!(
        phone.pair_id,
        Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap()
    );
    assert_eq!(
        phone.mobile_device_id,
        Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap()
    );
    assert!(store.exists());
    let stored = std::fs::read_to_string(&store).unwrap();
    assert!(stored.contains("33333333-3333-4333-8333-333333333333"));
    assert!(!stored.contains(TOKEN));

    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with(&format!("GET {PAIRING_PATH} HTTP/1.1\r\n")));
    assert!(!request.contains("\r\n\r\n{"));

    let empty = Server::spawn(200, EMPTY_PAIR_BODY.into());
    let cleared = read_pairing(&transport(), &empty.base_url, TOKEN, &store).unwrap();
    assert!(cleared.pair.is_none());
    assert!(!store.exists());
}

#[test]
fn revoke_sends_the_stored_pair_id_and_clears_matching_peer_identity() {
    let store = store_path("revoke");
    let seed = Server::spawn(200, PAIR_BODY.into());
    read_pairing(&transport(), &seed.base_url, TOKEN, &store).unwrap();
    assert!(store.exists());

    let pair_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
    let server = Server::spawn(200, REVOKE_BODY.into());
    let view = revoke_pairing(&transport(), &server.base_url, TOKEN, pair_id, &store).unwrap();
    assert!(view.revoked);
    assert!(!store.exists());

    let request = server.request.lock().unwrap().clone().unwrap();
    assert!(request.starts_with(&format!("DELETE {PAIRING_PATH} HTTP/1.1\r\n")));
    assert!(request.contains(&format!(r#""pair_id":"{pair_id}""#)));
    assert!(request.contains(&format!(r#""contract_version":"{CONTRACT_VERSION}""#)));
    assert!(!request.contains("mobile_public_key"));
}

#[test]
fn revoke_keeps_a_replacement_pair_when_the_deleted_id_differs() {
    let store = store_path("stale-revoke");
    let seed = Server::spawn(200, PAIR_BODY.into());
    read_pairing(&transport(), &seed.base_url, TOKEN, &store).unwrap();
    let other = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();
    let server = Server::spawn(200, REVOKE_BODY.into());
    revoke_pairing(&transport(), &server.base_url, TOKEN, other, &store).unwrap();
    assert!(store.exists());
}

#[test]
fn expiry_at_the_server_deadline_fails_closed() {
    let deadline = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:02:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert!(challenge_expired(deadline, deadline));
}

#[test]
fn strict_schema_rejects_invalid_pair_responses() {
    let store = store_path("invalid");
    let seed = Server::spawn(200, PAIR_BODY.into());
    read_pairing(&transport(), &seed.base_url, TOKEN, &store).unwrap();
    let stored = std::fs::read(&store).unwrap();
    let cases = [
        format!(r#"{{"contract_version":"{CONTRACT_VERSION}"}}"#),
        PAIR_BODY.replace("22222222-2222-4222-8222-222222222222", "not-a-uuid"),
        PAIR_BODY.replace(
            "\"mobile_public_key\":\"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM\"",
            "\"mobile_public_key\":\"short\"",
        ),
        PAIR_BODY.replace(
            "\"created_at\":\"2026-01-01T00:01:00.000Z\"",
            "\"created_at\":\"2026-01-01T00:01:00.000Z\",\"origin\":\"https://evil.example\"",
        ),
        format!("{PAIR_BODY} trailing-secret"),
    ];
    for body in cases {
        let server = Server::spawn(200, body);
        assert!(matches!(
            read_pairing(&transport(), &server.base_url, TOKEN, &store),
            Err(PairingError::MalformedResponse(_))
        ));
        assert_eq!(std::fs::read(&store).unwrap(), stored);
    }
}

#[test]
fn status_malformed_and_transport_errors_are_redacted() {
    let store = store_path("errors");
    let oversized = format!(
        r#"{{"contract_version":"{CONTRACT_VERSION}","pair":null,"padding":"{}"}}"#,
        "x".repeat(20_000)
    );
    let servers = [
        Server::spawn(401, "response-secret".into()),
        Server::spawn(200, "response-secret".into()),
        Server::spawn(200, oversized),
    ];
    for server in &servers {
        let error = read_pairing(&transport(), &server.base_url, TOKEN, &store).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(TOKEN));
        assert!(!rendered.contains("response-secret"));
    }
}

#[test]
fn invalid_bases_and_empty_credentials_fail_before_a_request() {
    let store = store_path("config");
    for base in [
        "http://example.com",
        "https://api.muniment.ai/path",
        "not a URL",
    ] {
        assert!(matches!(
            create_pairing_challenge(&transport(), base, TOKEN),
            Err(PairingError::Config(_))
        ));
    }
    let server = Server::spawn(201, CHALLENGE_BODY.into());
    assert_eq!(
        create_pairing_challenge(&transport(), &server.base_url, "").unwrap_err(),
        PairingError::CredentialsMissing
    );
    assert!(server.request.lock().unwrap().is_none());
    let _ = store;
}

#[test]
fn fixture_valid_bodies_match_the_published_contract() {
    let fixture = fixture();
    assert_eq!(fixture["contract_version"], CONTRACT_VERSION);
    let challenge = &fixture["valid"][0]["body"];
    assert_eq!(challenge["contract_version"], CONTRACT_VERSION);
    assert_eq!(challenge.as_object().unwrap().len(), 1);
    let encoded: PairingQr = serde_json::from_value(fixture["responses"][0]["qr"].clone()).unwrap();
    assert_eq!(
        qr_json(&encoded).unwrap(),
        r#"{"contract_version":"muniment.remote-control-pairing/1","desktop_device_id":"11111111-1111-4111-8111-111111111111","desktop_public_key":"ERERERERERERERERERERERERERERERERERERERERERE","challenge":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"}"#
    );
}
