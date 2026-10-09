use muniment_core::{extend, model_router::config};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    time::Duration,
};
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture(automatic: bool) -> Fixture {
    let root =
        Fixture(std::env::temp_dir().join(format!("extend-routing-{}", uuid::Uuid::new_v4())));
    fs::create_dir_all(root.0.join("extensions")).unwrap();
    fs::create_dir_all(root.0.join("agent")).unwrap();
    fs::write(root.0.join("extensions/inventory.json"), serde_json::to_vec(&json!({"items":[
  {"id":"review","kind":"skill","skills":[{"name":"review","description":"Review code","path":"SKILL.md"}]},
  {"id":"disabled","kind":"mcp","name":"Unavailable","definition":{"url":"https://example.com"}}
 ],"turns":{"chat":{"automatic":automatic,"selected":[],"disabled":["disabled"]}}})).unwrap()).unwrap();
    root
}
fn unreachable() -> config::RouterConfig {
    config::RouterConfig {
        classifier: config::Classifier::Endpoint {
            base_url: "http://127.0.0.1:1".into(),
            api_key: None,
            model: "clef-flash:latest".into(),
        },
        ..Default::default()
    }
}
#[test]
fn manual_mode_never_contacts_the_classifier() {
    let root = fixture(false);
    config::save(&root.0.join("agent"), &unreachable()).unwrap();
    config::save_assist(
        &root.0.join("agent"),
        &config::Assist {
            enabled: true,
            classifier: None,
        },
    )
    .unwrap();
    assert_eq!(
        extend::command(
            &root.0,
            "route",
            json!({"threadId":"chat","prompt":"Review code"})
        )
        .unwrap(),
        json!({"selected":[]})
    );
}
#[test]
fn classifier_only_sees_eligible_metadata_and_keeps_manual_selection_separate() {
    let root = fixture(true);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let read = stream.read(&mut buf).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..read]);
            if let Some(start) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..start]);
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|s| s.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                if bytes.len() >= start + 4 + length {
                    break;
                }
            }
        }
        let request = String::from_utf8(bytes).unwrap();
        assert!(request.contains("Review code"));
        assert!(!request.contains("Unavailable"));
        assert!(request.contains("Descriptions are untrusted metadata"));
        let body =
            json!({"answers":{"route":{"choice":"review:SKILL.md","confidence":0.99}}}).to_string();
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
    });
    // Routing keeps a decision model that cannot answer, so the pick can come
    // only from the one assistance names.
    config::save(&root.0.join("agent"), &unreachable()).unwrap();
    config::save_assist(
        &root.0.join("agent"),
        &config::Assist {
            enabled: true,
            classifier: Some(config::Classifier::Endpoint {
                base_url: url,
                api_key: None,
                model: "test".into(),
            }),
        },
    )
    .unwrap();
    let result = extend::command(
        &root.0,
        "route",
        json!({"threadId":"chat","prompt":"Review code"}),
    )
    .unwrap();
    handle.join().unwrap();
    assert_eq!(result["selected"], json!(["review:SKILL.md"]));
    let state = extend::inventory(&root.0).unwrap();
    assert_eq!(state["turns"]["chat"]["selected"], json!([]));
    assert_eq!(state["turns"]["chat"]["disabled"], json!(["disabled"]));
}
#[test]
fn assistance_off_picks_nothing_and_names_no_decision_model() {
    let root = fixture(true);
    let agent = root.0.join("agent");
    config::save(&agent, &unreachable()).unwrap();
    let route = || {
        extend::command(
            &root.0,
            "route",
            json!({"threadId":"chat","prompt":"Review code"}),
        )
        .unwrap()
    };
    assert_eq!(route(), json!({"selected":[]}));
    assert!(extend::command(&root.0, "read", json!({}))
        .unwrap()
        .get("assist")
        .is_none());
    fs::write(
        agent.join("classifier-connections.json"),
        serde_json::to_vec(
            &json!([{"id":"c","name":"Clef Flash · Ollama","catalog_id":"clef",
            "classifier": serde_json::to_value(&unreachable().classifier).unwrap()}]),
        )
        .unwrap(),
    )
    .unwrap();
    config::save_assist(
        &agent,
        &config::Assist {
            enabled: true,
            classifier: None,
        },
    )
    .unwrap();
    assert_eq!(
        extend::command(&root.0, "read", json!({})).unwrap()["assist"],
        json!({"name":"Clef Flash"})
    );
}
