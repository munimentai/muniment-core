//! The `muniment-pins` update logic against recorded registry responses.
#![cfg(feature = "cli")]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use muniment_pins::update::{
    check, fetch_assets, is_newer, parse_version, plan, title, BumpRequest, Change, Http, PinsFile,
    Result,
};
use muniment_pins::PINS_TOML;
use serde_json::{json, Value};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/registry");

/// Answers each URL from a recorded response and serves downloads from memory.
#[derive(Default)]
struct Recorded {
    json: BTreeMap<String, Value>,
    files: BTreeMap<String, Vec<u8>>,
    downloads: RefCell<Vec<String>>,
}

impl Recorded {
    fn registry() -> Self {
        let mut recorded = Self::default();
        let read = |file: &str| -> Value {
            serde_json::from_str(&std::fs::read_to_string(Path::new(FIXTURES).join(file)).unwrap())
                .unwrap()
        };
        recorded.json.insert(
            "https://api.github.com/repos/earendil-works/pi/releases/latest".into(),
            read("github-pi-latest.json"),
        );
        recorded.json.insert(
            "https://api.github.com/repos/earendil-works/pi/releases/tags/v1.0.2".into(),
            read("github-pi-v1.0.2.json"),
        );
        for (name, file) in [
            ("pi-web-access", "npm-pi-web-access.json"),
            ("pi-subagents", "npm-pi-subagents.json"),
            ("pi-background-tasks", "npm-pi-background-tasks.json"),
            ("pi-mcp-adapter", "npm-pi-mcp-adapter.json"),
            ("pi-claude-bridge", "npm-pi-claude-bridge.json"),
            (
                "@anthropic-ai/claude-code",
                "npm-anthropic-ai_claude-code.json",
            ),
        ] {
            recorded.json.insert(
                format!("https://registry.npmjs.org/{name}/latest"),
                read(file),
            );
        }
        recorded
    }
}

impl Http for Recorded {
    fn get_json(&self, url: &str) -> Result<Value> {
        self.json
            .get(url)
            .cloned()
            .ok_or_else(|| format!("GET {url}: HTTP 404"))
    }

    fn download(&self, url: &str, dest: &Path) -> Result<()> {
        self.downloads.borrow_mut().push(url.to_owned());
        let body = self.files.get(url).ok_or(format!("GET {url}: HTTP 404"))?;
        std::fs::write(dest, body).map_err(|error| error.to_string())
    }
}

/// The pins the recorded responses are newer than.
fn current() -> PinsFile {
    PinsFile::parse(include_str!("fixtures/pins-0.87.1.toml")).unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn temporary() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "muniment-pins-cli-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn the_rendered_file_matches_the_repository_layout() {
    assert_eq!(PinsFile::parse(PINS_TOML).unwrap().render(), PINS_TOML);
    let fixture = include_str!("fixtures/pins-0.87.1.toml");
    assert_eq!(current().render(), fixture);
}

#[test]
fn versions_compare_by_release_number_and_skip_prereleases() {
    assert_eq!(parse_version("v1.0.2"), Some((1, 0, 2)));
    assert_eq!(parse_version("1.0.0-rc.1"), None);
    assert!(is_newer("1.0.2", "0.87.1"));
    assert!(is_newer("0.100.0", "0.99.2"));
    assert!(!is_newer("0.87.1", "0.87.1"));
    assert!(!is_newer("2.0.0-beta.1", "1.0.0"));
}

#[test]
fn check_reports_each_pin_against_the_newest_release() {
    let pins = current();
    let report = check(&pins, &Recorded::registry()).unwrap();
    assert_eq!(report.pi.current, pins.pi.version);
    assert_eq!(report.pi.latest, "1.0.2");
    assert!(report.updates);
    let latest: Vec<_> = report
        .packages
        .iter()
        .map(|status| (status.name.as_str(), status.latest.as_str()))
        .collect();
    assert_eq!(
        latest,
        [
            ("pi-web-access", "0.35.0"),
            ("pi-subagents", "0.75.0"),
            ("pi-background-tasks", "2.6.9"),
            ("pi-mcp-adapter", "5.0.0"),
            ("pi-claude-bridge", "0.9.1"),
        ]
    );
    let bridge = &report.packages[4];
    assert_eq!(bridge.pi_peer.as_deref(), Some(">=0.86.1"));
    assert_eq!(report.claude_code.latest, "2.1.289");
    assert!(report.pi.newer && report.claude_code.newer);
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["packages"][3]["newer"], json!(true));
}

#[test]
fn a_full_bump_moves_the_current_release_to_rollback() {
    let pins = current();
    let request = BumpRequest {
        pi: Some("latest".into()),
        all_packages: true,
        packages: vec![("pi-mcp-adapter".into(), "4.0.0".into())],
        remove: Vec::new(),
        claude_code: Some("latest".into()),
    };
    let plan = plan(&pins, &request, &Recorded::registry()).unwrap();
    assert!(plan.pi_changed && plan.packages_changed);
    assert_eq!(plan.pins.pi.version, "1.0.2");
    assert_eq!(plan.pins.pi.rollback_version, pins.pi.version);
    assert_eq!(
        plan.pins.pi.release_base,
        "https://github.com/earendil-works/pi/releases/download/v1.0.2"
    );
    assert!(plan.pins.pi.assets.is_empty());
    let mcp = plan
        .pins
        .packages
        .iter()
        .find(|package| package.name == "pi-mcp-adapter")
        .unwrap();
    assert_eq!(mcp.version, "4.0.0");
    assert_eq!(plan.pins.claude_code.version, "2.1.289");
    assert_eq!(plan.changes.first().unwrap().component, "Pi");
    assert_eq!(plan.changes.last().unwrap().component, "Claude Code");
    assert!(title(&plan.changes)
        .unwrap()
        .starts_with("feat: update Pi to 1.0.2, "));
}

#[test]
fn an_empty_request_changes_nothing_and_unknown_packages_fail() {
    let pins = current();
    let unchanged = plan(&pins, &BumpRequest::default(), &Recorded::registry()).unwrap();
    assert!(unchanged.changes.is_empty());
    assert_eq!(unchanged.pins, pins);
    assert_eq!(title(&unchanged.changes), None);
    let request = BumpRequest {
        packages: vec![("left-pad".into(), "1.0.0".into())],
        ..BumpRequest::default()
    };
    let error = plan(&pins, &request, &Recorded::registry()).unwrap_err();
    assert!(error.contains("left-pad"), "{error}");
}

#[test]
fn a_removed_package_leaves_the_pins_and_relocks() {
    let pins = current();
    let request = BumpRequest {
        remove: vec!["pi-mcp-adapter".into()],
        ..BumpRequest::default()
    };
    let plan = plan(&pins, &request, &Recorded::registry()).unwrap();
    assert!(plan.packages_changed && !plan.pi_changed);
    assert!(!plan
        .pins
        .packages
        .iter()
        .any(|package| package.name == "pi-mcp-adapter"));
    assert_eq!(plan.pins.packages.len(), pins.packages.len() - 1);
    assert_eq!(plan.changes[0].to, "removed");
    assert_eq!(title(&plan.changes).unwrap(), "feat: remove pi-mcp-adapter");
    let unknown = BumpRequest {
        remove: vec!["left-pad".into()],
        ..BumpRequest::default()
    };
    assert!(plan_error(&pins, &unknown).contains("left-pad"));
}

fn plan_error(pins: &muniment_pins::update::PinsFile, request: &BumpRequest) -> String {
    plan(pins, request, &Recorded::registry()).unwrap_err()
}

#[test]
fn titles_follow_the_size_of_the_change() {
    let change = |component: &str, from: &str, to: &str| Change {
        component: component.into(),
        from: from.into(),
        to: to.into(),
    };
    assert_eq!(
        title(&[change("Claude Code", "2.1.282", "2.1.289")]).unwrap(),
        "fix: update Claude Code to 2.1.289"
    );
    assert_eq!(
        title(&[
            change("Pi", "1.0.1", "1.0.2"),
            change("pi-subagents", "0.75.0", "0.75.1")
        ])
        .unwrap(),
        "fix: update Pi to 1.0.2, pi-subagents to 0.75.1"
    );
    assert_eq!(
        title(&[change("Pi", "0.87.1", "1.0.2")]).unwrap(),
        "feat: update Pi to 1.0.2"
    );
    assert_eq!(
        title(&[change("pi-mcp-adapter", "2.37.0", "5.0.0")]).unwrap(),
        "feat: update pi-mcp-adapter to 5.0.0"
    );
}

/// A release whose archives are small in-memory bodies with matching digests.
fn synthetic_release(http: &mut Recorded, version: &str, pins: &PinsFile) {
    let mut assets = Vec::new();
    for template in pins.platforms() {
        let body = format!("{version} {}", template.archive).into_bytes();
        let url = format!(
            "https://github.com/earendil-works/pi/releases/download/v{version}/{}",
            template.archive
        );
        assets.push(json!({
            "name": template.archive,
            "size": body.len(),
            "digest": format!("sha256:{}", sha256(&body)),
            "browser_download_url": url,
        }));
        http.files.insert(url, body);
    }
    http.json.insert(
        format!("https://api.github.com/repos/earendil-works/pi/releases/tags/v{version}"),
        json!({"tag_name": format!("v{version}"), "assets": assets}),
    );
}

#[test]
fn assets_are_downloaded_hashed_and_cached() {
    let pins = current();
    let mut http = Recorded::default();
    synthetic_release(&mut http, "9.9.9", &pins);
    let cache = temporary();
    let assets = fetch_assets(&http, "9.9.9", &pins.platforms(), &pins, &cache).unwrap();
    assert_eq!(assets.len(), pins.platforms().len());
    for (asset, template) in assets.iter().zip(pins.platforms()) {
        let body = format!("9.9.9 {}", template.archive).into_bytes();
        assert_eq!(asset.version, "9.9.9");
        assert_eq!(asset.platform, template.platform);
        assert_eq!(asset.executable, template.executable);
        assert_eq!(asset.size, body.len() as u64);
        assert_eq!(asset.sha256, sha256(&body));
    }
    let downloads = http.downloads.borrow().len();
    fetch_assets(&http, "9.9.9", &pins.platforms(), &pins, &cache).unwrap();
    assert_eq!(
        http.downloads.borrow().len(),
        downloads,
        "cached archives download again"
    );
    std::fs::remove_dir_all(cache).unwrap();
}

#[test]
fn a_digest_or_pin_mismatch_fails_the_bump() {
    let pins = current();
    let mut http = Recorded::default();
    synthetic_release(&mut http, "9.9.9", &pins);
    let url = http.files.keys().next().unwrap().clone();
    http.files.insert(url, b"tampered".to_vec());
    let cache = temporary();
    let error = fetch_assets(&http, "9.9.9", &pins.platforms(), &pins, &cache).unwrap_err();
    assert!(error.contains("differs from the release"), "{error}");
    std::fs::remove_dir_all(&cache).unwrap();

    // A rollback archive must still match the pin recorded for it.
    let mut http = Recorded::default();
    synthetic_release(&mut http, &pins.pi.version, &pins);
    let cache = temporary();
    let error = fetch_assets(
        &http,
        &pins.pi.version.clone(),
        &pins.platforms(),
        &pins,
        &cache,
    )
    .unwrap_err();
    assert!(error.contains("pinned size and SHA-256"), "{error}");
    std::fs::remove_dir_all(cache).unwrap();
}

#[test]
fn the_package_manifest_names_exactly_the_pins() {
    let pins = current();
    let manifest: Value = serde_json::from_slice(&pins.package_manifest()).unwrap();
    assert_eq!(manifest["name"], "muniment-pi-packages");
    let dependencies = manifest["dependencies"].as_object().unwrap();
    assert_eq!(dependencies.len(), pins.packages.len());
    for package in &pins.packages {
        assert_eq!(dependencies[&package.name], package.version.as_str());
    }
}
