use muniment_pins::{
    find_pi_asset, package_pairs, pi_asset, PiAsset, CLAUDE_CODE, PACKAGES, PACKAGES_LOCK, PI,
    PINS_TOML,
};

/// The values the desktop compiled in before the pins moved to `pins.toml`.
const PREVIOUS_ASSETS: [(&str, &str, &str, u64, &str, &str); 10] = [
    (
        "0.87.1",
        "linux-x86_64",
        "pi-linux-x64.tar.gz",
        42_120_827,
        "80d78dd62d50049a006b981d994c61255bcc10e730b0c278d4ea0a755909764c",
        "pi/pi",
    ),
    (
        "0.87.1",
        "linux-aarch64",
        "pi-linux-arm64.tar.gz",
        42_217_308,
        "364b4a9f8491450b27a4857d4e3c780dbaf696790821c176a873e860cbbc3b89",
        "pi/pi",
    ),
    (
        "0.87.1",
        "macos-aarch64",
        "pi-darwin-arm64.tar.gz",
        30_563_988,
        "4f8d288b78c9768d3a4ac6f61f06cd34394b82ac17d5b42d1e44a437add401b7",
        "pi/pi",
    ),
    (
        "0.87.1",
        "macos-x86_64",
        "pi-darwin-x64.tar.gz",
        33_033_993,
        "01d8ee28d7114fec4f4eeedbb7561f790853040e9bfbdeebe79437ab66ea51f5",
        "pi/pi",
    ),
    (
        "0.87.1",
        "windows-x86_64",
        "pi-windows-x64.zip",
        44_615_504,
        "aab2ba67baf8ff97a52d05b62d88e9e65a840c6ea8fa1029a28d62d210d4e5fc",
        "pi/pi.exe",
    ),
    (
        "0.85.1",
        "linux-x86_64",
        "pi-linux-x64.tar.gz",
        42_560_927,
        "494e498f47d74d21f40b3386f6a5e921a3d49531a169cab55bbdaca0ea1fe25a",
        "pi/pi",
    ),
    (
        "0.85.1",
        "linux-aarch64",
        "pi-linux-arm64.tar.gz",
        42_628_180,
        "042d20ae885ee4f3b102815f3280b962c377b2e9fb44de4037908cc530eae4d4",
        "pi/pi",
    ),
    (
        "0.85.1",
        "macos-aarch64",
        "pi-darwin-arm64.tar.gz",
        31_035_676,
        "d5f70e3c0cf7398eac239fd0261ee074d98b7ba7f6b43fe3617f052ed5b79d06",
        "pi/pi",
    ),
    (
        "0.85.1",
        "macos-x86_64",
        "pi-darwin-x64.tar.gz",
        33_544_584,
        "adb918b845625f184d8bea408d55eacaf21aa87238793c0f5b4f3b9737bce62b",
        "pi/pi",
    ),
    (
        "0.85.1",
        "windows-x86_64",
        "pi-windows-x64.zip",
        45_009_021,
        "002fa95b90d521245b9985d8f168caebc237ad56e7e30b319807dee1b2e17e1c",
        "pi/pi.exe",
    ),
];

#[test]
fn pins_match_the_previously_compiled_values() {
    assert_eq!(PI.version, "0.87.1");
    assert_eq!(PI.rollback_version, "0.85.1");
    assert_eq!(
        PI.release_base,
        "https://github.com/earendil-works/pi/releases/download/v0.87.1"
    );
    let assets: Vec<_> = PI
        .assets
        .iter()
        .map(|a| {
            (
                a.version,
                a.platform,
                a.archive,
                a.size,
                a.sha256,
                a.executable,
            )
        })
        .collect();
    assert_eq!(assets, PREVIOUS_ASSETS);
    assert_eq!(
        package_pairs(),
        [
            ("pi-web-access", "0.31.0"),
            ("pi-subagents", "0.71.0"),
            ("pi-background-tasks", "2.5.0"),
            ("pi-mcp-adapter", "2.37.0"),
            ("pi-claude-bridge", "0.8.0"),
        ]
    );
    assert_eq!(CLAUDE_CODE.version, "2.1.282");
}

#[test]
fn the_compiled_constants_match_the_embedded_file() {
    let file: toml::Table = toml::from_str(PINS_TOML).unwrap();
    let pi = file["pi"].as_table().unwrap();
    assert_eq!(pi["version"].as_str(), Some(PI.version));
    assert_eq!(pi["rollback_version"].as_str(), Some(PI.rollback_version));
    assert_eq!(pi["release_base"].as_str(), Some(PI.release_base));
    let assets: Vec<PiAsset> = pi["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|asset| {
            let text =
                |key: &str| -> &'static str { asset[key].as_str().unwrap().to_owned().leak() };
            PiAsset {
                version: text("version"),
                platform: text("platform"),
                archive: text("archive"),
                size: asset["size"].as_integer().unwrap() as u64,
                sha256: text("sha256"),
                executable: text("executable"),
            }
        })
        .collect();
    assert_eq!(assets, PI.assets);
    let packages: Vec<_> = file["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| {
            (
                package["name"].as_str().unwrap().to_owned(),
                package["version"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let compiled: Vec<_> = PACKAGES
        .iter()
        .map(|package| (package.name.to_owned(), package.version.to_owned()))
        .collect();
    assert_eq!(packages, compiled);
    assert_eq!(
        file["claude_code"]["version"].as_str(),
        Some(CLAUDE_CODE.version)
    );
}

#[test]
fn lookups_find_current_and_rollback_assets() {
    for platform in [
        "linux-x86_64",
        "linux-aarch64",
        "macos-aarch64",
        "macos-x86_64",
        "windows-x86_64",
    ] {
        let current = pi_asset(PI.version, platform);
        let rollback = pi_asset(PI.rollback_version, platform);
        assert_eq!((current.version, current.platform), (PI.version, platform));
        assert_eq!(rollback.version, PI.rollback_version);
        assert_eq!(current.archive, rollback.archive);
        assert_eq!(current.executable, rollback.executable);
    }
    assert_eq!(find_pi_asset(PI.version, "linux-riscv64"), None);
    assert_eq!(find_pi_asset("0.0.0", "linux-x86_64"), None);
}

#[test]
fn the_lockfile_resolves_exactly_the_pinned_packages() {
    let start = PACKAGES_LOCK.find("\"dependencies\": {").unwrap();
    let end = start + PACKAGES_LOCK[start..].find('}').unwrap();
    let mut locked: Vec<_> = PACKAGES_LOCK[start..end]
        .lines()
        .skip(1)
        .map(|line| line.trim().trim_end_matches(','))
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let mut pinned: Vec<_> = PACKAGES
        .iter()
        .map(|package| format!("\"{}\": \"{}\"", package.name, package.version))
        .collect();
    locked.sort();
    pinned.sort();
    assert_eq!(locked, pinned);
}
