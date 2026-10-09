use muniment_pins::{
    find_pi_asset, package_pairs, pi_asset, PiAsset, CLAUDE_CODE, PACKAGES, PACKAGES_LOCK, PI,
    PINS_TOML,
};

/// Each supported platform, its release archive, and the executable inside it.
const PLATFORMS: [(&str, &str, &str); 5] = [
    ("linux-x86_64", "pi-linux-x64.tar.gz", "pi/pi"),
    ("linux-aarch64", "pi-linux-arm64.tar.gz", "pi/pi"),
    ("macos-aarch64", "pi-darwin-arm64.tar.gz", "pi/pi"),
    ("macos-x86_64", "pi-darwin-x64.tar.gz", "pi/pi"),
    ("windows-x86_64", "pi-windows-x64.zip", "pi/pi.exe"),
];

fn release(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.').map(|part| part.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

#[test]
fn pins_name_a_current_and_older_rollback_release_for_every_platform() {
    let current = release(PI.version).expect("pi.version is a release version");
    let rollback = release(PI.rollback_version).expect("pi.rollback_version is a release version");
    assert!(rollback < current);
    assert_eq!(
        PI.release_base,
        format!(
            "https://github.com/earendil-works/pi/releases/download/v{}",
            PI.version
        )
    );
    let mut expected = Vec::new();
    for version in [PI.version, PI.rollback_version] {
        for (platform, archive, executable) in PLATFORMS {
            expected.push((version, platform, archive, executable));
        }
    }
    let assets: Vec<_> = PI
        .assets
        .iter()
        .map(|a| (a.version, a.platform, a.archive, a.executable))
        .collect();
    assert_eq!(assets, expected);
    let names: Vec<_> = package_pairs().iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "pi-web-access",
            "pi-subagents",
            "pi-background-tasks",
            "pi-claude-bridge",
        ]
    );
    for (_, version) in package_pairs() {
        assert!(release(version).is_some(), "{version}");
    }
    assert!(release(CLAUDE_CODE.version).is_some());
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
    for (platform, _, _) in PLATFORMS {
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
