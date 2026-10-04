//! Compiles `pins/pins.toml` into Rust constants so callers keep const pins.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    pi: Pi,
    packages: Vec<Package>,
    claude_code: ClaudeCode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pi {
    version: String,
    rollback_version: String,
    release_base: String,
    assets: Vec<PiAsset>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PiAsset {
    version: String,
    platform: String,
    archive: String,
    size: u64,
    sha256: String,
    executable: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeCode {
    version: String,
}

fn platforms(pi: &Pi, version: &str) -> BTreeSet<String> {
    pi.assets
        .iter()
        .filter(|asset| asset.version == version)
        .map(|asset| asset.platform.clone())
        .collect()
}

fn validate(pins: &Pins) {
    let pi = &pins.pi;
    assert!(
        pi.release_base.ends_with(&format!("/v{}", pi.version)),
        "pins.toml: pi.release_base must name v{}",
        pi.version
    );
    let current = platforms(pi, &pi.version);
    assert!(!current.is_empty(), "pins.toml: pi.version has no assets");
    assert_eq!(
        current,
        platforms(pi, &pi.rollback_version),
        "pins.toml: the rollback assets must cover the current platforms"
    );
    let mut seen = BTreeSet::new();
    for asset in &pi.assets {
        assert!(
            asset.version == pi.version || asset.version == pi.rollback_version,
            "pins.toml: asset version {} is neither current nor rollback",
            asset.version
        );
        assert!(
            seen.insert((asset.version.clone(), asset.platform.clone())),
            "pins.toml: {} {} repeats",
            asset.version,
            asset.platform
        );
        assert!(asset.size > 0, "pins.toml: {} has no size", asset.archive);
        assert!(
            asset.sha256.len() == 64
                && asset
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "pins.toml: {} needs a lowercase SHA-256",
            asset.archive
        );
    }
    let names: BTreeSet<_> = pins.packages.iter().map(|package| &package.name).collect();
    assert!(
        !pins.packages.is_empty() && names.len() == pins.packages.len(),
        "pins.toml: packages must be present and unique"
    );
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let path = manifest.join("../../pins/pins.toml");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));
    let pins: Pins = toml::from_str(&text).unwrap_or_else(|error| panic!("pins.toml: {error}"));
    validate(&pins);

    let mut out = String::new();
    let pi = &pins.pi;
    writeln!(out, "/// The pinned Pi release and its platform assets.").unwrap();
    writeln!(out, "pub const PI: Pi = Pi {{").unwrap();
    writeln!(out, "    version: {:?},", pi.version).unwrap();
    writeln!(out, "    rollback_version: {:?},", pi.rollback_version).unwrap();
    writeln!(out, "    release_base: {:?},", pi.release_base).unwrap();
    writeln!(out, "    assets: &[").unwrap();
    for asset in &pi.assets {
        writeln!(
            out,
            "        PiAsset {{ version: {:?}, platform: {:?}, archive: {:?}, size: {}, sha256: {:?}, executable: {:?} }},",
            asset.version, asset.platform, asset.archive, asset.size, asset.sha256, asset.executable
        )
        .unwrap();
    }
    writeln!(out, "    ],\n}};").unwrap();
    writeln!(out, "/// The number of pinned Pi extension packages.").unwrap();
    writeln!(
        out,
        "pub const PACKAGE_COUNT: usize = {};",
        pins.packages.len()
    )
    .unwrap();
    writeln!(
        out,
        "/// The pinned Pi extension packages in install order."
    )
    .unwrap();
    writeln!(out, "pub const PACKAGES: [Package; PACKAGE_COUNT] = [").unwrap();
    for package in &pins.packages {
        writeln!(
            out,
            "    Package {{ name: {:?}, version: {:?} }},",
            package.name, package.version
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out, "/// The pinned Claude Code CLI release.").unwrap();
    writeln!(
        out,
        "pub const CLAUDE_CODE: ClaudeCode = ClaudeCode {{ version: {:?} }};",
        pins.claude_code.version
    )
    .unwrap();

    let target = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("pins.rs");
    fs::write(target, out).unwrap();
}
