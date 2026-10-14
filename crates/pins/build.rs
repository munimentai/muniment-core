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
    #[serde(default)]
    patch: Option<String>,
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
    for patch in pins
        .packages
        .iter()
        .filter_map(|package| package.patch.as_ref())
    {
        assert!(
            patch.starts_with("patches/")
                && patch.ends_with(".patch")
                && !patch.contains('\\')
                && !patch.split('/').any(|part| part.is_empty() || part == ".."),
            "pins.toml: the patch {patch} must be a file under patches/"
        );
    }
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let pins_directory = manifest.join("../../pins");
    let path = pins_directory.join("pins.toml");
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
    writeln!(
        out,
        "/// The local patches Bun applies to pinned packages through `patchedDependencies`."
    )
    .unwrap();
    writeln!(out, "pub const PACKAGE_PATCHES: &[PackagePatch] = &[").unwrap();
    for package in &pins.packages {
        let Some(patch) = &package.patch else {
            continue;
        };
        let file = pins_directory.join(patch);
        println!("cargo:rerun-if-changed={}", file.display());
        assert!(file.is_file(), "pins.toml: {patch} is missing");
        let file = file.to_str().expect("the patch path is UTF-8");
        writeln!(
            out,
            "    PackagePatch {{ name: {:?}, version: {:?}, path: {:?}, text: include_str!({:?}) }},",
            package.name, package.version, patch, file
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
