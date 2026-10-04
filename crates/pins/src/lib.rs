//! Typed access to `pins/pins.toml`: the Pi release, its extension packages,
//! and the Claude Code CLI version that the desktop and the factory share.
//!
//! The build script compiles the file into constants, so every value is
//! available in const contexts and a malformed file fails the build.

/// The text of `pins/pins.toml`.
pub const PINS_TOML: &str = include_str!("../../../pins/pins.toml");

/// The Bun lockfile for exactly [`PACKAGES`]. It records every transitive
/// version and its integrity hash.
pub const PACKAGES_LOCK: &str = include_str!("../../../pins/packages.bun.lock");

/// A pinned Pi release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pi {
    pub version: &'static str,
    /// The one older release admitted for rollback.
    pub rollback_version: &'static str,
    /// The download directory of the current release's assets.
    pub release_base: &'static str,
    /// The current and rollback assets for every supported platform.
    pub assets: &'static [PiAsset],
}

/// One Pi release archive for one platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiAsset {
    pub version: &'static str,
    /// `<target_os>-<target_arch>`, for example `macos-aarch64`.
    pub platform: &'static str,
    pub archive: &'static str,
    /// The archive size in bytes.
    pub size: u64,
    /// The lowercase hex SHA-256 digest of the archive.
    pub sha256: &'static str,
    /// The executable's path inside the extracted archive.
    pub executable: &'static str,
}

/// One pinned Pi extension package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Package {
    pub name: &'static str,
    pub version: &'static str,
}

/// The pinned Claude Code CLI release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaudeCode {
    pub version: &'static str,
}

#[cfg(feature = "cli")]
pub mod update;

include!(concat!(env!("OUT_DIR"), "/pins.rs"));

const fn same(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Returns the pinned asset for `version` on `platform`, or `None`.
pub const fn find_pi_asset(version: &str, platform: &str) -> Option<PiAsset> {
    let mut index = 0;
    while index < PI.assets.len() {
        let asset = PI.assets[index];
        if same(asset.version, version) && same(asset.platform, platform) {
            return Some(asset);
        }
        index += 1;
    }
    None
}

/// Returns the pinned asset for `version` on `platform`. A missing asset
/// fails const evaluation, so a const caller fails the build.
pub const fn pi_asset(version: &str, platform: &str) -> PiAsset {
    match find_pi_asset(version, platform) {
        Some(asset) => asset,
        None => panic!("pins.toml has no Pi asset for this version and platform"),
    }
}

/// Returns the packages as `(name, version)` pairs.
pub const fn package_pairs() -> [(&'static str, &'static str); PACKAGE_COUNT] {
    let mut pairs = [("", ""); PACKAGE_COUNT];
    let mut index = 0;
    while index < PACKAGE_COUNT {
        pairs[index] = (PACKAGES[index].name, PACKAGES[index].version);
        index += 1;
    }
    pairs
}
