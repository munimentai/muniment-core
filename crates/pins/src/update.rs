//! Checks `pins/pins.toml` against the Pi releases and the npm registry, and
//! rewrites it for newer versions. The `muniment-pins` binary drives it.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub type Result<T> = std::result::Result<T, String>;

/// The GitHub repository that publishes the Pi release archives.
pub const PI_REPOSITORY: &str = "earendil-works/pi";
pub const GITHUB_API: &str = "https://api.github.com";
pub const NPM_REGISTRY: &str = "https://registry.npmjs.org";
pub const PI_NPM: &str = "@earendil-works/pi-coding-agent";
pub const CLAUDE_CODE_NPM: &str = "@anthropic-ai/claude-code";
/// The package manifest name the lockfile is resolved from. The runtime install uses the same name.
pub const MANIFEST_NAME: &str = "muniment-pi-packages";

const HEADER: &str = "# Pinned runtime dependencies shared by the desktop and the factory.\n\
# The muniment-pins crate compiles this file into typed constants.\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinsFile {
    pub pi: PiPins,
    pub packages: Vec<PackagePin>,
    pub claude_code: ClaudeCodePin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiPins {
    pub version: String,
    pub rollback_version: String,
    pub release_base: String,
    pub assets: Vec<AssetPin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetPin {
    pub version: String,
    pub platform: String,
    pub archive: String,
    pub size: u64,
    pub sha256: String,
    pub executable: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePin {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeCodePin {
    pub version: String,
}

/// The `<target_os>-<target_arch>` name of the running host.
pub fn host_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

pub fn release_base(version: &str) -> String {
    format!("https://github.com/{PI_REPOSITORY}/releases/download/v{version}")
}

impl PinsFile {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|error| format!("pins.toml: {error}"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text)
    }

    /// The file text in the layout the repository keeps: Pi, its assets, the packages, Claude Code.
    pub fn render(&self) -> String {
        let quote = |text: &str| Value::String(text.to_owned()).to_string();
        let mut out = String::from(HEADER);
        out.push_str("\n[pi]\n");
        out.push_str(&format!("version = {}\n", quote(&self.pi.version)));
        out.push_str(&format!(
            "rollback_version = {}\n",
            quote(&self.pi.rollback_version)
        ));
        out.push_str(&format!(
            "release_base = {}\n",
            quote(&self.pi.release_base)
        ));
        for asset in &self.pi.assets {
            out.push_str("\n[[pi.assets]]\n");
            out.push_str(&format!("version = {}\n", quote(&asset.version)));
            out.push_str(&format!("platform = {}\n", quote(&asset.platform)));
            out.push_str(&format!("archive = {}\n", quote(&asset.archive)));
            out.push_str(&format!("size = {}\n", asset.size));
            out.push_str(&format!("sha256 = {}\n", quote(&asset.sha256)));
            out.push_str(&format!("executable = {}\n", quote(&asset.executable)));
        }
        for package in &self.packages {
            out.push_str("\n[[packages]]\n");
            out.push_str(&format!("name = {}\n", quote(&package.name)));
            out.push_str(&format!("version = {}\n", quote(&package.version)));
        }
        out.push_str("\n[claude_code]\n");
        out.push_str(&format!("version = {}\n", quote(&self.claude_code.version)));
        out
    }

    /// The platforms the current release pins, in file order.
    pub fn platforms(&self) -> Vec<&AssetPin> {
        self.pi
            .assets
            .iter()
            .filter(|asset| asset.version == self.pi.version)
            .collect()
    }

    pub fn asset(&self, version: &str, platform: &str) -> Option<&AssetPin> {
        self.pi
            .assets
            .iter()
            .find(|asset| asset.version == version && asset.platform == platform)
    }

    /// The package.json the lockfile is resolved from. It matches the runtime install's manifest.
    pub fn package_manifest(&self) -> Vec<u8> {
        let dependencies: Map<String, Value> = self
            .packages
            .iter()
            .map(|package| (package.name.clone(), Value::String(package.version.clone())))
            .collect();
        serde_json::to_vec_pretty(&json!({
            "name": MANIFEST_NAME,
            "private": true,
            "dependencies": dependencies,
        }))
        .expect("the package manifest serializes")
    }
}

/// A release version as `(major, minor, patch)`. Prereleases and build tags do not parse.
pub fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.trim().trim_start_matches('v').split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

/// True when `to` changes the major or minor version of `from`.
pub fn is_feature_change(from: &str, to: &str) -> bool {
    match (parse_version(from), parse_version(to)) {
        (Some(from), Some(to)) => (from.0, from.1) != (to.0, to.1),
        _ => true,
    }
}

/// The registry and release reads, and archive downloads. Tests answer from recorded responses.
pub trait Http {
    fn get_json(&self, url: &str) -> Result<Value>;
    /// Writes the body of `url` to `dest`.
    fn download(&self, url: &str, dest: &Path) -> Result<()>;
}

/// Plain HTTPS. A `GITHUB_TOKEN` raises the GitHub API rate limit.
pub struct Network {
    agent: ureq::Agent,
    github_token: Option<String>,
}

impl Network {
    pub fn from_env() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(std::time::Duration::from_secs(30))
                .timeout_read(std::time::Duration::from_secs(300))
                .build(),
            github_token: std::env::var("GITHUB_TOKEN")
                .ok()
                .or_else(|| std::env::var("GH_TOKEN").ok())
                .filter(|token| !token.is_empty()),
        }
    }

    fn request(&self, url: &str) -> ureq::Request {
        let mut request = self.agent.get(url).set("user-agent", "muniment-pins");
        if url.starts_with(GITHUB_API) {
            request = request.set("accept", "application/vnd.github+json");
            if let Some(token) = &self.github_token {
                request = request.set("authorization", &format!("Bearer {token}"));
            }
        }
        request
    }
}

impl Http for Network {
    fn get_json(&self, url: &str) -> Result<Value> {
        let mut last = String::new();
        for attempt in 0..3 {
            match self.request(url).call() {
                Ok(response) => {
                    return response
                        .into_json()
                        .map_err(|error| format!("GET {url}: {error}"))
                }
                Err(ureq::Error::Status(status, _)) if status < 500 => {
                    return Err(format!("GET {url}: HTTP {status}"))
                }
                Err(error) => last = format!("GET {url}: {error}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(2 << attempt));
        }
        Err(last)
    }

    fn download(&self, url: &str, dest: &Path) -> Result<()> {
        let response = self
            .agent
            .get(url)
            .set("user-agent", "muniment-pins")
            .call()
            .map_err(|error| format!("GET {url}: {error}"))?;
        let partial = dest.with_extension("partial");
        let mut file = fs::File::create(&partial)
            .map_err(|error| format!("{}: {error}", partial.display()))?;
        io::copy(&mut response.into_reader(), &mut file)
            .map_err(|error| format!("GET {url}: {error}"))?;
        file.flush().map_err(|error| error.to_string())?;
        fs::rename(&partial, dest).map_err(|error| format!("{}: {error}", dest.display()))
    }
}

/// The size and lowercase hex SHA-256 of a file.
pub fn digest_file(path: &Path) -> Result<(u64, String)> {
    let mut file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 16];
    let mut size = 0;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hasher.update(&buffer[..count]);
    }
    Ok((size, format!("{:x}", hasher.finalize())))
}

pub fn latest_pi(http: &dyn Http) -> Result<String> {
    let release = http.get_json(&format!(
        "{GITHUB_API}/repos/{PI_REPOSITORY}/releases/latest"
    ))?;
    let tag = release["tag_name"]
        .as_str()
        .ok_or("the latest Pi release names no tag")?;
    let version = tag.trim_start_matches('v');
    parse_version(version)
        .ok_or_else(|| format!("the latest Pi tag {tag} is not a release version"))?;
    Ok(version.to_owned())
}

/// The registry's `latest` manifest for `name`.
pub fn npm_latest(http: &dyn Http, name: &str) -> Result<Value> {
    let manifest = http.get_json(&format!("{NPM_REGISTRY}/{name}/latest"))?;
    if manifest["name"] != name
        || manifest["version"]
            .as_str()
            .and_then(parse_version)
            .is_none()
    {
        return Err(format!("the registry answered invalid metadata for {name}"));
    }
    Ok(manifest)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub name: String,
    pub current: String,
    pub latest: String,
    pub newer: bool,
    /// The package's declared range for the Pi coding agent, when it declares one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pi_peer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    pub pi: Status,
    pub packages: Vec<Status>,
    pub claude_code: Status,
    pub updates: bool,
}

pub fn check(pins: &PinsFile, http: &dyn Http) -> Result<CheckReport> {
    let status = |name: &str, current: &str, latest: String, pi_peer: Option<String>| Status {
        name: name.to_owned(),
        current: current.to_owned(),
        newer: is_newer(&latest, current),
        latest,
        pi_peer,
    };
    let pi = status("Pi", &pins.pi.version, latest_pi(http)?, None);
    let mut packages = Vec::new();
    for package in &pins.packages {
        let manifest = npm_latest(http, &package.name)?;
        let peer = manifest["peerDependencies"][PI_NPM]
            .as_str()
            .map(str::to_owned);
        packages.push(status(
            &package.name,
            &package.version,
            manifest["version"].as_str().unwrap_or_default().to_owned(),
            peer,
        ));
    }
    let claude = npm_latest(http, CLAUDE_CODE_NPM)?;
    let claude_code = status(
        "Claude Code",
        &pins.claude_code.version,
        claude["version"].as_str().unwrap_or_default().to_owned(),
        None,
    );
    let updates = pi.newer || claude_code.newer || packages.iter().any(|package| package.newer);
    Ok(CheckReport {
        pi,
        packages,
        claude_code,
        updates,
    })
}

/// What `bump` moves. `latest` resolves to the newest release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BumpRequest {
    pub pi: Option<String>,
    /// Moves every package to its registry `latest`.
    pub all_packages: bool,
    /// Explicit `(name, version)` targets. They win over `all_packages`.
    pub packages: Vec<(String, String)>,
    pub claude_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub component: String,
    pub from: String,
    pub to: String,
}

/// The new pins with the Pi assets still unresolved, and the changes they make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub pins: PinsFile,
    pub changes: Vec<Change>,
    pub pi_changed: bool,
    pub packages_changed: bool,
}

/// Resolves the request against the registries. Pi assets are fetched separately.
pub fn plan(current: &PinsFile, request: &BumpRequest, http: &dyn Http) -> Result<Plan> {
    let mut pins = current.clone();
    let mut changes = Vec::new();
    let mut change = |component: &str, from: &str, to: &str| {
        changes.push(Change {
            component: component.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
        })
    };
    let mut pi_changed = false;
    if let Some(target) = &request.pi {
        let target = if target == "latest" {
            latest_pi(http)?
        } else {
            target.trim_start_matches('v').to_owned()
        };
        parse_version(&target).ok_or_else(|| format!("{target} is not a Pi release version"))?;
        if target != current.pi.version {
            change("Pi", &current.pi.version, &target);
            pins.pi.rollback_version = current.pi.version.clone();
            pins.pi.version = target.clone();
            pins.pi.release_base = release_base(&target);
            pins.pi.assets.clear();
            pi_changed = true;
        }
    }
    let mut packages_changed = false;
    for package in &mut pins.packages {
        let explicit = request
            .packages
            .iter()
            .find(|(name, _)| *name == package.name)
            .map(|(_, version)| version.clone());
        let target = match explicit {
            Some(version) if version != "latest" => Some(version),
            Some(_) => Some(npm_version(http, &package.name)?),
            None if request.all_packages => Some(npm_version(http, &package.name)?),
            None => None,
        };
        if let Some(target) = target.filter(|target| *target != package.version) {
            change(&package.name, &package.version, &target);
            package.version = target;
            packages_changed = true;
        }
    }
    for (name, _) in &request.packages {
        if !current.packages.iter().any(|package| package.name == *name) {
            return Err(format!("{name} is not a pinned package"));
        }
    }
    if let Some(target) = &request.claude_code {
        let target = if target == "latest" {
            npm_version(http, CLAUDE_CODE_NPM)?
        } else {
            target.clone()
        };
        if target != current.claude_code.version {
            change("Claude Code", &current.claude_code.version, &target);
            pins.claude_code.version = target;
        }
    }
    Ok(Plan {
        pins,
        changes,
        pi_changed,
        packages_changed,
    })
}

fn npm_version(http: &dyn Http, name: &str) -> Result<String> {
    Ok(npm_latest(http, name)?["version"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

/// The conventional pull request title for `changes`: `feat:` when Pi or a
/// package moves a major or minor version, `fix:` otherwise.
pub fn title(changes: &[Change]) -> Option<String> {
    if changes.is_empty() {
        return None;
    }
    let feature = changes.iter().any(|change| {
        change.component != "Claude Code" && is_feature_change(&change.from, &change.to)
    });
    let list: Vec<_> = changes
        .iter()
        .map(|change| format!("{} to {}", change.component, change.to))
        .collect();
    Some(format!(
        "{}: update {}",
        if feature { "feat" } else { "fix" },
        list.join(", ")
    ))
}

/// Where `bump` and `compat` keep downloaded archives, keyed by version.
pub fn cache_path(cache: &Path, version: &str, archive: &str) -> PathBuf {
    cache.join(format!("pi-{version}")).join(archive)
}

/// Downloads every platform archive of `version`, checks it against the
/// release's published digest and any existing pin, and returns the pins.
pub fn fetch_assets(
    http: &dyn Http,
    version: &str,
    templates: &[&AssetPin],
    known: &PinsFile,
    cache: &Path,
) -> Result<Vec<AssetPin>> {
    let release = http.get_json(&format!(
        "{GITHUB_API}/repos/{PI_REPOSITORY}/releases/tags/v{version}"
    ))?;
    let published = release["assets"]
        .as_array()
        .ok_or_else(|| format!("Pi v{version} lists no assets"))?;
    let mut assets = Vec::new();
    for template in templates {
        let entry = published
            .iter()
            .find(|asset| asset["name"] == template.archive.as_str())
            .ok_or_else(|| format!("Pi v{version} has no {}", template.archive))?;
        let path = cache_path(cache, version, &template.archive);
        fs::create_dir_all(path.parent().unwrap()).map_err(|error| error.to_string())?;
        let expected = entry["digest"]
            .as_str()
            .and_then(|digest| digest.strip_prefix("sha256:"));
        let cached = path.exists()
            && expected.is_some()
            && digest_file(&path)?.1 == expected.unwrap_or_default();
        if !cached {
            let url = entry["browser_download_url"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{}/{}", release_base(version), template.archive));
            http.download(&url, &path)?;
        }
        let (size, sha256) = digest_file(&path)?;
        if entry["size"]
            .as_u64()
            .is_some_and(|published| published != size)
        {
            return Err(format!(
                "{} v{version}: the download size differs from the release",
                template.archive
            ));
        }
        if expected.is_some_and(|expected| expected != sha256) {
            return Err(format!(
                "{} v{version}: the SHA-256 differs from the release digest",
                template.archive
            ));
        }
        if let Some(pinned) = known.asset(version, &template.platform) {
            if (pinned.size, pinned.sha256.as_str()) != (size, sha256.as_str()) {
                return Err(format!(
                    "{} v{version}: the archive differs from the pinned size and SHA-256",
                    template.archive
                ));
            }
        }
        assets.push(AssetPin {
            version: version.to_owned(),
            platform: template.platform.clone(),
            archive: template.archive.clone(),
            size,
            sha256,
            executable: template.executable.clone(),
        });
    }
    Ok(assets)
}

/// Extracts a cached archive once and returns the Pi executable inside it.
pub fn extract(archive: &Path, executable: &str) -> Result<PathBuf> {
    let directory = archive.with_extension("").with_extension("extracted");
    let binary = directory.join(executable);
    if binary.exists() {
        return Ok(binary);
    }
    let staging = directory.with_extension("staging");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    // The system tar reads both tar.gz and zip archives on every supported host.
    let status = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(&staging)
        .status()
        .map_err(|error| format!("tar: {error}"))?;
    if !status.success() {
        return Err(format!("tar could not extract {}", archive.display()));
    }
    let _ = fs::remove_dir_all(&directory);
    fs::rename(&staging, &directory).map_err(|error| error.to_string())?;
    if !binary.exists() {
        return Err(format!("{} holds no {executable}", archive.display()));
    }
    Ok(binary)
}

/// Runs Pi's embedded Bun with `args` in `directory`.
pub fn pi_bun(pi: &Path, directory: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(pi)
        .env("BUN_BE_BUN", "1")
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{}: {error}", pi.display()))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!("pi {} failed: {text}", args.join(" ")));
    }
    Ok(text)
}

/// Resolves the package lockfile with the Pi executable's Bun.
pub fn resolve_lock(pi: &Path, pins: &PinsFile, work: &Path) -> Result<String> {
    let _ = fs::remove_dir_all(work);
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    fs::write(work.join("package.json"), pins.package_manifest())
        .map_err(|error| error.to_string())?;
    pi_bun(
        pi,
        work,
        &[
            "install",
            "--lockfile-only",
            "--omit=peer",
            "--ignore-scripts",
        ],
    )?;
    fs::read_to_string(work.join("bun.lock")).map_err(|error| format!("bun.lock: {error}"))
}
