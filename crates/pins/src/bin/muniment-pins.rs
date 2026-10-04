//! `muniment-pins check | bump | compat`: keeps `pins/pins.toml` current.
//!
//! - `check` prints the pinned and newest versions as JSON.
//! - `bump` rewrites `pins/pins.toml` and `pins/packages.bun.lock` for newer versions.
//! - `compat` runs the compatibility suite against the pinned versions.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use muniment_pins::update::{
    cache_path, check, digest_file, extract, fetch_assets, host_platform, pi_bun, plan,
    resolve_lock, title, BumpRequest, Http, Network, PinsFile, Result, CLAUDE_CODE_NPM,
};
use serde_json::{json, Value};

const USAGE: &str = "usage:
  muniment-pins check
  muniment-pins bump [--pi VERSION|latest] [--packages] [--package NAME@VERSION]... [--claude-code VERSION|latest]
  muniment-pins compat [--archive PATH] [--report PATH] [--skip-cargo]
common options: --root DIR (the muniment-core checkout), --cache DIR (downloads and work files)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("muniment-pins: {error}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    root: PathBuf,
    cache: PathBuf,
    rest: Vec<String>,
}

fn options(args: &[String]) -> Result<Options> {
    let mut root = None;
    let mut cache = None;
    let mut rest = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => root = Some(PathBuf::from(iter.next().ok_or("--root needs a value")?)),
            "--cache" => cache = Some(PathBuf::from(iter.next().ok_or("--cache needs a value")?)),
            _ => rest.push(arg.clone()),
        }
    }
    let root = match root {
        Some(root) => root,
        None => find_root()?,
    };
    let root = fs::canonicalize(&root).map_err(|error| format!("{}: {error}", root.display()))?;
    let cache = cache.unwrap_or_else(|| root.join("target").join("muniment-pins"));
    fs::create_dir_all(&cache).map_err(|error| format!("{}: {error}", cache.display()))?;
    Ok(Options { root, cache, rest })
}

/// The nearest ancestor of the working directory that holds `pins/pins.toml`.
fn find_root() -> Result<PathBuf> {
    let start = std::env::current_dir().map_err(|error| error.to_string())?;
    start
        .ancestors()
        .find(|directory| directory.join("pins/pins.toml").is_file())
        .map(Path::to_owned)
        .ok_or_else(|| "run inside a muniment-core checkout or pass --root".into())
}

fn run(args: &[String]) -> Result<ExitCode> {
    let Some((command, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    let options = options(rest)?;
    let http = Network::from_env();
    match command.as_str() {
        "check" => {
            let pins = PinsFile::load(&options.root.join("pins/pins.toml"))?;
            print_json(&serde_json::to_value(check(&pins, &http)?).unwrap());
            Ok(ExitCode::SUCCESS)
        }
        "bump" => bump(&options, &http),
        "compat" => compat(&options, &http),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

fn print_json(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

fn bump_request(args: &[String]) -> Result<BumpRequest> {
    let mut request = BumpRequest::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = || iter.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--pi" => request.pi = Some(value()?),
            "--claude-code" => request.claude_code = Some(value()?),
            "--packages" => request.all_packages = true,
            "--package" => {
                let spec = value()?;
                let (name, version) = spec
                    .rfind('@')
                    .filter(|index| *index > 0)
                    .map(|index| (&spec[..index], &spec[index + 1..]))
                    .ok_or(format!("--package takes NAME@VERSION, not {spec}"))?;
                request.packages.push((name.to_owned(), version.to_owned()));
            }
            other => return Err(format!("unknown bump option {other}\n{USAGE}")),
        }
    }
    Ok(request)
}

fn bump(options: &Options, http: &dyn Http) -> Result<ExitCode> {
    let request = bump_request(&options.rest)?;
    let pins_path = options.root.join("pins/pins.toml");
    let current = PinsFile::load(&pins_path)?;
    let mut plan = plan(&current, &request, http)?;
    if plan.pi_changed {
        let templates = current.platforms();
        let mut assets = Vec::new();
        for version in [&plan.pins.pi.version, &plan.pins.pi.rollback_version] {
            eprintln!("Downloading the Pi {version} archives.");
            assets.extend(fetch_assets(
                http,
                version,
                &templates,
                &current,
                &options.cache,
            )?);
        }
        plan.pins.pi.assets = assets;
    }
    if plan.pi_changed || plan.packages_changed {
        let asset = plan
            .pins
            .asset(&plan.pins.pi.version, &host_platform())
            .ok_or_else(|| format!("pins.toml has no Pi asset for {}", host_platform()))?
            .clone();
        let pi = host_pi(http, &plan.pins, &asset, &options.cache)?;
        eprintln!(
            "Resolving the package lockfile with Pi {}.",
            plan.pins.pi.version
        );
        let lock = resolve_lock(&pi, &plan.pins, &options.cache.join("lock"))?;
        fs::write(options.root.join("pins/packages.bun.lock"), lock)
            .map_err(|error| format!("packages.bun.lock: {error}"))?;
    }
    if !plan.changes.is_empty() {
        fs::write(&pins_path, plan.pins.render())
            .map_err(|error| format!("{}: {error}", pins_path.display()))?;
    }
    print_json(&json!({"changes": plan.changes, "title": title(&plan.changes)}));
    Ok(ExitCode::SUCCESS)
}

/// The verified host archive of `asset`, extracted, and the Pi executable in it.
fn host_pi(
    http: &dyn Http,
    pins: &PinsFile,
    asset: &muniment_pins::update::AssetPin,
    cache: &Path,
) -> Result<PathBuf> {
    let archive = cached_archive(http, pins, asset, cache)?;
    extract(&archive, &asset.executable)
}

fn cached_archive(
    http: &dyn Http,
    pins: &PinsFile,
    asset: &muniment_pins::update::AssetPin,
    cache: &Path,
) -> Result<PathBuf> {
    let path = cache_path(cache, &asset.version, &asset.archive);
    let verified = |path: &Path| -> Result<bool> {
        Ok(path.exists() && digest_file(path)? == (asset.size, asset.sha256.clone()))
    };
    if !verified(&path)? {
        fs::create_dir_all(path.parent().unwrap()).map_err(|error| error.to_string())?;
        let base = if asset.version == pins.pi.version {
            pins.pi.release_base.clone()
        } else {
            muniment_pins::update::release_base(&asset.version)
        };
        http.download(&format!("{base}/{}", asset.archive), &path)?;
        if !verified(&path)? {
            return Err(format!(
                "{} v{} differs from the pinned size and SHA-256",
                asset.archive, asset.version
            ));
        }
    }
    Ok(path)
}

/// One compatibility step: its name, whether it passed, and its output tail.
struct Step {
    name: &'static str,
    passed: bool,
    output: String,
}

fn compat(options: &Options, http: &dyn Http) -> Result<ExitCode> {
    let mut archive_override = None;
    let mut report = None;
    let mut cargo = true;
    let mut iter = options.rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--archive" => {
                archive_override =
                    Some(PathBuf::from(iter.next().ok_or("--archive needs a value")?))
            }
            "--report" => {
                report = Some(PathBuf::from(iter.next().ok_or("--report needs a value")?))
            }
            "--skip-cargo" => cargo = false,
            other => return Err(format!("unknown compat option {other}\n{USAGE}")),
        }
    }
    let root = &options.root;
    let pins = PinsFile::load(&root.join("pins/pins.toml"))?;
    let asset = pins
        .asset(&pins.pi.version, &host_platform())
        .ok_or_else(|| format!("pins.toml has no Pi asset for {}", host_platform()))?
        .clone();
    let archive = match archive_override {
        Some(path) => {
            if digest_file(&path)? != (asset.size, asset.sha256.clone()) {
                return Err(format!(
                    "{} differs from the pinned archive",
                    path.display()
                ));
            }
            fs::canonicalize(&path).map_err(|error| error.to_string())?
        }
        None => cached_archive(http, &pins, &asset, &options.cache)?,
    };
    let pi = extract(&archive, &asset.executable)?;
    let work = options.cache.join(format!("compat-{}", pins.pi.version));
    let _ = fs::remove_dir_all(&work);

    let frames = work.join("rpc-frames.jsonl");
    let mut steps = Vec::new();
    // The frozen install is the runtime's install: the lockfile must hold every package.
    let packages = work.join("packages");
    let install = (|| -> Result<String> {
        fs::create_dir_all(&packages).map_err(|error| error.to_string())?;
        fs::write(packages.join("package.json"), pins.package_manifest())
            .map_err(|error| error.to_string())?;
        fs::copy(
            root.join("pins/packages.bun.lock"),
            packages.join("bun.lock"),
        )
        .map_err(|error| error.to_string())?;
        pi_bun(
            &pi,
            &packages,
            &[
                "install",
                "--frozen-lockfile",
                "--force",
                "--omit=peer",
                "--ignore-scripts",
            ],
        )
    })();
    let installed = install.is_ok();
    steps.push(Step {
        name: "frozen package install",
        passed: installed,
        output: install.unwrap_or_else(|error| error),
    });
    let claude = install_claude_code(&pi, &pins, &work.join("claude-code"));
    let claude_binary = claude.as_ref().ok().cloned();
    steps.push(Step {
        name: "Claude Code install",
        passed: claude.is_ok(),
        output: match claude {
            Ok(path) => format!("{}", path.display()),
            Err(error) => error,
        },
    });

    if installed {
        let mut command = Command::new("node");
        command
            .arg("--test")
            .arg("--test-reporter=spec")
            .arg("--test-concurrency=1")
            .arg("scripts/pins/compat/*.test.mjs")
            .current_dir(root)
            .env("PI_RPC_CAPTURE", &frames)
            .env("PI_BINARY", &pi)
            .env("PI_PACKAGES", &packages)
            .env("PINS_JSON", serde_json::to_string(&pins).unwrap())
            .env("MUNIMENT_CORE_ROOT", root);
        if let Some(binary) = &claude_binary {
            command.env("CLAUDE_CODE_BINARY", binary);
        }
        steps.push(step("Pi, extension, and bridge checks", command));
    }
    if cargo {
        let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        command
            .args([
                "test",
                "--locked",
                "-p",
                "muniment-core",
                "--features",
                "network-tests",
                "--test",
                "pi_sidecar",
                "--test",
                "pi_launch",
                "--test",
                "pi_rpc_frames",
                "--",
                "--test-threads=1",
            ])
            .current_dir(root)
            .env("MUNIMENT_PI_RPC_FRAMES", &frames)
            .env("MUNIMENT_PI_ARCHIVE", &archive)
            .env("MUNIMENT_PI_WIRE_EXECUTABLE", &pi);
        steps.push(step("muniment-core sidecar tests on the real Pi", command));
        let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        command
            .args([
                "test",
                "--locked",
                "-p",
                "muniment-router",
                "--test",
                "claude_code_identity",
            ])
            .current_dir(root);
        steps.push(step("router Claude Code identity", command));
    }

    let passed = steps.iter().all(|step| step.passed);
    let summary = json!({
        "pi": pins.pi.version,
        "platform": host_platform(),
        "passed": passed,
        "steps": steps.iter().map(|step| json!({
            "name": step.name,
            "passed": step.passed,
            "output": tail(&step.output, 6000),
        })).collect::<Vec<_>>(),
    });
    if let Some(path) = report {
        fs::write(&path, serde_json::to_vec_pretty(&summary).unwrap())
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    for step in &steps {
        eprintln!(
            "{} {}",
            if step.passed { "PASS" } else { "FAIL" },
            step.name
        );
    }
    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Installs the pinned Claude Code CLI with Pi's Bun and returns its native binary.
fn install_claude_code(pi: &Path, pins: &PinsFile, work: &Path) -> Result<PathBuf> {
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let manifest = json!({
        "name": "muniment-claude-code",
        "private": true,
        "dependencies": {CLAUDE_CODE_NPM: pins.claude_code.version},
    });
    fs::write(work.join("package.json"), manifest.to_string())
        .map_err(|error| error.to_string())?;
    pi_bun(pi, work, &["install", "--ignore-scripts"])?;
    // The package's postinstall links the platform binary. Scripts stay off, so use it directly.
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        other => other,
    };
    let name = if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    };
    let binary = work
        .join("node_modules/@anthropic-ai")
        .join(format!("claude-code-{os}-{arch}"))
        .join(name);
    if !binary.exists() {
        return Err(format!("{} is missing after the install", binary.display()));
    }
    Ok(binary)
}

fn step(name: &'static str, mut command: Command) -> Step {
    eprintln!("Running {name}.");
    let output = command
        .stdin(Stdio::null())
        .output()
        .map(|output| {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let _ = std::io::stderr().write_all(text.as_bytes());
            (output.status.success(), text)
        })
        .unwrap_or_else(|error| (false, format!("{name} did not start: {error}")));
    Step {
        name,
        passed: output.0,
        output: output.1,
    }
}

fn tail(text: &str, limit: usize) -> String {
    let start = text.len().saturating_sub(limit);
    let start = (start..text.len())
        .find(|index| text.is_char_boundary(*index))
        .unwrap_or(text.len());
    text[start..].to_owned()
}
