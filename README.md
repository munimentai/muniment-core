# muniment-core

The shared Rust core of Muniment. The Muniment desktop and the Muniment AI
software factory build on the same crates, so local runtime behavior, model
routing and runtime pins match in both.

## Crates

| Crate | Path | What it is |
| --- | --- | --- |
| `muniment-core` | `crates/core` | Local runtime logic and storage contracts: the run journal, Pi sidecar supervision and install, memory, projects, attach server, on-device speech and voice. |
| `muniment-router` | `crates/router` | The multi-account model router: account pools, routing policy, the loopback OpenAI-compatible server, provider model discovery, and the `muniment-router-shadow` binary. |
| `muniment-pins` | `crates/pins` | Typed constants compiled from `pins/pins.toml`, plus the embedded package lockfile. |
| `muniment-attach` | `crates/attach` | The reader and companion attach protocol and its client. |
| `muniment-code-diff` | `crates/code-diff` | Portable code-diff values and fixtures. |
| `muniment-atomic-file` | `crates/atomic-file` | Atomic file replacement, including the Windows retry path. |

`muniment-core` re-exports `muniment-router` as `muniment_core::model_router`,
along with `provider_models`, `endpoint_models`, `http` and `atomic_file`, so
existing `muniment_core::...` paths keep working.

The modules `auth`, `chat_grant` and `browser_control` are desktop-only. They
compile only with the `desktop-integration` feature, which is on by default.
`docs/decisions/0030-public-core-boundary.md` lists every module and crate and
`scripts/check-core-boundary.sh` enforces the boundary.

## Pins

`pins/pins.toml` pins the Pi release (current and rollback), one archive per
platform with its size and SHA-256, the Pi extension packages, and the Claude
Code version. `pins/packages.bun.lock` locks the packages. Platform names use
`<target_os>-<target_arch>`, for example `macos-aarch64`.

## Consumers

The desktop depends on a release tag:

```toml
muniment-core = { git = "https://github.com/munimentai/muniment-core", tag = "v0.1.0", features = ["tls"] }
```

The repository carries no third-party OAuth client secrets. A host that offers
Antigravity sign-in registers its client at startup with
`muniment_router::native_auth::set_provider_clients`, or sets
`MUNIMENT_ANTIGRAVITY_CLIENT_ID` and `MUNIMENT_ANTIGRAVITY_CLIENT_SECRET`.
Without a client, Antigravity sign-in and token refresh answer a configuration
error and every other provider keeps working.

The factory builds the router binaries from a release tag and reads the pins
from the release asset:

```sh
cargo install --git https://github.com/munimentai/muniment-core --tag v0.1.0 muniment-router
gh release download v0.1.0 --repo munimentai/muniment-core --pattern pins.toml
```

## Development

```sh
cargo build --workspace
cargo test --workspace -- --test-threads=1
scripts/check-core-boundary.sh
```

`muniment-core` links `sherpa-onnx`. Its build script downloads the prebuilt
shared libraries on first build. `third-party/` holds the ONNX Runtime
libraries that the on-device tests load.

Pushes to `main` cut a release. Conventional commit prefixes pick the version:
`feat:` is minor, `fix:` and `perf:` are patch, `feat!:` or a `BREAKING CHANGE:`
trailer is major, and other prefixes cut no release.

## License

FSL-1.1-ALv2. See `LICENSE.md`.
