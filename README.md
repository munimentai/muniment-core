# muniment-core

The shared Rust core of Muniment. The Muniment desktop and the Muniment AI
software factory build on the same crates, so local runtime behavior, model
routing and runtime pins match in both.

## Crates

| Crate | Path | What it is |
| --- | --- | --- |
| `muniment-core` | `crates/core` | Local runtime logic and storage contracts: the run journal, Pi sidecar supervision and install, memory, projects, attach server, on-device speech and voice. |
| `muniment-router` | `crates/router` | The multi-account model router: account pools, routing policy, the loopback OpenAI-compatible server, provider model discovery, the `muniment-router` server binary (`server` feature) and the `muniment-router-shadow` binary. |
| `muniment-pins` | `crates/pins` | Typed constants compiled from `pins/pins.toml`, plus the embedded package lockfile. |
| `muniment-attach` | `crates/attach` | The reader and companion attach protocol and its client. |
| `muniment-code-diff` | `crates/code-diff` | Portable code-diff values and fixtures. |
| `muniment-atomic-file` | `crates/atomic-file` | Atomic file replacement, including the Windows retry path. |

`muniment-core` re-exports `muniment-router` as `muniment_core::model_router`,
along with `provider_models`, `endpoint_models`, `http` and `atomic_file`, so
existing `muniment_core::...` paths keep working.

Desktop-only code (cloud sign-in, cloud chat grants and browser control) lives in
the desktop. The host supplies it through the `account` and `chat_launch` values
and the `PiLaunchBoundaries` and `RunAttachBoundaries` traits.
`docs/decisions/0030-public-core-boundary.md` lists every module and crate and
`scripts/check-core-boundary.sh` enforces the boundary.

## Pins

`pins/pins.toml` pins the Pi release (current and rollback), one archive per
platform with its size and SHA-256, the Pi extension packages, and the Claude
Code version. `pins/packages.bun.lock` locks the packages. Platform names use
`<target_os>-<target_arch>`, for example `macos-aarch64`.

The `muniment-pins` binary keeps the pins current:

```sh
cargo run -p muniment-pins --features cli -- check
cargo run -p muniment-pins --features cli -- bump --pi latest --packages --claude-code latest
cargo run -p muniment-pins --features cli -- compat --report compat.json
```

`check` prints each pin beside its newest release as JSON. `bump` downloads
every platform archive of the new Pi release and of its rollback, records their
sizes and SHA-256 digests, and resolves `pins/packages.bun.lock` with the new
Pi's Bun. `--package NAME@VERSION` pins one package. `compat` runs the
compatibility suite on the host platform:

- the pinned Pi in JSON and RPC modes against a fake OpenAI-compatible stream
  server (`scripts/pins/compat/`),
- a load check for every pinned package and for the tools the system prompt names,
- muniment-core's sidecar, launch and RPC frame tests against the real Pi,
- the router against a fake Anthropic upstream with the pinned Claude Code identity,
- one `pi-claude-bridge` turn through the pinned Claude Code CLI against a fake
  Anthropic endpoint.

The `pins-update` workflow runs daily. It bumps every pin that passes the suite
on Linux, then runs the suite and the workspace tests on macOS and the CI checks
on Linux against the bumped tree. When all of them pass, it rebases the bump
onto `main`, pushes it with a `feat:` or `fix:` message, and tags the release
with `pins.toml` and `packages.bun.lock` attached. A pin that fails gets one
`Pin update blocked: <component> <version>` issue and stays at its version.

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
cargo install --git https://github.com/munimentai/muniment-core --tag v0.1.0 --features server muniment-router
gh release download v0.1.0 --repo munimentai/muniment-core --pattern pins.toml
```

## Router server

`muniment-router serve` runs the router for the factory. It builds only with
the `server` feature, so the desktop never compiles Postgres, OpenBao or the
run-token code. `deploy/router/Containerfile` builds a non-root image whose
health check runs `muniment-router health`.

Settings come from a TOML file (`--config` or `MUNIMENT_ROUTER_CONFIG`), and a
`MUNIMENT_ROUTER_*` variable overrides each one: `openbao.role_id` is
`MUNIMENT_ROUTER_OPENBAO_ROLE_ID`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:8790` | Bind address. |
| `admin_token` | required | Bearer for `/v1/runs` and `/v1/outcomes`, 16 characters or more. |
| `run_token_signing_key` | required | HMAC-SHA256 key for run tokens: 64 hex characters, or 32 bytes of text. |
| `database_url` | | Postgres store. Migrations run at start. |
| `state_dir` | | The desktop's JSON files instead of Postgres, for development. |
| `openbao.address`, `.mount`, `.prefix` | `secret`, `muniment-router/accounts` | KV v2 secret per account at `<mount>/data/<prefix>/<account id>`. |
| `openbao.token` or `.role_id` and `.secret_id` | | Token or AppRole login (`openbao.approle_mount`, default `approle`). |
| `openbao.cache_ttl_s` | `60` | How long a read credential is reused. |
| `openbao.tls_pin_sha256` | | SHA-256 of a self-signed OpenBao certificate to trust instead of the OS store. |
| `catalog`, `catalog_poll_s` | embedded, `5` | Catalog file, reloaded when its contents change. |
| `policy_mode` | `adaptive` | `current`, `strong`, `ratchet` or `adaptive`. |
| `classifier.kind` | `none` | `typesafe`, `endpoint` or `pooled`, with `base_url`, `api_key`, `model`, `family`. |
| `success.half_life_days`, `.min_samples` | `7`, `5` | Decay and sample floor of measured success rates. |
| `quota_probe_interval_s` | `900` | Subscription quota probes. `0` turns them off. |
| `drain_timeout_s` | `100` | How long SIGTERM waits for open streams. |
| `metrics` | `true` | Serve `/metrics`. |
| `langfuse.host`, `.public_key`, `.secret_key` | | Langfuse ingestion. Off unless all three are set. A key that starts with `PLACEHOLDER` counts as unset. |

Endpoints: `POST /v1/runs`, `GET` and `DELETE /v1/runs/{run_id}` and
`POST /v1/outcomes` take the admin token. A run's usage carries `last_status`,
the status of the run's most recent failed request, and `last_error_type`:
`budget_exhausted`, `routing_constraints`, `routing_budget`,
`upstream_unavailable`, `rate_limited`, `auth`, or null. `POST /v1/chat/completions` and
`GET /v1/models` take a run token and read the `x-muniment-task` and
`x-muniment-validation-failures` headers. With Langfuse on, each chat
completion becomes one generation with its model, usage, cost, latency, run id,
task id and role. It joins the trace that the `x-muniment-trace` header names,
or the task's own trace when the header is absent. A background thread posts
the generations in batches, so Langfuse never delays a turn. A run's turn reserves its uncached
cost estimate before it goes upstream and settles the priced cost after. Once
spend reaches the budget the router answers 402 with
`{"error":{"type":"budget_exhausted",…}}`. Routing constraints run before
any classifier sees text. The run's remaining budget replaces the configured
`policy.task_budget_usd`, and a turn that no eligible model's estimate fits
answers 422 with `{"error":{"type":"routing_constraints",…}}`. The desktop
keeps `policy.offline_only` (loopback endpoints only) and its own
`policy.task_budget_usd`. `GET /healthz` and `GET /metrics` take no token.

`muniment-router accounts list|add-key|login|import-pi-auth|set-weight|disable|enable|remove|probe`
manages the pool in the configured store and secret source. `muniment-router
catalog check <file>` checks a catalog file.

The catalog (`crates/router/catalog.toml`) is a list of `[[model]]` tables with
`family`, `model`, `name`, `tier` (`deep`, `balanced` or `fast`), `price` and
`output` in US dollars per million tokens, `context` (`400K`, `1M`),
`strengths` and `limits`. A file that fails the check keeps the last good
catalog in force.

## Development

```sh
cargo build --workspace
cargo test --workspace -- --test-threads=1
cargo test -p muniment-router --features server -- --test-threads=1
scripts/check-core-boundary.sh
```

The router's Postgres tests run when `MUNIMENT_ROUTER_TEST_DATABASE_URL` names a
database they may create schemas in. The OpenBao integration test runs when
`MUNIMENT_ROUTER_TEST_OPENBAO_ADDR` and `MUNIMENT_ROUTER_TEST_OPENBAO_TOKEN` are set.

`muniment-core` links `sherpa-onnx`. Its build script downloads the prebuilt
shared libraries on first build. `third-party/` holds the ONNX Runtime
libraries that the on-device tests load.

Pushes to `main` cut a release. Conventional commit prefixes pick the version:
`feat:` is minor, `fix:` and `perf:` are patch, `feat!:` or a `BREAKING CHANGE:`
trailer is major, and other prefixes cut no release.

## License

FSL-1.1-ALv2. See `LICENSE.md`.
