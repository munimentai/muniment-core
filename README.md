# muniment-core

The shared Rust core of Muniment. The Muniment desktop and headless router
hosts build on the same crates, so local runtime behavior, model routing and
runtime pins match in both.

This GitHub repository is a read-only mirror. It hosts the releases. It takes no
issues or pull requests.

## Crates

| Crate | Path | What it is |
| --- | --- | --- |
| `muniment-core` | `crates/core` | Local runtime logic and storage contracts: the run journal, Pi sidecar supervision and install, memory, projects, attach server, on-device speech and voice. |
| `muniment-models` | `crates/models` | Provider and model knowledge as data: the provider registry, local server kinds and their scan, provider and endpoint model discovery, context windows, the model catalog, and Pi's `models.json`. |
| `muniment-router` | `crates/router` | The multi-account model router: account pools, routing policy, the loopback OpenAI-compatible server, the `muniment-router` server binary (`server` feature) and the `muniment-router-shadow` binary. |
| `muniment-runtime-core` | `crates/runtime` | The platform-neutral runtime: attach serving and its accept loops, runs, retention and agent schedules, the company record and reader service, the model service that runs the model router and the web search server and writes provider settings, web search settings and credentials, and `run_runtime`, the entry a host without OS service registration runs. The host supplies cloud accounts, chat grants, credential storage, provider OAuth clients, the sign-in page and its executables through `RuntimeHost`. A host with a cloud account and a paired phone also gets the session relay publisher. The default `keyring` feature adds the keychain credential store and keychain prompt history. |
| `muniment-server` | `crates/server` | The headless runtime host: the `muniment-server` binary runs the runtime with no cloud account, no keychain and no OS service registration, for a container or a server. |
| `muniment-pins` | `crates/pins` | Typed constants compiled from `pins/pins.toml`, plus the embedded package lockfile. |
| `muniment-attach` | `crates/attach` | The reader and companion attach protocol and its client, with the pinned TLS transport, pairing links and device credentials of the remote route. |
| `muniment-code-diff` | `crates/code-diff` | Portable code-diff values and fixtures. |
| `muniment-atomic-file` | `crates/atomic-file` | Atomic file replacement, including the Windows retry path. |
| `muniment-search` | `crates/search` | Keyless web search: Brave, DuckDuckGo, Wikipedia, Yahoo and Bing parsers, paced per-engine sessions, metasearch, and a loopback server that answers the SearXNG JSON format. Brave uses the system `curl` program when one is present. `cargo run -p muniment-search --example live -- "query"` searches the real engines once. |

`muniment-core` re-exports `muniment-models` as `muniment_core::models` and
`muniment-router` as `muniment_core::model_router`, along with
`provider_models`, `endpoint_models`, `http` and `atomic_file`, so existing
`muniment_core::...` paths keep working. `muniment-router` re-exports the
models modules it routes with, such as `muniment_router::family`.

Desktop-only code (cloud sign-in, cloud chat grants and browser control) lives in
the desktop. The host supplies it through the `account` and `chat_launch` values,
the `PiLaunchBoundaries` and `RunAttachBoundaries` traits, and the runtime's
`RuntimeHost` value.
`docs/core-boundary.md` lists every module and crate and
`scripts/check-core-boundary.sh` enforces the boundary.

## Pins

`pins/pins.toml` pins the Pi release (current and rollback), one archive per
platform with its size and SHA-256, the Pi extension packages, and the Claude
Code version. `pins/packages.bun.lock` locks the packages. Platform names use
`<target_os>-<target_arch>`, for example `macos-aarch64`. A package entry's
`patch` field names a git diff under `pins/patches/` that Bun applies through
`patchedDependencies`, and `bump` refuses to move that package until the patch
is removed or remade for the new version.

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

A headless host builds the router binaries from a release tag and reads the
pins from the release asset:

```sh
cargo install --git https://github.com/munimentai/muniment-core --tag v0.1.0 --features server muniment-router
gh release download v0.1.0 --repo munimentai/muniment-core --pattern pins.toml
```

## Remote attach

A runtime can serve `muniment.attach/1` over TLS to clients on other machines,
such as over a LAN, a private overlay network or an SSH forward. Pairing needs no account. The
listener is off until the host binds it.

- `RemoteAccess::open(<state root>/remote, options)` creates, on first use, an
  ECDSA P-256 key, a self-signed certificate, a runtime id and a display name,
  all owner-only. Clients pin the certificate's SHA-256. The identity is never
  replaced: a missing key or certificate fails the open.
  `RuntimeAttachState::open_remote_access` opens it under the state root and
  shares it with the local desktop route.
- `RemoteAccess::create_pairing_link` answers
  `muniment://pair?v=1&id=…&name=…&fp=…&host=…#<secret>`. The secret is 128
  random bits in the fragment, works once, expires after ten minutes, and is
  stored only as its SHA-256. At most 16 links wait at once.
- Redeeming a link, through the optional `pairing` field of `hello`, issues a
  device credential: an id and a 256-bit secret, stored only as its SHA-256
  with the device's name, scopes and times. The client sends it as
  `authorized_client_id` and `authorized_client_credential` on later
  connections. `welcome` carries `runtime_id`, `runtime_name`,
  `runtime_version`, `install_kind` and, when the hardware says,
  `form_factor`: `laptop`, `all_in_one`, `desktop` or `server`.
- `RuntimeAttachState::serve_remote_listener` or `run_remote_listener` serves
  the route: TLS 1.3 only, a connection cap, handshake and first-frame
  deadlines, a 16 KiB first frame, and a growing hold on a peer address after
  repeated refusals.
- Scopes are `thread.read`, `run.write`, `runtime.update` and
  `runtime.admin`. A link grants `thread.read`, `run.write` and
  `runtime.update` unless its creator names others, and a client can ask for
  fewer, never more. Only the local owner and `runtime.admin` devices create
  links, list devices and revoke other devices, and a device delegates only
  scopes it holds. Any device may revoke itself. `runtime.update` or `runtime.admin` sends `runtime.update`.
- `remote_rule` names what a remote client may send: the desktop client
  operations except workspace onboarding, migration control, approval
  presentation, same-machine companions, and the host's cloud account and
  phone pairing. Reader connections and model changes need `runtime.admin`,
  except the choices a run makes, its model, thinking level, the models the
  picker hides and a capacity reading, which `run.write` covers.
  A refusal for a missing scope names what the device lacks.
- `models.share` replaces the model connections the calling device shares
  and needs `run.write`. The runtime writes the device's Pi entries beside its
  own in `auth.json`, keeps its own entry for a provider it already has, adds
  the device's router accounts as `shared:<device>:<id>`, and records each in
  `<state root>/agent/muniment-shared.json`. A sign-in whose provider rotates
  refresh tokens arrives without one, so only the sharing machine refreshes
  it. Revoking the device removes what it shared. `models.share_bundle`, on
  the local owner route only, answers this runtime's own connections, each
  rotating sign-in refreshed when it has under 30 minutes left.
- With a MuniCloud account, `models.vault` on the local owner route uploads
  this computer's connections to the account's model vault, releases them
  back, or issues a machine token for one paired machine. The vault then
  holds each rotating refresh token alone. A `models.share` bundle may carry
  `cloud`, the vault's base URL and a machine token, and the runtime then
  fetches the vault's leases at once and every five minutes, under the device
  `municloud`. The computer that uploaded fetches them with its own session.
  The route refuses requests that name a file on the runtime's machine: the
  `csv` reader source, and `run.submit` with `files`.
- Revoking a device closes its live sessions. `runtime.update` takes a
  version newer than the one the runtime announces, records it in
  `<state root>/remote/runtime-update.json` and sends it to
  `RemoteAccess::update_requests`. The host's updater applies it only from
  its own signed releases.
- The client side is `pair_with_link`, `connect_remote_runtime` and
  `RemoteRuntimeRecord`, which saves the credential to an owner-only file.
  `cargo run -p muniment-attach --features client --example remote-smoke --
  <link-or-record> [--record <path>]` pairs or reconnects once and prints the
  runtime's info and its thread count.

`RuntimeAttachState::start_remote_route` opens remote access and serves the
remote route as `<state root>/remote/settings.json` directs:
`{"version":1,"enabled":false,"listen":null,"endpoints":[],"allow_public":false}`
by default. A null `listen` binds port 7443 on every interface. Unless
`allow_public` is true, the listener closes a connection from a public
address before the handshake, and only loopback, private LAN, link-local and
overlay peers reach it. Empty `endpoints` let the runtime list its own
non-loopback interface addresses with the bound port, IPv4 first, at most
eight, and public addresses only when `allow_public` is true. Each listed endpoint carries a `kind`:
`configured`, `loopback`, `lan` (RFC 1918 or IPv6 unique local), `overlay`
(100.64.0.0/10 and fd7a:115c:a1e0::/48, which private overlay networks
assign) or `public`. Windows lists no interfaces, so a link there names
configured endpoints. A save starts, stops or rebinds the listener without a
restart. The serving listener publishes its address and endpoints in
`<state root>/remote/listener.json` for commands in other processes.

The local owner route, and never the remote route or a companion, also
answers:

- `remote.settings` with `{}`: `{"settings": {"enabled", "listen",
  "endpoints", "allow_public"}, "overridden", "runtime_id", "runtime_name",
  "certificate_sha256", "listening", "endpoints": [{"endpoint", "kind"}],
  "error"}`. `listening` is the bound address or null, and `error` says why
  the listener is not serving.
- `remote.settings_save` with `{"enabled": true, "listen": "0.0.0.0:7443" or
  null, "endpoints": ["host:port"], "allow_public": false}`, answered like
  `remote.settings`.
- `remote.pairing_create`, `remote.device_list`, `remote.device_revoke`,
  `runtime.info` and `runtime.update`, as a `runtime.admin` device sends them.

A local desktop session's welcome carries the same `runtime_id`,
`runtime_name`, `runtime_version` and `install_kind` once the host opened
remote access. Its chat-event subscription (`run.chat_events`) also carries
`runtime.update_requested` events with the body `{"version",
"requested_at", "requested_by"}`, so the desktop runs its updater. A remote
device never receives them.

## Phone relay

A desktop host with a cloud account relays its live runs to the one phone
paired with it, end to end encrypted under `muniment.relay-encryption/1`.
The cloud orders, stores and forwards the sealed payloads and reads only
their plaintext headers.

- `muniment_core::relay_encryption` holds the contract: the X25519 agreement
  of pairing revision 2, the phone's HMAC-SHA256 proof over the pairing
  transcript, HKDF-SHA256 for the desktop-to-phone and phone-to-desktop keys,
  AES-256-GCM sealing with a random 12-byte nonce and the canonical header as
  associated data, the per-direction counter and the 64-message command
  replay window. Its tests reproduce every vector of the contract's
  conformance package, kept at
  `protocol-fixtures/muniment.relay-encryption/1/relay-encryption-v1.json`.
- `muniment_core::relay_publisher` is the desktop side of
  `muniment.session-relay/1`. While the host's `AccountService` answers relay
  keys and a signed-in session, it keeps one WebSocket to the cloud's
  `/v1/events` with the native access token, waits for `connection.ready`,
  answers heartbeats and reconnects with backoff. It registers each live run
  as a relay session and publishes assistant text, tool activity, run status
  and permission asks as sealed events. It opens the phone's sealed stop,
  steer, follow-up and permission answers, checks their header binding,
  counter and expiry, applies them through the runtime's own operations and
  answers with a receipt or a failure.
- The runtime starts the publisher with its schedules when the host has a
  cloud. A host whose account answers no relay keys, such as
  `muniment-server`, opens no connection. The pair's counters and replay
  window live in `remote-control-relay.json` under the profile, and the host
  keeps the keys.

## Router server

`muniment-router serve` runs the router as a network server for headless agent
runs. It builds only with
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
`last_error_type` and `last_status_at` for the run's most recent request when
the router answered it with an error: the status, one of `budget_exhausted`,
`routing_constraints`, `routing_budget`, `upstream_unavailable`,
`rate_limited` or `auth` (or null), and the RFC 3339 time. A later request
the router answers without an error sets all three back to null. `POST /v1/chat/completions` and
`GET /v1/models` take a run token and read the `x-muniment-task` and
`x-muniment-validation-failures` headers. With Langfuse on, each chat
completion becomes one generation with its model, usage, cost, latency, run id,
task id and role. It joins the trace that the `x-muniment-trace` header names,
or the task's own trace when the header is absent. A background thread posts
the generations in batches, so Langfuse never delays a turn. `budget_usd` on
`POST /v1/runs` is optional. A run's turn reserves its uncached cost estimate
before it goes upstream and settles the priced cost after, and the run's usage
records the spend either way. A run without `budget_usd` is never refused on
spend. A run with one gets 402 with
`{"error":{"type":"budget_exhausted",…}}` once spend reaches it, and a turn
that no eligible model's estimate fits answers 422 with
`{"error":{"type":"routing_constraints",…}}`. Routing constraints run before
any classifier sees text. The server ignores `policy.task_budget_usd`. The
desktop keeps `policy.offline_only` (loopback endpoints only) and its own
`policy.task_budget_usd`. `GET /healthz` and `GET /metrics` take no token.

`muniment-router accounts list|add-key|login|import-pi-auth|set-weight|disable|enable|remove|probe`
manages the pool in the configured store and secret source. `muniment-router
catalog check <file>` checks a catalog file.

The catalog (`crates/models/catalog.toml`) is a list of `[[model]]` tables with
`family`, `model`, `name`, `tier` (`deep`, `balanced` or `fast`), `price` and
`output` in US dollars per million tokens, `context` (`400K`, `1M`),
`strengths` and `limits`. A file that fails the check keeps the last good
catalog in force.

## Runtime server

`muniment-server serve` runs the runtime headless on Linux and stops cleanly on
SIGTERM or SIGINT. It builds `muniment-runtime-core` without its `keyring`
feature, so it never opens a keychain: prompt history lives in files under the
state root and secrets live in `FileCredentialStore`. State lives in the
directory `MUNIMENT_STATE_DIR` names, or `~/.muniment`. The attach endpoint
sits under `XDG_RUNTIME_DIR`, or under `run` in the state root when that is
unset. One instance holds the endpoint's instance lock.

`muniment-server health` exits 0 when the runtime's attach endpoint answers a
handshake. `muniment-server prepare` installs the pinned Pi into the directory
`MUNIMENT_PI_ROOT` names, or `harness` in the state root, checking the
archive's size and SHA-256 against the pins, then installs the pinned extension
packages and prints the Pi executable's path.

A secret named `name` of service `service` lives in
`<state>/credentials/<service>/<name>` with mode 0600. The variable
`MUNIMENT_SECRET_<SERVICE>_<NAME>` overrides it: the service and the name
upper-cased, with each character other than an ASCII letter or digit written
as `_`. The reader's `ai.muniment.reader` secret `stripe` is
`MUNIMENT_SECRET_AI_MUNIMENT_READER_STRIPE`.

`serve` starts the remote route. These variables override the stored remote
access settings without changing them: `MUNIMENT_REMOTE_ACCESS` (`on` or
`off`), `MUNIMENT_REMOTE_LISTEN` (an IP address and port, such as
`0.0.0.0:7443`), `MUNIMENT_REMOTE_ENDPOINTS` (a comma list of `host:port`
the links name) and `MUNIMENT_REMOTE_ALLOW_PUBLIC` (`on` or `off`). `install_kind` is `server`, or `container` when
`MUNIMENT_INSTALL_KIND=container`. `MUNIMENT_REMOTE_NAME` sets the name links
and paired devices show, which defaults to `Muniment runtime`. The runtime
announces the release it was built from: a build sets
`MUNIMENT_RUNTIME_VERSION`, and a build without it announces the crate
version. At start `serve` logs the runtime id, the certificate fingerprint and
the listen address.

These commands work on the state directory while `serve` runs in another
process, such as over SSH or `docker exec`:

- `muniment-server pair [--scopes thread.read,run.write] [--json]` prints a
  one-time pairing link that names the endpoints the serving listener
  published. `--json` prints `{"link", "expires_at", "scopes", "endpoints",
  "fingerprint", "runtime_id", "runtime_name"}`.
- `muniment-server devices [--json]` lists the paired devices.
- `muniment-server revoke <device-id>` revokes one. Its live sessions close
  within a second.
- `muniment-server info [--json]` prints the runtime id, name, version,
  install kind, certificate fingerprint, remote access state and any update
  request.

`deploy/runtime/Containerfile` builds a non-root image with the server, the
pinned Pi for the image's architecture and the pinned packages. State lives in
the `/data` volume, and the health check runs `muniment-server health`. The
image sets `MUNIMENT_INSTALL_KIND=container` and `MUNIMENT_REMOTE_ACCESS=on`
and exposes port 7443. Publish the port on the address clients reach, such
as a LAN or tailnet address rather than every host interface, and set
`MUNIMENT_REMOTE_ENDPOINTS` to it:

```sh
docker build -f deploy/runtime/Containerfile \
  --build-arg MUNIMENT_RUNTIME_VERSION=1.13.1 -t muniment-runtime .
docker run -d --name muniment -p 192.0.2.20:7443:7443 \
  -e MUNIMENT_REMOTE_ENDPOINTS=runtime.example.net:7443 \
  -e MUNIMENT_REMOTE_NAME="Build box" \
  -v muniment-data:/data muniment-runtime
docker exec muniment muniment-server pair
```

Each release publishes the image for linux/amd64 as
`ghcr.io/munimentai/muniment-runtime:<version>` and `:latest`:

```sh
docker run -d --name muniment -p 192.0.2.20:7443:7443 \
  -e MUNIMENT_REMOTE_ENDPOINTS=runtime.example.net:7443 \
  -v muniment-data:/data ghcr.io/munimentai/muniment-runtime:latest
```

The CI `runtime-image-publish` job runs `deploy/runtime/publish.sh` after the
release job tags a version. It pushes to each image repository in the
`RUNTIME_IMAGE_REPOSITORIES` variable (a space list) and logs in with the
`RUNTIME_IMAGE_LOGINS` secret, one `<registry> <user> <password>` line per
registry. A repository whose registry has no login is skipped with a warning.

A `runtime.update` request writes `/data/remote/runtime-update.json`
(`<state root>/remote/runtime-update.json` outside the image), owner-only:

```json
{"version":"0.2.0","requested_at":"2026-01-01T00:00:00Z","requested_by":"<device id or local>"}
```

`version` starts with a digit and holds letters, digits, `.`, `-` and `+`.
A container host's updater reads the file, pulls that version's image,
recreates the container on the same volume and deletes the file.
`deploy/runtime/smoke.sh <image>` builds the `remote-smoke` target of the
same file, pairs it with the runtime, reconnects across a restart and checks
that a revoked device is refused.

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
