# 0034 — Portable runtime and engine boundary

- Status: proposed

## Context

The Muniment runtime is the one process per user that owns execution: the
agent child, the run journal, schedules and the attach listener. Clients
attach to it. The desktop is one client, beside the CLI, the ACP bridge and
mobile.

Three outcomes depend on where code lives:

- The desktop is a UI layer. It holds no model knowledge and writes no engine
  file.
- Anyone runs the Muniment runtime as a container on a server, and the
  factory runs the same container.
- The agent engine can change from the Pi coding agent in RPC mode to Pi
  Durable without a change to any client.

Pi Durable is a TypeScript library for a durable agent harness. One process
owns its storage, and clients attach to that process. Models and extensions
are set in code, not in `models.json`. It offers crash resume, background
compaction and manual compaction with instructions. Its API is experimental.

## Decision

Six rules govern the runtime, core and every client.

### 1. One engine boundary

The runtime reaches the agent engine through one interface in
`muniment-core`. Its operations are open a conversation, submit, steer,
cancel, compact with optional instructions, configure the model and tools,
read context usage, resume after a crash, and receive events. An adapter
implements the interface for one engine. The Pi RPC adapter is the
implementation. No code outside an adapter reads Pi RPC frames, Pi session
files or Pi settings files.

### 2. Model knowledge is data in core

A `muniment-models` crate holds every fact about providers and models:
provider ids, names, sign-in methods and aliases, local server kinds and
their ports, model lists, context windows, output limits and prices. It
resolves a model's window from discovery first, then the catalog, and answers
no window when neither knows the model. It renders that data into the form an
engine reads: Pi's `models.json` for the Pi adapter. `muniment-router`
depends on `muniment-models`, and `muniment-core` re-exports it as
`muniment_core::models`.

### 3. The runtime owns execution

The runtime runs the model router, applies model settings, writes
credentials and starts compaction. A client asks the runtime for each of
these. A client never starts the router and never writes an engine file.

### 4. Attach is the only client API

Every client capability is an attach message. A feature reaches a client
only through attach, so the desktop, the CLI, the ACP bridge, mobile and the
factory see the same features. The message set does not depend on the
transport.

### 5. Platform code stays at the edge

The runtime binary is platform-neutral. The keychain, cloud sign-in, chat
grants, browser control and OS service registration reach it through
interfaces that the host supplies. The desktop supplies the native ones. A
container supplies a file and environment credential store and no service
registration.

### 6. Many runtimes per client

A client keeps a list of runtimes: the one on its machine and any paired
server runtime. Each thread, run and project carries the id of the runtime
that owns it, and a thread stays on that runtime. Settings pages show the
selected runtime's models, memory, extensions and context settings. A
server's provider keys stay on the server. A server thread's files live on
the server, and a client reads them through attach.

## Authorization

A client and a runtime on the same machine under the same OS user need no
user step. The runtime admits the client by OS peer identity: the socket
peer's credentials on macOS and Linux and the pipe client's token on
Windows. This needs no account.

A runtime in a container runs with no account. Without a pairing it admits
only clients that reach its socket on its host, such as a mounted socket.
The factory connects this way. OS peer identity does not cross the container
boundary, so a container on the same machine as a desktop pairs like any
server.

Pairing a desktop with a container is optional, and it uses a free MUNICLOUD
account, like mobile pairing. A headless server has no camera or screen, so
the container prints a one-time code, and the user enters it in the desktop.
The pairing binds the desktop to the same account and gives it a device
credential that the runtime can revoke. A paired connection goes direct over
TLS when the server is reachable, and through the MUNICLOUD relay otherwise,
end-to-end encrypted, like the mobile relay leg. One runtime serves one
owner. Several people on one runtime are outside this design.

## Containers

The container image holds the Linux runtime binary, the pinned Pi and its
packages. State lives in a volume at the path `MUNIMENT_STATE_DIR` names.
Secrets come from files or environment variables through the credential
store interface. The image carries no desktop integration and no keychain.
Core's CI builds the image from the same pins as the desktop.

## Pi Durable

The Pi Durable adapter implements rule 1 when these three conditions hold:

- Pi Durable has a release with a stable API.
- The tools and extension packages Muniment pins run on it.
- A supported way exists to host it in a process the runtime supervises.

Its `root.compact(instructions)` maps to the compact operation, `submit`
with `whenBusy: "steer"` maps to steer, and `harness.resume()` maps to
resume. Models reach it through `muniment-models`, rendered as Pi Durable
providers instead of `models.json`. Both the run journal and Pi Durable's
storage record a conversation. The adapter owns the engine's storage, and the
run journal stays the runtime's record until a separate decision names one
owner of the transcript.

## Consequences

- The desktop drops its provider tables, server scan, `models.json` writes
  and router start. Each becomes a runtime operation behind attach.
- The runtime crate moves from the desktop repository into
  `muniment-core`. The desktop bundles and registers the binary.
- Attach gains a TLS transport with device credentials beside the local
  socket and named pipe.
- Manual compaction and the context meter are the first features built on
  rules 1 and 4.
