# Agent operating instructions

`muniment-core` is the shared Rust core of Muniment. Two consumers build on it:

- The Muniment desktop (`munimentai/muniment`), a Tauri app. It depends on tagged
  releases of this repository through a git dependency.
- The AI software factory, a headless Python service. It runs the router and
  reads `pins/pins.toml` from a tagged release.

`README.md` describes each crate. `docs/decisions/` holds the decision records
that tests and checks read.

## Boundary

No crate may depend on Tauri, on a desktop crate, or on a desktop-only module.
The desktop-only modules `auth`, `chat_grant` and `browser_control` live in the
desktop. No source file here may name them, and no file has an exception. The
host supplies desktop behavior through port-owned values and traits.
`scripts/check-core-boundary.sh` checks the inventory in
`docs/decisions/0030-public-core-boundary.md` and every source edge.

`muniment-router` and `muniment-pins` never depend on `muniment-core`.
`muniment-core` re-exports them at the module paths callers use, such as
`muniment_core::model_router`. Keep those paths stable: the desktop imports
`muniment_core::...` throughout.

## Pins

`pins/pins.toml` is the one source for the Pi release, its platform assets with
size and SHA-256, the Pi extension packages, and the Claude Code version.
`pins/packages.bun.lock` locks the packages. The `muniment-pins` build script
compiles the file into constants, so a malformed file fails the build. Change
pins with `muniment-pins bump`, which rewrites both files, and run
`muniment-pins compat` before you commit. The daily `pins-update` workflow does
both, runs the CI checks on Linux and macOS, then pushes to `main` and tags
the release itself.

## Verification loop

CI runs formatting, clippy, tests on Linux and macOS, a Windows check, and the
boundary check. Use focused local checks while you develop:

- `cargo test -p <crate>` for the crate you changed.
- `cargo fmt --all --check` before each commit.
- `scripts/check-core-boundary.sh` when you add an import between modules.

Core tests that spawn stub processes run with `--test-threads=1`.

## Windows code

Windows-only code cannot compile on a Linux or macOS host. The Windows CI job is
the only Windows check. Re-read every changed `#[cfg(windows)]` path by hand
before you push. A green local build does not cover that code.

## Code

- Match the surrounding code and keep changes small.
- Keep edition, dependency versions and `Cargo.lock` stable unless the change is
  a dependency update.
- Comments describe the code: what it does, and why a non-obvious constraint
  exists. Reasons for a change belong in the commit message.

## Steering files

This repository's steering files are `AGENTS.md`, `README.md` and
`docs/decisions/`. They are instruction, not record: present tense, stating what
is. No dates, ticket ids, commit shas, or pull request numbers. No history
phrases. No ledger file under any name: no open-items, build-history,
decision-log, handoff, journal, notes, or todo file. `AGENTS.md` stays under 120
lines. Issues track work and git holds history. `CLAUDE.md` imports this file
and carries no separate rules.

## Commits

- `feat:` → minor
- `fix:` / `perf:` → patch
- `feat!:` or `BREAKING CHANGE:` trailer → major
- `chore:` / `docs:` / `test:` / `refactor:` → no release
- Before a direct commit to `main`, run `git pull --rebase`. Push right after you commit.
- Never force-push `main`. On a rebase conflict in an append-only file, keep both lines in time order.

The release workflow tags `main` with the next version from these prefixes and
attaches `pins/pins.toml` to the GitHub release.
