#!/usr/bin/env bash
# Install the stable Rust toolchain with the named components on a runner, and
# put cargo on PATH for the later steps of the job.
# Usage: .forgejo/rust-toolchain.sh [component...]
#
# The runner container keeps /root between jobs, so rustup installs once.
# rustup-init is pinned by version and checked against the SHA-256 that
# static.rust-lang.org publishes beside it.
set -euo pipefail

rustup_version=1.29.1
rustup_sha256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
rustup="$HOME/.cargo/bin/rustup"

if [ ! -x "$rustup" ]; then
  installer=$(mktemp "${RUNNER_TEMP:-/tmp}/rustup-init.XXXXXX")
  trap 'rm -f "$installer"' EXIT
  curl --proto '=https' --tlsv1.2 -sSfL -o "$installer" \
    "https://static.rust-lang.org/rustup/archive/${rustup_version}/x86_64-unknown-linux-gnu/rustup-init"
  printf '%s  %s\n' "$rustup_sha256" "$installer" | sha256sum --check --quiet
  chmod +x "$installer"
  "$installer" -y --profile minimal --default-toolchain none --no-modify-path
fi

components=()
for component in "$@"; do
  components+=(--component "$component")
done
"$rustup" toolchain install stable --profile minimal "${components[@]}"
"$rustup" default stable
echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
