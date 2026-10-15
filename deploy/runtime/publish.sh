#!/usr/bin/env bash
# Build the runtime image for a release tag and push it, as `<version>` and
# `latest`, to each image repository in RUNTIME_IMAGE_REPOSITORIES (a space
# list such as `ghcr.io/owner/muniment-runtime`).
#
# RUNTIME_IMAGE_LOGINS holds one `<registry> <user> <password>` line per
# registry. A repository whose registry has no login is skipped with a
# warning, so a registry can be added before its credential exists. The logins
# live in a throwaway Docker config, so none stays on the runner.
#
# Usage: deploy/runtime/publish.sh <vX.Y.Z> [revision]
set -euo pipefail

tag=$1
revision=${2:-$(git rev-parse HEAD)}
if [[ ! $tag =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  echo "publish.sh: $tag is not a vX.Y.Z tag" >&2
  exit 2
fi
version=${BASH_REMATCH[1]}
read -r -a repositories <<<"${RUNTIME_IMAGE_REPOSITORIES:-}"
if [ ${#repositories[@]} -eq 0 ]; then
  echo "publish.sh: RUNTIME_IMAGE_REPOSITORIES names no repository" >&2
  exit 2
fi
context=$(cd "$(dirname "$0")/../.." && pwd)
local_image="muniment-runtime:publish-$$"

DOCKER_CONFIG=$(mktemp -d)
export DOCKER_CONFIG
# A config with no auth entry makes docker pick the platform credential store,
# which outlives this directory. An entry keeps the logins in this file.
printf '{"auths":{"publish.invalid":{}}}\n' >"$DOCKER_CONFIG/config.json"
cleanup() {
  rm -rf "$DOCKER_CONFIG"
  docker image rm "$local_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

declare -A logged_in=()
while read -r registry user password; do
  [ -n "${registry:-}" ] || continue
  if [ -z "${user:-}" ] || [ -z "${password:-}" ]; then
    echo "publish.sh: the login line for $registry lacks a user or password" >&2
    exit 2
  fi
  printf '%s' "$password" | docker login "$registry" --username "$user" --password-stdin >/dev/null
  logged_in[$registry]=1
done <<<"${RUNTIME_IMAGE_LOGINS:-}"

targets=()
for repository in "${repositories[@]}"; do
  registry=${repository%%/*}
  if [ -n "${logged_in[$registry]:-}" ]; then
    targets+=("$repository")
  else
    echo "::warning::No login for $registry, so $repository is skipped."
  fi
done
if [ ${#targets[@]} -eq 0 ]; then
  echo "publish.sh: no repository has a login, so nothing is pushed" >&2
  exit 1
fi

docker build -f "$context/deploy/runtime/Containerfile" \
  --build-arg "MUNIMENT_RUNTIME_VERSION=$version" \
  --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.revision=$revision" \
  -t "$local_image" "$context"

for repository in "${targets[@]}"; do
  for name in "$repository:$version" "$repository:latest"; do
    docker tag "$local_image" "$name"
    docker push "$name"
    docker image rm "$name" >/dev/null
  done
  echo "Pushed $repository:$version and :latest."
done
