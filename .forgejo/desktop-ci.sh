#!/usr/bin/env bash
# Run a command on a fresh macOS or Windows VM on pve01 through
# `sudo desktop-ci`, and exit with its status.
# Usage: .forgejo/desktop-ci.sh <macos|windows|linux> <command>
#
# The VM fetches REF from this repository with the job token, checks out
# SOURCE_SHA, drops the token, and runs the command. The token belongs to
# Forgejo, so muniment-pins would send it to the GitHub API if it stayed set.
# The runner carries DESKTOP_CI_SSH_KEY. The command may not hold a single
# quote, and a Windows command may not hold a double quote or a dollar sign.
#
# Environment: DESKTOP_CI_HOST, the SSH destination of the desktop-ci host as
# user@address; REF, SOURCE_SHA, REPO_TOKEN, SERVER_URL, REPOSITORY,
# DESKTOP_CI_KNOWN_HOSTS, and BUILD_TIMEOUT in seconds (default 3600).
set -uo pipefail

platform=${1:?usage: desktop-ci.sh <platform> <command>}
command=${2:?usage: desktop-ci.sh <platform> <command>}
build_timeout=${BUILD_TIMEOUT:-3600}

case "$platform" in
  macos|windows|linux) ;;
  *) printf 'unknown desktop-ci platform: %s\n' "$platform" >&2; exit 2 ;;
esac
host=${DESKTOP_CI_HOST:-}
if [ -z "$host" ]; then
  echo 'set the DESKTOP_CI_HOST variable to the desktop-ci host as user@address' >&2
  exit 2
fi
case "$REF" in
  ''|*[!A-Za-z0-9._/-]*) printf 'unsafe ref for desktop-ci: %s\n' "$REF" >&2; exit 2 ;;
esac
case "$SOURCE_SHA" in
  *[!0-9a-f]*|'') echo 'invalid source SHA' >&2; exit 2 ;;
esac
case "$command" in
  *"'"*) echo 'the desktop-ci command may not hold a single quote' >&2; exit 2 ;;
esac

umask 077
key="$RUNNER_TEMP/desktop_ci_key"
known_hosts="$RUNNER_TEMP/desktop_ci_known_hosts"
trap 'rm -f "$key" "$known_hosts"' EXIT
printf '%s' "${DESKTOP_CI_SSH_KEY:?the runner has no DESKTOP_CI_SSH_KEY}" > "$key"
printf '%s\n' "${DESKTOP_CI_KNOWN_HOSTS:?set the DESKTOP_CI_KNOWN_HOSTS variable to the desktop-ci host keys}" > "$known_hosts"

drop='unset GH_TOKEN && '
if [ "$platform" = windows ]; then
  drop='set GH_TOKEN=&& '
fi
command="git fetch -q --depth 1 origin $SOURCE_SHA && git checkout -q --detach $SOURCE_SHA && $drop$command"
remote="sudo -n desktop-ci $platform --repo '$SERVER_URL/$REPOSITORY' --ref '$REF' --cmd '$command' --build-timeout '$build_timeout' --env-stdin"
guest_env="GH_TOKEN=$REPO_TOKEN"$'\n'"GITHUB_API_TOKEN="

# Exit status 3 and 255 mean the VM or the SSH session failed before the
# command ran, so the run tries once more.
attempt=1
while true; do
  ssh -i "$key" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" \
      -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=8 \
      "$host" "$remote" <<<"$guest_env"
  status=$?
  if { [ "$status" -ne 3 ] && [ "$status" -ne 255 ]; } || [ "$attempt" -ge 2 ]; then
    exit "$status"
  fi
  echo "desktop-ci infrastructure setup failed. Retrying once."
  attempt=$((attempt + 1))
done
