#!/usr/bin/env bash
# Reject private-network hosts in tracked files: the RFC 1918 ranges written
# as dotted quads, and names under the internal domain.
# Usage: check-private-addresses.sh [root]
set -euo pipefail

root="${1:-$(dirname "$0")/..}"

octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
tail3="\\.${octet}\\.${octet}\\.${octet}"
pattern="(^|[^0-9.])(10${tail3}|192\\.168\\.${octet}\\.${octet}|172\\.(1[6-9]|2[0-9]|3[01])\\.${octet}\\.${octet})([^0-9]|\$)"
pattern="${pattern}|[Rr][Oo][Oo]\\.[Rr][Uu][Nn]"

status=0
git -C "$root" grep -nIE -e "$pattern" -- . \
  ':(exclude,glob)third-party/**' \
  ':(exclude,glob)**/Cargo.lock' \
  ':(exclude,glob)**/*.lock' \
  ':(exclude,glob)**/*.lock.*' \
  ':(exclude,glob)**/packages.bun.lock' || status=$?

case "$status" in
  0)
    echo "error: private-network hosts found in tracked files" >&2
    exit 1
    ;;
  1) exit 0 ;;
  *)
    echo "error: git grep failed with status $status" >&2
    exit "$status"
    ;;
esac
