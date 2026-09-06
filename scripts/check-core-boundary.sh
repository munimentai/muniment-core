#!/usr/bin/env bash
# Check the inventory, named exceptions, dependency trees, and port tests.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -B scripts/check-core-boundary.py "$@"
