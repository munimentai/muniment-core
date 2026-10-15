#!/usr/bin/env bash
# Run a runtime image once: it turns healthy, answers its own health check,
# stops cleanly on SIGTERM and starts again on the same volume.
# Usage: deploy/runtime/smoke.sh <image>
set -euo pipefail

image=$1
name="muniment-runtime-smoke-$$"
volume="$name-data"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker volume rm "$volume" >/dev/null 2>&1 || true' EXIT

wait_healthy() {
  for _ in $(seq 120); do
    case "$(docker inspect --format '{{.State.Health.Status}}' "$name")" in
      healthy) return 0 ;;
      unhealthy) break ;;
    esac
    sleep 1
  done
  docker logs "$name" >&2
  echo "The runtime did not turn healthy." >&2
  return 1
}

for start in first second; do
  docker run -d --name "$name" -v "$volume:/data" \
    --health-interval 2s --health-start-period 60s "$image" >/dev/null
  wait_healthy
  docker exec "$name" muniment-server health
  docker exec "$name" pi --version
  docker stop --time 30 "$name" >/dev/null
  status=$(docker inspect --format '{{.State.ExitCode}}' "$name")
  docker logs "$name" 2>&1 | grep -q 'muniment-server: stopped' || {
    docker logs "$name" >&2
    echo "The $start start did not stop cleanly." >&2
    exit 1
  }
  [ "$status" = 0 ] || { echo "The $start start exited $status." >&2; exit 1; }
  docker rm "$name" >/dev/null
done
echo "The runtime image served, stopped cleanly and restarted on its volume."
