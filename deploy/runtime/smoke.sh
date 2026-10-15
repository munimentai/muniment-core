#!/usr/bin/env bash
# Run a runtime image once: it turns healthy, answers its own health check,
# pairs a remote client that reconnects, stops cleanly on SIGTERM and starts
# again on the same volume, where the paired client reconnects until the
# device is revoked.
# Usage: deploy/runtime/smoke.sh <image>
set -euo pipefail

image=$1
name="muniment-runtime-smoke-$$"
volume="$name-data"
client_image="$name-client"
client_volume="$name-client"
context=$(cd "$(dirname "$0")/../.." && pwd)
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" "$client_volume" >/dev/null 2>&1 || true
  docker image rm "$client_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The client shares the runtime's network namespace, so the link names
# loopback.
docker build -q -f "$context/deploy/runtime/Containerfile" --target remote-smoke \
  -t "$client_image" "$context" >/dev/null
client() {
  docker run --rm --network "container:$name" -v "$client_volume:/client" "$client_image" "$@"
}

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

device=
for start in first second; do
  docker run -d --name "$name" -v "$volume:/data" \
    -e MUNIMENT_REMOTE_ENDPOINTS=127.0.0.1:7443 \
    --health-interval 2s --health-start-period 60s "$image" >/dev/null
  wait_healthy
  docker exec "$name" muniment-server health
  docker exec "$name" pi --version
  docker exec "$name" muniment-server info | grep -qx 'install_kind=container'
  if [ "$start" = first ]; then
    link=$(docker exec "$name" muniment-server pair)
    paired=$(client "$link" --record /client/runtime.json)
    device=$(printf '%s\n' "$paired" | sed -n 's/^paired device_id=\([^ ]*\).*/\1/p')
    [ -n "$device" ] || { echo "The client did not pair: $paired" >&2; exit 1; }
    if client "$link" --record /client/second.json >/dev/null 2>&1; then
      echo "A pairing link worked twice." >&2
      exit 1
    fi
  else
    client /client/runtime.json >/dev/null
    docker exec "$name" muniment-server devices | grep -q "^$device "
    docker exec "$name" muniment-server revoke "$device" >/dev/null
    if client /client/runtime.json >/dev/null 2>&1; then
      echo "A revoked device reconnected." >&2
      exit 1
    fi
  fi
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
echo "The runtime image served, paired a remote client, stopped cleanly, restarted on its volume and refused the revoked device."
