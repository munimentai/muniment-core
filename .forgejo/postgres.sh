#!/usr/bin/env bash
# Start a throwaway PostgreSQL 17 server for the router tests and print its
# URL, or stop it.
# Usage: .forgejo/postgres.sh start|stop
#
# Jobs run in host mode, where `services:` does not work. initdb and the server
# run as the postgres user, which cannot reach RUNNER_TEMP under /root, so the
# data directory lives under /tmp. Each runner container has its own network
# namespace, so the fixed port never collides with another runner.
set -euo pipefail

bin=/usr/lib/postgresql/17/bin
dir=/tmp/muniment-core-postgres
port=54329

stop() {
  if [ -d "$dir/data" ]; then
    runuser -u postgres -- "$bin/pg_ctl" -D "$dir/data" -m fast -w stop >/dev/null 2>&1 || true
  fi
  rm -rf "$dir"
}

case "${1:-}" in
  start)
    stop
    mkdir -p "$dir"
    chown postgres:postgres "$dir"
    runuser -u postgres -- "$bin/initdb" -D "$dir/data" -U postgres --auth=trust >/dev/null
    runuser -u postgres -- "$bin/pg_ctl" -D "$dir/data" -l "$dir/server.log" \
      -o "-p $port -k $dir -c listen_addresses=127.0.0.1" -w start >/dev/null
    runuser -u postgres -- "$bin/createdb" -h 127.0.0.1 -p "$port" -U postgres router
    echo "postgres://postgres:postgres@127.0.0.1:$port/router"
    ;;
  stop)
    stop
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac
