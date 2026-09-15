#!/usr/bin/env bash
# Exercise the built homeserver through the public Matrix discovery and
# federation endpoints. This is intentionally local and deterministic so the
# workflow does not depend on an unavailable third-party action.

set -Eeuo pipefail

BINARY="${1:-target/release/vauxl-server}"
BASE_URL="${BASE_URL:-http://127.0.0.1:8008}"
LOG_FILE="${SYTEST_LOG:-sytest-server.log}"

if [[ ! -x "$BINARY" ]]; then
  echo "Server binary not found or not executable: $BINARY" >&2
  exit 1
fi

mkdir -p data
"$BINARY" >"$LOG_FILE" 2>&1 &
server_pid=$!

cleanup() {
  status=$?
  if kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if ((status != 0)); then
    echo "Homeserver smoke check failed. Recent server log:" >&2
    tail -n 80 "$LOG_FILE" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT

wait_for_health() {
  for _ in {1..60}; do
    if [[ "$(curl --silent --show-error --max-time 2 "$BASE_URL/_vauxl/health" 2>/dev/null || true)" == "ok" ]]; then
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      return 1
    fi
    sleep 1
  done
  return 1
}

echo "Waiting for the homeserver to become ready"
wait_for_health
echo "PASS health endpoint"

health="$(curl --fail --silent --show-error "$BASE_URL/_vauxl/health")"
[[ "$health" == "ok" ]]

versions="$(curl --fail --silent --show-error "$BASE_URL/_matrix/client/versions")"
python3 -c '
import json, sys
versions = json.load(sys.stdin).get("versions", [])
required = {"v1.1", "v1.6"}
missing = required.difference(versions)
if missing:
    raise SystemExit(f"missing client API versions: {sorted(missing)}")
' <<<"$versions"
echo "PASS client versions"

client_well_known="$(curl --fail --silent --show-error "$BASE_URL/.well-known/matrix/client")"
python3 -c '
import json, sys
base_url = json.load(sys.stdin).get("m.homeserver", {}).get("base_url", "")
if not base_url.startswith(("http://", "https://")):
    raise SystemExit("m.homeserver.base_url is missing or invalid")
' <<<"$client_well_known"
echo "PASS client well-known"

server_well_known="$(curl --fail --silent --show-error "$BASE_URL/.well-known/matrix/server")"
python3 -c '
import json, sys
server = json.load(sys.stdin).get("m.server", "")
if not server or ":" not in server:
    raise SystemExit("m.server is missing a host and port")
' <<<"$server_well_known"
echo "PASS server well-known"

keys="$(curl --fail --silent --show-error "$BASE_URL/_matrix/key/v2/server")"
python3 -c '
import json, sys, time
data = json.load(sys.stdin)
if not data.get("server_name"):
    raise SystemExit("key response has no server_name")
if not data.get("verify_keys"):
    raise SystemExit("key response has no verify_keys")
if data.get("valid_until_ts", 0) <= int(time.time() * 1000):
    raise SystemExit("key response is already expired")
' <<<"$keys"
echo "PASS federation keys"

federation_version="$(curl --fail --silent --show-error "$BASE_URL/_matrix/federation/v1/version")"
python3 -c '
import json, sys
server = json.load(sys.stdin).get("server", {})
if not server.get("name") or not server.get("version"):
    raise SystemExit("federation version response is incomplete")
' <<<"$federation_version"
echo "PASS federation version"

echo "Matrix smoke checks completed successfully"
