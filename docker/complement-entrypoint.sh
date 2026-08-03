#!/bin/sh
set -eu

export VAUXL_SERVER__SERVER_NAME="${SERVER_NAME:-localhost}"
export VAUXL_SERVER__LISTEN_ADDRESS=0.0.0.0
export VAUXL_SERVER__PORT=8008

exec /app/vauxl-server "$@"
