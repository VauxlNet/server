#!/usr/bin/env bash
# =============================================================
# db-init-local.sh — Arch Linux Docker Workaround
#
# Führt Migrations direkt im Container aus, umgeht das
# localhost→container TCP Problem auf Arch/nftables.
#
# Verwendung: ./scripts/db-init-local.sh
# Voraussetzung: docker compose -f docker/compose.dev.yml up -d
# =============================================================

set -euo pipefail

DB_USER="vauxl"
DB_NAME="vauxl"
MIGRATIONS_DIR="$(dirname "$0")/../migrations"

CONTAINER=""
for id in $(docker compose -f "$(dirname "$0")/../docker/compose.dev.yml" ps -q); do
  service="$(docker inspect "$id" --format '{{ index .Config.Labels "com.docker.compose.service" }}')"
  if [[ "$service" == "db" ]]; then
    CONTAINER="$id"
    break
  fi
done
if [[ -z "$CONTAINER" ]]; then
  echo "DB container not found. Start it with: docker compose -f docker/compose.dev.yml up -d db"
  exit 1
fi

echo "→ Warte auf Postgres..."
until docker exec "$CONTAINER" pg_isready -U "$DB_USER" -q; do
  sleep 1
done
echo "✓ Postgres bereit"

# Migrations in aufsteigender Reihenfolge ausführen
for f in $(ls "$MIGRATIONS_DIR"/*.sql | sort); do
  echo "→ Führe aus: $(basename $f)"
  docker exec -i "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$f"
  echo "✓ $(basename $f) fertig"
done

echo ""
echo "✓ Alle Migrations ausgeführt"
echo ""
docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "\dt"
