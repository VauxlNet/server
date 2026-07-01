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

CONTAINER="docker-db-1"
DB_USER="vauxl"
DB_NAME="vauxl"
MIGRATIONS_DIR="$(dirname "$0")/../migrations"

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
