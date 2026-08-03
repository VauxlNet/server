#!/usr/bin/env bash
set -euo pipefail

# Konfiguration
BASE_URL="${BASE_URL:-http://localhost:8008}"
ROOM_ID="${ROOM_ID:-!db0db72633f44a37:localhost}"
: "${TOKEN:?Set TOKEN to a valid development access token}"

echo "--- Starte API-Integritätsprüfung ---"
# 1. Test: Öffentliche Endpunkte (Erwartung: 200 OK)
echo -e "\n[Prüfe öffentliche Endpunkte]"
for path in "/_matrix/client/versions" "/_matrix/client/v3/capabilities"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$path")
    echo "$code  $path"
done

# 2. Test: Filter-Endpunkt (Muss POST sein!)
echo -e "\n[Prüfe Filter-Endpunkt]"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/_matrix/client/v3/user/alice/filter" \
    -d '{"room":{"timeline":{"limit":20}}}')
echo "$code  /_matrix/client/v3/user/alice/filter (POST)"

# 3. Test: Room-Send Endpunkt (Hier kam das 403)
echo -e "\n[Prüfe Room-Send Endpunkt]"
code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "$BASE_URL/_matrix/client/v3/rooms/$ROOM_ID/send/m.room.message/test_txn_$(date +%s)" \
    -d '{"msgtype":"m.text","body":"test"}' \
    -w " - Response: %{http_code}")
echo "$code"

echo -e "\n--- Test beendet. Prüfe Server-Logs auf '403 Forbidden' Fehlerdetails. ---"
