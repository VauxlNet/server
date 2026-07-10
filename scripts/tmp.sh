#!/bin/bash

# Pfade zu den Tools (falls curl/python3 im PATH nicht gefunden werden)
CURL="/usr/bin/curl"
PYTHON="/usr/bin/python3"
JQ="/usr/bin/jq" # Falls vorhanden, besser als Python

echo "--- Starte Überprüfung der Endpunkte ---"

echo -e "\n[Öffentliche Discovery-Endpunkte]"
for path in \
  "/_matrix/client/versions" \
  "/_matrix/client/v3/capabilities" \
  "/_matrix/client/v3/publicRooms" \
  "/.well-known/matrix/client"; do
  code=$($CURL -s -o /dev/null -w "%{http_code}" "http://localhost:8008$path")
  echo "$code  $path"
done

echo -e "\n[Login & Private Endpunkte]"
# Token abrufen
TOKEN=$($CURL -s -X POST http://localhost:8008/_matrix/client/v3/login \
  -H "Content-Type: application/json" \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"correcthorsebattery"}' \
  | $PYTHON -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

if [ "$TOKEN" == "null" ]; then
    echo "Fehler: Login konnte kein Token abrufen."
    exit 1
fi

for path in \
  "/_matrix/client/v3/pushrules/" \
  "/_matrix/client/v3/capabilities" \
  "/_matrix/client/v3/account/whoami" \
  "/_matrix/client/v3/user/%40alice%3Alocalhost/filter" \
  "/_matrix/client/v3/thirdparty/protocols"; do
  code=$($CURL -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "http://localhost:8008$path")
  echo "$code  $path"
done
