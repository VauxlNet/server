#!/bin/bash

# Konfiguration
HOMESERVER="http://localhost:8008"
USER="@alice:localhost"
PASS="correcthorsebattery"

echo "--- Logge Benutzer $USER ein ---"

# Matrix Login-Request
RESPONSE=$(curl -s -X POST "$HOMESERVER/_matrix/client/v3/login" \
    -H "Content-Type: application/json" \
    -d "{
        \"type\": \"m.login.password\",
        \"identifier\": { \"type\": \"m.id.user\", \"user\": \"$USER\" },
        \"password\": \"$PASS\"
    }")

# Extrahiere den Access Token mit jq (falls installiert) oder einfach als String
TOKEN=$(echo $RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

if [ "$TOKEN" == "null" ]; then
    echo "Login fehlgeschlagen! Antwort:"
    echo $RESPONSE | python3 -m json.tool
else
    echo "Login erfolgreich!"
    echo "Neuer Token: $TOKEN"
    export TOKEN=$TOKEN
    # Optional: Speichere den Token für andere Skripte
    echo "TOKEN=$TOKEN" > .current_token
fi
