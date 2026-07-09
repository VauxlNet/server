#!/usr/bin/env bash
set -euo pipefail

BASE="http://localhost:8008"
PASS="correcthorsebattery"

echo "── Register alice and bob ──────────────────────────────────"
curl -sf -X POST "$BASE/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"'"$PASS"'","auth":{"type":"m.login.dummy","session":"a1"}}' \
  > /dev/null 2>&1 || echo "alice already exists"

curl -sf -X POST "$BASE/_matrix/client/v3/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"'"$PASS"'","auth":{"type":"m.login.dummy","session":"b1"}}' \
  > /dev/null 2>&1 || echo "bob already exists"

echo "── Login both users ────────────────────────────────────────"
TOKEN_A=$(curl -sf -X POST "$BASE/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"'"$PASS"'"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['access_token'])")

DEVICE_A=$(curl -sf -X POST "$BASE/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"'"$PASS"'"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['device_id'])")

TOKEN_B=$(curl -sf -X POST "$BASE/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"bob"},"password":"'"$PASS"'"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['access_token'])")

DEVICE_B=$(curl -sf -X POST "$BASE/_matrix/client/v3/login" \
  -H "Content-Type: application/json" \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"bob"},"password":"'"$PASS"'"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['device_id'])")

echo "  Alice: device=$DEVICE_A"
echo "  Bob:   device=$DEVICE_B"

echo "── Upload device keys ──────────────────────────────────────"
curl -sf -X POST "$BASE/_matrix/client/v3/keys/upload" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{
    \"device_keys\": {
      \"user_id\":    \"@alice:localhost\",
      \"device_id\":  \"$DEVICE_A\",
      \"algorithms\": [\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],
      \"keys\": {
        \"curve25519:$DEVICE_A\": \"alice_curve25519_pubkey_base64==\",
        \"ed25519:$DEVICE_A\":    \"alice_ed25519_pubkey_base64==\"
      },
      \"signatures\": {}
    },
    \"one_time_keys\": {
      \"signed_curve25519:ALICE01\": {\"key\": \"alice_otk_1==\", \"signatures\": {}},
      \"signed_curve25519:ALICE02\": {\"key\": \"alice_otk_2==\", \"signatures\": {}}
    }
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Alice OTK count:', d['one_time_key_counts'])"

curl -sf -X POST "$BASE/_matrix/client/v3/keys/upload" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d "{
    \"device_keys\": {
      \"user_id\":    \"@bob:localhost\",
      \"device_id\":  \"$DEVICE_B\",
      \"algorithms\": [\"m.olm.v1.curve25519-aes-sha2\",\"m.megolm.v1.aes-sha2\"],
      \"keys\": {
        \"curve25519:$DEVICE_B\": \"bob_curve25519_pubkey_base64==\",
        \"ed25519:$DEVICE_B\":    \"bob_ed25519_pubkey_base64==\"
      },
      \"signatures\": {}
    },
    \"one_time_keys\": {
      \"signed_curve25519:BOB01\": {\"key\": \"bob_otk_1==\", \"signatures\": {}},
      \"signed_curve25519:BOB02\": {\"key\": \"bob_otk_2==\", \"signatures\": {}}
    }
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Bob OTK count:', d['one_time_key_counts'])"

echo "── Alice creates E2EE room and invites Bob ─────────────────"
ROOM=$(curl -sf -X POST "$BASE/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{
    "name":   "E2EE Test Room",
    "preset": "private_chat",
    "invite": ["@bob:localhost"],
    "initial_state": [{
      "type":    "m.room.encryption",
      "content": {"algorithm": "m.megolm.v1.aes-sha2"}
    }]
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['room_id'])")
echo "  Room: $ROOM"

echo "── Query keys before Olm session setup ─────────────────────"
curl -sf -X POST "$BASE/_matrix/client/v3/keys/query" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"device_keys": {"@bob:localhost": []}}' \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
devices = d.get('device_keys', {}).get('@bob:localhost', {})
print(f'  Bob has {len(devices)} device(s) with keys')
for dev_id, keys in devices.items():
    algos = keys.get('algorithms', [])
    print(f'  Device {dev_id}: algorithms={algos}')
"

echo "── Alice claims Bob OTK for Olm setup ──────────────────────"
curl -sf -X POST "$BASE/_matrix/client/v3/keys/claim" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"one_time_keys\": {\"@bob:localhost\": {\"$DEVICE_B\": \"signed_curve25519\"}}}" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
otks = d.get('one_time_keys', {}).get('@bob:localhost', {})
print(f'  Claimed OTK for {len(otks)} device(s):', list(otks.keys()))
"

echo "── Alice sends Olm pre-key to Bob via to-device ────────────"
curl -sf -X PUT \
  "$BASE/_matrix/client/v3/sendToDevice/m.room.key/olm_txn_001" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{
    \"messages\": {
      \"@bob:localhost\": {
        \"$DEVICE_B\": {
          \"algorithm\":   \"m.megolm.v1.aes-sha2\",
          \"room_id\":     \"$ROOM\",
          \"session_id\":  \"fake_session_id_abc123\",
          \"session_key\": \"fake_megolm_session_key_data\"
        }
      }
    }
  }" > /dev/null
echo "  ✓ Room key sent to Bob"

echo "── Bob joins the room ──────────────────────────────────────"
curl -sf -X POST "$BASE/_matrix/client/v3/rooms/$ROOM/join" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{}' > /dev/null
echo "  ✓ Bob joined"

echo "── Bob syncs — should receive to-device room key ───────────"
BOB_SYNC=$(curl -sf "$BASE/_matrix/client/v3/sync" \
  -H "Authorization: Bearer $TOKEN_B")

echo "$BOB_SYNC" | python3 -c "
import sys, json
d = json.load(sys.stdin)
td = d.get('to_device', {}).get('events', [])
print(f'  to_device events: {len(td)}')
for e in td:
    print(f'  type={e[\"type\"]} session_id={e[\"content\"].get(\"session_id\",\"?\")}')
rooms = d.get('rooms', {}).get('invite', {})
print(f'  Pending invites: {len(rooms)}')
"

echo "── Alice sends encrypted message ───────────────────────────"
MSG_RESP=$(curl -sf -X PUT \
  "$BASE/_matrix/client/v3/rooms/$ROOM/send/m.room.encrypted/txn_enc_001" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm":  "m.megolm.v1.aes-sha2",
    "sender_key": "alice_curve25519_pubkey_base64==",
    "ciphertext": "FAKE_ENCRYPTED_CIPHERTEXT_FOR_TESTING",
    "session_id": "fake_session_id_abc123",
    "device_id":  "'"$DEVICE_A"'"
  }')
EVENT_ID=$(echo "$MSG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['event_id'])")
echo "  ✓ Encrypted message sent: $EVENT_ID"

echo "── Bob syncs and receives the message ──────────────────────"
curl -sf "$BASE/_matrix/client/v3/sync" \
  -H "Authorization: Bearer $TOKEN_B" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
joined = d.get('rooms', {}).get('join', {})
for room_id, room in joined.items():
    events = room.get('timeline', {}).get('events', [])
    enc = [e for e in events if e.get('type') == 'm.room.encrypted']
    print(f'  Room {room_id}: {len(events)} events, {len(enc)} encrypted')
    for e in enc:
        print(f'    event_id={e[\"event_id\"]}')
        print(f'    signatures present: {\"signatures\" in e}')
        print(f'    signed by server: {\"localhost\" in e.get(\"signatures\", {})}')
"

echo "── GET /messages — paginated history ───────────────────────"
curl -sf "$BASE/_matrix/client/v3/rooms/$ROOM/messages?dir=b&limit=10" \
  -H "Authorization: Bearer $TOKEN_A" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Events in history: {len(d[\"chunk\"])}')
for e in d['chunk']:
    signed = 'localhost' in e.get('signatures', {})
    print(f'  {e[\"type\"]:30s} signed={signed} id={e[\"event_id\"][:20]}...')
"

echo ""
echo "════════════════════════════════════════"
echo "  M2 Integration Test Complete"
echo "  All endpoints responding correctly."
echo "  Next: P1-010 federation gate test"
echo "════════════════════════════════════════"
