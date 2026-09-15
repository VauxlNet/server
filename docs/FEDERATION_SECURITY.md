# Federation security and supported behavior

The server implements an experimental subset of Matrix room version 11. The
security checks below do not establish complete Matrix interoperability.

## Authentication and authorization

Protected federation routes verify Ed25519 request signatures against the HTTP
method, original encoded path and query, origin, destination, and canonical JSON
content. A well-formed `X-Matrix` header alone grants no access.

Remote signing keys must come from HTTPS discovery and a matching, unexpired,
self-signed key document. Redis caches the complete document and revalidates its
identity, signature, and expiry on reads. Rotation to a new key triggers a fresh
fetch. Retired keys can verify events only before their recorded expiry; they
cannot authenticate live requests. Key discovery restricts destinations to
public addresses, pins DNS results, rejects redirects, and bounds response sizes.
Private-network federation and SRV discovery are currently unsupported.

Room access requires a participating server and respects `m.federate` and
`m.room.server_acl`. Incoming events additionally require valid sender signatures,
content hashes, reference IDs, and room authorization. Relay servers and event
senders are both subject to room ACLs.

Local and federated state, membership, and message writes check permissions and
persist under one room transaction lock. Generic state endpoints cannot bypass
membership or power-level rules. Message retries are scoped to the user, device,
room, event type, and endpoint, and return the original persisted event ID.
Rejected authorization or invalid event content leaves no transaction marker.

## History and unsupported operations

Historical messages are filtered using membership and visibility at the accepted
event's position, including invitations, leave/rejoin gaps, and policy changes.
This applies to client `/messages`, sync timelines, federation backfill, and
individual event reads. Current state snapshots remain available to authorized
members and joining servers.

Only events extending the known linear predecessor and current authorization
state are accepted. Outbound remote room bootstrap, historical state
reconstruction, stale or forked histories, and unsupported membership proofs are
rejected. Complete auth-chain validation and state resolution remain follow-up
work. Redacted events with mismatching content hashes are also rejected rather
than imported.

**Existing data:** historical reads require a continuous, verifiable v11
depth/predecessor sequence. Older stored events without this ordering cause
history reads for that room to be denied. Records are retained. A trusted rebuild
or migration is required before serving such history; there is no automatic
conversion that assumes old membership or ordering was trustworthy.
Sync omits only that room's timeline and marks it limited, while continuing to
deliver authorized current state, other rooms, and queued device messages.

History checks scan event-order and authorization metadata, without loading every
message body. This is linear in room history size. Existing timestamp-based sync
and pagination behavior remains limited and is not a new conformance guarantee.
Backfill remains a bounded recent-history subset.

## Local validation

On Debian/Ubuntu, install Rust stable plus `pkg-config`, `libssl-dev`, and
`postgresql-client`. Use isolated PostgreSQL and Redis services. SQLx tests create
temporary databases, so the test database role must have `CREATEDB` permission.

```bash
export DATABASE_URL='postgres://vauxl:vauxl@127.0.0.1:55432/vauxl_pr2?sslmode=disable'
export REDIS_URL='redis://127.0.0.1:56379'
export SQLX_OFFLINE=true
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

The HTTP security regression tests use the production Axum router with real
PostgreSQL and Redis. A second server identity publishes its own signed key
document, which the fixture pins in isolated Redis. Tests cover accepted joins
and PDUs, tampered requests/events, expired cached keys, room permissions, retry
atomicity, ACLs, and historical visibility. This fixture does not establish public
TLS discovery or interoperability with an independent homeserver implementation.
The discovery smoke script is an additional startup check, not a conformance suite.
