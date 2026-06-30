-- ============================================================
-- Migration 001: Initial schema
-- Vauxl Matrix Homeserver
-- ============================================================

-- Users
CREATE TABLE users (
    user_id      TEXT PRIMARY KEY,          -- @user:homeserver.tld
    display_name TEXT,
    password_hash TEXT,                     -- Argon2id, NULL wenn WebAuthn-only
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated  BOOLEAN NOT NULL DEFAULT FALSE
);

-- Devices (ein User kann mehrere Geräte haben)
CREATE TABLE devices (
    user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    display_name TEXT,
    -- keys_json enthält: ed25519, curve25519, und org.vauxl.capability (Kyber)
    keys_json    JSONB NOT NULL DEFAULT '{}',
    -- One-time prekeys werden separat verwaltet (siehe tabelle unten)
    last_seen    TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

-- One-time prekeys für Olm-Session-Setup (jeder Key kann nur einmal claimed werden)
CREATE TABLE one_time_keys (
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    key_json    JSONB NOT NULL,
    claimed     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id, key_id),
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
);

-- Rooms
CREATE TABLE rooms (
    room_id     TEXT PRIMARY KEY,           -- !randomid:homeserver.tld
    version     TEXT NOT NULL DEFAULT '11', -- Matrix room version
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Events (append-only — nie löschen, nie updaten)
CREATE TABLE events (
    event_id    TEXT PRIMARY KEY,
    room_id     TEXT NOT NULL REFERENCES rooms(room_id),
    event_type  TEXT NOT NULL,
    state_key   TEXT,                       -- NULL für Message-Events
    sender      TEXT NOT NULL,
    origin_ts   BIGINT NOT NULL,
    content     JSONB NOT NULL,
    unsigned    JSONB,
    raw_event   JSONB NOT NULL              -- vollständiges signiertes Event-JSON
);

CREATE INDEX idx_events_room_ts   ON events(room_id, origin_ts DESC);
CREATE INDEX idx_events_type      ON events(room_id, event_type);
CREATE INDEX idx_events_state     ON events(room_id, event_type, state_key)
    WHERE state_key IS NOT NULL;

-- Current room state (schnelle Lookups ohne DAG-Traversal)
CREATE TABLE room_state (
    room_id     TEXT NOT NULL REFERENCES rooms(room_id),
    event_type  TEXT NOT NULL,
    state_key   TEXT NOT NULL,
    event_id    TEXT NOT NULL REFERENCES events(event_id),
    PRIMARY KEY (room_id, event_type, state_key)
);

-- Room membership (denormalisiert für schnelle Sync-Queries)
CREATE TABLE room_members (
    room_id     TEXT NOT NULL REFERENCES rooms(room_id),
    user_id     TEXT NOT NULL,
    membership  TEXT NOT NULL,              -- join | invite | leave | ban
    PRIMARY KEY (room_id, user_id)
);

CREATE INDEX idx_room_members_user ON room_members(user_id, membership);

-- To-Device-Messages (Olm Pre-Key Messages, Megolm Room Key Shares)
CREATE TABLE to_device_messages (
    id          BIGSERIAL PRIMARY KEY,
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    content     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_to_device ON to_device_messages(user_id, device_id, id);

-- Access Tokens (in Redis gespiegelt für schnelle Lookups, hier als Backup)
CREATE TABLE access_tokens (
    token_hash  TEXT PRIMARY KEY,           -- SHA-256 des Tokens
    user_id     TEXT NOT NULL REFERENCES users(user_id),
    device_id   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used   TIMESTAMPTZ
);

-- Audit Log (append-only, für DSGVO-Compliance)
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     TEXT,                       -- NULL für System-Events
    event_type  TEXT NOT NULL,              -- z.B. "user.login", "user.deactivate"
    ip_address  INET,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_type ON audit_log(event_type, created_at DESC);
