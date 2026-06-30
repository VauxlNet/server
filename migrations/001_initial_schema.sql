-- Users and devices
CREATE TABLE users (
    user_id     TEXT PRIMARY KEY,
    display_name TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE devices (
    user_id     TEXT REFERENCES users(user_id),
    device_id   TEXT NOT NULL,
    display_name TEXT,
    keys_json   JSONB NOT NULL DEFAULT '{}',
    last_seen   TIMESTAMPTZ,
    PRIMARY KEY (user_id, device_id)
);

-- Rooms and events
CREATE TABLE rooms (
    room_id     TEXT PRIMARY KEY,
    version     TEXT NOT NULL DEFAULT '11',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE events (
    event_id    TEXT PRIMARY KEY,
    room_id     TEXT REFERENCES rooms(room_id),
    event_type  TEXT NOT NULL,
    sender      TEXT NOT NULL,
    origin_ts   BIGINT NOT NULL,
    content     JSONB NOT NULL,
    unsigned    JSONB,
    raw_event   JSONB NOT NULL
);
CREATE INDEX ON events(room_id, origin_ts DESC);
