-- Read receipts per room
CREATE TABLE read_receipts (
    room_id     TEXT    NOT NULL,
    user_id     TEXT    NOT NULL,
    event_id    TEXT    NOT NULL,
    receipt_type TEXT   NOT NULL DEFAULT 'm.read',  -- m.read or m.read.private
    ts          BIGINT  NOT NULL,
    PRIMARY KEY (room_id, user_id, receipt_type)
);
CREATE INDEX idx_receipts_room ON read_receipts(room_id);

-- Room aliases
CREATE TABLE room_aliases (
    alias    TEXT PRIMARY KEY,   -- #alias:server.tld
    room_id  TEXT NOT NULL REFERENCES rooms(room_id),
    creator  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_aliases_room ON room_aliases(room_id);

-- Media uploads
CREATE TABLE media (
    media_id     TEXT PRIMARY KEY,
    server_name  TEXT NOT NULL,
    uploader_id  TEXT NOT NULL,
    content_type TEXT NOT NULL,
    file_size    BIGINT NOT NULL,
    filename     TEXT,
    storage_path TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
