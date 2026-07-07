-- Track per-device one-time key counts for /keys/upload response.
-- The server tells the client how many OTKs remain so it knows when to replenish.
CREATE TABLE IF NOT EXISTS device_otk_counts (
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,   -- e.g. "signed_curve25519"
    count     INT  NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, device_id, algorithm),
    FOREIGN KEY (user_id, device_id)
        REFERENCES devices(user_id, device_id) ON DELETE CASCADE
);
