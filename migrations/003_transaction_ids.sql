-- Transaction ID deduplication for PUT /send and PUT /sendToDevice.
-- Prevents duplicate events if a client retries after a network failure.
CREATE TABLE transaction_ids (
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    txn_id    TEXT NOT NULL,
    event_id  TEXT,                    -- the event that was created
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id, txn_id)
);

-- Auto-expire after 24 hours via a cleanup job (or pg_cron if available).
-- For now we index by created_at so we can clean up periodically.
CREATE INDEX idx_txn_created ON transaction_ids(created_at);
