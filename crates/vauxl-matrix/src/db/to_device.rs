//! Database queries for to-device message delivery.
//!
//! To-device messages are direct device-to-device messages that never
//! appear in a room timeline. Used for:
//! - Olm pre-key messages (E2EE session setup)
//! - Megolm room key shares
//! - Verification requests (cross-signing)

use serde_json::Value;
use sqlx::PgPool;

use crate::error::MatrixError;

/// Stores to-device messages for delivery on the recipient's next /sync.
/// One row per target device.
pub async fn store_to_device_messages(
    pool: &PgPool,
    event_type: &str,
    messages: &[(String, String, Value)], // (user_id, device_id, content)
) -> Result<(), MatrixError> {
    for (user_id, device_id, content) in messages {
        if device_id == "*" {
            // Wildcard — deliver to all devices for this user
            sqlx::query!(
                r#"
                INSERT INTO to_device_messages (user_id, device_id, event_type, content)
                SELECT $1, device_id, $2, $3
                FROM   devices
                WHERE  user_id = $1
                "#,
                user_id,
                event_type,
                content,
            )
            .execute(pool)
            .await?;
        } else {
            sqlx::query!(
                r#"
                INSERT INTO to_device_messages
                    (user_id, device_id, event_type, content)
                VALUES ($1, $2, $3, $4)
                "#,
                user_id,
                device_id,
                event_type,
                content,
            )
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Returns all pending to-device messages for a user and marks them delivered.
/// Called by /sync — returns messages then deletes them atomically.
pub async fn pop_to_device_messages(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
) -> Result<Vec<Value>, MatrixError> {
    // Fetch pending messages for this specific device
    let rows = sqlx::query!(
        r#"
        DELETE FROM to_device_messages
        WHERE id IN (
            SELECT id FROM to_device_messages
            WHERE  user_id   = $1
            AND    device_id = $2
            ORDER  BY id ASC
            LIMIT  100
        )
        RETURNING event_type, content
        "#,
        user_id,
        device_id,
    )
    .fetch_all(pool)
    .await?;

    let events = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "type":    r.event_type,
                "content": r.content,
                "sender":  user_id,   // approximation — sender stored in content for Olm
            })
        })
        .collect();

    Ok(events)
}

/// Checks and records a transaction ID to prevent duplicate event sends.
/// Returns true if this txn_id is new (should process), false if duplicate.
pub async fn check_and_store_txn(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
    txn_id: &str,
) -> Result<bool, MatrixError> {
    // Store txn with 24h expiry using a dedicated table
    let result = sqlx::query!(
        r#"
        INSERT INTO transaction_ids (user_id, device_id, txn_id, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_id, device_id, txn_id) DO NOTHING
        "#,
        user_id,
        device_id,
        txn_id,
    )
    .execute(pool)
    .await?;

    // rows_affected = 0 means it already existed → duplicate
    Ok(result.rows_affected() > 0)
}
