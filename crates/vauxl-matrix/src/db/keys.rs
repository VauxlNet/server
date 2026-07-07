//! Database queries for device key management.

use serde_json::Value;
use sqlx::PgPool;

use crate::error::MatrixError;

// ── Upload ────────────────────────────────────────────────────────────────

/// Stores or replaces the device keys for a device.
/// The keys_json field on devices holds Ed25519, Curve25519,
/// and our custom org.vauxl.capability + kyber keys.
pub async fn upsert_device_keys(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
    keys: &Value,
) -> Result<(), MatrixError> {
    sqlx::query!(
        r#"
        UPDATE devices
        SET    keys_json = $3
        WHERE  user_id   = $1
        AND    device_id = $2
        "#,
        user_id,
        device_id,
        keys,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Stores one-time prekeys for a device.
/// Each key can only be claimed once (see claim_one_time_key).
pub async fn store_one_time_keys(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
    otks: &Value, // {"signed_curve25519:KEYID": {key, signatures}, ...}
) -> Result<u32, MatrixError> {
    let obj = match otks.as_object() {
        Some(o) => o,
        None => return Ok(0),
    };

    let mut stored = 0u32;

    for (key_id, key_data) in obj {
        // key_id format: "algorithm:id" e.g. "signed_curve25519:ABCDEF"
        let result = sqlx::query!(
            r#"
            INSERT INTO one_time_keys (user_id, device_id, key_id, key_json)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, device_id, key_id) DO NOTHING
            "#,
            user_id,
            device_id,
            key_id,
            key_data,
        )
        .execute(pool)
        .await?;

        stored += result.rows_affected() as u32;
    }

    // Update the OTK count
    update_otk_count(pool, user_id, device_id).await?;

    Ok(stored)
}

/// Returns the current unclaimed OTK count per algorithm for a device.
pub async fn get_otk_counts(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
) -> Result<Value, MatrixError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            split_part(key_id, ':', 1) AS algorithm,
            COUNT(*) AS count
        FROM one_time_keys
        WHERE user_id   = $1
        AND   device_id = $2
        AND   claimed   = FALSE
        GROUP BY split_part(key_id, ':', 1)
        "#,
        user_id,
        device_id,
    )
    .fetch_all(pool)
    .await?;

    let mut map = serde_json::Map::new();
    for row in rows {
        if let (Some(algo), Some(count)) = (row.algorithm, row.count) {
            map.insert(algo, Value::Number(count.into()));
        }
    }
    Ok(Value::Object(map))
}

async fn update_otk_count(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
) -> Result<(), MatrixError> {
    // Recount and upsert into device_otk_counts
    sqlx::query!(
        r#"
        INSERT INTO device_otk_counts (user_id, device_id, algorithm, count)
        SELECT
            $1, $2,
            split_part(key_id, ':', 1),
            COUNT(*)::int
        FROM one_time_keys
        WHERE user_id   = $1
        AND   device_id = $2
        AND   claimed   = FALSE
        GROUP BY split_part(key_id, ':', 1)
        ON CONFLICT (user_id, device_id, algorithm)
        DO UPDATE SET count = EXCLUDED.count
        "#,
        user_id,
        device_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ── Query ─────────────────────────────────────────────────────────────────

/// Returns device keys for a list of users.
/// If device_ids is empty for a user, returns keys for all their devices.
pub async fn query_device_keys(pool: &PgPool, user_id: &str) -> Result<Value, MatrixError> {
    let rows = sqlx::query!(
        r#"
        SELECT device_id, keys_json
        FROM   devices
        WHERE  user_id = $1
        AND    keys_json != '{}'::jsonb
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await?;

    let mut device_map = serde_json::Map::new();
    for row in rows {
        device_map.insert(row.device_id, row.keys_json);
    }
    Ok(Value::Object(device_map))
}

// ── Claim ─────────────────────────────────────────────────────────────────

/// Claims one one-time key per device for each requested algorithm.
/// Marks claimed keys so they are never returned again.
pub async fn claim_one_time_key(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
    algorithm: &str,
) -> Result<Option<(String, Value)>, MatrixError> {
    // Find and claim in a single atomic operation using FOR UPDATE SKIP LOCKED
    let row = sqlx::query!(
        r#"
        UPDATE one_time_keys
        SET    claimed = TRUE
        WHERE  ctid = (
            SELECT ctid FROM one_time_keys
            WHERE  user_id   = $1
            AND    device_id = $2
            AND    key_id LIKE $3
            AND    claimed   = FALSE
            ORDER  BY created_at ASC
            LIMIT  1
            FOR    UPDATE SKIP LOCKED
        )
        RETURNING key_id, key_json
        "#,
        user_id,
        device_id,
        format!("{}:%", algorithm),
    )
    .fetch_optional(pool)
    .await?;

    // Update count after claiming
    update_otk_count(pool, user_id, device_id).await?;

    Ok(row.map(|r| (r.key_id, r.key_json)))
}
