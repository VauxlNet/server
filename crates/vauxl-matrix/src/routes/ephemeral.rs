//! Typing notifications and read receipts (P1-011).
//!
//! Typing is stored in Redis with a TTL — auto-clears when user stops.
//! Receipts are stored in PostgreSQL and returned in /sync ephemeral events.

use axum::{
    extract::{Path, State},
    Json,
};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::AuthenticatedUser, error::MatrixError, state::SharedState};

// ── Typing ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TypingRequest {
    pub typing: bool,
    pub timeout: Option<u64>, // ms, default 30000
}

/// PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
pub async fn send_typing(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, _user_id)): Path<(String, String)>,
    Json(body): Json<TypingRequest>,
) -> Result<Json<Value>, MatrixError> {
    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| MatrixError::Internal(e.to_string()))?;

    let key = format!("typing:{}:{}", room_id, auth.user_id);

    if body.typing {
        let ttl_secs = (body.timeout.unwrap_or(30_000) / 1000).clamp(1, 60) as i64;
        let _: () = conn
            .set_ex(&key, "1", ttl_secs as u64)
            .await
            .map_err(|e| MatrixError::Internal(e.to_string()))?;
    } else {
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| MatrixError::Internal(e.to_string()))?;
    }

    Ok(Json(json!({})))
}

/// Returns current typers for a room — used by /sync ephemeral.
pub async fn get_typing_users(redis: &redis::Client, room_id: &str) -> Vec<String> {
    let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
        return vec![];
    };

    let pattern = format!("typing:{}:*", room_id);
    let keys: Vec<String> = conn.keys(&pattern).await.unwrap_or_default();

    keys.iter()
        .filter_map(|k| k.strip_prefix(&format!("typing:{}:", room_id)))
        .map(|u| u.to_owned())
        .collect()
}

// ── Read receipts ─────────────────────────────────────────────────────────

/// POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
pub async fn send_receipt(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, receipt_type, event_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    // Only store m.read and m.read.private
    match receipt_type.as_str() {
        "m.read" | "m.read.private" | "m.fully_read" => {}
        _ => return Ok(Json(json!({}))),
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    sqlx::query!(
        r#"
        INSERT INTO read_receipts (room_id, user_id, event_id, receipt_type, ts)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (room_id, user_id, receipt_type)
        DO UPDATE SET event_id = EXCLUDED.event_id, ts = EXCLUDED.ts
        "#,
        room_id,
        auth.user_id,
        event_id,
        receipt_type,
        now_ms,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;

    Ok(Json(json!({})))
}

/// Returns receipt events for a room — used by /sync ephemeral.
/// Only returns public m.read receipts (m.read.private is not shared).
pub async fn get_room_receipts(pool: &sqlx::PgPool, room_id: &str) -> Vec<Value> {
    let rows = sqlx::query!(
        r#"
        SELECT user_id, event_id, ts
        FROM   read_receipts
        WHERE  room_id      = $1
        AND    receipt_type = 'm.read'
        "#,
        room_id,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return vec![];
    }

    // Matrix receipt format:
    // {"type": "m.receipt", "content": {event_id: {"m.read": {user_id: {ts}}}}}
    let mut content = serde_json::Map::new();
    for row in rows {
        content.insert(
            row.event_id,
            json!({
                "m.read": {
                    row.user_id: { "ts": row.ts }
                }
            }),
        );
    }

    vec![json!({
        "type":    "m.receipt",
        "content": content
    })]
}
