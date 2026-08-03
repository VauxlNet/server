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

use crate::{auth::AuthenticatedUser, db::assert_joined, error::MatrixError, state::SharedState};

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
    Path((room_id, user_id)): Path<(String, String)>,
    Json(body): Json<TypingRequest>,
) -> Result<Json<Value>, MatrixError> {
    if user_id != auth.user_id {
        return Err(MatrixError::Forbidden);
    }
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| MatrixError::Internal(e.to_string()))?;

    let key = format!("typing:{}:{}", room_id, auth.user_id);
    let dirty_key = format!("typing-dirty:{room_id}");

    if body.typing {
        let timeout_ms = body.timeout.unwrap_or(30_000).clamp(1, 60_000);
        let dirty_ttl_ms = timeout_ms.saturating_add(35_000);
        let _: () = conn
            .pset_ex(&key, "1", timeout_ms)
            .await
            .map_err(|e| MatrixError::Internal(e.to_string()))?;
        let _: () = conn
            .pset_ex(&dirty_key, "1", dirty_ttl_ms)
            .await
            .map_err(|e| MatrixError::Internal(e.to_string()))?;
    } else {
        let _: () = conn
            .del(&key)
            .await
            .map_err(|e| MatrixError::Internal(e.to_string()))?;
        let _: () = conn
            .pset_ex(&dirty_key, "1", 35_000)
            .await
            .map_err(|e| MatrixError::Internal(e.to_string()))?;
    }

    let _ = state.wake_tx.send(());
    Ok(Json(json!({})))
}

/// Returns the current typing state when a typing update is pending.
pub async fn get_typing_users(redis: &redis::Client, room_id: &str) -> Option<Vec<String>> {
    let Ok(mut conn) = redis.get_multiplexed_async_connection().await else {
        return None;
    };

    let pattern = format!("typing:{}:*", room_id);
    let keys: Vec<String> = conn.keys(&pattern).await.unwrap_or_default();

    let mut users: Vec<String> = keys
        .iter()
        .filter_map(|k| k.strip_prefix(&format!("typing:{}:", room_id)))
        .map(|u| u.to_owned())
        .collect();
    users.sort();

    let dirty: bool = conn
        .exists(format!("typing-dirty:{room_id}"))
        .await
        .unwrap_or(false);

    (!users.is_empty() || dirty).then_some(users)
}

// ── Read receipts ─────────────────────────────────────────────────────────

/// POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
pub async fn send_receipt(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, receipt_type, event_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    match receipt_type.as_str() {
        "m.read" | "m.read.private" => {}
        _ => return Err(MatrixError::BadJson("Unsupported receipt type".into())),
    }

    let event_exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM events WHERE room_id = $1 AND event_id = $2
        ) AS "exists!"
        "#,
        room_id,
        event_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(MatrixError::from)?;

    if !event_exists {
        return Err(MatrixError::NotFound);
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

    let _ = state.wake_tx.send(());
    Ok(Json(json!({})))
}

/// Returns public receipts plus the syncing user's private receipts.
pub async fn get_room_receipts(pool: &sqlx::PgPool, room_id: &str, user_id: &str) -> Vec<Value> {
    let rows = sqlx::query!(
        r#"
        SELECT user_id, event_id, receipt_type, ts
        FROM   read_receipts
        WHERE  room_id      = $1
        AND   (receipt_type = 'm.read'
               OR (receipt_type = 'm.read.private' AND user_id = $2))
        "#,
        room_id,
        user_id,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return vec![];
    }

    let mut content = serde_json::Map::new();
    for row in rows {
        let event = content.entry(row.event_id).or_insert_with(|| json!({}));
        let receipt_types = event.as_object_mut().expect("receipt event is an object");
        let receipt = receipt_types
            .entry(row.receipt_type)
            .or_insert_with(|| json!({}));
        receipt
            .as_object_mut()
            .expect("receipt users are an object")
            .insert(row.user_id, json!({ "ts": row.ts }));
    }

    vec![json!({
        "type":    "m.receipt",
        "content": content
    })]
}
