//! Presence endpoints (P1-012).
//!
//! Stored in Redis with a 5-minute TTL — auto-offline when it expires.
//! org.vauxl.presence_shield suppresses presence for opted-in users.

use axum::{
    extract::{Path, State},
    Json,
};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::AuthenticatedUser, error::MatrixError, state::SharedState};

#[derive(Debug, Deserialize)]
pub struct SetPresenceRequest {
    pub presence: String, // online | offline | unavailable
    pub status_msg: Option<String>,
}

/// PUT /_matrix/client/v3/presence/{userId}/status
pub async fn set_presence(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(_user_id): Path<String>,
    Json(body): Json<SetPresenceRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Check presence_shield — if opted in, store nothing
    if is_presence_shielded(&state.redis, &auth.user_id).await {
        return Ok(Json(json!({})));
    }

    match body.presence.as_str() {
        "online" | "offline" | "unavailable" => {}
        _ => {
            return Err(MatrixError::BadJson(format!(
                "Invalid presence state: {}",
                body.presence
            )))
        }
    }

    let mut conn = state
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| MatrixError::Internal(e.to_string()))?;

    let key = format!("presence:{}", auth.user_id);
    let val = serde_json::to_string(&json!({
        "presence":   body.presence,
        "status_msg": body.status_msg,
        "last_active_ts": now_ms()
    }))
    .unwrap_or_default();

    // TTL: 5 minutes for online/unavailable, immediate expire for offline
    let ttl: u64 = if body.presence == "offline" { 1 } else { 300 };
    let _: () = conn
        .set_ex(&key, val, ttl)
        .await
        .map_err(|e| MatrixError::Internal(e.to_string()))?;

    Ok(Json(json!({})))
}

/// GET /_matrix/client/v3/presence/{userId}/status
pub async fn get_presence(
    State(state): State<SharedState>,
    _auth: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let val = get_presence_for_user(&state.redis, &user_id).await;

    Ok(Json(val.unwrap_or_else(|| {
        json!({
            "presence":        "offline",
            "last_active_ago": null
        })
    })))
}

/// Returns presence data for a user — used by /sync.
pub async fn get_presence_for_user(client: &redis::Client, user_id: &str) -> Option<Value> {
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return None;
    };

    let key = format!("presence:{}", user_id);
    let raw: Option<String> = conn.get(&key).await.ok()?;
    let val: Value = serde_json::from_str(&raw?).ok()?;

    let last_active = val["last_active_ts"].as_i64().unwrap_or(0);
    let last_active_ago = now_ms() - last_active;

    Some(json!({
        "presence":        val["presence"],
        "status_msg":      val["status_msg"],
        "last_active_ago": last_active_ago,
        "currently_active": val["presence"] == "online"
    }))
}

/// Returns presence events for joined room members — used by /sync.
pub async fn get_room_presence_events(
    client: &redis::Client,
    pool: &sqlx::PgPool,
    room_id: &str,
    user_id: &str, // the syncing user — don't include self
) -> Vec<Value> {
    // Get joined members for this room
    let Ok(rows) = sqlx::query!(
        "SELECT user_id FROM room_members WHERE room_id = $1 AND membership = 'join'",
        room_id,
    )
    .fetch_all(pool)
    .await
    else {
        return vec![];
    };

    let mut events = vec![];
    for row in rows {
        if row.user_id == user_id {
            continue;
        }
        if is_presence_shielded(client, &row.user_id).await {
            continue;
        }

        if let Some(presence) = get_presence_for_user(client, &row.user_id).await {
            events.push(json!({
                "type":    "m.presence",
                "sender":  row.user_id,
                "content": presence
            }));
        }
    }
    events
}

async fn is_presence_shielded(client: &redis::Client, user_id: &str) -> bool {
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return false;
    };
    let key = format!("presence_shield:{}", user_id);
    let val: Option<String> = conn.get(&key).await.unwrap_or(None);
    val.is_some()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
