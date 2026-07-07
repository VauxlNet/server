//! GET /_matrix/client/v3/sync

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

use crate::{
    auth::AuthenticatedUser,
    db::{
        pop_to_device_messages,
        sync::{get_room_state, get_room_timeline, get_user_rooms},
    },
    error::MatrixError,
    state::SharedState,
    sync_token::{get_next_batch, parse_since},
};

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    pub since: Option<String>,
    pub timeout: Option<u64>,
    pub filter: Option<String>,
    pub full_state: Option<bool>,
}

pub async fn sync(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Query(query): Query<SyncQuery>,
) -> Result<Json<Value>, MatrixError> {
    let since_pos = parse_since(query.since.as_deref());
    let timeout = query.timeout.unwrap_or(0).min(30_000);

    if timeout > 0 && since_pos > 0 {
        sleep(Duration::from_millis(timeout.min(5_000))).await;
    }

    let response = build_sync_response(&state, &auth.user_id, &auth.device_id, since_pos).await?;

    Ok(Json(response))
}

async fn build_sync_response(
    state: &SharedState,
    user_id: &str,
    device_id: &str,
    since_pos: u64,
) -> Result<Value, MatrixError> {
    let next_batch = get_next_batch(&state.redis, user_id).await?;
    let rooms = get_user_rooms(&state.db, user_id).await?;

    // Fetch and drain pending to-device messages for this device
    let to_device_events = pop_to_device_messages(&state.db, user_id, device_id).await?;

    let mut join_rooms: HashMap<String, Value> = HashMap::new();
    let mut invite_rooms: HashMap<String, Value> = HashMap::new();

    for (room_id, membership) in rooms {
        match membership.as_str() {
            "join" => {
                let room = build_joined_room(&state.db, &room_id, since_pos).await?;
                join_rooms.insert(room_id, room);
            }
            "invite" => {
                let room = build_invited_room(&state.db, &room_id, user_id).await?;
                invite_rooms.insert(room_id, room);
            }
            _ => {}
        }
    }

    Ok(json!({
        "next_batch": next_batch,
        "rooms": {
            "join":   join_rooms,
            "invite": invite_rooms,
            "leave":  {}
        },
        "presence":     { "events": [] },
        "account_data": { "events": [] },
        "to_device":    { "events": to_device_events },
        "device_lists": { "changed": [], "left": [] },
        "device_one_time_keys_count": {}
    }))
}

async fn build_joined_room(
    pool: &sqlx::PgPool,
    room_id: &str,
    since: u64,
) -> Result<Value, MatrixError> {
    let state_events = get_room_state(pool, room_id).await?;
    let timeline_events = get_room_timeline(pool, room_id, since).await?;
    let limited = since == 0;

    Ok(json!({
        "summary": {
            "m.heroes":               [],
            "m.joined_member_count":  0,
            "m.invited_member_count": 0
        },
        "state":    { "events": state_events },
        "timeline": {
            "events":    timeline_events,
            "limited":   limited,
            "prev_batch": format!("s0_{}", since)
        },
        "ephemeral":    { "events": [] },
        "account_data": { "events": [] },
        "unread_notifications": {
            "highlight_count":    0,
            "notification_count": 0
        }
    }))
}

async fn build_invited_room(
    pool: &sqlx::PgPool,
    room_id: &str,
    user_id: &str,
) -> Result<Value, MatrixError> {
    let invite_event = sqlx::query!(
        r#"
        SELECT raw_event FROM events
        WHERE  room_id    = $1
        AND    event_type = 'm.room.member'
        AND    state_key  = $2
        ORDER  BY origin_ts DESC
        LIMIT  1
        "#,
        room_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(MatrixError::from)?
    .and_then(|r| serde_json::from_value(r.raw_event).ok())
    .unwrap_or(json!({}));

    Ok(json!({
        "invite_state": { "events": [invite_event] }
    }))
}
