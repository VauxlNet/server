//! Database queries for room creation and state management.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{error::MatrixError, event_signing::sign_event, signing_key::HomeserverSigningKey};

/// Creates a room and inserts all initial state events atomically.
pub async fn create_room_with_state(
    pool: &PgPool,
    room_id: &str,
    creator_id: &str,
    state_events: Vec<(String, String, Value)>,
    server_name: &str,
    signing_key: &HomeserverSigningKey,
) -> Result<(), MatrixError> {
    let mut tx = pool.begin().await?;

    sqlx::query!("INSERT INTO rooms (room_id) VALUES ($1)", room_id)
        .execute(&mut *tx)
        .await?;

    let now_ms = now_millis();

    for (event_type, state_key, content) in state_events {
        let event_id = generate_event_id(server_name);

        let mut raw_event = serde_json::json!({
            "event_id":         event_id,
            "room_id":          room_id,
            "type":             event_type,
            "state_key":        state_key,
            "sender":           creator_id,
            "origin_server_ts": now_ms,
            "content":          content,
            "unsigned":         {}
        });

        sign_event(&mut raw_event, server_name, signing_key);

        let event_id = raw_event["event_id"].as_str().unwrap().to_owned();
        let ev_type = raw_event["type"].as_str().unwrap().to_owned();
        let ev_key = raw_event["state_key"].as_str().unwrap().to_owned();
        let ev_content = raw_event["content"].clone();

        sqlx::query!(
            r#"
            INSERT INTO events
                (event_id, room_id, event_type, state_key, sender, origin_ts, content, raw_event)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            event_id,
            room_id,
            ev_type,
            ev_key,
            creator_id,
            now_ms as i64,
            ev_content,
            raw_event,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            r#"
            INSERT INTO room_state (room_id, event_type, state_key, event_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (room_id, event_type, state_key)
            DO UPDATE SET event_id = EXCLUDED.event_id
            "#,
            room_id,
            ev_type,
            ev_key,
            event_id,
        )
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query!(
        r#"
        INSERT INTO room_members (room_id, user_id, membership)
        VALUES ($1, $2, 'join')
        ON CONFLICT (room_id, user_id) DO UPDATE SET membership = 'join'
        "#,
        room_id,
        creator_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Sends a single state event, signed, updating room_state.
#[allow(clippy::too_many_arguments)]
pub async fn put_room_state_event(
    pool: &PgPool,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    sender: &str,
    content: Value,
    server_name: &str,
    signing_key: &HomeserverSigningKey,
) -> Result<String, MatrixError> {
    let now_ms = now_millis();
    let event_id = generate_event_id(server_name);

    let mut raw_event = serde_json::json!({
        "event_id":         event_id,
        "room_id":          room_id,
        "type":             event_type,
        "state_key":        state_key,
        "sender":           sender,
        "origin_server_ts": now_ms,
        "content":          content,
        "unsigned":         {}
    });

    sign_event(&mut raw_event, server_name, signing_key);

    let event_id = raw_event["event_id"].as_str().unwrap().to_owned();
    let ev_content = raw_event["content"].clone();

    let mut tx = pool.begin().await?;

    sqlx::query!(
        r#"
        INSERT INTO events
            (event_id, room_id, event_type, state_key, sender, origin_ts, content, raw_event)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        event_id,
        room_id,
        event_type,
        state_key,
        sender,
        now_ms as i64,
        ev_content,
        raw_event,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        r#"
        INSERT INTO room_state (room_id, event_type, state_key, event_id)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (room_id, event_type, state_key)
        DO UPDATE SET event_id = EXCLUDED.event_id
        "#,
        room_id,
        event_type,
        state_key,
        &event_id,
    )
    .execute(&mut *tx)
    .await?;

    if event_type == "m.room.member" {
        let membership = ev_content
            .get("membership")
            .and_then(|v| v.as_str())
            .unwrap_or("leave");

        sqlx::query!(
            r#"
            INSERT INTO room_members (room_id, user_id, membership)
            VALUES ($1, $2, $3)
            ON CONFLICT (room_id, user_id) DO UPDATE SET membership = EXCLUDED.membership
            "#,
            room_id,
            state_key,
            membership,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(event_id)
}

/// Sends a message event (non-state), signed.
pub async fn put_room_event(
    pool: &PgPool,
    room_id: &str,
    event_type: &str,
    sender: &str,
    content: Value,
    server_name: &str,
    signing_key: &HomeserverSigningKey,
) -> Result<String, MatrixError> {
    let now_ms = now_millis();
    let event_id = generate_event_id(server_name);

    let mut raw_event = serde_json::json!({
        "event_id":         event_id,
        "room_id":          room_id,
        "type":             event_type,
        "sender":           sender,
        "origin_server_ts": now_ms,
        "content":          content,
        "unsigned":         {}
    });

    sign_event(&mut raw_event, server_name, signing_key);

    let event_id = raw_event["event_id"].as_str().unwrap().to_owned();
    let ev_content = raw_event["content"].clone();

    sqlx::query!(
        r#"
        INSERT INTO events
            (event_id, room_id, event_type, state_key, sender, origin_ts, content, raw_event)
        VALUES ($1, $2, $3, NULL, $4, $5, $6, $7)
        "#,
        event_id,
        room_id,
        event_type,
        sender,
        now_ms as i64,
        ev_content,
        raw_event,
    )
    .execute(pool)
    .await?;

    Ok(event_id)
}

/// Checks that a user is a joined member of a room.
pub async fn assert_joined(pool: &PgPool, room_id: &str, user_id: &str) -> Result<(), MatrixError> {
    let row = sqlx::query!(
        "SELECT membership FROM room_members WHERE room_id = $1 AND user_id = $2",
        room_id,
        user_id,
    )
    .fetch_optional(pool)
    .await?;

    match row.as_ref().map(|r| r.membership.as_str()) {
        Some("join") => Ok(()),
        _ => Err(MatrixError::Forbidden),
    }
}

/// Returns all current state events for a room.
pub async fn get_full_room_state(pool: &PgPool, room_id: &str) -> Result<Vec<Value>, MatrixError> {
    let rows = sqlx::query!(
        r#"
        SELECT e.raw_event
        FROM   room_state rs
        JOIN   events e ON e.event_id = rs.event_id
        WHERE  rs.room_id = $1
        "#,
        room_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| serde_json::from_value(r.raw_event).ok())
        .collect())
}

/// Paginated room message history.
pub async fn get_room_messages(
    pool: &PgPool,
    room_id: &str,
    from: Option<&str>,
    to: Option<&str>,
    dir: &str, // "f" (forward) or "b" (backward)
    limit: i64,
) -> Result<(Vec<Value>, Option<String>), MatrixError> {
    // Parse pagination tokens — we use origin_ts as the cursor
    let from_ts: Option<i64> = from
        .and_then(|t| t.strip_prefix('t'))
        .and_then(|n| n.parse().ok());

    let _to_ts: Option<i64> = to
        .and_then(|t| t.strip_prefix('t'))
        .and_then(|n| n.parse().ok());

    struct MessageRow {
        raw_event: serde_json::Value,
        origin_ts: i64,
    }

    let events = if dir == "b" {
        // Backward — newest first
        let anchor = from_ts.unwrap_or(i64::MAX);
        let rows = sqlx::query_as!(
            MessageRow,
            r#"
            SELECT raw_event, origin_ts FROM events
            WHERE  room_id   = $1
            AND    state_key IS NULL
            AND    origin_ts < $2
            ORDER  BY origin_ts DESC
            LIMIT  $3
            "#,
            room_id,
            anchor,
            limit + 1,
        )
        .fetch_all(pool)
        .await?;
        rows
    } else {
        // Forward — oldest first
        let anchor = from_ts.unwrap_or(0);
        let rows = sqlx::query_as!(
            MessageRow,
            r#"
            SELECT raw_event, origin_ts FROM events
            WHERE  room_id   = $1
            AND    state_key IS NULL
            AND    origin_ts > $2
            ORDER  BY origin_ts ASC
            LIMIT  $3
            "#,
            room_id,
            anchor,
            limit + 1,
        )
        .fetch_all(pool)
        .await?;
        rows
    };

    // Check if there are more results (we fetched limit+1)
    let has_more = events.len() as i64 > limit;
    let events = &events[..events.len().min(limit as usize)];

    // Build next_batch token from the last event's timestamp
    let end_token = if has_more {
        events.last().map(|r| format!("t{}", r.origin_ts))
    } else {
        None
    };

    let result: Vec<Value> = events
        .iter()
        .filter_map(|r| serde_json::from_value(r.raw_event.clone()).ok())
        .collect();

    Ok((result, end_token))
}

pub fn generate_event_id(server_name: &str) -> String {
    let random = Uuid::new_v4().as_bytes().to_vec();
    format!("${}:{}", URL_SAFE_NO_PAD.encode(random), server_name)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
