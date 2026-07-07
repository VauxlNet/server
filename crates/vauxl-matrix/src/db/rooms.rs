//! Database queries for room creation and state management.

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::MatrixError;

/// Creates a room and inserts all initial state events atomically.
pub async fn create_room_with_state(
    pool: &PgPool,
    room_id: &str,
    creator_id: &str,
    state_events: Vec<(String, String, Value)>, // (event_type, state_key, content)
    server_name: &str,
) -> Result<(), MatrixError> {
    let mut tx = pool.begin().await?;

    // Insert the room row
    sqlx::query!("INSERT INTO rooms (room_id) VALUES ($1)", room_id,)
        .execute(&mut *tx)
        .await?;

    let now_ms = now_millis();

    for (event_type, state_key, content) in state_events {
        let event_id = generate_event_id(server_name);

        let raw_event = serde_json::json!({
            "event_id":       event_id,
            "room_id":        room_id,
            "type":           event_type,
            "state_key":      state_key,
            "sender":         creator_id,
            "origin_server_ts": now_ms,
            "content":        content,
            "unsigned":       {}
        });

        // Insert into events table
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
            creator_id,
            now_ms as i64,
            content,
            raw_event,
        )
        .execute(&mut *tx)
        .await?;

        // Upsert into room_state (current state snapshot)
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
            event_id,
        )
        .execute(&mut *tx)
        .await?;
    }

    // Add creator as a joined member
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

/// Sends a single state event to a room, updating room_state.
pub async fn put_room_state_event(
    pool: &PgPool,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    sender: &str,
    content: Value,
    server_name: &str,
) -> Result<String, MatrixError> {
    let event_id = generate_event_id(server_name);
    let now_ms = now_millis();

    let raw_event = serde_json::json!({
        "event_id":         event_id,
        "room_id":          room_id,
        "type":             event_type,
        "state_key":        state_key,
        "sender":           sender,
        "origin_server_ts": now_ms,
        "content":          content,
        "unsigned":         {}
    });

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
        content,
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
        event_id,
    )
    .execute(&mut *tx)
    .await?;

    // Update membership table for m.room.member events
    if event_type == "m.room.member" {
        let membership = content
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

/// Sends a message event (non-state) to a room.
pub async fn put_room_event(
    pool: &PgPool,
    room_id: &str,
    event_type: &str,
    sender: &str,
    content: Value,
    server_name: &str,
) -> Result<String, MatrixError> {
    let event_id = generate_event_id(server_name);
    let now_ms = now_millis();

    let raw_event = serde_json::json!({
        "event_id":         event_id,
        "room_id":          room_id,
        "type":             event_type,
        "sender":           sender,
        "origin_server_ts": now_ms,
        "content":          content,
        "unsigned":         {}
    });

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
        content,
        raw_event,
    )
    .execute(pool)
    .await?;

    Ok(event_id)
}

/// Checks that a user is a joined member of a room.
pub async fn assert_joined(pool: &PgPool, room_id: &str, user_id: &str) -> Result<(), MatrixError> {
    let row = sqlx::query!(
        r#"
        SELECT membership FROM room_members
        WHERE room_id = $1 AND user_id = $2
        "#,
        room_id,
        user_id,
    )
    .fetch_optional(pool)
    .await?;

    match row.as_ref().map(|r| r.membership.as_str()) {
        Some("join") => Ok(()),
        Some(_) => Err(MatrixError::Forbidden),
        None => Err(MatrixError::Forbidden),
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

/// Generates a Matrix event ID: $base64url_random:server_name
pub fn generate_event_id(server_name: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let random = Uuid::new_v4().as_bytes().to_vec();
    format!("${}:{}", URL_SAFE_NO_PAD.encode(random), server_name)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
