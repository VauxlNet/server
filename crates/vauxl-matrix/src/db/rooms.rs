//! Database queries for room creation and state management.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::room_auth::{authorize_event, lock_room};
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
        authorize_event(
            &mut tx,
            room_id,
            creator_id,
            &event_type,
            Some(&state_key),
            &content,
        )
        .await?;
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

        populate_event_auth(&mut tx, room_id, &mut raw_event).await?;
        sign_event(&mut raw_event, server_name, signing_key)?;

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

        if ev_type == "m.room.member" {
            let membership = ev_content["membership"]
                .as_str()
                .ok_or(MatrixError::Forbidden)?;
            sqlx::query(
                "INSERT INTO room_members (room_id, user_id, membership) VALUES ($1, $2, $3)
                 ON CONFLICT (room_id, user_id) DO UPDATE SET membership = EXCLUDED.membership",
            )
            .bind(room_id)
            .bind(&ev_key)
            .bind(membership)
            .execute(&mut *tx)
            .await?;
        }
    }

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
    let mut tx = pool.begin().await?;
    lock_room(&mut tx, room_id).await?;
    authorize_event(
        &mut tx,
        room_id,
        sender,
        event_type,
        Some(state_key),
        &content,
    )
    .await?;
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

    populate_event_auth(&mut tx, room_id, &mut raw_event).await?;
    sign_event(&mut raw_event, server_name, signing_key)?;

    let event_id = raw_event["event_id"].as_str().unwrap().to_owned();
    let ev_content = raw_event["content"].clone();

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
            .ok_or(MatrixError::Forbidden)?;

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
    put_room_event_inner(
        pool,
        room_id,
        event_type,
        sender,
        None,
        content,
        server_name,
        signing_key,
    )
    .await
    .map(|(event_id, _)| event_id)
}

/// Atomically authorize and send once for an endpoint-scoped client transaction.
/// Returns the stored event ID and whether this call inserted a new event.
#[allow(clippy::too_many_arguments)]
pub async fn put_room_event_idempotent(
    pool: &PgPool,
    room_id: &str,
    event_type: &str,
    sender: &str,
    device_id: &str,
    txn_id: &str,
    content: Value,
    server_name: &str,
    signing_key: &HomeserverSigningKey,
) -> Result<(String, bool), MatrixError> {
    put_room_event_inner(
        pool,
        room_id,
        event_type,
        sender,
        Some((device_id, txn_id)),
        content,
        server_name,
        signing_key,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn put_room_event_inner(
    pool: &PgPool,
    room_id: &str,
    event_type: &str,
    sender: &str,
    transaction: Option<(&str, &str)>,
    content: Value,
    server_name: &str,
    signing_key: &HomeserverSigningKey,
) -> Result<(String, bool), MatrixError> {
    let mut tx = pool.begin().await?;
    lock_room(&mut tx, room_id).await?;
    authorize_event(&mut tx, room_id, sender, event_type, None, &content).await?;
    // The room lock serializes retries for this endpoint scope. Check after
    // authorization so a departed or demoted sender cannot reuse a transaction.
    let scoped_txn = transaction.map(|(_, txn_id)| {
        serde_json::to_string(&("room.send", room_id, event_type, txn_id))
            .expect("string tuple is serializable")
    });
    if let (Some((device_id, _)), Some(scoped_txn)) = (transaction, scoped_txn.as_ref()) {
        let existing: Option<Option<String>> = sqlx::query_scalar(
            "SELECT event_id FROM transaction_ids WHERE user_id = $1 AND device_id = $2 AND txn_id = $3",
        )
        .bind(sender).bind(device_id).bind(scoped_txn)
        .fetch_optional(&mut *tx).await?;
        if let Some(event_id) = existing {
            let event_id = event_id
                .ok_or_else(|| MatrixError::Internal("Transaction has no event ID".into()))?;
            tx.commit().await?;
            return Ok((event_id, false));
        }
    }
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

    populate_event_auth(&mut tx, room_id, &mut raw_event).await?;
    sign_event(&mut raw_event, server_name, signing_key)?;

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
    .execute(&mut *tx)
    .await?;

    if let (Some((device_id, _)), Some(scoped_txn)) = (transaction, scoped_txn.as_ref()) {
        sqlx::query(
            "INSERT INTO transaction_ids (user_id, device_id, txn_id, event_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(sender).bind(device_id).bind(scoped_txn).bind(&event_id)
        .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok((event_id, true))
}

/// Checks that a user is a joined member of a room.
pub async fn assert_joined<'e, E>(db: E, room_id: &str, user_id: &str) -> Result<(), MatrixError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query!(
        "SELECT membership FROM room_members WHERE room_id = $1 AND user_id = $2",
        room_id,
        user_id,
    )
    .fetch_optional(db)
    .await?;

    match row.as_ref().map(|r| r.membership.as_str()) {
        Some("join") => Ok(()),
        _ => Err(MatrixError::Forbidden),
    }
}

/// Returns all current state events for a room.
pub async fn get_full_room_state<'e, E>(db: E, room_id: &str) -> Result<Vec<Value>, MatrixError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query!(
        r#"
        SELECT e.raw_event
        FROM   room_state rs
        JOIN   events e ON e.event_id = rs.event_id
        WHERE  rs.room_id = $1
        "#,
        room_id,
    )
    .fetch_all(db)
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
    user_id: &str,
    from: Option<&str>,
    to: Option<&str>,
    dir: &str, // "f" (forward) or "b" (backward)
    limit: i64,
) -> Result<(Vec<Value>, Option<String>), MatrixError> {
    let mut tx = pool.begin().await?;
    lock_room(&mut tx, room_id).await?;
    assert_joined(&mut *tx, room_id, user_id).await?;
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
        .fetch_all(&mut *tx)
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
        .fetch_all(&mut *tx)
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

    let result =
        super::history_visibility::filter_for_user(&mut tx, room_id, result, user_id).await?;
    tx.commit().await?;
    Ok((result, end_token))
}

/// Add graph references for a local event while holding the room write lock.
/// The supported event model is a single accepted chain, not state resolution.
pub async fn populate_event_auth(
    tx: &mut Transaction<'_, Postgres>,
    room_id: &str,
    event: &mut Value,
) -> Result<(), MatrixError> {
    let previous: Option<(String, Value)> = sqlx::query_as(
        "SELECT event_id, raw_event FROM events WHERE room_id = $1
         ORDER BY COALESCE((raw_event->>'depth')::bigint, 0) DESC, origin_ts DESC, event_id DESC LIMIT 1",
    )
    .bind(room_id).fetch_optional(&mut **tx).await?;
    let (prev_events, depth) = match previous {
        Some((id, raw)) => {
            let depth = raw.get("depth").and_then(Value::as_u64).unwrap_or(0);
            let next = depth
                .checked_add(1)
                .filter(|n| *n <= 9_007_199_254_740_991)
                .ok_or(MatrixError::Forbidden)?;
            (serde_json::json!([id]), next)
        }
        None => (serde_json::json!([]), 1),
    };
    let event_type = event["type"].as_str().ok_or(MatrixError::Forbidden)?;
    let sender = event["sender"].as_str().ok_or(MatrixError::Forbidden)?;
    let target = if event_type == "m.room.member" {
        event["state_key"].as_str()
    } else {
        None
    };
    let needs_join_rules = event_type == "m.room.member"
        && matches!(
            event["content"]["membership"].as_str(),
            Some("join" | "invite")
        );
    let auth_events: Vec<String> = if event_type == "m.room.create" {
        Vec::new()
    } else {
        sqlx::query_scalar(
            "SELECT event_id FROM room_state WHERE room_id = $1 AND (
             (state_key = '' AND event_type IN ('m.room.create', 'm.room.power_levels')) OR
             (event_type = 'm.room.member' AND (state_key = $2 OR state_key = $3)) OR
             (event_type = 'm.room.join_rules' AND state_key = '' AND $4))
             ORDER BY event_id",
        )
        .bind(room_id)
        .bind(sender)
        .bind(target)
        .bind(needs_join_rules)
        .fetch_all(&mut **tx)
        .await?
    };
    event["prev_events"] = prev_events;
    event["depth"] = depth.into();
    event["auth_events"] = serde_json::json!(auth_events);
    Ok(())
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
