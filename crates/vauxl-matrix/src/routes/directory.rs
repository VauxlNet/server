//! Room directory and alias endpoints (P1-014).

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::AuthenticatedUser, error::MatrixError, state::SharedState};

// ── Public room directory ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PublicRoomsQuery {
    pub limit: Option<i64>,
    pub since: Option<String>,
    pub server: Option<String>,
}

/// GET /_matrix/client/v3/publicRooms
pub async fn public_rooms_full(
    State(state): State<SharedState>,
    Query(query): Query<PublicRoomsQuery>,
) -> Result<Json<Value>, MatrixError> {
    let limit = query.limit.unwrap_or(20).min(100);

    let rows = sqlx::query!(
        r#"
            SELECT
                r.room_id,
                -- Name from room state
                (SELECT e.content->>'name'
                 FROM room_state rs
                 JOIN events e ON e.event_id = rs.event_id
                 WHERE rs.room_id = r.room_id AND rs.event_type = 'm.room.name'
                 LIMIT 1) AS name,
                -- Topic from room state
                (SELECT e.content->>'topic'
                 FROM room_state rs
                 JOIN events e ON e.event_id = rs.event_id
                 WHERE rs.room_id = r.room_id AND rs.event_type = 'm.room.topic'
                 LIMIT 1) AS topic,
                -- Join rule
                (SELECT e.content->>'join_rule'
                 FROM room_state rs
                 JOIN events e ON e.event_id = rs.event_id
                 WHERE rs.room_id = r.room_id AND rs.event_type = 'm.room.join_rules'
                 LIMIT 1) AS join_rule,
                -- Member count
                (SELECT COUNT(*) FROM room_members
                 WHERE room_id = r.room_id AND membership = 'join')::BIGINT AS "member_count!"
            FROM rooms r
            WHERE (
                SELECT e.content->>'join_rule'
                FROM room_state rs
                JOIN events e ON e.event_id = rs.event_id
                WHERE rs.room_id = r.room_id AND rs.event_type = 'm.room.join_rules'
                LIMIT 1
            ) = 'public'
            LIMIT $1
            "#,
        limit as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(MatrixError::from)?;

    let chunk: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "room_id":          r.room_id,
                "name":             r.name,
                "topic":            r.topic,
                "num_joined_members": r.member_count,
                "world_readable":   false,
                "guest_can_join":   false,
                "join_rule":        r.join_rule.as_deref().unwrap_or("public"),
                "canonical_alias":  null,
                "avatar_url":       null
            })
        })
        .collect();

    Ok(Json(json!({
        "chunk":              chunk,
        "total_room_count_estimate": chunk.len(),
        "next_batch":         null,
        "prev_batch":         null
    })))
}

/// POST /_matrix/client/v3/publicRooms (with filter body)
pub async fn public_rooms_post(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let limit = body
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(20)
        .min(100);

    let rows = sqlx::query!(
        r#"
        SELECT r.room_id,
            (SELECT e.content->>'name' FROM room_state rs JOIN events e ON e.event_id = rs.event_id
             WHERE rs.room_id = r.room_id AND rs.event_type = 'm.room.name' LIMIT 1) AS name,
            (SELECT COUNT(*) FROM room_members WHERE room_id = r.room_id AND membership = 'join')
             AS member_count
        FROM rooms r
        WHERE (
            SELECT e.content->>'join_rule'
            FROM room_state rs
            JOIN events e ON e.event_id = rs.event_id
            WHERE rs.room_id = r.room_id AND rs.event_type = 'm.room.join_rules'
            LIMIT 1
        ) = 'public'
        LIMIT $1
        "#,
        limit,
    )
    .fetch_all(&state.db)
    .await
    .map_err(MatrixError::from)?;

    let chunk: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "room_id": r.room_id,
                "name":    r.name,
                "num_joined_members": r.member_count.unwrap_or(0),
                "world_readable": false,
                "guest_can_join": false,
            })
        })
        .collect();

    Ok(Json(json!({
        "chunk":   chunk,
        "next_batch": null
    })))
}

// ── Room aliases ──────────────────────────────────────────────────────────

/// PUT /_matrix/client/v3/directory/room/{roomAlias}
pub async fn put_room_alias(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(alias): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let room_id = body
        .get("room_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MatrixError::BadJson("Missing room_id".into()))?;

    // Validate alias format: #alias:server
    if !alias.starts_with('#') || !alias.contains(':') {
        return Err(MatrixError::BadJson(
            "Alias must be in format #alias:server".into(),
        ));
    }

    sqlx::query!(
        r#"
        INSERT INTO room_aliases (alias, room_id, creator)
        VALUES ($1, $2, $3)
        ON CONFLICT (alias) DO NOTHING
        "#,
        alias,
        room_id,
        auth.user_id,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;

    Ok(Json(json!({})))
}

/// GET /_matrix/client/v3/directory/room/{roomAlias}
pub async fn get_room_alias(
    State(state): State<SharedState>,
    Path(alias): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let row = sqlx::query!("SELECT room_id FROM room_aliases WHERE alias = $1", alias,)
        .fetch_optional(&state.db)
        .await
        .map_err(MatrixError::from)?
        .ok_or(MatrixError::NotFound)?;

    Ok(Json(json!({
        "room_id": row.room_id,
        "servers": [state.config.server.server_name]
    })))
}

/// DELETE /_matrix/client/v3/directory/room/{roomAlias}
pub async fn delete_room_alias(
    State(state): State<SharedState>,
    _auth: AuthenticatedUser,
    Path(alias): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    sqlx::query!("DELETE FROM room_aliases WHERE alias = $1", alias,)
        .execute(&state.db)
        .await
        .map_err(MatrixError::from)?;

    Ok(Json(json!({})))
}
