//! Database queries for room membership operations.

use sqlx::PgPool;

use crate::{
    db::rooms::put_room_state_event, error::MatrixError, signing_key::HomeserverSigningKey,
};

pub async fn get_membership(
    pool: &PgPool,
    room_id: &str,
    user_id: &str,
) -> Result<Option<String>, MatrixError> {
    let row = sqlx::query!(
        "SELECT membership FROM room_members WHERE room_id = $1 AND user_id = $2",
        room_id,
        user_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.membership))
}

pub async fn get_join_rule(pool: &PgPool, room_id: &str) -> Result<String, MatrixError> {
    let row = sqlx::query!(
        r#"
        SELECT e.content->>'join_rule' AS join_rule
        FROM   room_state rs
        JOIN   events e ON e.event_id = rs.event_id
        WHERE  rs.room_id    = $1
        AND    rs.event_type = 'm.room.join_rules'
        "#,
        room_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row
        .and_then(|r| r.join_rule)
        .unwrap_or_else(|| "invite".into()))
}

pub async fn resolve_room_alias(pool: &PgPool, alias: &str) -> Result<Option<String>, MatrixError> {
    let row = sqlx::query!(
        r#"
        SELECT rs.room_id
        FROM   room_state rs
        JOIN   events e ON e.event_id = rs.event_id
        WHERE  rs.event_type = 'm.room.canonical_alias'
        AND    e.content->>'alias' = $1
        LIMIT  1
        "#,
        alias,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.room_id))
}

pub async fn room_exists(pool: &PgPool, room_id: &str) -> Result<bool, MatrixError> {
    let row = sqlx::query!("SELECT 1 AS exists FROM rooms WHERE room_id = $1", room_id,)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

#[allow(clippy::too_many_arguments)]
pub async fn set_membership(
    pool: &PgPool,
    room_id: &str,
    user_id: &str,
    sender: &str,
    membership: &str,
    displayname: Option<&str>,
    server_name: &str,
    signing_key: &HomeserverSigningKey,
) -> Result<String, MatrixError> {
    let content = serde_json::json!({
        "membership":  membership,
        "displayname": displayname,
        "avatar_url":  null,
    });

    put_room_state_event(
        pool,
        room_id,
        "m.room.member",
        user_id,
        sender,
        content,
        server_name,
        signing_key,
    )
    .await
}

pub async fn store_invite_notification(
    pool: &PgPool,
    invitee_id: &str,
    room_id: &str,
    inviter_id: &str,
) -> Result<(), MatrixError> {
    let content = serde_json::json!({
        "room_id": room_id, "sender": inviter_id,
        "type": "m.room.member", "state_key": invitee_id,
        "content": {"membership": "invite"}
    });

    sqlx::query!(
        r#"
        INSERT INTO to_device_messages (user_id, device_id, event_type, content)
        SELECT $1, device_id, 'm.room.invite_notification', $2
        FROM   devices WHERE user_id = $1
        "#,
        invitee_id,
        content,
    )
    .execute(pool)
    .await?;

    Ok(())
}
