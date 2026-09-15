//! Database queries used by the /sync endpoint.

use serde_json::Value;
use sqlx::PgPool;

use crate::error::MatrixError;

/// A room the user is a member of, with recent events.
pub struct SyncRoom {
    pub room_id: String,
    pub membership: String,
    pub state_events: Vec<Value>,
    pub timeline: Vec<Value>,
}

/// Returns all rooms a user is currently joined or invited to.
pub async fn get_user_rooms(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<(String, String)>, MatrixError> {
    let rows = sqlx::query!(
        r#"
        SELECT room_id, membership
        FROM   room_members
        WHERE  user_id = $1
        AND    membership IN ('join', 'invite')
        ORDER  BY room_id
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| (r.room_id, r.membership))
        .collect())
}

/// Returns current state events for a room (m.room.create, m.room.name, etc.)
pub async fn get_room_state<'e, E>(db: E, room_id: &str) -> Result<Vec<Value>, MatrixError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    super::rooms::get_full_room_state(db, room_id).await
}

/// Returns the most recent timeline events for a room (last 50).
// 1. Wir definieren das Struct explizit für die Abfrage
struct EventRow {
    raw_event: Value,
}

/// Returns the most recent timeline events for a room (last 50).
pub async fn get_room_timeline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    room_id: &str,
    user_id: &str,
    since: u64, // position counter — 0 means initial sync
) -> Result<Vec<Value>, MatrixError> {
    super::rooms::assert_joined(&mut **tx, room_id, user_id).await?;
    // For initial sync we return the last 50 events.
    // For incremental sync we return events newer than the since position.
    // We use origin_ts as a proxy for position — good enough for MVP.
    let rows = if since == 0 {
        // 2. Wir nutzen query_as! und übergeben EventRow
        sqlx::query_as!(
            EventRow,
            r#"
            SELECT raw_event
            FROM   events
            WHERE  room_id   = $1
            AND    state_key IS NULL
            ORDER  BY origin_ts DESC
            LIMIT  50
            "#,
            room_id,
        )
        .fetch_all(&mut **tx)
        .await?
    } else {
        // 3. Auch hier nutzen wir query_as! mit EventRow
        sqlx::query_as!(
            EventRow,
            r#"
            SELECT raw_event
            FROM   events
            WHERE  room_id    = $1
            AND    state_key  IS NULL
            AND    origin_ts  > $2
            ORDER  BY origin_ts ASC
            "#,
            room_id,
            since as i64,
        )
        .fetch_all(&mut **tx)
        .await?
    };

    let mut events: Vec<Value> = rows
        .into_iter()
        .filter_map(|r| serde_json::from_value(r.raw_event).ok())
        .collect();

    // Initial sync: reverse so oldest-first (Matrix spec requires this)
    if since == 0 {
        events.reverse();
    }

    super::history_visibility::filter_for_user(tx, room_id, events, user_id).await
}
