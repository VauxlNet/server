//! Room creation and state management endpoints.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedUser,
    db::{
        assert_joined, check_and_store_txn, create_room_with_state, get_full_room_state,
        get_room_messages, put_room_event, put_room_state_event,
    },
    error::MatrixError,
    state::SharedState,
};

#[derive(Debug, Deserialize, Default)]
pub struct CreateRoomRequest {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub alias: Option<String>,
    pub preset: Option<String>,
    pub visibility: Option<String>,
    pub invite: Option<Vec<String>>,
    pub is_direct: Option<bool>,
    pub initial_state: Option<Vec<InitialStateEvent>>,
    pub power_level_content_override: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct InitialStateEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub state_key: Option<String>,
    pub content: Value,
}

pub async fn create_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Json(body): Json<CreateRoomRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;
    let room_id = generate_room_id(server_name);
    let creator = &auth.user_id;

    let preset = body.preset.as_deref().unwrap_or("private_chat");
    let (join_rule, history_visibility, guest_access) = match preset {
        "public_chat" => ("public", "shared", "forbidden"),
        "trusted_private_chat" => ("invite", "shared", "forbidden"),
        _ => ("invite", "invited", "forbidden"),
    };

    let mut state_events: Vec<(String, String, Value)> = vec![
        (
            "m.room.create".into(),
            "".into(),
            json!({
                "creator": creator, "room_version": "11", "m.federate": true
            }),
        ),
        (
            "m.room.member".into(),
            creator.clone(),
            json!({
                "membership": "join", "displayname": null, "avatar_url": null
            }),
        ),
        (
            "m.room.power_levels".into(),
            "".into(),
            build_power_levels(creator, body.power_level_content_override.as_ref()),
        ),
        (
            "m.room.join_rules".into(),
            "".into(),
            json!({"join_rule": join_rule}),
        ),
        (
            "m.room.history_visibility".into(),
            "".into(),
            json!({"history_visibility": history_visibility}),
        ),
        (
            "m.room.guest_access".into(),
            "".into(),
            json!({"guest_access": guest_access}),
        ),
    ];

    if let Some(name) = &body.name {
        state_events.push(("m.room.name".into(), "".into(), json!({"name": name})));
    }
    if let Some(topic) = &body.topic {
        state_events.push(("m.room.topic".into(), "".into(), json!({"topic": topic})));
    }
    if let Some(initial) = &body.initial_state {
        for e in initial {
            state_events.push((
                e.event_type.clone(),
                e.state_key.clone().unwrap_or_default(),
                e.content.clone(),
            ));
        }
    }

    create_room_with_state(
        &state.db,
        &room_id,
        creator,
        state_events,
        server_name,
        &state.signing_key,
    )
    .await?;

    tracing::info!(room_id = %room_id, creator = %creator, "Room created");
    Ok(Json(json!({ "room_id": room_id })))
}

pub async fn send_state_event(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let event_id = put_room_state_event(
        &state.db,
        &room_id,
        &event_type,
        &state_key,
        &auth.user_id,
        content,
        &state.config.server.server_name,
        &state.signing_key,
    )
    .await?;

    let _ = state.wake_tx.send(());
    Ok(Json(json!({ "event_id": event_id })))
}

pub async fn send_state_event_no_key(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, event_type)): Path<(String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let event_id = put_room_state_event(
        &state.db,
        &room_id,
        &event_type,
        "",
        &auth.user_id,
        content,
        &state.config.server.server_name,
        &state.signing_key,
    )
    .await?;

    let _ = state.wake_tx.send(());
    Ok(Json(json!({ "event_id": event_id })))
}

pub async fn send_message_event(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, event_type, txn_id)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let is_new = check_and_store_txn(&state.db, &auth.user_id, &auth.device_id, &txn_id).await?;

    if !is_new {
        tracing::debug!(txn_id = %txn_id, "Duplicate txn — skipping");
        return Ok(Json(json!({ "event_id": format!("$dup:{}", txn_id) })));
    }

    let event_id = put_room_event(
        &state.db,
        &room_id,
        &event_type,
        &auth.user_id,
        content,
        &state.config.server.server_name,
        &state.signing_key,
    )
    .await?;

    // Wake any long-polling /sync handlers.
    let _ = state.wake_tx.send(());

    tracing::debug!(room_id = %room_id, event_id = %event_id, "Message sent");
    Ok(Json(json!({ "event_id": event_id })))
}

pub async fn get_room_state(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;
    let events = get_full_room_state(&state.db, &room_id).await?;
    Ok(Json(Value::Array(events)))
}

pub async fn get_room_members(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let rows = sqlx::query!(
        r#"
        SELECT e.raw_event
        FROM   room_state rs
        JOIN   events e ON e.event_id = rs.event_id
        WHERE  rs.room_id    = $1
        AND    rs.event_type = 'm.room.member'
        "#,
        room_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(MatrixError::from)?;

    let members: Vec<Value> = rows
        .into_iter()
        .filter_map(|r| serde_json::from_value(r.raw_event).ok())
        .collect();

    Ok(Json(json!({ "chunk": members })))
}

// ── GET /rooms/{id}/messages ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MessagesQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub dir: Option<String>, // "f" or "b" — default "b"
    pub limit: Option<i64>,
    pub filter: Option<String>,
}

pub async fn get_room_messages_handler(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let dir = query.dir.as_deref().unwrap_or("b");
    let limit = query.limit.unwrap_or(10).clamp(1, 100);

    let (events, end) = get_room_messages(
        &state.db,
        &room_id,
        query.from.as_deref(),
        query.to.as_deref(),
        dir,
        limit,
    )
    .await?;

    let start_token = query.from.clone().unwrap_or_else(|| "t0".into());

    Ok(Json(json!({
        "start":  start_token,
        "end":    end,
        "chunk":  events,
        "state":  []
    })))
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn generate_room_id(server_name: &str) -> String {
    format!(
        "!{}:{}",
        &Uuid::new_v4().simple().to_string()[..16],
        server_name
    )
}

fn build_power_levels(creator: &str, override_val: Option<&Value>) -> Value {
    let default = json!({
        "ban": 50, "events": {}, "events_default": 0,
        "invite": 50, "kick": 50,
        "notifications": {"room": 20},
        "redact": 50, "state_default": 50,
        "users": {creator: 100}, "users_default": 0
    });
    match override_val {
        Some(ov) => merge_json(default, ov.clone()),
        None => default,
    }
}

fn merge_json(mut base: Value, ov: Value) -> Value {
    if let (Some(b), Some(o)) = (base.as_object_mut(), ov.as_object()) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}
