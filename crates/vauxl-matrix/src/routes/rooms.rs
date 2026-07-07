//! Room creation and state management endpoints.
//!
//! POST /_matrix/client/v3/createRoom
//! PUT  /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
//! PUT  /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
//! GET  /_matrix/client/v3/rooms/{roomId}/state
//! GET  /_matrix/client/v3/rooms/{roomId}/members

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedUser,
    db::{
        assert_joined, create_room_with_state, get_full_room_state, put_room_event,
        put_room_state_event,
    },
    error::MatrixError,
    state::SharedState,
};

// ── Create room ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct CreateRoomRequest {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub alias: Option<String>,      // local alias part only
    pub preset: Option<String>,     // private_chat | public_chat | trusted_private_chat
    pub visibility: Option<String>, // public | private (default: private)
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

/// POST /_matrix/client/v3/createRoom
pub async fn create_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Json(body): Json<CreateRoomRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;
    let room_id = generate_room_id(server_name);
    let creator = &auth.user_id;
    let _now_ms = now_millis();

    // Determine join_rules and history_visibility from preset
    let preset = body.preset.as_deref().unwrap_or("private_chat");
    let (join_rule, history_visibility, guest_access) = match preset {
        "public_chat" => ("public", "shared", "forbidden"),
        "trusted_private_chat" => ("invite", "shared", "forbidden"),
        _ => ("invite", "invited", "forbidden"), // private_chat (default)
    };

    // Build mandatory initial state events in the correct order
    let mut state_events: Vec<(String, String, Value)> = vec![
        // 1. m.room.create — must be first
        (
            "m.room.create".into(),
            "".into(),
            json!({
                "creator":      creator,
                "room_version": "11",
                "m.federate":   true
            }),
        ),
        // 2. Creator joins
        (
            "m.room.member".into(),
            creator.clone(),
            json!({
                "membership":   "join",
                "displayname":  null,
                "avatar_url":   null
            }),
        ),
        // 3. Power levels
        (
            "m.room.power_levels".into(),
            "".into(),
            build_power_levels(creator, body.power_level_content_override.as_ref()),
        ),
        // 4. Join rules
        (
            "m.room.join_rules".into(),
            "".into(),
            json!({ "join_rule": join_rule }),
        ),
        // 5. History visibility
        (
            "m.room.history_visibility".into(),
            "".into(),
            json!({ "history_visibility": history_visibility }),
        ),
        // 6. Guest access
        (
            "m.room.guest_access".into(),
            "".into(),
            json!({ "guest_access": guest_access }),
        ),
    ];

    // Optional: room name
    if let Some(name) = &body.name {
        state_events.push(("m.room.name".into(), "".into(), json!({ "name": name })));
    }

    // Optional: room topic
    if let Some(topic) = &body.topic {
        state_events.push(("m.room.topic".into(), "".into(), json!({ "topic": topic })));
    }

    // Optional: encryption (default to m.megolm.v1.aes-sha2 if requested)
    if body
        .initial_state
        .as_ref()
        .is_some_and(|events| events.iter().any(|e| e.event_type == "m.room.encryption"))
    {
        // Caller explicitly set encryption — we'll add it below with initial_state
    }

    // Append caller-provided initial state events
    if let Some(initial) = &body.initial_state {
        for event in initial {
            state_events.push((
                event.event_type.clone(),
                event.state_key.clone().unwrap_or_default(),
                event.content.clone(),
            ));
        }
    }

    // Persist everything atomically
    create_room_with_state(&state.db, &room_id, creator, state_events, server_name).await?;

    tracing::info!(
        room_id   = %room_id,
        creator   = %creator,
        preset    = %preset,
        "Room created"
    );

    Ok(Json(json!({ "room_id": room_id })))
}

// ── Send state event ──────────────────────────────────────────────────────

/// PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}
/// PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
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
    )
    .await?;

    Ok(Json(json!({ "event_id": event_id })))
}

/// PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}
/// (no state key — defaults to empty string)
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
    )
    .await?;

    Ok(Json(json!({ "event_id": event_id })))
}

// ── Send message event ────────────────────────────────────────────────────

/// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
pub async fn send_message_event(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((room_id, event_type, _txn_id)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    // TODO P1-008: deduplicate by txn_id (store in Redis)
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let event_id = put_room_event(
        &state.db,
        &room_id,
        &event_type,
        &auth.user_id,
        content,
        &state.config.server.server_name,
    )
    .await?;

    tracing::debug!(
        room_id    = %room_id,
        event_type = %event_type,
        event_id   = %event_id,
        "Message event sent"
    );

    Ok(Json(json!({ "event_id": event_id })))
}

// ── Read state ────────────────────────────────────────────────────────────

/// GET /_matrix/client/v3/rooms/{roomId}/state
pub async fn get_room_state(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    let events = get_full_room_state(&state.db, &room_id).await?;
    Ok(Json(Value::Array(events)))
}

/// GET /_matrix/client/v3/rooms/{roomId}/members
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

// ── Helpers ───────────────────────────────────────────────────────────────

fn generate_room_id(server_name: &str) -> String {
    let random = &Uuid::new_v4().simple().to_string()[..16];
    format!("!{}:{}", random, server_name)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_power_levels(creator: &str, override_val: Option<&Value>) -> Value {
    let default = json!({
        "ban":           50,
        "events":        {},
        "events_default": 0,
        "invite":        50,
        "kick":          50,
        "notifications": { "room": 20 },
        "redact":        50,
        "state_default": 50,
        "users":         { creator: 100 },
        "users_default": 0
    });

    match override_val {
        Some(ov) => merge_json(default, ov.clone()),
        None => default,
    }
}

fn merge_json(mut base: Value, override_val: Value) -> Value {
    if let (Some(b), Some(o)) = (base.as_object_mut(), override_val.as_object()) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}
