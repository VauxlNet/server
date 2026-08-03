//! Client information endpoints required by Element for stable operation.
//!
//! These return minimal valid responses. Full implementations come in M3.

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::{auth::AuthenticatedUser, error::MatrixError, state::SharedState};

/// GET /_matrix/client/v3/capabilities
/// Tells Element what the server supports. Empty is valid.
pub async fn capabilities() -> Json<Value> {
    Json(json!({
        "capabilities": {
            "m.change_password": { "enabled": false },
            "m.room_versions": {
                "default":   "11",
                "available": { "11": "stable" }
            },
            "m.set_displayname": { "enabled": true },
            "m.set_avatar_url":  { "enabled": false }
        }
    }))
}

/// GET /_matrix/client/v3/pushrules/
/// Returns empty push rules. Without this Element's sync loop never exits.
pub async fn get_push_rules() -> Json<Value> {
    Json(json!({
        "global": {
            "content":    [],
            "override":   [],
            "room":       [],
            "sender":     [],
            "underride":  []
        }
    }))
}

/// PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}
pub async fn put_push_rule(
    _auth: AuthenticatedUser,
    Path((_scope, _kind, _rule_id)): Path<(String, String, String)>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    Json(json!({}))
}

/// DELETE /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}
pub async fn delete_push_rule(
    _auth: AuthenticatedUser,
    Path((_scope, _kind, _rule_id)): Path<(String, String, String)>,
) -> Json<Value> {
    Json(json!({}))
}

/// GET /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}
pub async fn get_push_rule(
    _auth: AuthenticatedUser,
    Path((_scope, _kind, _rule_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::NotFound)
}

/// GET /_matrix/client/v3/user/{userId}/account_data/{type}
pub async fn get_account_data(
    _auth: AuthenticatedUser,
    Path((_user_id, _event_type)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    // Return empty object — clients handle missing account data gracefully
    Ok(Json(json!({})))
}

/// PUT /_matrix/client/v3/user/{userId}/account_data/{type}
pub async fn put_account_data(
    _auth: AuthenticatedUser,
    Path((_user_id, _event_type)): Path<(String, String)>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    Json(json!({}))
}

/// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn get_room_account_data(
    _auth: AuthenticatedUser,
    Path((_user_id, _room_id, _event_type)): Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    Ok(Json(json!({})))
}

/// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn put_room_account_data(
    _auth: AuthenticatedUser,
    Path((_user_id, _room_id, _event_type)): Path<(String, String, String)>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    Json(json!({}))
}

/// GET /_matrix/client/v3/profile/{userId}
pub async fn get_profile(
    State(state): State<SharedState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let row = sqlx::query!("SELECT display_name FROM users WHERE user_id = $1", user_id,)
        .fetch_optional(&state.db)
        .await
        .map_err(MatrixError::from)?;

    match row {
        Some(r) => Ok(Json(json!({
            "displayname": r.display_name,
            "avatar_url":  null
        }))),
        None => Err(MatrixError::NotFound),
    }
}

/// PUT /_matrix/client/v3/profile/{userId}/displayname
pub async fn set_displayname(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(_user_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let name = body.get("displayname").and_then(|v| v.as_str());
    sqlx::query!(
        "UPDATE users SET display_name = $1 WHERE user_id = $2",
        name,
        auth.user_id,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;
    Ok(Json(json!({})))
}

/// PUT /_matrix/client/v3/profile/{userId}/avatar_url
pub async fn set_avatar_url(
    _auth: AuthenticatedUser,
    Path(_user_id): Path<String>,
    Json(_body): Json<Value>,
) -> Json<Value> {
    Json(json!({}))
}

/// POST /_matrix/client/v3/logout
pub async fn logout(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
) -> Result<Json<Value>, MatrixError> {
    // Delete all tokens for this device
    sqlx::query!(
        "DELETE FROM access_tokens WHERE user_id = $1 AND device_id = $2",
        auth.user_id,
        auth.device_id,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;
    Ok(Json(json!({})))
}

/// POST /_matrix/client/v3/logout/all
pub async fn logout_all(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
) -> Result<Json<Value>, MatrixError> {
    sqlx::query!("DELETE FROM access_tokens WHERE user_id = $1", auth.user_id,)
        .execute(&state.db)
        .await
        .map_err(MatrixError::from)?;
    Ok(Json(json!({})))
}

/// POST /_matrix/client/v3/user/{userId}/filter
pub async fn create_filter(
    _auth: AuthenticatedUser,
    Path(_user_id): Path<String>,
    body: Option<Json<Value>>, // Option so it doesn't fail if body is empty
) -> Json<Value> {
    let _ = body;
    Json(json!({ "filter_id": "1" }))
}

/// GET /_matrix/client/v3/user/{userId}/filter/{filterId}
pub async fn get_filter(
    _auth: AuthenticatedUser,
    Path((_user_id, _filter_id)): Path<(String, String)>,
) -> Json<Value> {
    // Return a permissive filter — accept everything
    Json(json!({
        "room": {
            "timeline":   { "limit": 50 },
            "state":      { "limit": 50 },
            "ephemeral":  { "limit": 50 }
        },
        "presence": {},
        "account_data": {}
    }))
}

/// GET /_matrix/client/v3/account/whoami
pub async fn whoami(State(state): State<SharedState>, auth: AuthenticatedUser) -> Json<Value> {
    Json(json!({
        "user_id":   auth.user_id,
        "device_id": auth.device_id,
        "is_guest":  false,
        "home_server": state.config.server.server_name
    }))
}

/// GET /_matrix/client/v3/room_keys/version
pub async fn room_keys_version(_auth: AuthenticatedUser) -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::NotFound) // intentional — key backup not implemented yet
}

/// GET /_matrix/client/v3/voip/turnServer — not implemented, return empty
pub async fn turn_server(_auth: AuthenticatedUser) -> Result<Json<Value>, MatrixError> {
    Err(MatrixError::NotFound)
}

/// GET /_matrix/client/v3/thirdparty/protocols — return empty
pub async fn third_party_protocols() -> Json<Value> {
    Json(json!({}))
}
