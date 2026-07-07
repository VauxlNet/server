//! Room join, leave, and invite endpoints.
//!
//! POST /_matrix/client/v3/join/{roomIdOrAlias}
//! POST /_matrix/client/v3/rooms/{roomId}/join
//! POST /_matrix/client/v3/rooms/{roomId}/leave
//! POST /_matrix/client/v3/rooms/{roomId}/invite
//! POST /_matrix/client/v3/rooms/{roomId}/kick
//! POST /_matrix/client/v3/rooms/{roomId}/ban

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::AuthenticatedUser,
    db::{
        assert_joined, get_join_rule, get_membership, resolve_room_alias, room_exists,
        set_membership, store_invite_notification,
    },
    error::MatrixError,
    state::SharedState,
};

// ── Join ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct JoinRequest {
    pub reason: Option<String>,
    pub third_party_signed: Option<Value>, // ignored in MVP
}

/// POST /_matrix/client/v3/join/{roomIdOrAlias}
pub async fn join_room_by_id_or_alias(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id_or_alias): Path<String>,
    Json(_body): Json<JoinRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Resolve alias to room_id if needed
    let room_id = if room_id_or_alias.starts_with('#') {
        resolve_room_alias(&state.db, &room_id_or_alias)
            .await?
            .ok_or(MatrixError::NotFound)?
    } else {
        room_id_or_alias.clone()
    };

    join_room_inner(&state, &auth.user_id, &room_id, server_name).await?;

    Ok(Json(json!({ "room_id": room_id })))
}

/// POST /_matrix/client/v3/rooms/{roomId}/join
pub async fn join_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
    Json(_body): Json<JoinRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;
    join_room_inner(&state, &auth.user_id, &room_id, server_name).await?;
    Ok(Json(json!({ "room_id": room_id })))
}

async fn join_room_inner(
    state: &crate::state::AppState,
    user_id: &str,
    room_id: &str,
    server_name: &str,
) -> Result<(), MatrixError> {
    // Room must exist
    if !room_exists(&state.db, room_id).await? {
        return Err(MatrixError::NotFound);
    }

    // Already joined — idempotent, just return ok
    if get_membership(&state.db, room_id, user_id).await? == Some("join".into()) {
        return Ok(());
    }

    // Check join rules
    let join_rule = get_join_rule(&state.db, room_id).await?;
    match join_rule.as_str() {
        "public" => {
            // Anyone can join
        }
        "invite" => {
            // Must have a pending invite
            let membership = get_membership(&state.db, room_id, user_id).await?;
            if membership.as_deref() != Some("invite") {
                return Err(MatrixError::Forbidden);
            }
        }
        _ => return Err(MatrixError::Forbidden),
    }

    set_membership(
        &state.db,
        room_id,
        user_id,
        user_id, // sender = the user joining themselves
        "join",
        None,
        server_name,
    )
    .await?;

    tracing::info!(user_id = %user_id, room_id = %room_id, "User joined room");
    Ok(())
}

// ── Leave ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct LeaveRequest {
    pub reason: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/leave
pub async fn leave_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
    Json(_body): Json<LeaveRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Must be joined or invited to leave
    let membership = get_membership(&state.db, &room_id, &auth.user_id).await?;
    match membership.as_deref() {
        Some("join") | Some("invite") => {}
        _ => return Err(MatrixError::Forbidden),
    }

    set_membership(
        &state.db,
        &room_id,
        &auth.user_id,
        &auth.user_id,
        "leave",
        None,
        server_name,
    )
    .await?;

    tracing::info!(
        user_id = %auth.user_id,
        room_id = %room_id,
        "User left room"
    );

    Ok(Json(json!({})))
}

// ── Invite ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/invite
pub async fn invite_to_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
    Json(body): Json<InviteRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Inviter must be joined
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    // Don't double-invite
    let existing = get_membership(&state.db, &room_id, &body.user_id).await?;
    if existing.as_deref() == Some("invite") || existing.as_deref() == Some("join") {
        return Ok(Json(json!({})));
    }

    // Write the invite membership event
    set_membership(
        &state.db,
        &room_id,
        &body.user_id,
        &auth.user_id, // sender = the inviter
        "invite",
        None,
        server_name,
    )
    .await?;

    // Notify the invitee via to_device so they see it on next /sync
    let is_local = body.user_id.ends_with(&format!(":{}", server_name));
    if is_local {
        store_invite_notification(&state.db, &body.user_id, &room_id, &auth.user_id).await?;
    }
    // Remote users: federation invite — deferred to P1-M4

    tracing::info!(
        inviter   = %auth.user_id,
        invitee   = %body.user_id,
        room_id   = %room_id,
        "User invited to room"
    );

    Ok(Json(json!({})))
}

// ── Kick ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct KickRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/kick
pub async fn kick_from_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
    Json(body): Json<KickRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Kicker must be joined
    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    // Target must be joined
    if get_membership(&state.db, &room_id, &body.user_id)
        .await?
        .as_deref()
        != Some("join")
    {
        return Err(MatrixError::Forbidden);
    }

    set_membership(
        &state.db,
        &room_id,
        &body.user_id,
        &auth.user_id, // sender = the kicker
        "leave",
        None,
        server_name,
    )
    .await?;

    tracing::info!(
        kicker  = %auth.user_id,
        kicked  = %body.user_id,
        room_id = %room_id,
        "User kicked from room"
    );

    Ok(Json(json!({})))
}

// ── Ban ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BanRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/ban
pub async fn ban_from_room(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path(room_id): Path<String>,
    Json(body): Json<BanRequest>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    assert_joined(&state.db, &room_id, &auth.user_id).await?;

    set_membership(
        &state.db,
        &room_id,
        &body.user_id,
        &auth.user_id,
        "ban",
        None,
        server_name,
    )
    .await?;

    tracing::info!(
        banner  = %auth.user_id,
        banned  = %body.user_id,
        room_id = %room_id,
        "User banned from room"
    );

    Ok(Json(json!({})))
}
