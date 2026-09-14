//! Server-Server (federation) API endpoints.
//!
//! P1-015: Server discovery & key exchange
//! P1-016: Event signing & signature verification
//! P1-017: Federation room join flow
//! P1-018: Event backfill & state resolution
//! P1-019: Sending federation events (/send)

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    db::rooms::{
        create_room_with_state, generate_event_id, get_full_room_state, put_room_state_event,
    },
    error::MatrixError,
    event_signing::{canonical_json, sign_event},
    state::SharedState,
};

// ── P1-015: Key server ────────────────────────────────────────────────────

/// GET /_matrix/key/v2/query/{serverName}
/// Proxy key queries to remote servers and return their keys.
pub async fn key_query_remote(
    State(state): State<SharedState>,
    Path(server_name): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    // If querying ourselves, return our own keys
    if server_name == state.config.server.server_name {
        return key_v2_server_inner(&state);
    }

    // Otherwise fetch from the remote server and return
    // This is used during event verification when we need a remote server's key
    let url = format!("https://{}/_matrix/key/v2/server", server_name);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| MatrixError::Internal(format!("Key fetch failed: {e}")))?;

    let body: Value = resp
        .json()
        .await
        .map_err(|e| MatrixError::Internal(format!("Key parse failed: {e}")))?;

    Ok(Json(body))
}

fn key_v2_server_inner(state: &SharedState) -> Result<Json<Value>, MatrixError> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Ok(Json(json!({
        "server_name":    state.config.server.server_name,
        "valid_until_ts": now_ms + 86_400_000,
        "verify_keys": {
            state.signing_key.key_id.clone(): {
                "key": BASE64.encode(state.signing_key.verifying_key.as_bytes())
            }
        },
        "old_verify_keys": {}
    })))
}

// ── P1-017: Federation join flow (receiving side) ─────────────────────────

/// GET /_matrix/federation/v1/make_join/{roomId}/{userId}
/// Called by a remote server that wants to join one of our rooms.
pub async fn make_join(
    State(state): State<SharedState>,
    Path((room_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Verify room exists
    let room_exists = sqlx::query!("SELECT room_id FROM rooms WHERE room_id = $1", room_id,)
        .fetch_optional(&state.db)
        .await
        .map_err(MatrixError::from)?;

    if room_exists.is_none() {
        return Err(MatrixError::NotFound);
    }

    // Check join rules
    let join_rule = sqlx::query!(
        r#"
        SELECT e.content->>'join_rule' AS join_rule
        FROM room_state rs
        JOIN events e ON e.event_id = rs.event_id
        WHERE rs.room_id = $1 AND rs.event_type = 'm.room.join_rules'
        "#,
        room_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(MatrixError::from)?
    .and_then(|r| r.join_rule)
    .unwrap_or_else(|| "invite".to_string());

    if join_rule != "public" {
        return Err(MatrixError::Forbidden);
    }

    let now_ms = now_millis();
    let _event_id = generate_event_id(server_name);

    // Return a join event template for the remote server to fill in and sign
    let template = json!({
        "type":       "m.room.member",
        "room_id":    room_id,
        "sender":     user_id,
        "state_key":  user_id,
        "origin":     server_name,
        "origin_server_ts": now_ms,
        "content": { "membership": "join" },
        "auth_events":  [],
        "prev_events":  [],
        "depth":        1,
        "room_version": "11"
    });

    Ok(Json(json!({
        "room_version": "11",
        "event":        template
    })))
}

/// PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
/// Remote server sends back the signed join event.
pub async fn send_join(
    State(state): State<SharedState>,
    Path((room_id, _event_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Verify this is actually a join event
    let event_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let membership = body
        .get("content")
        .and_then(|c| c.get("membership"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if event_type != "m.room.member" || membership != "join" {
        return Err(MatrixError::BadJson(
            "Expected m.room.member join event".into(),
        ));
    }

    let joining_user = body
        .get("sender")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MatrixError::BadJson("Missing sender".into()))?
        .to_owned();

    // Verify the origin from Authorization header
    let origin = extract_federation_origin(&headers).unwrap_or_else(|| "unknown".to_string());

    tracing::info!(
        room_id      = %room_id,
        joining_user = %joining_user,
        origin       = %origin,
        "Processing federation join"
    );

    // Store the join membership event
    put_room_state_event(
        &state.db,
        &room_id,
        "m.room.member",
        &joining_user,
        &joining_user,
        json!({ "membership": "join", "displayname": null, "avatar_url": null }),
        server_name,
        &state.signing_key,
    )
    .await?;

    // Return the full room state for the joining server
    let state_events = get_full_room_state(&state.db, &room_id).await?;

    Ok(Json(json!({
        "origin":          server_name,
        "auth_chain":      [],
        "state":           state_events,
        "event":           body,
    })))
}

// ── P1-018: Backfill & state ──────────────────────────────────────────────

/// GET /_matrix/federation/v1/backfill/{roomId}
pub async fn backfill(
    State(state): State<SharedState>,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let rows = sqlx::query!(
        r#"
        SELECT raw_event FROM events
        WHERE  room_id = $1
        ORDER  BY origin_ts DESC
        LIMIT  20
        "#,
        room_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(MatrixError::from)?;

    let events: Vec<Value> = rows
        .into_iter()
        .filter_map(|r| serde_json::from_value(r.raw_event).ok())
        .collect();

    Ok(Json(json!({
        "origin": state.config.server.server_name,
        "pdus":   events
    })))
}

/// GET /_matrix/federation/v1/state/{roomId}
pub async fn federation_room_state(
    State(state): State<SharedState>,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let state_events = get_full_room_state(&state.db, &room_id).await?;

    Ok(Json(json!({
        "pdus":       state_events,
        "auth_chain": []
    })))
}

/// GET /_matrix/federation/v1/state_ids/{roomId}
pub async fn federation_room_state_ids(
    State(state): State<SharedState>,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let rows = sqlx::query!(
        "SELECT event_id FROM room_state WHERE room_id = $1",
        room_id,
    )
    .fetch_all(&state.db)
    .await
    .map_err(MatrixError::from)?;

    let ids: Vec<String> = rows.into_iter().map(|r| r.event_id).collect();

    Ok(Json(json!({
        "pdu_ids":    ids,
        "auth_chain_ids": []
    })))
}

/// GET /_matrix/federation/v1/event/{eventId}
pub async fn get_event(
    State(state): State<SharedState>,
    Path(event_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let row = sqlx::query!("SELECT raw_event FROM events WHERE event_id = $1", event_id,)
        .fetch_optional(&state.db)
        .await
        .map_err(MatrixError::from)?
        .ok_or(MatrixError::NotFound)?;

    let event: Value =
        serde_json::from_value(row.raw_event).map_err(|e| MatrixError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "origin": state.config.server.server_name,
        "pdus":   [event]
    })))
}

// ── P1-019: Receiving federation events (/send) ───────────────────────────

/// PUT /_matrix/federation/v1/send/{txnId}
/// Receive PDUs (events) from remote servers.
pub async fn federation_send(
    State(state): State<SharedState>,
    Path(txn_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let origin = extract_federation_origin(&headers).unwrap_or_else(|| "unknown".to_string());

    let pdus = body
        .get("pdus")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    tracing::debug!(
        origin  = %origin,
        txn_id  = %txn_id,
        count   = pdus.len(),
        "Received federation transaction"
    );

    let mut results = HashMap::new();

    for pdu in &pdus {
        let event_id = pdu
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();

        match process_incoming_pdu(&state, pdu, &origin).await {
            Ok(()) => {
                results.insert(event_id, json!({}));
            }
            Err(e) => {
                tracing::warn!(event_id = %event_id, error = %e, "PDU rejected");
                results.insert(
                    event_id,
                    json!({
                        "error": e.to_string()
                    }),
                );
            }
        }
    }

    Ok(Json(json!({ "pdus": results })))
}

async fn process_incoming_pdu(
    state: &SharedState,
    pdu: &Value,
    origin: &str,
) -> Result<(), MatrixError> {
    let event_type = pdu.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let room_id = pdu.get("room_id").and_then(|v| v.as_str()).unwrap_or("");
    let sender = pdu.get("sender").and_then(|v| v.as_str()).unwrap_or("");
    let event_id = pdu.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
    let content = pdu.get("content").cloned().unwrap_or(json!({}));
    let origin_ts = pdu
        .get("origin_server_ts")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let state_key = pdu.get("state_key").and_then(|v| v.as_str());

    // Skip if we already have this event
    let exists = sqlx::query!(
        "SELECT 1 AS exists FROM events WHERE event_id = $1",
        event_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(MatrixError::from)?;

    if exists.is_some() {
        return Ok(());
    }

    // Basic validation — sender must be from the origin server
    let sender_server = sender.split(':').nth(1).unwrap_or("");
    if sender_server != origin {
        return Err(MatrixError::Forbidden);
    }

    // Store the event
    sqlx::query!(
        r#"
        INSERT INTO events
            (event_id, room_id, event_type, state_key, sender, origin_ts, content, raw_event)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (event_id) DO NOTHING
        "#,
        event_id,
        room_id,
        event_type,
        state_key,
        sender,
        origin_ts,
        content,
        pdu,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;

    // Update state if this is a state event
    if let Some(sk) = state_key {
        sqlx::query!(
            r#"
            INSERT INTO room_state (room_id, event_type, state_key, event_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (room_id, event_type, state_key)
            DO UPDATE SET event_id = EXCLUDED.event_id
            "#,
            room_id,
            event_type,
            sk,
            event_id,
        )
        .execute(&state.db)
        .await
        .map_err(MatrixError::from)?;

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
                sk,
                membership,
            )
            .execute(&state.db)
            .await
            .map_err(MatrixError::from)?;
        }
    }

    // Wake /sync handlers so local users see the new event
    let _ = state.wake_tx.send(crate::state::WakeEvent {
        room_id: room_id.to_owned(),
    });

    tracing::debug!(event_id = %event_id, event_type = %event_type, "PDU stored");
    Ok(())
}

// ── Federation join (outgoing) ────────────────────────────────────────────

/// Join a room on a remote server.
/// Called when a local user wants to join a room that lives on another homeserver.
pub async fn join_remote_room(
    state: &SharedState,
    room_id: &str,
    user_id: &str,
) -> Result<(), MatrixError> {
    let server_name = &state.config.server.server_name;

    // Extract the remote server from the room ID
    let remote_server = room_id
        .split(':')
        .nth(1)
        .ok_or_else(|| MatrixError::BadJson("Invalid room ID".into()))?;

    if remote_server == server_name {
        return Err(MatrixError::BadJson("Room is local".into()));
    }

    tracing::info!(
        room_id       = %room_id,
        user_id       = %user_id,
        remote_server = %remote_server,
        "Initiating federation room join"
    );

    let client = reqwest::Client::new();
    let resolved = vauxl_federation::resolver::resolve_server_name(remote_server).await;

    // Step 1: make_join — get the join event template
    let make_join_url = format!(
        "https://{}:{}/_matrix/federation/v1/make_join/{}/{}",
        resolved.host,
        resolved.port,
        urlencoding::encode(room_id),
        urlencoding::encode(user_id),
    );

    let make_join_resp = client
        .get(&make_join_url)
        .send()
        .await
        .map_err(|e| MatrixError::Internal(format!("make_join failed: {e}")))?;

    if !make_join_resp.status().is_success() {
        return Err(MatrixError::Internal(format!(
            "make_join returned {}",
            make_join_resp.status()
        )));
    }

    let make_join_body: Value = make_join_resp
        .json()
        .await
        .map_err(|e| MatrixError::Internal(format!("make_join parse: {e}")))?;

    let mut join_event = make_join_body
        .get("event")
        .cloned()
        .ok_or_else(|| MatrixError::Internal("No event in make_join response".into()))?;

    // Step 2: fill in and sign the event
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let event_id = generate_event_id(server_name);

    if let Some(obj) = join_event.as_object_mut() {
        obj.insert("event_id".into(), json!(event_id));
        obj.insert("origin".into(), json!(server_name));
        obj.insert("origin_server_ts".into(), json!(now_ms));
        obj.insert("sender".into(), json!(user_id));
        obj.insert("state_key".into(), json!(user_id));
        obj.insert("content".into(), json!({"membership": "join"}));
    }

    sign_event(&mut join_event, server_name, &state.signing_key);

    // Step 3: send_join — submit the signed event
    let send_join_url = format!(
        "https://{}:{}/_matrix/federation/v2/send_join/{}/{}",
        resolved.host,
        resolved.port,
        urlencoding::encode(room_id),
        urlencoding::encode(&event_id),
    );

    let send_join_resp = client
        .put(&send_join_url)
        .json(&join_event)
        .send()
        .await
        .map_err(|e| MatrixError::Internal(format!("send_join failed: {e}")))?;

    if !send_join_resp.status().is_success() {
        return Err(MatrixError::Internal(format!(
            "send_join returned {}",
            send_join_resp.status()
        )));
    }

    let send_join_body: Value = send_join_resp
        .json()
        .await
        .map_err(|e| MatrixError::Internal(format!("send_join parse: {e}")))?;

    // Step 4 & 5: store room state from response
    let room_exists = sqlx::query!("SELECT 1 AS exists FROM rooms WHERE room_id = $1", room_id,)
        .fetch_optional(&state.db)
        .await
        .map_err(MatrixError::from)?;

    if room_exists.is_none() {
        sqlx::query!("INSERT INTO rooms (room_id) VALUES ($1)", room_id)
            .execute(&state.db)
            .await
            .map_err(MatrixError::from)?;
    }

    // Import state events from the remote server
    if let Some(state_events) = send_join_body.get("state").and_then(|v| v.as_array()) {
        for event in state_events {
            let _ = process_incoming_pdu(state, event, remote_server).await;
        }
    }

    // Mark local user as joined
    sqlx::query!(
        r#"
        INSERT INTO room_members (room_id, user_id, membership)
        VALUES ($1, $2, 'join')
        ON CONFLICT (room_id, user_id) DO UPDATE SET membership = 'join'
        "#,
        room_id,
        user_id,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;

    tracing::info!(
        room_id = %room_id,
        user_id = %user_id,
        "Federation join completed"
    );

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Extract the origin server from the X-Matrix Authorization header.
pub fn extract_federation_origin(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    if !auth.starts_with("X-Matrix ") {
        return None;
    }

    // Parse: X-Matrix origin="server",destination="...",key="...",sig="..."
    for part in auth[9..].split(',') {
        let part = part.trim();
        if let Some(val) = part
            .strip_prefix("origin=")
            .or(part.strip_prefix("origin=\""))
        {
            return Some(val.trim_matches('"').to_owned());
        }
    }
    None
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
