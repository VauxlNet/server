//! Server-Server (federation) API endpoints.
//!
//! P1-015: Server discovery & key exchange
//! P1-016: Event signing & signature verification
//! P1-017: Federation room join flow
//! P1-018: Event backfill & state resolution
//! P1-019: Sending federation events (/send)

use axum::{
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, Method},
    Json,
};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    db::{
        history_visibility::filter_for_server,
        room_auth::{authorize_event, lock_room},
        rooms::{get_full_room_state, populate_event_auth},
    },
    error::MatrixError,
    federation_auth::{authenticate, verify_event, with_event_id},
    state::SharedState,
};

// ── P1-015: Key server ────────────────────────────────────────────────────

/// GET /_matrix/key/v2/query/{serverName}
/// Proxy key queries to remote servers and return their keys.
pub async fn key_query_remote(
    State(state): State<SharedState>,
    Path(server_name): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if server_name == state.config.server.server_name {
        return crate::well_known::key_v2_server(State(state)).await;
    }
    if !is_valid_server_name(&server_name) {
        return Err(MatrixError::BadJson("Invalid server name".into()));
    }
    let document = vauxl_federation::keys::fetch_key_document(&server_name)
        .await
        .map_err(|_| MatrixError::Forbidden)?;
    Ok(Json(document))
}

// ── P1-017: Federation join flow (receiving side) ─────────────────────────

/// GET /_matrix/federation/v1/make_join/{roomId}/{userId}
/// Called by a remote server that wants to join one of our rooms.
pub async fn make_join(
    State(state): State<SharedState>,
    Path((room_id, user_id)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, None).await?;

    if !is_valid_room_id(&room_id) || !is_valid_user_id(&user_id) {
        return Err(MatrixError::BadJson("Invalid room or user ID".into()));
    }
    if user_server_name(&user_id) != Some(origin.as_str()) {
        return Err(MatrixError::Forbidden);
    }

    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, &room_id).await?;
    require_federated_room(&mut *tx, &room_id).await?;
    require_server_acl(&mut *tx, &room_id, &origin).await?;
    authorize_event(
        &mut tx,
        &room_id,
        &user_id,
        "m.room.member",
        Some(&user_id),
        &json!({"membership":"join"}),
    )
    .await?;

    let now_ms = now_millis();
    // Return a join event template for the remote server to fill in and sign
    let mut template = json!({
        "type":       "m.room.member",
        "room_id":    room_id,
        "sender":     user_id,
        "state_key":  user_id,
        "origin":     origin,
        "origin_server_ts": now_ms,
        "content": { "membership": "join" },
        "auth_events":  [],
        "prev_events":  [],
        "depth":        1,
        "room_version": "11"
    });

    populate_event_auth(&mut tx, &room_id, &mut template).await?;
    tx.commit().await?;

    Ok(Json(json!({
        "room_version": "11",
        "event":        template
    })))
}

/// PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
/// Remote server sends back the signed join event.
pub async fn send_join(
    State(state): State<SharedState>,
    Path((room_id, event_id)): Path<(String, String)>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, Some(&body)).await?;
    let body = with_event_id(&body)?;
    if user_server_name(required_string(&body, "sender")?) != Some(origin.as_str()) {
        return Err(MatrixError::Forbidden);
    }
    if body.get("room_id").and_then(Value::as_str) != Some(&room_id)
        || body.get("event_id").and_then(Value::as_str) != Some(&event_id)
        || body.get("type").and_then(Value::as_str) != Some("m.room.member")
        || body
            .get("content")
            .and_then(|v| v.get("membership"))
            .and_then(Value::as_str)
            != Some("join")
        || body.get("sender") != body.get("state_key")
    {
        return Err(MatrixError::BadJson(
            "Expected matching self-join event".into(),
        ));
    }
    process_incoming_pdu(&state, &body, &origin, true).await?;
    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, &room_id).await?;
    require_federated_room(&mut *tx, &room_id).await?;
    require_server_acl(&mut *tx, &room_id, &origin).await?;
    require_server_participation(&mut *tx, &room_id, &origin).await?;
    let state_events = get_full_room_state(&mut *tx, &room_id).await?;
    let state_events: Vec<Value> = state_events.into_iter().map(wire_pdu).collect();
    Ok(Json(
        json!({"origin":state.config.server.server_name, "auth_chain":[], "state":state_events, "event":wire_pdu(body)}),
    ))
}

// ── P1-018: Backfill & state ──────────────────────────────────────────────

/// GET /_matrix/federation/v1/backfill/{roomId}
pub async fn backfill(
    State(state): State<SharedState>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, None).await?;
    if !is_valid_room_id(&room_id) {
        return Err(MatrixError::BadJson("Invalid room ID".into()));
    }

    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, &room_id).await?;
    require_federated_room(&mut *tx, &room_id).await?;
    require_server_acl(&mut *tx, &room_id, &origin).await?;
    require_server_participation(&mut *tx, &room_id, &origin).await?;

    let rows = sqlx::query!(
        r#"
        SELECT raw_event FROM events
        WHERE  room_id = $1
        ORDER  BY origin_ts DESC
        LIMIT  20
        "#,
        room_id,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(MatrixError::from)?;

    let events: Vec<Value> = rows
        .into_iter()
        .filter_map(|r| serde_json::from_value(r.raw_event).ok())
        .collect();
    let events = filter_for_server(&mut tx, &room_id, events, &origin).await?;
    let events: Vec<Value> = events.into_iter().map(wire_pdu).collect();

    Ok(Json(json!({
        "origin": state.config.server.server_name,
        "pdus":   events
    })))
}

/// GET /_matrix/federation/v1/state/{roomId}
pub async fn federation_room_state(
    State(state): State<SharedState>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, None).await?;
    reject_historical_state_query(&uri)?;
    if !is_valid_room_id(&room_id) {
        return Err(MatrixError::BadJson("Invalid room ID".into()));
    }

    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, &room_id).await?;
    require_federated_room(&mut *tx, &room_id).await?;
    require_server_acl(&mut *tx, &room_id, &origin).await?;
    require_server_participation(&mut *tx, &room_id, &origin).await?;

    let state_events = get_full_room_state(&mut *tx, &room_id).await?;
    let state_events: Vec<Value> = state_events.into_iter().map(wire_pdu).collect();

    Ok(Json(json!({
        "pdus":       state_events,
        "auth_chain": []
    })))
}

/// GET /_matrix/federation/v1/state_ids/{roomId}
pub async fn federation_room_state_ids(
    State(state): State<SharedState>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, None).await?;
    reject_historical_state_query(&uri)?;
    if !is_valid_room_id(&room_id) {
        return Err(MatrixError::BadJson("Invalid room ID".into()));
    }

    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, &room_id).await?;
    require_federated_room(&mut *tx, &room_id).await?;
    require_server_acl(&mut *tx, &room_id, &origin).await?;
    require_server_participation(&mut *tx, &room_id, &origin).await?;

    let ids: Vec<String> = sqlx::query_scalar("SELECT event_id FROM room_state WHERE room_id = $1")
        .bind(&room_id)
        .fetch_all(&mut *tx)
        .await?;

    Ok(Json(json!({
        "pdu_ids":    ids,
        "auth_chain_ids": []
    })))
}

/// GET /_matrix/federation/v1/event/{eventId}
pub async fn get_event(
    State(state): State<SharedState>,
    Path(event_id): Path<String>,
    headers: HeaderMap,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, None).await?;
    if event_id.is_empty() || !is_safe_identifier(&event_id) {
        return Err(MatrixError::BadJson("Invalid event ID".into()));
    }

    let room_id: String = sqlx::query_scalar("SELECT room_id FROM events WHERE event_id = $1")
        .bind(&event_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(MatrixError::NotFound)?;
    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, &room_id).await?;
    require_federated_room(&mut *tx, &room_id).await?;
    require_server_acl(&mut *tx, &room_id, &origin).await?;
    require_server_participation(&mut *tx, &room_id, &origin).await?;

    let row = sqlx::query!("SELECT raw_event FROM events WHERE event_id = $1", event_id,)
        .fetch_optional(&mut *tx)
        .await
        .map_err(MatrixError::from)?
        .ok_or(MatrixError::NotFound)?;

    let event: Value =
        serde_json::from_value(row.raw_event).map_err(|e| MatrixError::Internal(e.to_string()))?;

    let mut events = filter_for_server(&mut tx, &room_id, vec![event], &origin).await?;
    let event = wire_pdu(events.pop().ok_or(MatrixError::Forbidden)?);
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let origin = authenticate(&state, &headers, &method, &uri, Some(&body)).await?;

    if body
        .get("origin")
        .is_some_and(|value| value.as_str() != Some(&origin))
    {
        return Err(MatrixError::Forbidden);
    }
    let pdus = body
        .get("pdus")
        .and_then(|v| v.as_array())
        .cloned()
        .ok_or_else(|| MatrixError::BadJson("Missing pdus array".into()))?;

    if pdus.len() > 50 {
        return Err(MatrixError::BadJson("Too many PDUs".into()));
    }

    tracing::debug!(
        origin  = %origin,
        txn_id  = %txn_id,
        count   = pdus.len(),
        "Received federation transaction"
    );

    let mut results = HashMap::new();

    for pdu in &pdus {
        let normalized = with_event_id(pdu);
        let pdu = normalized.as_ref().unwrap_or(pdu);
        let event_id = pdu
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();

        match process_incoming_pdu(&state, pdu, &origin, false).await {
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
    state: &crate::state::AppState,
    pdu: &Value,
    origin: &str,
    joining: bool,
) -> Result<(), MatrixError> {
    let event_type = required_string(pdu, "type")?;
    let room_id = required_string(pdu, "room_id")?;
    let sender = required_string(pdu, "sender")?;
    let event_id = required_string(pdu, "event_id")?;
    let content = pdu
        .get("content")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| MatrixError::BadJson("Missing object content".into()))?;
    let origin_ts = pdu
        .get("origin_server_ts")
        .and_then(|v| v.as_i64())
        .filter(|timestamp| *timestamp >= 0)
        .ok_or_else(|| MatrixError::BadJson("Missing origin_server_ts".into()))?;
    let state_key = match pdu.get("state_key") {
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err(MatrixError::BadJson("Invalid state_key".into())),
        None => None,
    };

    if !is_valid_room_id(room_id)
        || !is_safe_identifier(event_type)
        || !is_valid_user_id(sender)
        || !is_safe_identifier(event_id)
    {
        return Err(MatrixError::BadJson("Invalid event fields".into()));
    }
    verify_event(state, pdu).await?;
    let mut tx = state.db.begin().await?;
    lock_room(&mut tx, room_id).await?;
    require_federated_room(&mut *tx, room_id).await?;
    require_server_acl(&mut *tx, room_id, origin).await?;
    require_server_acl(
        &mut *tx,
        room_id,
        user_server_name(sender).ok_or(MatrixError::Forbidden)?,
    )
    .await?;
    if !joining {
        require_server_participation(&mut *tx, room_id, origin).await?;
    }
    authorize_event(&mut tx, room_id, sender, event_type, state_key, &content).await?;

    // Skip if we already have this event
    let exists = sqlx::query!(
        "SELECT 1 AS exists FROM events WHERE event_id = $1",
        event_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(MatrixError::from)?;

    if exists.is_some() {
        return Ok(());
    }

    require_current_event_auth(&mut tx, room_id, pdu).await?;

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
    .execute(&mut *tx)
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
        .execute(&mut *tx)
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
            .execute(&mut *tx)
            .await
            .map_err(MatrixError::from)?;
        }
    }

    tx.commit().await?;

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
    _state: &crate::state::AppState,
    _room_id: &str,
    _user_id: &str,
) -> Result<(), MatrixError> {
    Err(MatrixError::BadJson("Remote room bootstrap requires auth-chain validation and state resolution, which are not supported yet".into()))
}

/// V11 reference IDs belong to the storage/client representation, not the signed
/// wire PDU. Strip them at every federation response boundary.
fn wire_pdu(mut event: Value) -> Value {
    if let Some(object) = event.as_object_mut() {
        object.remove("event_id");
    }
    event
}

fn reject_historical_state_query(uri: &axum::http::Uri) -> Result<(), MatrixError> {
    let query: Vec<(String, String)> = serde_urlencoded::from_str(uri.query().unwrap_or_default())
        .map_err(|_| MatrixError::BadJson("Invalid state query".into()))?;
    if query.iter().any(|(key, _)| key == "event_id") {
        return Err(MatrixError::BadJson(
            "Historical state reconstruction is not supported".into(),
        ));
    }
    Ok(())
}

fn acl_allows(content: Value, server: &str) -> Result<bool, MatrixError> {
    if !is_valid_server_name(server) {
        return Ok(false);
    }
    let mut acl: ruma::events::room::server_acl::RoomServerAclEventContent =
        serde_json::from_value(content).map_err(|_| MatrixError::Forbidden)?;
    // Matrix server ACL matching is case-insensitive and ignores ports. Ruma
    // handles host/port/IP semantics; normalize case before its glob matching.
    for pattern in acl.allow.iter_mut().chain(acl.deny.iter_mut()) {
        pattern.make_ascii_lowercase();
    }
    let server = server.to_ascii_lowercase();
    let server =
        <&ruma::ServerName>::try_from(server.as_str()).map_err(|_| MatrixError::Forbidden)?;
    Ok(acl.is_allowed(server))
}

async fn require_server_acl<'e, E>(db: E, room_id: &str, server: &str) -> Result<(), MatrixError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let content: Option<Value> = sqlx::query_scalar("SELECT e.content FROM room_state rs JOIN events e ON e.event_id = rs.event_id WHERE rs.room_id = $1 AND rs.event_type = 'm.room.server_acl' AND rs.state_key = ''")
        .bind(room_id).fetch_optional(db).await?;
    if let Some(content) = content {
        if !acl_allows(content, server)? {
            return Err(MatrixError::Forbidden);
        }
    }
    Ok(())
}

async fn require_federated_room<'e, E>(db: E, room_id: &str) -> Result<(), MatrixError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let create: Option<Value> = sqlx::query_scalar("SELECT e.content FROM room_state rs JOIN events e ON e.event_id = rs.event_id WHERE rs.room_id = $1 AND rs.event_type = 'm.room.create' AND rs.state_key = ''")
        .bind(room_id).fetch_optional(db).await?;
    let create = create.ok_or(MatrixError::Forbidden)?;
    if create
        .get("m.federate")
        .is_some_and(|value| value != &Value::Bool(true))
    {
        return Err(MatrixError::Forbidden);
    }
    Ok(())
}

async fn require_server_participation<'e, E>(
    db: E,
    room_id: &str,
    origin: &str,
) -> Result<(), MatrixError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let users: Vec<String> = sqlx::query_scalar(
        "SELECT user_id FROM room_members WHERE room_id = $1 AND membership = 'join'",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?;
    if !users
        .iter()
        .any(|user| user_server_name(user) == Some(origin))
    {
        return Err(MatrixError::Forbidden);
    }
    Ok(())
}

/// Until DAG auth-chain/state resolution exists, accept only events extending the
/// locally known predecessor and authenticated current state. Reject stale forks.
async fn require_current_event_auth(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    room_id: &str,
    event: &Value,
) -> Result<(), MatrixError> {
    let mut expected = event.clone();
    populate_event_auth(tx, room_id, &mut expected).await?;
    for field in ["prev_events", "auth_events"] {
        let ids = |value: &Value| -> Option<std::collections::BTreeSet<String>> {
            let array = value.get(field)?.as_array()?;
            let ids: std::collections::BTreeSet<String> = array
                .iter()
                .map(|id| id.as_str().map(str::to_owned))
                .collect::<Option<_>>()?;
            (ids.len() == array.len()).then_some(ids)
        };
        if ids(event).is_none() || ids(event) != ids(&expected) {
            return Err(MatrixError::Forbidden);
        }
    }
    if event.get("depth") != expected.get("depth") {
        return Err(MatrixError::Forbidden);
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, MatrixError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MatrixError::BadJson(format!("Missing {field}")))
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn is_valid_server_name(value: &str) -> bool {
    vauxl_federation::resolver::is_valid_server_name(value)
}

fn is_valid_room_id(value: &str) -> bool {
    let Some((localpart, server)) = value
        .strip_prefix('!')
        .and_then(|value| value.split_once(':'))
    else {
        return false;
    };
    is_safe_identifier(localpart) && is_valid_server_name(server)
}

fn is_valid_user_id(value: &str) -> bool {
    let Some((localpart, server)) = value
        .strip_prefix('@')
        .and_then(|value| value.split_once(':'))
    else {
        return false;
    };
    is_safe_identifier(localpart) && is_valid_server_name(server)
}

fn user_server_name(value: &str) -> Option<&str> {
    value
        .strip_prefix('@')?
        .split_once(':')
        .map(|(_, server)| server)
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federation_acl_checks_denies_ports_case_and_ip_literals() {
        let acl =
            json!({"allow":["*.example"],"deny":["BLOCKED.EXAMPLE"],"allow_ip_literals":false});
        assert!(acl_allows(acl.clone(), "ALLOWED.EXAMPLE:8448").unwrap());
        assert!(!acl_allows(acl.clone(), "blocked.example:443").unwrap());
        assert!(!acl_allows(acl, "unrelated.test").unwrap());
        for server in ["1.1.1.1:8448", "[2606:4700:4700::1111]"] {
            assert!(!acl_allows(json!({"allow":["*"],"allow_ip_literals":false}), server).unwrap());
        }
        assert!(!acl_allows(json!({}), "remote.example").unwrap());
        assert!(acl_allows(json!({"allow":"*"}), "remote.example").is_err());
    }

    #[test]
    fn acl_ip_ban_cannot_be_bypassed_with_public_ip_aliases() {
        let acl = json!({"allow":["*"], "allow_ip_literals":false});
        for server in [
            "8.8.8.8",
            "0x08080808",
            "134744072",
            "010.010.010.010",
            "8.8.2056",
            "134744072:8448",
        ] {
            assert!(!acl_allows(acl.clone(), server).unwrap(), "{server}");
        }
        assert!(acl_allows(acl, "dns.google:8448").unwrap());
    }

    #[test]
    fn historical_state_query_cannot_silently_return_current_state() {
        assert!(reject_historical_state_query(
            &"/_matrix/federation/v1/state/room?event_id=%24old"
                .parse()
                .unwrap()
        )
        .is_err());
        assert!(reject_historical_state_query(
            &"/_matrix/federation/v1/state/room".parse().unwrap()
        )
        .is_ok());
    }
}
