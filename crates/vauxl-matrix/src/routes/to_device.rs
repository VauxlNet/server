//! PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
//!
//! Sends a message directly to specific devices — never into a room.
//! Primary use: Olm pre-key messages and Megolm room key distribution.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    auth::AuthenticatedUser, db::store_to_device_messages, error::MatrixError, state::SharedState,
};

#[derive(Debug, Deserialize)]
pub struct SendToDeviceRequest {
    /// {user_id: {device_id: content}}
    /// device_id can be "*" to target all devices for that user
    pub messages: HashMap<String, HashMap<String, Value>>,
}

/// PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
pub async fn send_to_device(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Path((event_type, _txn_id)): Path<(String, String)>,
    Json(body): Json<SendToDeviceRequest>,
) -> Result<Json<Value>, MatrixError> {
    // TODO: deduplicate by txn_id (needs Redis or txn table per-sender)
    // For now we process all sends — duplicate sends are rare in practice

    let server_name = &state.config.server.server_name;
    let mut to_store: Vec<(String, String, Value)> = Vec::new();

    for (user_id, devices) in &body.messages {
        let is_local = user_id.ends_with(&format!(":{}", server_name));

        if is_local {
            for (device_id, content) in devices {
                to_store.push((user_id.clone(), device_id.clone(), content.clone()));
            }
        } else {
            // Remote user — federation to-device not yet implemented
            // Log and skip; clients will handle missing deliveries
            tracing::debug!(
                user_id    = %user_id,
                event_type = %event_type,
                "Skipping to-device for remote user (federation not yet implemented)"
            );
        }
    }

    if !to_store.is_empty() {
        store_to_device_messages(&state.db, &event_type, &to_store).await?;

        tracing::debug!(
            sender     = %auth.user_id,
            event_type = %event_type,
            count      = to_store.len(),
            "To-device messages stored"
        );
    }

    Ok(Json(json!({})))
}
