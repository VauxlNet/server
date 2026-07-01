//! Matrix well-known and key discovery endpoints.
//!
//! These are the first endpoints any Matrix client or server hits
//! when discovering your homeserver.
//!
//! GET /.well-known/matrix/client  — tells clients where the CS API is
//! GET /.well-known/matrix/server  — tells servers where the SS API is
//! GET /_matrix/key/v2/server      — publishes the homeserver signing key

use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::signing_key::HomeserverSigningKey;

/// Shared application state passed to all handlers.
pub struct MatrixState {
    pub server_name: String,
    pub signing_key: HomeserverSigningKey,
    pub port: u16,
}

/// GET /.well-known/matrix/client
///
/// Tells Matrix clients (Element, etc.) the base URL of the CS API.
pub async fn well_known_client(State(state): State<Arc<MatrixState>>) -> Json<Value> {
    Json(json!({
        "m.homeserver": {
            "base_url": format!("https://{}", state.server_name)
        },
        "m.identity_server": {
            "base_url": "https://vector.im"
        }
    }))
}

/// GET /.well-known/matrix/server
///
/// Tells other Matrix homeservers where our federation port is.
pub async fn well_known_server(State(state): State<Arc<MatrixState>>) -> Json<Value> {
    Json(json!({
        "m.server": format!("{}:{}", state.server_name, state.port)
    }))
}

/// GET /_matrix/key/v2/server
///
/// Publishes the homeserver's Ed25519 signing key.
/// Other servers use this to verify signatures on events we send them.
pub async fn key_v2_server(State(state): State<Arc<MatrixState>>) -> Json<Value> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Valid for 24 hours
    let valid_until_ms = now_ms + 86_400_000;

    Json(json!({
        "server_name": &state.server_name,
        "valid_until_ts": valid_until_ms,
        "verify_keys": {
            state.signing_key.key_id.clone(): {
                "key": state.signing_key.public_key_base64()
            }
        },
        "old_verify_keys": {}
    }))
}

/// GET /_matrix/federation/v1/version
///
/// Identifies this server to other homeservers.
pub async fn federation_version() -> Json<Value> {
    Json(json!({
        "server": {
            "name":    "Vauxl",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}
