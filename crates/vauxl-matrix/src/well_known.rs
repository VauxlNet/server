use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    error::MatrixError,
    state::{AppState, SharedState},
};

pub async fn well_known_client(State(s): State<SharedState>) -> Json<Value> {
    // Use http for local dev — Element Web rejects https:// when TLS is not configured
    let scheme = if s.config.server.server_name.starts_with("localhost")
        || s.config.server.server_name.starts_with("127.")
    {
        "http"
    } else {
        "https"
    };

    Json(json!({
        "m.homeserver": {
            "base_url": format!("{}://{}:{}", scheme,
                s.config.server.server_name,
                s.config.server.port)
        }
    }))
}

pub async fn well_known_server(State(s): State<SharedState>) -> Json<Value> {
    Json(json!({
        "m.server": format!("{}:{}", s.config.server.server_name, s.config.server.port)
    }))
}

pub async fn key_v2_server(State(s): State<SharedState>) -> Result<Json<Value>, MatrixError> {
    Ok(Json(signing_key_document(&s)?))
}

pub fn signing_key_document(s: &AppState) -> Result<Value, MatrixError> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut document = serde_json::from_value(json!({
        "server_name":    s.config.server.server_name,
        "valid_until_ts": now_ms + 86_400_000,
        "verify_keys": {
            s.signing_key.key_id.clone(): {
                "key": s.signing_key.public_key_base64()
            }
        },
        "old_verify_keys": {}
    }))
    .map_err(|e| MatrixError::Internal(format!("Cannot construct signing key document: {e}")))?;
    ruma::signatures::sign_json(&s.config.server.server_name, &s.signing_key, &mut document)
        .map_err(|e| MatrixError::Internal(format!("Cannot sign server keys: {e}")))?;
    serde_json::to_value(document)
        .map_err(|e| MatrixError::Internal(format!("Cannot serialize server keys: {e}")))
}

pub async fn federation_version() -> Json<Value> {
    Json(json!({
        "server": {
            "name":    "Vauxl",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}
