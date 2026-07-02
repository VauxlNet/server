use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::state::SharedState;

pub async fn well_known_client(State(s): State<SharedState>) -> Json<Value> {
    Json(json!({
        "m.homeserver": {
            "base_url": format!("https://{}", s.config.server.server_name)
        }
    }))
}

pub async fn well_known_server(State(s): State<SharedState>) -> Json<Value> {
    Json(json!({
        "m.server": format!("{}:{}", s.config.server.server_name, s.config.server.port)
    }))
}

pub async fn key_v2_server(State(s): State<SharedState>) -> Json<Value> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Json(json!({
        "server_name":    s.config.server.server_name,
        "valid_until_ts": now_ms + 86_400_000,
        "verify_keys": {
            s.signing_key.key_id.clone(): {
                "key": s.signing_key.public_key_base64()
            }
        },
        "old_verify_keys": {}
    }))
}

pub async fn federation_version() -> Json<Value> {
    Json(json!({
        "server": {
            "name":    "Vauxl",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}
