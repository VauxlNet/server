//! GET /_matrix/client/versions
//!
//! The very first endpoint Element hits. Without it the server is not
//! recognised as a Matrix homeserver at all.

use axum::Json;
use serde_json::{json, Value};

pub async fn client_versions() -> Json<Value> {
    Json(json!({
        "versions": ["v1.1"],
        "unstable_features": {}
    }))
}
