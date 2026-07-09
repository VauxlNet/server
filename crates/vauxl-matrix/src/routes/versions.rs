//! GET /_matrix/client/versions
//!
//! The very first endpoint Element hits. Without it the server is not
//! recognised as a Matrix homeserver at all.

use axum::Json;
use serde_json::{json, Value};

pub async fn client_versions() -> Json<Value> {
    Json(json!({
        "versions": [
            "r0.0.1", "r0.1.0", "r0.2.0", "r0.3.0", "r0.4.0",
            "r0.5.0", "r0.6.0", "r0.6.1",
            "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6"
        ],
        "unstable_features": {
            "org.matrix.label_based_filtering": true,
            "org.matrix.e2e_cross_signing":     true
        }
    }))
}
