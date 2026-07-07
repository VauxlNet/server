//! Device key endpoints — the foundation of Matrix E2EE.
//!
//! POST /_matrix/client/v3/keys/upload  — upload device + one-time keys
//! POST /_matrix/client/v3/keys/query   — query keys for a list of users
//! POST /_matrix/client/v3/keys/claim   — claim one-time keys for Olm setup

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    auth::AuthenticatedUser,
    db::{
        claim_one_time_key, get_otk_counts, query_device_keys, store_one_time_keys,
        upsert_device_keys,
    },
    error::MatrixError,
    state::SharedState,
};

// ── Upload ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct KeysUploadRequest {
    /// The device keys (Ed25519, Curve25519, and optionally org.vauxl.* keys)
    pub device_keys: Option<Value>,
    /// One-time prekeys for Olm session setup
    pub one_time_keys: Option<Value>,
    /// Fallback keys (used when OTKs are exhausted)
    pub fallback_keys: Option<Value>,
}

/// POST /_matrix/client/v3/keys/upload
pub async fn upload_keys(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    Json(body): Json<KeysUploadRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Store device identity keys (Ed25519, Curve25519, Kyber, etc.)
    if let Some(device_keys) = &body.device_keys {
        upsert_device_keys(&state.db, &auth.user_id, &auth.device_id, device_keys).await?;

        tracing::debug!(
            user_id   = %auth.user_id,
            device_id = %auth.device_id,
            "Device keys uploaded"
        );
    }

    // Store one-time prekeys
    if let Some(otks) = &body.one_time_keys {
        let count = store_one_time_keys(&state.db, &auth.user_id, &auth.device_id, otks).await?;

        tracing::debug!(
            user_id   = %auth.user_id,
            device_id = %auth.device_id,
            count     = count,
            "One-time keys stored"
        );
    }

    // Return current OTK counts so client knows when to replenish
    let counts = get_otk_counts(&state.db, &auth.user_id, &auth.device_id).await?;

    Ok(Json(json!({
        "one_time_key_counts": counts
    })))
}

// ── Query ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct KeysQueryRequest {
    /// Map of user_id → [device_id] — empty list means all devices
    pub device_keys: HashMap<String, Vec<String>>,
    /// Token for incremental key updates — ignored in MVP
    pub token: Option<String>,
}

/// POST /_matrix/client/v3/keys/query
pub async fn query_keys(
    State(state): State<SharedState>,
    _auth: AuthenticatedUser,
    Json(body): Json<KeysQueryRequest>,
) -> Result<Json<Value>, MatrixError> {
    let mut device_keys: HashMap<String, Value> = HashMap::new();
    let mut failures: HashMap<String, Value> = HashMap::new();

    for user_id in body.device_keys.keys() {
        // Check if this user is on our server
        let is_local = user_id.ends_with(&format!(":{}", state.config.server.server_name));

        if is_local {
            match query_device_keys(&state.db, user_id).await {
                Ok(keys) => {
                    device_keys.insert(user_id.clone(), keys);
                }
                Err(e) => {
                    tracing::warn!(user_id = %user_id, error = %e, "Failed to query keys");
                    failures.insert(
                        user_id.clone(),
                        json!({
                            "errcode": "M_UNKNOWN",
                            "error":   e.to_string()
                        }),
                    );
                }
            }
        } else {
            // Remote user — federation key query not yet implemented
            // Return empty rather than error so clients can still function
            tracing::debug!(user_id = %user_id, "Remote key query not yet implemented");
            device_keys.insert(user_id.clone(), json!({}));
        }
    }

    Ok(Json(json!({
        "device_keys": device_keys,
        "failures":    failures,
        "master_keys":       {},
        "self_signing_keys": {},
        "user_signing_keys": {}
    })))
}

// ── Claim ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct KeysClaimRequest {
    /// Map of user_id → device_id → algorithm
    pub one_time_keys: HashMap<String, HashMap<String, String>>,
}

/// POST /_matrix/client/v3/keys/claim
///
/// Called when a client wants to start an Olm session with another device.
/// Returns one unclaimed one-time key per requested device.
pub async fn claim_keys(
    State(state): State<SharedState>,
    _auth: AuthenticatedUser,
    Json(body): Json<KeysClaimRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Result shape: {user_id: {device_id: {algorithm:key_id: key_data}}}
    let mut one_time_keys: HashMap<String, HashMap<String, Value>> = HashMap::new();
    let mut failures: HashMap<String, Value> = HashMap::new();

    for (user_id, devices) in &body.one_time_keys {
        let is_local = user_id.ends_with(&format!(":{}", state.config.server.server_name));

        if !is_local {
            tracing::debug!(user_id = %user_id, "Remote key claim not yet implemented");
            continue;
        }

        let user_entry = one_time_keys.entry(user_id.clone()).or_default();

        for (device_id, algorithm) in devices {
            match claim_one_time_key(&state.db, user_id, device_id, algorithm).await {
                Ok(Some((key_id, key_data))) => {
                    tracing::debug!(
                        user_id   = %user_id,
                        device_id = %device_id,
                        key_id    = %key_id,
                        "One-time key claimed"
                    );
                    // Matrix format: {algorithm:key_id: key_data}
                    user_entry.insert(device_id.clone(), json!({ key_id: key_data }));
                }
                Ok(None) => {
                    // No keys available — client will retry later
                    tracing::warn!(
                        user_id   = %user_id,
                        device_id = %device_id,
                        algorithm = %algorithm,
                        "No one-time keys available"
                    );
                    user_entry.insert(device_id.clone(), json!({}));
                }
                Err(e) => {
                    failures.insert(
                        user_id.clone(),
                        json!({
                            "errcode": "M_UNKNOWN",
                            "error":   e.to_string()
                        }),
                    );
                }
            }
        }
    }

    Ok(Json(json!({
        "one_time_keys": one_time_keys,
        "failures":      failures
    })))
}
