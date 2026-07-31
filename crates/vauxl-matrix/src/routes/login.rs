//! POST /_matrix/client/v3/login
//! GET  /_matrix/client/v3/login  (returns supported flows)

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    db::{create_device, generate_access_token, generate_device_id, get_password_hash},
    error::MatrixError,
    state::SharedState,
};

// ── Request / Response ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(rename = "type")]
    pub login_type: String,

    // m.login.password fields
    pub identifier: Option<UserIdentifier>,
    pub password: Option<String>,

    // Optional device info
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub user: Option<String>, // local part or full MXID
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// GET /_matrix/client/v3/login
/// Tells clients which login flows we support.
pub async fn get_login_flows() -> Json<Value> {
    Json(json!({
        "flows": [
            { "type": "m.login.password" }
        ]
    }))
}

/// POST /_matrix/client/v3/login
pub async fn login(
    State(state): State<SharedState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<Value>, MatrixError> {
    match body.login_type.as_str() {
        "m.login.password" => login_password(state, body).await,
        other => Err(MatrixError::BadJson(format!(
            "Unsupported login type: {other}. Only m.login.password is supported."
        ))),
    }
}

// ── m.login.password ──────────────────────────────────────────────────────

async fn login_password(
    state: SharedState,
    body: LoginRequest,
) -> Result<Json<Value>, MatrixError> {
    let server_name = &state.config.server.server_name;

    // Extract and resolve the user identifier
    let identifier = body
        .identifier
        .as_ref()
        .ok_or_else(|| MatrixError::BadJson("Missing 'identifier' field".into()))?;

    let user_id = resolve_user_id(identifier, server_name)?;

    // Password must be present for m.login.password
    let password = body
        .password
        .as_ref()
        .ok_or_else(|| MatrixError::BadJson("Missing 'password' field".into()))?;

    // Look up the stored hash
    let stored_hash = get_password_hash(&state.db, &user_id)
        .await?
        .ok_or(MatrixError::Forbidden)?; // user not found → same error as wrong password

    // Verify password
    verify_password(password, &stored_hash)?;

    // Create device + access token
    let device_id = body.device_id.clone().unwrap_or_else(generate_device_id);

    let (token, token_hash) = generate_access_token();

    create_device(
        &state.db,
        &user_id,
        &device_id,
        body.initial_device_display_name.as_deref(),
        &token_hash,
    )
    .await?;

    tracing::info!(
        user_id   = %user_id,
        device_id = %device_id,
        "User logged in"
    );

    Ok(Json(json!({
        "user_id":      user_id,
        "access_token": token,
        "device_id":    device_id,
        "home_server":  server_name,
    })))
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Resolves a Matrix UserIdentifier to a full MXID.
/// Supports m.id.user (local part or full MXID).
fn resolve_user_id(identifier: &UserIdentifier, server_name: &str) -> Result<String, MatrixError> {
    match identifier.id_type.as_str() {
        "m.id.user" => {
            let user = identifier
                .user
                .as_deref()
                .ok_or_else(|| MatrixError::BadJson("Missing 'user' in identifier".into()))?;

            if user.starts_with('@') {
                // Already a full MXID — use as-is
                Ok(user.to_owned())
            } else {
                // Local part only — prepend @ and server name
                Ok(format!("@{}:{}", user.to_lowercase(), server_name))
            }
        }
        other => Err(MatrixError::BadJson(format!(
            "Unsupported identifier type: {other}"
        ))),
    }
}

fn verify_password(password: &str, hash: &str) -> Result<(), MatrixError> {
    use argon2::password_hash::PasswordHash;
    use argon2::{Argon2, PasswordVerifier};

    let parsed = PasswordHash::new(hash)
        .map_err(|_| MatrixError::Internal("Invalid stored password hash".into()))?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| MatrixError::Forbidden)
}
