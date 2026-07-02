//! POST /_matrix/client/v3/register
//!
//! Matrix User Interactive Authentication (UIA) registration flow.
//!
//! Flow:
//!   1. Client posts with no `auth` field → 401 with supported flows + session ID
//!   2. Client posts again with `auth: {type: "m.login.dummy", session: "..."}` → 200 + tokens

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    db::{create_device, create_user, generate_access_token, generate_device_id},
    error::MatrixError,
    state::SharedState,
};

// ── Request / Response types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    pub auth: Option<AuthData>,
    #[serde(default)]
    pub inhibit_login: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthData {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub session: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub access_token: Option<String>,
    pub device_id: Option<String>,
    pub home_server: String,
}

// ── Handler ───────────────────────────────────────────────────────────────

pub async fn register(
    State(state): State<SharedState>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, MatrixError> {
    let server_name = &state.config.server.server_name;

    // ── Stage 1: no auth provided → return UIA challenge ─────────────────
    if body.auth.is_none() {
        let session = generate_session_id();
        let response = json!({
            "flows": [
                { "stages": ["m.login.dummy"] },
                { "stages": ["m.login.password"] }
            ],
            "params":  {},
            "session": session,
        });
        return Ok((StatusCode::UNAUTHORIZED, Json(response)).into_response());
    }

    // ── Stage 2: auth provided → validate and create account ─────────────
    let auth = body.auth.as_ref().unwrap();

    // Validate auth type
    match auth.auth_type.as_str() {
        "m.login.dummy" => {
            // No credentials needed — accept as-is (dev/testing only)
        }
        "m.login.password" => {
            // Password was already provided in body.password
            // Full validation happens at login time
        }
        other => {
            return Err(MatrixError::BadJson(format!(
                "Unsupported auth type: {other}"
            )));
        }
    }

    // Validate and normalise username
    let username = match &body.username {
        Some(u) => validate_username(u)?,
        None => generate_guest_username(),
    };

    let user_id = format!("@{}:{}", username, server_name);

    // Hash password if provided
    let password_hash = if let Some(pw) = &body.password {
        if pw.len() < 8 {
            return Err(MatrixError::WeakPassword);
        }
        Some(hash_password(pw)?)
    } else {
        None
    };

    // Create the user (errors if already taken)
    create_user(&state.db, &user_id, password_hash.as_deref()).await?;

    // Create device + access token
    if body.inhibit_login {
        let response = RegisterResponse {
            user_id,
            access_token: None,
            device_id: None,
            home_server: server_name.clone(),
        };
        return Ok((StatusCode::OK, Json(json!(response))).into_response());
    }

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

    tracing::info!(user_id = %user_id, device_id = %device_id, "User registered");

    let response = RegisterResponse {
        user_id,
        access_token: Some(token),
        device_id: Some(device_id),
        home_server: server_name.clone(),
    };

    Ok((StatusCode::OK, Json(json!(response))).into_response())
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Matrix username rules: lowercase a-z, 0-9, and . _ - /
fn validate_username(username: &str) -> Result<String, MatrixError> {
    let lower = username.to_lowercase();

    if lower.is_empty() || lower.len() > 255 {
        return Err(MatrixError::InvalidUsername);
    }

    let valid = lower.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-' || c == '/'
    });

    if !valid {
        return Err(MatrixError::InvalidUsername);
    }

    Ok(lower)
}

fn generate_guest_username() -> String {
    use uuid::Uuid;
    format!("guest_{}", &Uuid::new_v4().simple().to_string()[..8])
}

fn generate_session_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().simple().to_string()
}

fn hash_password(password: &str) -> Result<String, MatrixError> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| MatrixError::Internal(format!("Password hashing failed: {e}")))
}
