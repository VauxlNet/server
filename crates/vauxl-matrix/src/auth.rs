//! Access token authentication middleware.
//!
//! Extracts and validates the Bearer token from the Authorization header
//! or the `access_token` query parameter (Matrix spec allows both).
//!
//! Usage in handlers:
//!   pub async fn my_handler(
//!       auth: AuthenticatedUser,
//!       ...
//!   )

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::error::MatrixError;

/// An authenticated Matrix user, extracted from the request token.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub device_id: String,
}

/// Query param fallback: ?access_token=...
#[derive(Debug, Deserialize)]
struct TokenQuery {
    access_token: Option<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    S: axum::extract::FromRef<S>,
{
    type Rejection = MatrixError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, MatrixError> {
        // Extract token from Authorization header or query param
        let token = extract_token(&parts.headers, parts.uri.query().unwrap_or(""))
            .ok_or(MatrixError::MissingToken)?;

        // Get DB pool from extensions (set in router)
        let pool = parts
            .extensions
            .get::<PgPool>()
            .ok_or_else(|| MatrixError::Internal("No DB pool in request".into()))?;

        // Hash the token and look it up
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let row = sqlx::query!(
            r#"
            SELECT user_id, device_id FROM access_tokens
            WHERE token_hash = $1
            "#,
            hash,
        )
        .fetch_optional(pool)
        .await
        .map_err(MatrixError::from)?
        .ok_or(MatrixError::UnknownToken)?;

        // Update last_seen
        let _ = sqlx::query!(
            "UPDATE access_tokens SET last_used = NOW() WHERE token_hash = $1",
            hash,
        )
        .execute(pool)
        .await;

        Ok(AuthenticatedUser {
            user_id: row.user_id,
            device_id: row.device_id,
        })
    }
}

fn extract_token(headers: &HeaderMap, query: &str) -> Option<String> {
    // Try Authorization: Bearer <token> first
    if let Some(val) = headers.get("Authorization") {
        if let Ok(s) = val.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                return Some(token.trim().to_owned());
            }
        }
    }

    // Fall back to ?access_token= query parameter
    if let Ok(q) = serde_urlencoded::from_str::<TokenQuery>(query) {
        return q.access_token;
    }

    None
}
