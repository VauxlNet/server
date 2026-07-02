//! Database helpers — user and device management.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::MatrixError;

/// Creates a new user row. Returns `MatrixError::UserInUse` if taken.
pub async fn create_user(
    pool: &PgPool,
    user_id: &str,
    password_hash: Option<&str>,
) -> Result<(), MatrixError> {
    let result = sqlx::query!(
        r#"
        INSERT INTO users (user_id, password_hash)
        VALUES ($1, $2)
        "#,
        user_id,
        password_hash,
    )
    .execute(pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.constraint() == Some("users_pkey") => {
            Err(MatrixError::UserInUse)
        }
        Err(e) => Err(MatrixError::from(e)),
    }
}

/// Looks up a user's password hash for login verification.
pub async fn get_password_hash(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<String>, MatrixError> {
    let row = sqlx::query!(
        "SELECT password_hash FROM users WHERE user_id = $1 AND deactivated = FALSE",
        user_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|r| r.password_hash))
}

/// Creates a new device and stores an access token hash.
/// Returns the plaintext access token (only time we see it).
pub async fn create_device(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
    display_name: Option<&str>,
    token_hash: &str,
) -> Result<(), MatrixError> {
    let mut tx = pool.begin().await?;

    sqlx::query!(
        r#"
        INSERT INTO devices (user_id, device_id, display_name)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, device_id) DO NOTHING
        "#,
        user_id,
        device_id,
        display_name,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        r#"
        INSERT INTO access_tokens (token_hash, user_id, device_id)
        VALUES ($1, $2, $3)
        "#,
        token_hash,
        user_id,
        device_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Generates a unique device ID (8 uppercase hex chars).
pub fn generate_device_id() -> String {
    let id = Uuid::new_v4().simple().to_string();
    id[..8].to_uppercase()
}

/// Generates a new access token and its SHA-256 hash.
/// Returns (plaintext_token, hash).
pub fn generate_access_token() -> (String, String) {
    use sha2::{Digest, Sha256};

    let token = format!("vauxl_{}", Uuid::new_v4().simple());
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    (token, hash)
}
