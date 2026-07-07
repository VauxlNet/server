pub mod keys;
pub mod sync;

// Re-export commonly used functions from the top level
pub use keys::{
    claim_one_time_key, get_otk_counts, query_device_keys, store_one_time_keys, upsert_device_keys,
};

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::MatrixError;

pub async fn create_user(
    pool: &PgPool,
    user_id: &str,
    password_hash: Option<&str>,
) -> Result<(), MatrixError> {
    let result = sqlx::query!(
        "INSERT INTO users (user_id, password_hash) VALUES ($1, $2)",
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

pub async fn get_password_hash(
    pool: &PgPool,
    user_id: &str,
) -> Result<Option<String>, MatrixError> {
    let row = sqlx::query!(
        "SELECT password_hash FROM users WHERE user_id = $1 AND deactivated = FALSE",
        user_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.password_hash))
}

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
        "INSERT INTO access_tokens (token_hash, user_id, device_id) VALUES ($1, $2, $3)",
        token_hash,
        user_id,
        device_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

pub fn generate_device_id() -> String {
    let id = Uuid::new_v4().simple().to_string();
    id[..8].to_uppercase()
}

pub fn generate_access_token() -> (String, String) {
    let token = format!("vauxl_{}", Uuid::new_v4().simple());
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    (token, hash)
}
pub mod rooms;

pub use rooms::{
    assert_joined, create_room_with_state, generate_event_id, get_full_room_state, put_room_event,
    put_room_state_event,
};
pub mod membership;

pub use membership::{
    get_join_rule, get_membership, resolve_room_alias, room_exists, set_membership,
    store_invite_notification,
};
