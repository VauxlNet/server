use crate::error::MatrixError;
use redis::AsyncCommands;

pub async fn get_next_batch(client: &redis::Client, user_id: &str) -> Result<String, MatrixError> {
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| MatrixError::Internal(format!("Redis connection error: {e}")))?;

    let key = format!("sync:pos:{}", user_id);

    let pos: u64 = conn
        .incr(&key, 1_u64)
        .await
        .map_err(|e| MatrixError::Internal(format!("Redis incr error: {e}")))?;

    let _: () = conn
        .expire(&key, 30 * 24 * 3600_i64)
        .await
        .map_err(|e| MatrixError::Internal(format!("Redis expire error: {e}")))?;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Ok(format!("s{}_{}", ts, pos))
}

pub fn parse_since(since: Option<&str>) -> u64 {
    since
        .and_then(|s| s.split('_').next_back())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}
