//! Remote server key fetching and caching.
//!
//! We fetch remote server signing keys and cache them in Redis
//! for the validity period specified by the remote server.

use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use serde_json::Value;
use std::time::Duration;

use crate::resolver::resolve_server_name;

/// Fetch the signing keys for a remote server.
/// Returns a map of key_id → base64-encoded Ed25519 public key.
pub async fn fetch_server_keys(
    server_name: &str,
) -> Result<std::collections::HashMap<String, Vec<u8>>, String> {
    let resolved = resolve_server_name(server_name).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "https://{}:{}/_matrix/key/v2/server",
        resolved.host, resolved.port
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Key fetch failed for {server_name}: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Key server returned {}", resp.status()));
    }

    let json: Value = resp.json().await.map_err(|e| e.to_string())?;

    let mut keys = std::collections::HashMap::new();

    if let Some(verify_keys) = json.get("verify_keys").and_then(|v| v.as_object()) {
        for (key_id, key_obj) in verify_keys {
            if let Some(key_b64) = key_obj.get("key").and_then(|v| v.as_str()) {
                if let Ok(key_bytes) = BASE64.decode(key_b64) {
                    keys.insert(key_id.clone(), key_bytes);
                }
            }
        }
    }

    Ok(keys)
}

/// Get (or fetch + cache) remote server keys.
pub async fn get_server_keys(
    server_name: &str,
    redis: &redis::Client,
) -> Result<std::collections::HashMap<String, Vec<u8>>, String> {
    use redis::AsyncCommands;

    let cache_key = format!("federation:keys:{}", server_name);

    // Try cache first
    if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
        let cached: Option<String> = conn.get(&cache_key).await.unwrap_or(None);
        if let Some(json_str) = cached {
            if let Ok(map) =
                serde_json::from_str::<std::collections::HashMap<String, Vec<u8>>>(&json_str)
            {
                return Ok(map);
            }
        }
    }

    // Fetch fresh
    let keys = fetch_server_keys(server_name).await?;

    // Cache for 24 hours
    if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
        if let Ok(serialized) = serde_json::to_string(&keys) {
            let _: Result<(), _> = conn.set_ex(&cache_key, serialized, 86400).await;
        }
    }

    Ok(keys)
}
