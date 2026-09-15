//! HTTPS-authenticated, self-signed remote key documents, cached until expiry.
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use redis::AsyncCommands;
use serde_json::Value;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn verify_signature(key: &[u8], signature: &str, message: &[u8]) -> Result<(), String> {
    let bytes: &[u8; 32] = key.try_into().map_err(|_| "Invalid Ed25519 key length")?;
    let key = VerifyingKey::from_bytes(bytes).map_err(|e| e.to_string())?;
    let signature = BASE64.decode(signature).map_err(|e| e.to_string())?;
    let signature = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
    key.verify_strict(message, &signature)
        .map_err(|e| e.to_string())
}

/// Retired keys are deliberately excluded from live request authentication. Historical
/// event verification may use them only before their documented expired_ts.
pub fn document_keys(
    document: &Value,
    server: &str,
    now: u64,
    event_ts: Option<u64>,
) -> Result<HashMap<String, Vec<u8>>, String> {
    if !crate::resolver::is_valid_server_name(server)
        || document.get("server_name").and_then(Value::as_str) != Some(server)
    {
        return Err("Key document server identity mismatch".into());
    }
    let valid_until = document
        .get("valid_until_ts")
        .and_then(Value::as_u64)
        .ok_or("Missing key validity")?;
    if valid_until <= now {
        return Err("Expired server key document".into());
    }
    let current = document
        .get("verify_keys")
        .and_then(Value::as_object)
        .ok_or("Missing verify_keys")?;
    let mut signable = document.as_object().ok_or("Invalid key document")?.clone();
    signable.remove("signatures");
    signable.remove("unsigned");
    let canonical = crate::signing_json(&Value::Object(signable))?;
    let signatures = document
        .get("signatures")
        .and_then(|v| v.get(server))
        .and_then(Value::as_object)
        .ok_or("Missing key self-signature")?;
    let mut keys = HashMap::new();
    for (id, value) in current {
        if !id.starts_with("ed25519:") {
            continue;
        }
        let Some(encoded) = value.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Ok(key) = BASE64.decode(encoded) else {
            continue;
        };
        if key.len() == 32 {
            keys.insert(id.clone(), key);
        }
    }
    let self_signed = keys.iter().any(|(id, key)| {
        signatures
            .get(id)
            .and_then(Value::as_str)
            .is_some_and(|sig| verify_signature(key, sig, canonical.as_bytes()).is_ok())
    });
    if !self_signed {
        return Err("Invalid key self-signature".into());
    }
    if let Some(timestamp) = event_ts {
        if timestamp > valid_until {
            return Err("Event exceeds key validity".into());
        }
        if let Some(old) = document.get("old_verify_keys").and_then(Value::as_object) {
            for (id, value) in old {
                if !id.starts_with("ed25519:")
                    || value
                        .get("expired_ts")
                        .and_then(Value::as_u64)
                        .is_none_or(|expiry| timestamp >= expiry)
                {
                    continue;
                }
                if let Some(key) = value
                    .get("key")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64.decode(s).ok())
                    .filter(|key| key.len() == 32)
                {
                    keys.entry(id.clone()).or_insert(key);
                }
            }
        }
    }
    Ok(keys)
}

pub async fn fetch_key_document(server: &str) -> Result<Value, String> {
    let resolved = crate::resolver::resolve_server_name(server).await?;
    let client = crate::resolver::http_client(Duration::from_secs(10))?;
    let response = client
        .get(format!(
            "https://{}:{}/_matrix/key/v2/server",
            resolved.host, resolved.port
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Key server returned {}", response.status()));
    }
    let document = crate::resolver::bounded_json(response).await?;
    document_keys(&document, server, now_millis(), None)?;
    Ok(document)
}

/// Cache complete validated documents, using a new namespace to exclude old unsigned
/// key-map cache entries. Refresh immediately for a newly advertised rotation key.
pub async fn get_verification_key(
    server: &str,
    key_id: &str,
    redis: &redis::Client,
    event_ts: Option<u64>,
) -> Result<Vec<u8>, String> {
    if !crate::resolver::is_valid_server_name(server) {
        return Err("Invalid server name".into());
    }
    let cache_key = format!("federation:verified-key-document:{server}");
    if let Ok(mut connection) = redis.get_multiplexed_async_connection().await {
        let cached: Option<String> = connection.get(&cache_key).await.unwrap_or(None);
        if let Some(document) = cached.and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            if let Ok(keys) = document_keys(&document, server, now_millis(), event_ts) {
                if let Some(key) = keys.get(key_id) {
                    return Ok(key.clone());
                }
            }
        }
    }
    let document = fetch_key_document(server).await?;
    let now = now_millis();
    let keys = document_keys(&document, server, now, event_ts)?;
    if let Ok(mut connection) = redis.get_multiplexed_async_connection().await {
        // Cap cache lifetime even if a remote server publishes an unusually long validity.
        let ttl = (document["valid_until_ts"]
            .as_u64()
            .unwrap_or(now)
            .saturating_sub(now)
            / 1000)
            .min(86400);
        if ttl > 0 {
            let _: Result<(), _> = connection
                .set_ex(cache_key, document.to_string(), ttl)
                .await;
        }
    }
    keys.get(key_id)
        .cloned()
        .ok_or_else(|| "No valid verification key".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    fn document() -> Value {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut document = json!({"server_name":"remote.example", "valid_until_ts":2000, "verify_keys":{"ed25519:new":{"key":BASE64.encode(key.verifying_key().as_bytes())}}, "old_verify_keys":{"ed25519:old":{"key":BASE64.encode([9;32]), "expired_ts":900}}});
        let signature = key.sign(crate::signing_json(&document).unwrap().as_bytes());
        document["signatures"] =
            json!({"remote.example":{"ed25519:new":BASE64.encode(signature.to_bytes())}});
        document
    }
    #[test]
    fn rejects_untrusted_expired_or_modified_key_documents() {
        let d = document();
        assert!(document_keys(&d, "remote.example", 1000, None).is_ok());
        assert!(document_keys(&d, "other.example", 1000, None).is_err());
        assert!(document_keys(&d, "remote.example", 2000, None).is_err());
        let mut tampered = d.clone();
        tampered["valid_until_ts"] = json!(9000);
        assert!(document_keys(&tampered, "remote.example", 1000, None).is_err());
        let mut unsigned = d;
        unsigned.as_object_mut().unwrap().remove("signatures");
        assert!(document_keys(&unsigned, "remote.example", 1000, None).is_err());
    }
    #[test]
    fn retired_keys_only_verify_events_from_before_expiry() {
        let d = document();
        assert!(!document_keys(&d, "remote.example", 1000, None)
            .unwrap()
            .contains_key("ed25519:old"));
        assert!(document_keys(&d, "remote.example", 1000, Some(899))
            .unwrap()
            .contains_key("ed25519:old"));
        assert!(!document_keys(&d, "remote.example", 1000, Some(900))
            .unwrap()
            .contains_key("ed25519:old"));
    }
}
