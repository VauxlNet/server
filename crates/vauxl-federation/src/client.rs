//! HTTP client for sending federation requests to remote servers.

use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use ed25519_dalek::Signer;
use serde_json::Value;
use std::time::Duration;

use crate::resolver::resolve_server_name;

/// Signs a federation request and sends it to a remote server.
pub async fn send_federation_request(
    method: &str,
    origin: &str,
    destination: &str,
    path: &str,
    body: Option<&Value>,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> Result<reqwest::Response, String> {
    let resolved = resolve_server_name(destination).await;

    let url = format!("https://{}:{}{}", resolved.host, resolved.port, path);

    // Build the authorization header (signed request)
    let auth_header =
        build_auth_header(method, origin, destination, path, body, signing_key, key_id)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut req = match method {
        "GET" => client.get(&url),
        "PUT" => client.put(&url),
        "POST" => client.post(&url),
        _ => return Err(format!("Unsupported method: {method}")),
    };

    req = req
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json");

    if let Some(b) = body {
        req = req.body(b.to_string());
    }

    req.send().await.map_err(|e| format!("Request failed: {e}"))
}

/// Builds the Matrix federation Authorization header.
/// Format: X-Matrix origin=<server>,key="<key_id>",sig="<base64sig>"
fn build_auth_header(
    method: &str,
    origin: &str,
    destination: &str,
    path: &str,
    body: Option<&Value>,
    signing_key: &ed25519_dalek::SigningKey,
    key_id: &str,
) -> Result<String, String> {
    // Build the object to sign
    let mut to_sign = serde_json::json!({
        "method":      method,
        "uri":         path,
        "origin":      origin,
        "destination": destination,
    });

    if let Some(b) = body {
        to_sign["content"] = b.clone();
    }

    // Canonical JSON
    let canonical = crate::canonical_json(&to_sign);

    // Sign
    let sig = signing_key.sign(canonical.as_bytes());
    let sig_b64 = BASE64.encode(sig.to_bytes());

    Ok(format!(
        r#"X-Matrix origin="{}",destination="{}",key="{}",sig="{}""#,
        origin, destination, key_id, sig_b64
    ))
}
