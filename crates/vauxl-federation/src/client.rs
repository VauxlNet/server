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

/// Simple canonical JSON for federation signing.
fn canonical_json_inner(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            let pairs: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("{}:{}", json_str(k), canonical_json_inner(v)))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json_inner).collect();
            format!("[{}]", items.join(","))
        }
        Value::String(s) => json_str(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
