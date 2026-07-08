//! Matrix event signing.
//!
//! Every event the homeserver creates must be signed with the server's
//! Ed25519 key before storage and before sending to federation.
//!
//! Matrix signing spec:
//! 1. Remove "unsigned" and "signatures" fields
//! 2. Canonical JSON encode the result
//! 3. Sign with Ed25519
//! 4. Add signature back as {"signatures": {"server_name": {"ed25519:key_id": "base64sig"}}}

use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use ed25519_dalek::Signer;
use serde_json::Value;

use crate::signing_key::HomeserverSigningKey;

/// Signs a Matrix event JSON object in-place.
/// Adds the "signatures" field required by the Matrix spec.
pub fn sign_event(event: &mut Value, server_name: &str, key: &HomeserverSigningKey) {
    // Step 1: build the object to sign (no "unsigned" or "signatures")
    let signable = signable_content(event);

    // Step 2: canonical JSON — sorted keys, no extra whitespace
    let canonical = canonical_json(&signable);

    // Step 3: sign
    let signature = key.signing_key.sign(canonical.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());

    // Step 4: attach signature
    let signatures = serde_json::json!({
        server_name: {
            key.key_id.clone(): sig_b64
        }
    });

    if let Some(obj) = event.as_object_mut() {
        obj.insert("signatures".into(), signatures);
    }
}

/// Builds the content to be signed: the event minus "unsigned" and "signatures".
fn signable_content(event: &Value) -> Value {
    let mut obj = match event.as_object() {
        Some(o) => o.clone(),
        None => return event.clone(),
    };
    obj.remove("unsigned");
    obj.remove("signatures");
    Value::Object(obj)
}

/// Produces canonical JSON: keys sorted lexicographically, no whitespace.
/// This is the Matrix canonical JSON format (MSC1301).
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            // Sort keys
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());

            let pairs: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("{}:{}", json_string(k), canonical_json(v)))
                .collect();

            format!("{{{}}}", pairs.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        Value::String(s) => json_string(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
    }
}

fn json_string(s: &str) -> String {
    // Escape according to JSON spec
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_sorts_keys() {
        let val = json!({"b": 2, "a": 1, "c": 3});
        assert_eq!(canonical_json(&val), r#"{"a":1,"b":2,"c":3}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let val = json!({"z": {"b": 2, "a": 1}});
        assert_eq!(canonical_json(&val), r#"{"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_signable_removes_unsigned() {
        let val = json!({"type": "m.room.message", "unsigned": {"age": 100}});
        let signable = signable_content(&val);
        assert!(signable.get("unsigned").is_none());
        assert!(signable.get("type").is_some());
    }
}
