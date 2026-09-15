//! Request authentication uses the original encoded request target, including its query.
use crate::{error::MatrixError, state::AppState};
use axum::http::{HeaderMap, Method, Uri};
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use serde_json::{json, Value};

#[derive(Debug)]
struct Authorization {
    origin: String,
    destination: String,
    key: String,
    signature: String,
}

fn parse_authorization(value: &str) -> Option<Authorization> {
    let (scheme, mut rest) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("X-Matrix") {
        return None;
    }
    let mut fields = std::collections::HashMap::new();
    loop {
        rest = rest.trim_start();
        let equals = rest.find('=')?;
        let name = rest[..equals].trim();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        rest = rest[equals + 1..].trim_start();
        let value;
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"')?;
            value = &quoted[..end];
            rest = &quoted[end + 1..];
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            value = rest[..end].trim_end();
            rest = &rest[end..];
        }
        if value.is_empty()
            || value
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || c == '\\' || c == '"')
            || fields.insert(name, value).is_some()
        {
            return None;
        }
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        rest = rest.strip_prefix(',')?;
        if rest.trim().is_empty() {
            return None;
        }
    }
    let auth = Authorization {
        origin: fields.get("origin")?.to_string(),
        destination: fields.get("destination")?.to_string(),
        key: fields.get("key")?.to_string(),
        signature: fields.get("sig")?.to_string(),
    };
    if !vauxl_federation::resolver::is_valid_server_name(&auth.origin)
        || !vauxl_federation::resolver::is_valid_server_name(&auth.destination)
        || !auth.key.strip_prefix("ed25519:").is_some_and(|v| {
            !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        || BASE64.decode(&auth.signature).ok()?.len() != 64
    {
        return None;
    }
    Some(auth)
}

fn request_json(
    auth: &Authorization,
    method: &Method,
    uri: &Uri,
    content: Option<&Value>,
) -> Result<String, MatrixError> {
    let mut request = json!({"method":method.as_str(), "uri":uri.path_and_query().ok_or(MatrixError::Forbidden)?.as_str(), "origin":auth.origin, "destination":auth.destination});
    if let Some(body) = content {
        request["content"] = body.clone();
    }
    vauxl_federation::signing_json(&request)
        .map_err(|_| MatrixError::BadJson("Invalid canonical JSON".into()))
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    original_uri: &Uri,
    content: Option<&Value>,
) -> Result<String, MatrixError> {
    let mut authorizations = Vec::new();
    for header in headers.get_all("authorization") {
        let value = header.to_str().map_err(|_| MatrixError::Forbidden)?;
        let auth = parse_authorization(value).ok_or(MatrixError::Forbidden)?;
        if auth.destination != state.config.server.server_name {
            return Err(MatrixError::Forbidden);
        }
        if authorizations
            .first()
            .is_some_and(|first: &Authorization| first.origin != auth.origin)
        {
            return Err(MatrixError::Forbidden);
        }
        authorizations.push(auth);
        if authorizations.len() > 8 {
            return Err(MatrixError::Forbidden);
        }
    }
    if authorizations.is_empty() {
        return Err(MatrixError::MissingToken);
    }
    for auth in authorizations {
        let canonical = request_json(&auth, method, original_uri, content)?;
        let key = if auth.origin == state.config.server.server_name {
            if auth.key != state.signing_key.key_id {
                continue;
            }
            state.signing_key.verifying_key.as_bytes().to_vec()
        } else {
            match vauxl_federation::keys::get_verification_key(
                &auth.origin,
                &auth.key,
                &state.redis,
                None,
            )
            .await
            {
                Ok(key) => key,
                Err(error) => {
                    tracing::debug!(%error, origin = %auth.origin, "Federation key rejected");
                    continue;
                }
            }
        };
        if vauxl_federation::keys::verify_signature(&key, &auth.signature, canonical.as_bytes())
            .is_ok()
        {
            return Ok(auth.origin);
        }
    }
    Err(MatrixError::Forbidden)
}

/// Attach the v11 reference-hash ID for the internal storage representation.
pub fn with_event_id(event: &Value) -> Result<Value, MatrixError> {
    let canonical =
        ruma::canonical_json::to_canonical_value(event).map_err(|_| MatrixError::Forbidden)?;
    let mut object = canonical.as_object().ok_or(MatrixError::Forbidden)?.clone();
    let supplied = object.remove("event_id");
    let hash = ruma::signatures::reference_hash(&object, &ruma::RoomVersionId::V11)
        .map_err(|_| MatrixError::Forbidden)?;
    let id = format!("${hash}");
    if supplied.is_some_and(|value| value.as_str() != Some(&id)) {
        return Err(MatrixError::Forbidden);
    }
    let mut event = event.clone();
    event["event_id"] = json!(id);
    Ok(event)
}

/// Verify the sender signature, content hash and room-v11 reference hash before any
/// authorization/database mutation. Event auth against current room state is separate.
pub async fn verify_event(state: &AppState, event: &Value) -> Result<(), MatrixError> {
    let sender = event
        .get("sender")
        .and_then(Value::as_str)
        .ok_or(MatrixError::Forbidden)?;
    let sender = <&ruma::UserId>::try_from(sender).map_err(|_| MatrixError::Forbidden)?;
    let server = sender.server_name().as_str();
    let timestamp = event
        .get("origin_server_ts")
        .and_then(Value::as_u64)
        .ok_or(MatrixError::Forbidden)?;
    let signatures = event
        .get("signatures")
        .and_then(|s| s.get(server))
        .and_then(Value::as_object)
        .ok_or(MatrixError::Forbidden)?;
    if signatures.len() > 8 {
        return Err(MatrixError::Forbidden);
    }
    let mut keys = std::collections::BTreeMap::new();
    for id in signatures.keys() {
        if !id.starts_with("ed25519:") {
            continue;
        }
        let key = if server == state.config.server.server_name && id == &state.signing_key.key_id {
            Some(state.signing_key.verifying_key.as_bytes().to_vec())
        } else if server == state.config.server.server_name {
            None
        } else {
            vauxl_federation::keys::get_verification_key(server, id, &state.redis, Some(timestamp))
                .await
                .ok()
        };
        if let Some(key) = key {
            keys.insert(id.clone(), ruma::serde::Base64::new(key));
        }
    }
    let public_keys = std::collections::BTreeMap::from([(server.to_owned(), keys)]);
    verify_event_integrity(event, &public_keys)
}

fn verify_event_integrity(
    event: &Value,
    public_keys: &ruma::signatures::PublicKeyMap,
) -> Result<(), MatrixError> {
    let mut object =
        ruma::canonical_json::to_canonical_value(event).map_err(|_| MatrixError::Forbidden)?;
    let object = object.as_object_mut().ok_or(MatrixError::Forbidden)?;
    // event_id is a transport/storage field, absent from v3+ signed PDUs.
    let event_id = object
        .remove("event_id")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(MatrixError::Forbidden)?;
    let version = ruma::RoomVersionId::V11;
    if ruma::signatures::verify_event(public_keys, object, &version)
        .map_err(|_| MatrixError::Forbidden)?
        != ruma::signatures::Verified::All
    {
        return Err(MatrixError::Forbidden);
    }
    let hash =
        ruma::signatures::reference_hash(object, &version).map_err(|_| MatrixError::Forbidden)?;
    if event_id != format!("${hash}") {
        return Err(MatrixError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn auth() -> Authorization {
        Authorization {
            origin: "remote.example".into(),
            destination: "local.example".into(),
            key: "ed25519:a".into(),
            signature: BASE64.encode([0; 64]),
        }
    }
    #[test]
    fn only_intact_sender_signed_v11_events_are_accepted() {
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let key = crate::signing_key::HomeserverSigningKey {
            verifying_key: signing_key.verifying_key(),
            signing_key,
            key_id: "ed25519:a".into(),
        };
        let keys = std::collections::BTreeMap::from([(
            "remote.example".into(),
            std::collections::BTreeMap::from([(
                "ed25519:a".into(),
                ruma::serde::Base64::new(key.verifying_key.as_bytes().to_vec()),
            )]),
        )]);
        let mut event = json!({"type":"m.room.message","sender":"@alice:remote.example","room_id":"!room:local.example", "origin_server_ts":100, "content":{"body":"hello","msgtype":"m.text"},"prev_events":["$prev"],"auth_events":["$create","$member"],"depth":3});
        crate::event_signing::sign_event(&mut event, "remote.example", &key).unwrap();
        assert!(verify_event_integrity(&event, &keys).is_ok());
        let mut wire = event.clone();
        wire.as_object_mut().unwrap().remove("event_id");
        assert_eq!(with_event_id(&wire).unwrap()["event_id"], event["event_id"]);
        for (field, value) in [
            ("event_id", json!("$forged")),
            ("sender", json!("@admin:local.example")),
            ("content", json!({"body":"tampered","msgtype":"m.text"})),
            ("signatures", json!({})),
            ("auth_events", json!(["$forged"])),
        ] {
            let mut tampered = event.clone();
            tampered[field] = value;
            assert!(verify_event_integrity(&tampered, &keys).is_err(), "{field}");
        }
        event["event_id"] = json!("$forged");
        assert!(with_event_id(&event).is_err());
    }
    #[test]
    fn rejects_ambiguous_or_malformed_authorization() {
        let signature = BASE64.encode([0; 64]);
        let valid = format!("X-Matrix origin=remote.example,destination=local.example,key=\"ed25519:a\",sig=\"{signature}\"");
        assert!(parse_authorization(&valid).is_some());
        for suffix in [",origin=evil.example", ",sig=x", ",", " trailing"] {
            assert!(parse_authorization(&(valid.clone() + suffix)).is_none());
        }
        assert!(parse_authorization(&valid.replace("remote.example", "evil@localhost")).is_none());
        assert!(parse_authorization(&valid.replace("ed25519:a", "ed25519:")).is_none());
        assert!(parse_authorization(&valid.replace(&signature, "garbage")).is_none());
    }
    #[test]
    fn signature_binds_every_request_component_and_encoded_uri() {
        let auth = auth();
        let key = SigningKey::from_bytes(&[42; 32]);
        let uri: Uri = "/_matrix/federation/v1/state/%21room%3Aremote.example?event_id=%24one&x=2"
            .parse()
            .unwrap();
        let body = json!({"nested":{"z":1,"a":2}});
        let canonical = request_json(&auth, &Method::PUT, &uri, Some(&body)).unwrap();
        let sig = BASE64.encode(key.sign(canonical.as_bytes()).to_bytes());
        let verify = |value: String| {
            vauxl_federation::keys::verify_signature(
                key.verifying_key().as_bytes(),
                &sig,
                value.as_bytes(),
            )
            .is_ok()
        };
        assert!(verify(canonical));
        assert!(!verify(
            request_json(&auth, &Method::GET, &uri, Some(&body)).unwrap()
        ));
        assert!(!verify(
            request_json(&auth, &Method::PUT, &uri, None).unwrap()
        ));
        assert!(!verify(
            request_json(
                &auth,
                &Method::PUT,
                &uri,
                Some(&json!({"nested":{"z":2,"a":2}}))
            )
            .unwrap()
        ));
        for changed in [
            "/_matrix/federation/v1/state/!room:remote.example?event_id=%24one&x=2",
            "/_matrix/federation/v1/state/%21room%3Aremote.example?event_id=%24two&x=2",
        ] {
            assert!(!verify(
                request_json(&auth, &Method::PUT, &changed.parse().unwrap(), Some(&body)).unwrap()
            ));
        }
        let mut changed = auth;
        changed.origin = "other.example".into();
        assert!(!verify(
            request_json(&changed, &Method::PUT, &uri, Some(&body)).unwrap()
        ));
        changed.destination = "other.example".into();
        assert!(!verify(
            request_json(&changed, &Method::PUT, &uri, Some(&body)).unwrap()
        ));
    }
    #[test]
    fn rejects_noncanonical_numbers() {
        assert!(request_json(
            &auth(),
            &Method::PUT,
            &"/".parse().unwrap(),
            Some(&json!({"n":1.5}))
        )
        .is_err());
        assert!(request_json(
            &auth(),
            &Method::PUT,
            &"/".parse().unwrap(),
            Some(&json!({"n":9007199254740992u64}))
        )
        .is_err());
    }
}
