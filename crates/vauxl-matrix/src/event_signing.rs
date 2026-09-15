//! Matrix room-version 11 event hashes, reference IDs, and Ed25519 signatures.

use ruma::{
    signatures::{hash_and_sign_event, reference_hash},
    CanonicalJsonObject, RoomVersionId,
};
use serde_json::Value;

use crate::{error::MatrixError, signing_key::HomeserverSigningKey};

pub use vauxl_federation::canonical_json;

/// Hash and sign a locally constructed v11 event, then attach its client-facing ID.
///
/// `event_id` is not part of a v11 wire PDU. Remove it before signing or verifying;
/// the database and client API representation carry the derived ID separately.
pub fn sign_event(
    event: &mut Value,
    server_name: &str,
    key: &HomeserverSigningKey,
) -> Result<(), MatrixError> {
    let mut object: CanonicalJsonObject = serde_json::from_value(event.clone())
        .map_err(|_| MatrixError::BadJson("Event is not Matrix canonical JSON".into()))?;
    object.remove("event_id");
    object.remove("signatures");
    object.remove("hashes");

    hash_and_sign_event(server_name, key, &mut object, &RoomVersionId::V11)
        .map_err(|e| MatrixError::BadJson(format!("Cannot sign event: {e}")))?;
    let event_id = format!(
        "${}",
        reference_hash(&object, &RoomVersionId::V11)
            .map_err(|e| MatrixError::BadJson(format!("Cannot derive event ID: {e}")))?
    );
    object.insert("event_id".into(), event_id.into());
    *event = serde_json::to_value(object)
        .map_err(|e| MatrixError::Internal(format!("Cannot serialize signed event: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ruma::{
        serde::Base64,
        signatures::{verify_event, PublicKeyMap, Verified},
    };
    use serde_json::json;

    fn key() -> HomeserverSigningKey {
        let signing_key = SigningKey::from_bytes(&[31; 32]);
        HomeserverSigningKey {
            verifying_key: signing_key.verifying_key(),
            signing_key,
            key_id: "ed25519:a".into(),
        }
    }

    fn event() -> Value {
        json!({
            "event_id": "$temporary:example.test",
            "room_id": "!room:example.test", "type": "m.room.message",
            "sender": "@alice:example.test", "origin_server_ts": 123,
            "content": {"msgtype": "m.text", "body": "hello"},
            "prev_events": ["$previous"], "auth_events": ["$create", "$member"],
            "depth": 3
        })
    }

    fn keys(key: &HomeserverSigningKey) -> PublicKeyMap {
        [(
            "example.test".into(),
            [(
                key.key_id.clone(),
                Base64::new(key.verifying_key.to_bytes().to_vec()),
            )]
            .into(),
        )]
        .into()
    }

    #[test]
    fn generated_event_verifies_with_ruma_and_has_reference_id() {
        let key = key();
        let mut event = event();
        sign_event(&mut event, "example.test", &key).unwrap();
        let mut wire: CanonicalJsonObject = serde_json::from_value(event.clone()).unwrap();
        wire.remove("event_id");
        assert_eq!(
            verify_event(&keys(&key), &wire, &RoomVersionId::V11).unwrap(),
            Verified::All
        );
        assert_eq!(
            event["event_id"],
            format!("${}", reference_hash(&wire, &RoomVersionId::V11).unwrap())
        );

        event["content"]["body"] = json!("tampered");
        let mut tampered: CanonicalJsonObject = serde_json::from_value(event).unwrap();
        tampered.remove("event_id");
        assert_eq!(
            verify_event(&keys(&key), &tampered, &RoomVersionId::V11).unwrap(),
            Verified::Signatures
        );
    }

    #[test]
    fn malformed_canonical_numbers_are_rejected_without_mutating_event() {
        let key = key();
        for number in [json!(1.5), json!(9_007_199_254_740_992_u64)] {
            let mut event = event();
            event["content"]["number"] = number;
            let original = event.clone();
            assert!(sign_event(&mut event, "example.test", &key).is_err());
            assert_eq!(event, original);
        }
    }

    #[test]
    fn successive_events_with_same_content_and_timestamp_have_distinct_ids() {
        let key = key();
        let mut first = event();
        sign_event(&mut first, "example.test", &key).unwrap();
        let mut next = event();
        next["prev_events"] = json!([first["event_id"]]);
        next["depth"] = json!(4);
        sign_event(&mut next, "example.test", &key).unwrap();
        assert_ne!(first["event_id"], next["event_id"]);
    }
}
