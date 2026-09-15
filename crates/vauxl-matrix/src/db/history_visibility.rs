//! Historical visibility for the accepted, linear room-version 11 event model.
//!
//! Callers hold the room lock and enforce current access separately. History is
//! rejected if any event lacks a continuous depth/predecessor chain: legacy
//! timestamp-only history requires a trusted rebuild before it can be disclosed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sqlx::{Postgres, Transaction};

use crate::error::MatrixError;

type HistoryRow = (
    String,
    String,
    Option<String>,
    Option<Value>,
    Option<Value>,
    Value,
);

struct HistoryEvent {
    id: String,
    event_type: String,
    state_key: Option<String>,
    depth: u64,
    content: Value,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Visibility {
    WorldReadable,
    Shared,
    Invited,
    Joined,
}

impl Visibility {
    fn parse(content: &Value) -> Result<Self, MatrixError> {
        match content.get("history_visibility").and_then(Value::as_str) {
            Some("world_readable") => Ok(Self::WorldReadable),
            Some("shared") => Ok(Self::Shared),
            Some("invited") => Ok(Self::Invited),
            Some("joined") => Ok(Self::Joined),
            _ => Err(MatrixError::Forbidden),
        }
    }
}

enum Audience<'a> {
    User(&'a str),
    Server(&'a str),
}

impl Audience<'_> {
    fn includes(&self, user: &str) -> bool {
        match self {
            Self::User(expected) => user == *expected,
            Self::Server(expected) => {
                ruma::UserId::parse(user).is_ok_and(|id| id.server_name().as_str() == *expected)
            }
        }
    }
}

/// Filter persisted events by a local user's historical membership.
pub async fn filter_for_user(
    tx: &mut Transaction<'_, Postgres>,
    room_id: &str,
    events: Vec<Value>,
    user_id: &str,
) -> Result<Vec<Value>, MatrixError> {
    filter(tx, room_id, events, Audience::User(user_id)).await
}

/// A server can receive an event when at least one of its users could see it.
pub async fn filter_for_server(
    tx: &mut Transaction<'_, Postgres>,
    room_id: &str,
    events: Vec<Value>,
    server: &str,
) -> Result<Vec<Value>, MatrixError> {
    filter(tx, room_id, events, Audience::Server(server)).await
}

async fn filter(
    tx: &mut Transaction<'_, Postgres>,
    room_id: &str,
    events: Vec<Value>,
    audience: Audience<'_>,
) -> Result<Vec<Value>, MatrixError> {
    // Read only ordering and authorization metadata for the history scan.
    let rows: Vec<HistoryRow> = sqlx::query_as(
        "SELECT event_id, event_type, state_key, raw_event->'depth', raw_event->'prev_events',
         CASE WHEN event_type IN ('m.room.create','m.room.member','m.room.history_visibility') THEN content ELSE '{}'::jsonb END
         FROM events WHERE room_id=$1",
    ).bind(room_id).fetch_all(&mut **tx).await?;
    // Distinguish unprovable history from permission or database failures so a
    // sync response can omit this timeline without blocking unrelated rooms.
    let history = validate_history(rows).map_err(|_| MatrixError::HistoryUnavailable)?;
    let allowed = visible_ids(&history, audience).map_err(|_| MatrixError::HistoryUnavailable)?;
    Ok(events
        .into_iter()
        .filter(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .is_some_and(|id| allowed.contains(id))
        })
        .collect())
}

fn validate_history(rows: Vec<HistoryRow>) -> Result<Vec<HistoryEvent>, MatrixError> {
    let mut ordered = BTreeMap::new();
    for (id, event_type, state_key, depth, previous, content) in rows {
        let depth = depth
            .and_then(|v| v.as_u64())
            .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
            .ok_or(MatrixError::Forbidden)?;
        if ordered
            .insert(depth, (id, event_type, state_key, previous, content))
            .is_some()
        {
            return Err(MatrixError::Forbidden);
        }
    }
    let mut history: Vec<HistoryEvent> = Vec::new();
    for (depth, (id, event_type, state_key, previous, content)) in ordered {
        if depth != history.len() as u64 + 1 {
            return Err(MatrixError::Forbidden);
        }
        let previous = previous
            .and_then(|v| v.as_array().cloned())
            .ok_or(MatrixError::Forbidden)?;
        if let Some(last) = history.last() {
            if previous.len() != 1 || previous[0].as_str() != Some(&last.id) {
                return Err(MatrixError::Forbidden);
            }
        } else if event_type != "m.room.create"
            || state_key.as_deref() != Some("")
            || !previous.is_empty()
            || content.get("room_version").and_then(Value::as_str) != Some("11")
        {
            return Err(MatrixError::Forbidden);
        }
        history.push(HistoryEvent {
            id,
            event_type,
            state_key,
            depth,
            content,
        });
    }
    if history.is_empty() {
        return Err(MatrixError::Forbidden);
    }
    Ok(history)
}

fn visible_ids(
    history: &[HistoryEvent],
    audience: Audience<'_>,
) -> Result<BTreeSet<String>, MatrixError> {
    let latest_join = history
        .iter()
        .filter(|event| {
            event.event_type == "m.room.member"
                && event
                    .state_key
                    .as_deref()
                    .is_some_and(|user| audience.includes(user))
                && event.content.get("membership").and_then(Value::as_str) == Some("join")
        })
        .map(|event| event.depth)
        .max()
        .unwrap_or(0);
    let mut memberships: BTreeMap<String, String> = BTreeMap::new();
    let mut policy = Visibility::Shared;
    let mut allowed = BTreeSet::new();
    for event in history {
        let joined_before = memberships.values().any(|membership| membership == "join");
        let invited_before = memberships
            .values()
            .any(|membership| membership == "invite");
        if event.event_type == "m.room.member" {
            let user = event.state_key.as_deref().ok_or(MatrixError::Forbidden)?;
            let membership = event
                .content
                .get("membership")
                .and_then(Value::as_str)
                .filter(|m| matches!(*m, "join" | "invite" | "leave" | "ban"))
                .ok_or(MatrixError::Forbidden)?;
            if audience.includes(user) {
                memberships.insert(user.into(), membership.into());
            }
        }
        let joined = joined_before || memberships.values().any(|membership| membership == "join");
        let invited = invited_before
            || memberships
                .values()
                .any(|membership| membership == "invite");
        let next_policy = if event.event_type == "m.room.history_visibility" {
            if event.state_key.as_deref() != Some("") {
                return Err(MatrixError::Forbidden);
            }
            Visibility::parse(&event.content)?
        } else {
            policy
        };
        // The policy-change event itself uses the less restrictive policy. A
        // membership transition similarly uses membership on either side.
        let visible = match policy.min(next_policy) {
            Visibility::WorldReadable => true,
            Visibility::Shared => joined || latest_join >= event.depth,
            Visibility::Invited => joined || invited,
            Visibility::Joined => joined,
        };
        if visible {
            allowed.insert(event.id.clone());
        }
        policy = next_policy;
    }
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const USER: &str = "@user:remote.example";
    const OTHER: &str = "@other:remote.example";
    const ROOM: &str = "!room:example.org";
    const OWNER: &str = "@owner:example.org";

    fn history(sequence: &[(&str, Option<&str>, Value)]) -> Vec<HistoryEvent> {
        let mut events = vec![HistoryEvent {
            id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some("".into()),
            depth: 1,
            content: json!({"room_version":"11"}),
        }];
        for (index, (kind, key, content)) in sequence.iter().enumerate() {
            events.push(HistoryEvent {
                id: format!("${index}"),
                event_type: (*kind).into(),
                state_key: key.map(str::to_owned),
                depth: index as u64 + 2,
                content: content.clone(),
            });
        }
        events
    }

    #[test]
    fn membership_intervals_and_policy_changes_are_historical() {
        for (policy, expected) in [
            ("invited", vec!["$3", "$5", "$9"]),
            ("joined", vec!["$5", "$9"]),
            ("shared", vec!["$1", "$3", "$5", "$7", "$9"]),
            ("world_readable", vec!["$1", "$3", "$5", "$7", "$9"]),
        ] {
            let events = history(&[
                (
                    "m.room.history_visibility",
                    Some(""),
                    json!({"history_visibility":policy}),
                ),
                ("m.room.message", None, json!({})),
                ("m.room.member", Some(USER), json!({"membership":"invite"})),
                ("m.room.message", None, json!({})),
                ("m.room.member", Some(USER), json!({"membership":"join"})),
                ("m.room.message", None, json!({})),
                ("m.room.member", Some(USER), json!({"membership":"leave"})),
                ("m.room.message", None, json!({})),
                ("m.room.member", Some(USER), json!({"membership":"join"})),
                ("m.room.message", None, json!({})),
            ]);
            for audience in [Audience::User(USER), Audience::Server("remote.example")] {
                let allowed = visible_ids(&events, audience).unwrap();
                let visible: Vec<_> = events
                    .iter()
                    .filter(|e| e.event_type == "m.room.message" && allowed.contains(&e.id))
                    .map(|e| e.id.as_str())
                    .collect();
                assert_eq!(visible, expected, "{policy}");
            }
        }
        let events = history(&[
            (
                "m.room.history_visibility",
                Some(""),
                json!({"history_visibility":"invited"}),
            ),
            ("m.room.message", None, json!({})),
            (
                "m.room.history_visibility",
                Some(""),
                json!({"history_visibility":"shared"}),
            ),
            ("m.room.message", None, json!({})),
            ("m.room.member", Some(USER), json!({"membership":"join"})),
            (
                "m.room.history_visibility",
                Some(""),
                json!({"history_visibility":"joined"}),
            ),
            ("m.room.member", Some(USER), json!({"membership":"leave"})),
            ("m.room.message", None, json!({})),
            (
                "m.room.history_visibility",
                Some(""),
                json!({"history_visibility":"world_readable"}),
            ),
            ("m.room.message", None, json!({})),
            ("m.room.member", Some(USER), json!({"membership":"join"})),
        ]);
        let allowed = visible_ids(&events, Audience::User(USER)).unwrap();
        assert!(!allowed.contains("$1")); // later shared policy does not expose invited history
        assert!(allowed.contains("$3")); // shared before join is visible
        assert!(!allowed.contains("$7")); // later rejoin does not fill a joined-only gap
        assert!(allowed.contains("$9")); // world-readable gap is visible
        assert!(allowed.contains("$8")); // policy transition itself uses the less restrictive mode
    }

    #[test]
    fn server_visibility_is_the_union_of_its_users() {
        let events = history(&[
            (
                "m.room.history_visibility",
                Some(""),
                json!({"history_visibility":"joined"}),
            ),
            ("m.room.member", Some(USER), json!({"membership":"join"})),
            ("m.room.message", None, json!({})),
            ("m.room.member", Some(USER), json!({"membership":"leave"})),
            ("m.room.message", None, json!({})),
            ("m.room.member", Some(OTHER), json!({"membership":"join"})),
            ("m.room.message", None, json!({})),
        ]);
        let allowed = visible_ids(&events, Audience::Server("remote.example")).unwrap();
        assert!(allowed.contains("$2"));
        assert!(!allowed.contains("$4"));
        assert!(allowed.contains("$6"));
        assert!(!visible_ids(&events, Audience::User(USER))
            .unwrap()
            .contains("$6"));
        assert!(!visible_ids(&events, Audience::Server("unrelated.example"))
            .unwrap()
            .contains("$2"));
    }

    #[test]
    fn untrusted_legacy_order_is_rejected() {
        let create = (
            "$create".into(),
            "m.room.create".into(),
            Some("".into()),
            Some(json!(1)),
            Some(json!([])),
            json!({"room_version":"11"}),
        );
        let message = (
            "$message".into(),
            "m.room.message".into(),
            None,
            Some(json!(2)),
            Some(json!(["$create"])),
            json!({}),
        );
        assert!(validate_history(vec![message.clone(), create.clone()]).is_ok());
        let mut legacy = message.clone();
        legacy.3 = None;
        assert!(validate_history(vec![create.clone(), legacy]).is_err());
        let mut gap = message.clone();
        gap.3 = Some(json!(3));
        assert!(validate_history(vec![create.clone(), gap]).is_err());
        let mut fork = message.clone();
        fork.4 = Some(json!(["$untrusted"]));
        assert!(validate_history(vec![create.clone(), fork]).is_err());
        assert!(validate_history(vec![create, message.clone(), message]).is_err());
    }

    fn key() -> crate::signing_key::HomeserverSigningKey {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        crate::signing_key::HomeserverSigningKey {
            verifying_key: signing_key.verifying_key(),
            signing_key,
            key_id: "ed25519:test".into(),
        }
    }
    async fn member(pool: &sqlx::PgPool, target: &str, sender: &str, membership: &str) {
        crate::db::rooms::put_room_state_event(
            pool,
            ROOM,
            "m.room.member",
            target,
            sender,
            json!({"membership":membership}),
            "example.org",
            &key(),
        )
        .await
        .unwrap();
    }
    async fn message(pool: &sqlx::PgPool, body: &str) -> String {
        crate::db::rooms::put_room_event(
            pool,
            ROOM,
            "m.room.message",
            OWNER,
            json!({"body":body}),
            "example.org",
            &key(),
        )
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn local_history_and_sync_omit_preinvite_and_leave_gap_events(pool: sqlx::PgPool) {
        crate::db::rooms::create_room_with_state(
            &pool,
            ROOM,
            OWNER,
            vec![
                (
                    "m.room.create".into(),
                    "".into(),
                    json!({"room_version":"11"}),
                ),
                (
                    "m.room.member".into(),
                    OWNER.into(),
                    json!({"membership":"join"}),
                ),
                (
                    "m.room.power_levels".into(),
                    "".into(),
                    json!({"users":{OWNER:100},"invite":50}),
                ),
                (
                    "m.room.join_rules".into(),
                    "".into(),
                    json!({"join_rule":"invite"}),
                ),
                (
                    "m.room.history_visibility".into(),
                    "".into(),
                    json!({"history_visibility":"invited"}),
                ),
            ],
            "example.org",
            &key(),
        )
        .await
        .unwrap();
        let hidden = message(&pool, "before invite").await;
        member(&pool, USER, OWNER, "invite").await;
        let invited = message(&pool, "invited").await;
        member(&pool, USER, USER, "join").await;
        let joined = message(&pool, "joined").await;
        member(&pool, USER, USER, "leave").await;
        let gap = message(&pool, "leave gap").await;
        member(&pool, USER, OWNER, "invite").await;
        member(&pool, USER, USER, "join").await;
        let rejoined = message(&pool, "rejoined").await;
        // Hostile timestamps may affect legacy pagination, never permission.
        sqlx::query("UPDATE events SET origin_ts=9999999999999 WHERE event_id=$1")
            .bind(&hidden)
            .execute(&pool)
            .await
            .unwrap();
        let (events, _) =
            crate::db::rooms::get_room_messages(&pool, ROOM, USER, None, None, "b", 100)
                .await
                .unwrap();
        let ids: BTreeSet<_> = events
            .iter()
            .map(|e| e["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            BTreeSet::from([invited.as_str(), joined.as_str(), rejoined.as_str()])
        );
        assert!(!ids.contains(hidden.as_str()) && !ids.contains(gap.as_str()));
        let mut tx = pool.begin().await.unwrap();
        crate::db::room_auth::lock_room(&mut tx, ROOM)
            .await
            .unwrap();
        for since in [0, 1] {
            let events = crate::db::sync::get_room_timeline(&mut tx, ROOM, USER, since)
                .await
                .unwrap();
            let ids: BTreeSet<_> = events
                .iter()
                .map(|e| e["event_id"].as_str().unwrap())
                .collect();
            assert_eq!(
                ids,
                BTreeSet::from([invited.as_str(), joined.as_str(), rejoined.as_str()])
            );
        }
    }
}
