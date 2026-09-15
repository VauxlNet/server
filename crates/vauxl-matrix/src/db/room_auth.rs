//! Authorization for the supported local room-version 11 event model.
//!
//! This checks current room state, not federation DAG/state resolution. Callers
//! must lock the room before reading authorization state and hold that lock until
//! the authorized event and its state/membership updates have committed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sqlx::{Postgres, Transaction};

use crate::error::MatrixError;

type Result<T> = std::result::Result<T, MatrixError>;

/// Serialize every event writer for an existing room, including federation.
pub async fn lock_room(tx: &mut Transaction<'_, Postgres>, room_id: &str) -> Result<()> {
    let room: Option<String> =
        sqlx::query_scalar("SELECT room_id FROM rooms WHERE room_id = $1 FOR UPDATE")
            .bind(room_id)
            .fetch_optional(&mut **tx)
            .await?;
    room.ok_or(MatrixError::NotFound).map(|_| ())
}

/// Authorize against state read inside the caller's locked write transaction.
pub async fn authorize_event(
    tx: &mut Transaction<'_, Postgres>,
    room_id: &str,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
) -> Result<()> {
    let rows: Vec<(String, String, String, Value)> = sqlx::query_as(
        "SELECT rs.event_type, rs.state_key, e.sender, e.content
         FROM room_state rs JOIN events e ON e.event_id = rs.event_id
         WHERE rs.room_id = $1 AND rs.event_type IN
         ('m.room.create', 'm.room.member', 'm.room.power_levels', 'm.room.join_rules')",
    )
    .bind(room_id)
    .fetch_all(&mut **tx)
    .await?;
    let state = AuthState(
        rows.into_iter()
            .map(|(t, k, s, c)| ((t, k), (s, c)))
            .collect(),
    );
    state.authorize(room_id, sender, event_type, state_key, content)
}

#[derive(Default)]
struct AuthState(BTreeMap<(String, String), (String, Value)>);

impl AuthState {
    fn get(&self, event_type: &str, key: &str) -> Option<&Value> {
        self.0.get(&(event_type.into(), key.into())).map(|(_, c)| c)
    }

    fn membership(&self, user: &str) -> Option<&str> {
        self.get("m.room.member", user)?.get("membership")?.as_str()
    }

    fn authorize(
        &self,
        room_id: &str,
        sender: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Result<()> {
        let sender_id = ruma::UserId::parse(sender).map_err(|_| MatrixError::Forbidden)?;
        let room = ruma::RoomId::parse(room_id).map_err(|_| MatrixError::Forbidden)?;
        ensure(content.is_object() && !event_type.is_empty())?;
        let create = self.0.get(&("m.room.create".into(), String::new()));
        if event_type == "m.room.create" {
            // Bootstrap is possible only in a newly inserted, empty room.
            return ensure(
                create.is_none()
                    && self.0.is_empty()
                    && state_key == Some("")
                    && room.server_name() == Some(sender_id.server_name())
                    && content.get("room_version").and_then(Value::as_str) == Some("11"),
            );
        }
        let (creator, create_content) = create.ok_or(MatrixError::Forbidden)?;
        ensure(create_content.get("room_version").and_then(Value::as_str) == Some("11"))?;
        if create_content.get("m.federate") == Some(&Value::Bool(false)) {
            let creator_id = ruma::UserId::parse(creator).map_err(|_| MatrixError::Forbidden)?;
            ensure(creator_id.server_name() == sender_id.server_name())?;
        }
        let empty = serde_json::json!({});
        let old_power = self.get("m.room.power_levels", "");
        let power = PowerLevels::parse(old_power.unwrap_or(&empty))?;
        let sender_level = if old_power.is_none() && sender == creator {
            100
        } else {
            power.user(sender)
        };

        if event_type == "m.room.member" {
            let target = state_key.ok_or(MatrixError::Forbidden)?;
            ruma::UserId::parse(target).map_err(|_| MatrixError::Forbidden)?;
            // Third-party invites, restricted joins and knocks need additional
            // proofs and auth events which this server does not implement.
            ensure(
                !content
                    .as_object()
                    .unwrap()
                    .contains_key("third_party_invite")
                    && !content
                        .as_object()
                        .unwrap()
                        .contains_key("join_authorised_via_users_server"),
            )?;
            let next = content
                .get("membership")
                .and_then(Value::as_str)
                .ok_or(MatrixError::Forbidden)?;
            let previous = self.membership(target);
            if next == "join" {
                ensure(sender == target && previous != Some("ban"))?;
                if sender == creator && self.0.len() == 1 {
                    return Ok(());
                }
                if previous == Some("join") {
                    return Ok(());
                }
                let rule = self
                    .get("m.room.join_rules", "")
                    .and_then(|v| v.get("join_rule"))
                    .and_then(Value::as_str)
                    .unwrap_or("invite");
                return ensure(
                    rule == "public" || (rule == "invite" && previous == Some("invite")),
                );
            }
            if next == "leave" && sender == target {
                return ensure(matches!(previous, Some("join" | "invite")));
            }
            ensure(self.membership(sender) == Some("join"))?;
            let target_level = if old_power.is_none() && target == creator {
                100
            } else {
                power.user(target)
            };
            return match next {
                "invite" => ensure(
                    sender_level >= power.scalar("invite")
                        && !matches!(previous, Some("join" | "ban")),
                ),
                "ban" => ensure(sender_level >= power.scalar("ban") && sender_level > target_level),
                "leave" => ensure(
                    matches!(previous, Some("join" | "invite" | "ban"))
                        && sender_level >= power.scalar("kick")
                        && sender_level > target_level
                        && (previous != Some("ban") || sender_level >= power.scalar("ban")),
                ),
                _ => Err(MatrixError::Forbidden),
            };
        }
        ensure(self.membership(sender) == Some("join"))?;
        // These types require a state key (and the singleton types an empty one).
        if matches!(
            event_type,
            "m.room.power_levels"
                | "m.room.join_rules"
                | "m.room.history_visibility"
                | "m.room.server_acl"
        ) {
            ensure(state_key == Some(""))?;
        }
        // Unsupported special auth must not fall through to ordinary event auth.
        ensure(!matches!(
            event_type,
            "m.room.third_party_invite" | "m.room.redaction"
        ))?;
        if let Some(key) = state_key {
            ensure(!key.starts_with('@') || key == sender)?;
        }
        let required = power
            .map("events")
            .get(event_type)
            .copied()
            .unwrap_or_else(|| {
                power.scalar(if state_key.is_some() {
                    "state_default"
                } else {
                    "events_default"
                })
            });
        ensure(sender_level >= required)?;
        if event_type == "m.room.history_visibility" {
            ensure(matches!(
                content.get("history_visibility").and_then(Value::as_str),
                Some("world_readable" | "shared" | "invited" | "joined")
            ))?;
        }
        if event_type == "m.room.server_acl" {
            serde_json::from_value::<ruma::events::room::server_acl::RoomServerAclEventContent>(
                content.clone(),
            )
            .map_err(|_| MatrixError::Forbidden)?;
        }
        if event_type == "m.room.power_levels" {
            power.authorize_change(&PowerLevels::parse(content)?, sender, sender_level)?;
        }
        if event_type == "m.room.join_rules" {
            ensure(matches!(
                content.get("join_rule").and_then(Value::as_str),
                Some("public" | "invite")
            ))?;
        }
        Ok(())
    }
}

fn ensure(allowed: bool) -> Result<()> {
    if allowed {
        Ok(())
    } else {
        Err(MatrixError::Forbidden)
    }
}

const SCALARS: &[(&str, i64)] = &[
    ("users_default", 0),
    ("events_default", 0),
    ("state_default", 50),
    ("ban", 50),
    ("kick", 50),
    ("redact", 50),
    ("invite", 0),
];

struct PowerLevels {
    scalars: BTreeMap<String, i64>,
    maps: BTreeMap<String, BTreeMap<String, i64>>,
}

impl PowerLevels {
    fn parse(value: &Value) -> Result<Self> {
        let object = value.as_object().ok_or(MatrixError::Forbidden)?;
        let mut scalars = BTreeMap::new();
        for &(key, default) in SCALARS {
            scalars.insert(
                key.into(),
                object.get(key).map(level).transpose()?.unwrap_or(default),
            );
        }
        let mut maps = BTreeMap::new();
        for key in ["users", "events", "notifications"] {
            let empty = Map::new();
            let values = match object.get(key) {
                Some(v) => v.as_object().ok_or(MatrixError::Forbidden)?,
                None => &empty,
            };
            let mut levels = BTreeMap::new();
            for (name, value) in values {
                if key == "users" {
                    ruma::UserId::parse(name).map_err(|_| MatrixError::Forbidden)?;
                }
                levels.insert(name.clone(), level(value)?);
            }
            if key == "notifications" {
                levels.entry("room".into()).or_insert(50);
            }
            maps.insert(key.into(), levels);
        }
        Ok(Self { scalars, maps })
    }

    fn scalar(&self, key: &str) -> i64 {
        self.scalars[key]
    }
    fn map(&self, key: &str) -> &BTreeMap<String, i64> {
        &self.maps[key]
    }
    fn user(&self, user: &str) -> i64 {
        self.map("users")
            .get(user)
            .copied()
            .unwrap_or_else(|| self.scalar("users_default"))
    }

    fn authorize_change(&self, next: &Self, sender: &str, sender_level: i64) -> Result<()> {
        for &(key, _) in SCALARS {
            let old = self.scalar(key);
            let new = next.scalar(key);
            if old != new {
                ensure(old <= sender_level && new <= sender_level)?;
            }
        }
        for map in ["users", "events", "notifications"] {
            let old = self.map(map);
            let new = next.map(map);
            let keys: BTreeSet<_> = old.keys().chain(new.keys()).collect();
            for key in keys {
                if old.get(key) == new.get(key) {
                    continue;
                }
                ensure(
                    old.get(key).is_none_or(|v| *v <= sender_level)
                        && new.get(key).is_none_or(|v| *v <= sender_level),
                )?;
                if map == "users" {
                    // Removing an entry assigns users_default. Check the
                    // resulting effective level too, or deleting a low explicit
                    // level could promote the sender or a subordinate above it.
                    ensure(self.user(key) <= sender_level && next.user(key) <= sender_level)?;
                    if key != sender {
                        // An equal-power peer cannot be demoted, including by
                        // deleting their entry and falling back to default.
                        ensure(self.user(key) < sender_level)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn level(value: &Value) -> Result<i64> {
    let number = value.as_i64().ok_or(MatrixError::Forbidden)?;
    ensure((-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&number))?;
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ROOM: &str = "!room:example.org";
    const OWNER: &str = "@owner:example.org";
    const MOD: &str = "@mod:example.org";
    const PEER: &str = "@peer:example.org";
    const USER: &str = "@user:example.org";
    const OUTSIDER: &str = "@outsider:example.org";

    fn state() -> AuthState {
        let mut state = AuthState::default();
        state.insert("m.room.create", "", json!({"room_version":"11"}));
        state.insert(
            "m.room.power_levels",
            "",
            json!({
                "users": {OWNER:100, MOD:50, PEER:50}, "invite":50,
            }),
        );
        state.insert("m.room.join_rules", "", json!({"join_rule":"invite"}));
        for user in [OWNER, MOD, PEER, USER] {
            state.insert("m.room.member", user, json!({"membership":"join"}));
        }
        state
    }

    impl AuthState {
        fn insert(&mut self, t: &str, key: &str, c: Value) {
            self.0.insert((t.into(), key.into()), (OWNER.into(), c));
        }
        fn allowed(&self, sender: &str, t: &str, key: Option<&str>, c: Value) -> bool {
            self.authorize(ROOM, sender, t, key, &c).is_ok()
        }
    }

    #[test]
    fn event_thresholds_and_special_types_cannot_bypass_state_auth() {
        let state = state();
        for (sender, kind, key, content, allowed) in [
            (USER, "m.room.message", None, json!({"body":"hello"}), true),
            (OUTSIDER, "m.room.message", None, json!({}), false),
            (
                USER,
                "m.room.topic",
                Some(""),
                json!({"topic":"takeover"}),
                false,
            ),
            (
                MOD,
                "m.room.topic",
                Some(""),
                json!({"topic":"allowed"}),
                true,
            ),
            (
                OWNER,
                "m.room.create",
                Some(""),
                json!({"room_version":"11"}),
                false,
            ),
            (OWNER, "m.room.power_levels", None, json!({}), false),
            (
                OWNER,
                "m.room.power_levels",
                Some("other"),
                json!({}),
                false,
            ),
            (
                OWNER,
                "m.room.member",
                None,
                json!({"membership":"ban"}),
                false,
            ),
            (
                OWNER,
                "m.room.join_rules",
                None,
                json!({"join_rule":"public"}),
                false,
            ),
            (
                OWNER,
                "m.room.join_rules",
                Some(""),
                json!({"join_rule":"restricted"}),
                false,
            ),
            (
                OWNER,
                "m.room.third_party_invite",
                Some("token"),
                json!({}),
                false,
            ),
            (OWNER, "m.room.redaction", None, json!({}), false),
            (OWNER, "custom.state", Some(USER), json!({}), false),
            (USER, "m.room.message", None, Value::Null, false),
            (
                OWNER,
                "m.room.history_visibility",
                None,
                json!({"history_visibility":"shared"}),
                false,
            ),
            (
                OWNER,
                "m.room.history_visibility",
                Some(""),
                json!({"history_visibility":"invalid"}),
                false,
            ),
            (
                OWNER,
                "m.room.server_acl",
                Some("other"),
                json!({"allow":["*"]}),
                false,
            ),
            (
                OWNER,
                "m.room.server_acl",
                Some(""),
                json!({"allow":"*"}),
                false,
            ),
            (
                OWNER,
                "m.room.server_acl",
                Some(""),
                json!({"allow":["*"]}),
                true,
            ),
        ] {
            assert_eq!(
                state.allowed(sender, kind, key, content),
                allowed,
                "{sender} {kind} {key:?}"
            );
        }
        let mut state = state;
        state.insert(
            "m.room.power_levels",
            "",
            json!({"users":{OWNER:100}, "events":{"m.room.message":50}}),
        );
        assert!(!state.allowed(USER, "m.room.message", None, json!({})));
    }

    #[test]
    fn membership_transitions_enforce_hierarchy_and_bans() {
        for (sender, target, previous, next, public, allowed) in [
            (USER, OWNER, "join", "leave", false, false),
            (MOD, PEER, "join", "leave", false, false),
            (MOD, USER, "join", "leave", false, true),
            (MOD, USER, "invite", "leave", false, true),
            (MOD, OWNER, "join", "ban", false, false),
            (MOD, PEER, "join", "ban", false, false),
            (MOD, USER, "join", "ban", false, true),
            (USER, OUTSIDER, "leave", "invite", false, false),
            (MOD, OUTSIDER, "leave", "invite", false, true),
            (OWNER, OUTSIDER, "ban", "invite", false, false),
            (OUTSIDER, OUTSIDER, "ban", "join", true, false),
            (OUTSIDER, OUTSIDER, "ban", "leave", true, false),
            (OUTSIDER, OUTSIDER, "leave", "join", false, false),
            (OUTSIDER, OUTSIDER, "invite", "join", false, true),
            (OUTSIDER, OUTSIDER, "leave", "join", true, true),
            (OWNER, OUTSIDER, "leave", "join", true, false),
            (OUTSIDER, OUTSIDER, "invite", "leave", false, true),
            (USER, USER, "join", "leave", false, true),
            (MOD, USER, "ban", "leave", false, true),
            (USER, USER, "join", "knock", false, false),
            (USER, USER, "join", "invalid", false, false),
        ] {
            let mut state = state();
            state.insert("m.room.member", target, json!({"membership":previous}));
            state.insert(
                "m.room.join_rules",
                "",
                json!({"join_rule":if public {"public"} else {"invite"}}),
            );
            assert_eq!(
                state.allowed(
                    sender,
                    "m.room.member",
                    Some(target),
                    json!({"membership":next})
                ),
                allowed,
                "{sender} {target} {previous}->{next}, public={public}"
            );
        }
        let state = state();
        for content in [
            json!({}),
            json!({"membership":null}),
            json!({"membership":"join","join_authorised_via_users_server":OWNER}),
            json!({"membership":"invite","third_party_invite":{}}),
        ] {
            assert!(!state.allowed(OWNER, "m.room.member", Some(OUTSIDER), content));
        }
    }

    #[test]
    fn power_changes_cannot_escalate_or_demote_equal_power_peers() {
        let state = state();
        let old = state.get("m.room.power_levels", "").unwrap();
        for (sender, field, value, allowed) in [
            (USER, "users_default", json!(100), false),
            (MOD, "users_default", json!(51), false),
            (MOD, "events_default", json!(51), false),
            (MOD, "state_default", json!(51), false),
            (MOD, "ban", json!(51), false),
            (MOD, "kick", json!(51), false),
            (MOD, "invite", json!(51), false),
            (MOD, "redact", json!(51), false),
            (MOD, "events", json!({"m.room.message":51}), false),
            (MOD, "notifications", json!({"room":51}), false),
            (MOD, "notifications", json!({"room":40}), true),
            (OWNER, "users_default", json!(50), true),
            (OWNER, "users_default", json!("50"), false),
            (OWNER, "events", json!({"x":1.5}), false),
            (OWNER, "users", json!({"bad":50}), false),
            (OWNER, "notifications", Value::Null, false),
        ] {
            let mut content = old.clone();
            content[field] = value;
            assert_eq!(
                state.allowed(sender, "m.room.power_levels", Some(""), content),
                allowed,
                "{sender} {field}"
            );
        }
        for (sender, target, new, allowed) in [
            (MOD, MOD, Some(51), false),
            (MOD, MOD, Some(0), true),
            (MOD, USER, Some(50), true),
            (MOD, PEER, Some(0), false),
            (MOD, PEER, None, false),
            (MOD, OWNER, None, false),
            (OWNER, OWNER, None, true),
            (OWNER, USER, Some(101), false),
        ] {
            let mut content = old.clone();
            if let Some(level) = new {
                content["users"][target] = json!(level);
            } else {
                content["users"].as_object_mut().unwrap().remove(target);
            }
            assert_eq!(
                state.allowed(sender, "m.room.power_levels", Some(""), content),
                allowed,
                "{sender} changes {target} to {new:?}"
            );
        }
        let mut old = old.clone();
        let mut state = state;
        old["events"] = json!({"protected":100});
        old["notifications"] = json!({"room":100});
        old["ban"] = json!(100);
        state.insert("m.room.power_levels", "", old.clone());
        for field in ["events", "notifications", "ban"] {
            let mut content = old.clone();
            content.as_object_mut().unwrap().remove(field);
            assert!(
                !state.allowed(MOD, "m.room.power_levels", Some(""), content),
                "removed {field}"
            );
        }
    }

    #[test]
    fn removing_user_levels_checks_the_effective_default() {
        for (default, sender, target, allowed) in [
            (100, MOD, MOD, false),
            (100, MOD, USER, false),
            (0, MOD, MOD, true),
            (0, MOD, USER, true),
            (50, MOD, MOD, true),
            (50, MOD, USER, true),
            (100, OWNER, OWNER, true),
            (100, OWNER, USER, true),
        ] {
            let mut state = state();
            let old = json!({"users_default":default, "users":{OWNER:100,MOD:50,USER:0}});
            state.insert("m.room.power_levels", "", old.clone());
            let mut next = old;
            next["users"].as_object_mut().unwrap().remove(target);
            assert_eq!(
                state.allowed(sender, "m.room.power_levels", Some(""), next),
                allowed,
                "{sender} removes {target} with users_default={default}"
            );
        }
    }

    fn signing_key() -> crate::signing_key::HomeserverSigningKey {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        crate::signing_key::HomeserverSigningKey {
            verifying_key: signing_key.verifying_key(),
            signing_key,
            key_id: "ed25519:test".into(),
        }
    }

    async fn create_test_room(pool: &sqlx::PgPool) {
        create_test_room_with_id(pool, ROOM).await;
    }

    async fn create_test_room_with_id(pool: &sqlx::PgPool, room: &str) {
        crate::db::rooms::create_room_with_state(
            pool,
            room,
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
                    json!({"join_rule":"public"}),
                ),
            ],
            "example.org",
            &signing_key(),
        )
        .await
        .unwrap();
    }

    async fn member(
        pool: &sqlx::PgPool,
        sender: &str,
        target: &str,
        membership: &str,
    ) -> Result<String> {
        crate::db::rooms::put_room_state_event(
            pool,
            ROOM,
            "m.room.member",
            target,
            sender,
            json!({"membership":membership}),
            "example.org",
            &signing_key(),
        )
        .await
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn unauthorized_writes_leave_events_state_and_membership_unchanged(pool: sqlx::PgPool) {
        create_test_room(&pool).await;
        member(&pool, USER, USER, "join").await.unwrap();
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(member(&pool, USER, OWNER, "ban").await.is_err());
        assert!(crate::db::rooms::put_room_state_event(
            &pool,
            ROOM,
            "m.room.power_levels",
            "",
            USER,
            json!({"users":{USER:100}}),
            "example.org",
            &signing_key()
        )
        .await
        .is_err());
        assert!(crate::db::rooms::put_room_event(
            &pool,
            ROOM,
            "m.room.member",
            USER,
            json!({"membership":"ban"}),
            "example.org",
            &signing_key()
        )
        .await
        .is_err());
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            crate::db::membership::get_membership(&pool, ROOM, OWNER)
                .await
                .unwrap()
                .as_deref(),
            Some("join")
        );
        member(&pool, OWNER, USER, "ban").await.unwrap();
        assert!(member(&pool, USER, USER, "join").await.is_err());
        assert!(member(&pool, USER, USER, "leave").await.is_err());
        assert!(member(&pool, OWNER, USER, "invite").await.is_err());
        assert_eq!(
            crate::db::membership::get_membership(&pool, ROOM, USER)
                .await
                .unwrap()
                .as_deref(),
            Some("ban")
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn authorization_reads_state_after_waiting_for_the_room_lock(pool: sqlx::PgPool) {
        create_test_room(&pool).await;
        member(&pool, USER, USER, "join").await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        lock_room(&mut tx, ROOM).await.unwrap();
        let write_pool = pool.clone();
        let mut writer = tokio::spawn(async move {
            crate::db::rooms::put_room_event(
                &write_pool,
                ROOM,
                "m.room.message",
                USER,
                json!({"body":"must not pass after ban"}),
                "example.org",
                &signing_key(),
            )
            .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                .await
                .is_err()
        );
        // Publish a ban while owning the lock, as another authorized writer does.
        sqlx::query("UPDATE events SET content = '{\"membership\":\"ban\"}'::jsonb WHERE event_id IN
            (SELECT event_id FROM room_state WHERE room_id=$1 AND event_type='m.room.member' AND state_key=$2)")
            .bind(ROOM).bind(USER).execute(&mut *tx).await.unwrap();
        sqlx::query("UPDATE room_members SET membership='ban' WHERE room_id=$1 AND user_id=$2")
            .bind(ROOM)
            .bind(USER)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(matches!(writer.await.unwrap(), Err(MatrixError::Forbidden)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn invalid_initial_state_rolls_back_the_entire_room(pool: sqlx::PgPool) {
        let result = crate::db::rooms::create_room_with_state(
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
                    "m.room.create".into(),
                    "".into(),
                    json!({"room_version":"11"}),
                ),
            ],
            "example.org",
            &signing_key(),
        )
        .await;
        assert!(result.is_err());
        let rooms: i64 = sqlx::query_scalar("SELECT count(*) FROM rooms")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rooms, 0);
    }
    async fn send_once(
        pool: &sqlx::PgPool,
        sender: &str,
        txn: &str,
        content: Value,
    ) -> Result<(String, bool)> {
        crate::db::rooms::put_room_event_idempotent(
            pool,
            ROOM,
            "m.room.message",
            sender,
            "DEVICE",
            txn,
            content,
            "example.org",
            &signing_key(),
        )
        .await
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_retries_return_one_real_event_id(pool: sqlx::PgPool) {
        create_test_room(&pool).await;
        let (first, second) = tokio::join!(
            send_once(&pool, OWNER, "retry", json!({"body":"one"})),
            send_once(&pool, OWNER, "retry", json!({"body":"one"})),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.0, second.0);
        assert_ne!(first.1, second.1);
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE event_id=$1 AND state_key IS NULL",
        )
        .bind(&first.0)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, 1);
        let messages: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE state_key IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        let markers: i64 = sqlx::query_scalar("SELECT count(*) FROM transaction_ids")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!((messages, markers), (1, 1));
        assert_eq!(
            send_once(&pool, OWNER, "retry", json!({"body":"ignored retry body"}))
                .await
                .unwrap(),
            (first.0, false)
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejected_sends_do_not_consume_transactions(pool: sqlx::PgPool) {
        create_test_room(&pool).await;
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(matches!(
            send_once(&pool, USER, "retry", json!({"body":"not joined"})).await,
            Err(MatrixError::Forbidden)
        ));
        // Floats cannot be signed as Matrix canonical JSON.
        assert!(matches!(
            send_once(&pool, OWNER, "bad-json", json!({"number":1.5})).await,
            Err(MatrixError::BadJson(_))
        ));
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
            .fetch_one(&pool)
            .await
            .unwrap();
        let markers: i64 = sqlx::query_scalar("SELECT count(*) FROM transaction_ids")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(markers, 0);
        member(&pool, USER, USER, "join").await.unwrap();
        assert!(
            send_once(&pool, USER, "retry", json!({"body":"now permitted"}))
                .await
                .unwrap()
                .1
        );
        assert!(
            send_once(&pool, OWNER, "bad-json", json!({"number":1}))
                .await
                .unwrap()
                .1
        );
        // A valid old transaction does not grant current room authorization.
        member(&pool, OWNER, USER, "ban").await.unwrap();
        assert!(matches!(
            send_once(&pool, USER, "retry", json!({"body":"banned retry"})).await,
            Err(MatrixError::Forbidden)
        ));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn transaction_scope_separates_room_type_device_and_endpoint(pool: sqlx::PgPool) {
        create_test_room(&pool).await;
        let other_room = "!other:example.org";
        create_test_room_with_id(&pool, other_room).await;
        // A to-device marker with the same client transaction must not collide.
        sqlx::query(
            "INSERT INTO transaction_ids (user_id,device_id,txn_id) VALUES ($1,'DEVICE','same')",
        )
        .bind(OWNER)
        .execute(&pool)
        .await
        .unwrap();
        let mut ids = BTreeSet::new();
        for (room, kind, device) in [
            (ROOM, "m.room.message", "DEVICE"),
            (other_room, "m.room.message", "DEVICE"),
            (ROOM, "m.reaction", "DEVICE"),
            (ROOM, "m.room.message", "OTHER_DEVICE"),
        ] {
            let (id, is_new) = crate::db::rooms::put_room_event_idempotent(
                &pool,
                room,
                kind,
                OWNER,
                device,
                "same",
                json!({"body":"separate event"}),
                "example.org",
                &signing_key(),
            )
            .await
            .unwrap();
            assert!(is_new);
            assert!(ids.insert(id));
        }
        assert_eq!(ids.len(), 4);
    }
}
