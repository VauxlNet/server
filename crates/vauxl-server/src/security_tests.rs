//! Exercise the production router with real PostgreSQL and Redis.
//! The peer publishes its own signed key document; an isolated Redis entry pins
//! it for local tests without weakening production HTTPS/DNS verification.

use super::router;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use redis::AsyncCommands;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tower::ServiceExt;
use vauxl_matrix::{
    config::{AppConfig, DatabaseConfig, RedisConfig, ServerConfig, SigningKeyConfig},
    db::{room_auth::lock_room, rooms::populate_event_auth},
    event_signing::sign_event,
    signing_key::HomeserverSigningKey,
    state::{AppState, SharedState},
};

static NEXT_SERVER: AtomicU64 = AtomicU64::new(1);

struct Servers {
    local: SharedState,
    peer: SharedState,
    app: Router,
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    authorization: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(auth) = authorization {
        request = request.header("authorization", auth);
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"non_json_response":String::from_utf8_lossy(&bytes)}));
    (status, json)
}

fn state(pool: PgPool, name: String, seed: u8) -> SharedState {
    let redis_url = std::env::var("REDIS_URL").expect("security tests require REDIS_URL");
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    Arc::new(AppState {
        config: AppConfig {
            server: ServerConfig {
                server_name: name,
                listen_address: "127.0.0.1".into(),
                port: 8008,
            },
            database: DatabaseConfig {
                url: "unused: test pool supplied directly".into(),
            },
            redis: RedisConfig {
                url: redis_url.clone(),
            },
            signing_key: SigningKeyConfig {
                path: "unused: test key supplied directly".into(),
            },
        },
        db: pool,
        redis: redis::Client::open(redis_url).unwrap(),
        signing_key: HomeserverSigningKey {
            verifying_key: signing_key.verifying_key(),
            signing_key,
            key_id: "ed25519:a".into(),
        },
        wake_tx: tokio::sync::broadcast::channel(16).0,
    })
}

impl Servers {
    fn verify_wire_pdu(&self, event: &Value) {
        assert!(
            event.get("event_id").is_none(),
            "v11 wire PDU contains storage event_id: {event}"
        );
        let keys: ruma::signatures::PublicKeyMap = [
            (
                self.local.config.server.server_name.clone(),
                [(
                    self.local.signing_key.key_id.clone(),
                    ruma::serde::Base64::new(
                        self.local.signing_key.verifying_key.as_bytes().to_vec(),
                    ),
                )]
                .into(),
            ),
            (
                self.peer.config.server.server_name.clone(),
                [(
                    self.peer.signing_key.key_id.clone(),
                    ruma::serde::Base64::new(
                        self.peer.signing_key.verifying_key.as_bytes().to_vec(),
                    ),
                )]
                .into(),
            ),
        ]
        .into();
        let object: ruma::CanonicalJsonObject = serde_json::from_value(event.clone()).unwrap();
        assert_eq!(
            ruma::signatures::verify_event(&keys, &object, &ruma::RoomVersionId::V11).unwrap(),
            ruma::signatures::Verified::All
        );
    }

    async fn new(pool: PgPool) -> Self {
        let id = NEXT_SERVER.fetch_add(1, Ordering::Relaxed);
        let local = state(pool.clone(), format!("local-{id}.test"), 41);
        let peer = state(pool, format!("peer-{id}.test"), 42);
        let (status, document) = request(
            &router(peer.clone()),
            "GET",
            "/_matrix/key/v2/server",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{document}");
        assert!(document["signatures"][&peer.config.server.server_name]["ed25519:a"].is_string());
        let mut redis = local
            .redis
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let _: () = redis
            .set_ex(
                format!(
                    "federation:verified-key-document:{}",
                    peer.config.server.server_name
                ),
                document.to_string(),
                1200,
            )
            .await
            .unwrap();
        Self {
            app: router(local.clone()),
            local,
            peer,
        }
    }

    fn user(&self, localpart: &str) -> String {
        format!("@{localpart}:{}", self.local.config.server.server_name)
    }

    fn peer_user(&self) -> String {
        format!("@remote:{}", self.peer.config.server.server_name)
    }

    fn authorization(&self, method: &str, path: &str, body: Option<&Value>) -> String {
        let origin = &self.peer.config.server.server_name;
        let destination = &self.local.config.server.server_name;
        let mut signed =
            json!({"method":method,"uri":path,"origin":origin,"destination":destination});
        if let Some(body) = body {
            signed["content"] = body.clone();
        }
        let canonical: ruma::CanonicalJsonObject = serde_json::from_value(signed).unwrap();
        let signature = self
            .peer
            .signing_key
            .signing_key
            .sign(&serde_json::to_vec(&canonical).unwrap());
        format!("X-Matrix origin=\"{origin}\",destination=\"{destination}\",key=\"ed25519:a\",sig=\"{}\"", BASE64.encode(signature.to_bytes()))
    }

    async fn signed(&self, method: &str, path: &str, body: Option<&Value>) -> (StatusCode, Value) {
        request(
            &self.app,
            method,
            path,
            Some(&self.authorization(method, path, body)),
            body,
        )
        .await
    }

    async fn register(&self, name: &str) -> String {
        let body = json!({"username":name,"password":"testing-password-only","auth":{"type":"m.login.dummy"}});
        let (status, response) = request(
            &self.app,
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        format!("Bearer {}", response["access_token"].as_str().unwrap())
    }

    async fn room(&self, token: &str) -> String {
        let (status, response) = request(
            &self.app,
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(&json!({"preset":"public_chat","name":"Security regression room"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["room_id"].as_str().unwrap().to_owned()
    }

    fn make_join_path(&self, room: &str) -> String {
        format!(
            "/_matrix/federation/v1/make_join/{}/{}?ver=11",
            urlencoding::encode(room),
            urlencoding::encode(&self.peer_user())
        )
    }

    async fn join_peer(&self, room: &str) -> Value {
        let path = self.make_join_path(room);
        let (status, response) = self.signed("GET", &path, None).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let mut event = response["event"].clone();
        sign_event(
            &mut event,
            &self.peer.config.server.server_name,
            &self.peer.signing_key,
        )
        .unwrap();
        let path = format!(
            "/_matrix/federation/v2/send_join/{}/{}",
            urlencoding::encode(room),
            urlencoding::encode(event["event_id"].as_str().unwrap())
        );
        let mut wire = event.clone();
        wire.as_object_mut().unwrap().remove("event_id");
        let (status, response) = self.signed("PUT", &path, Some(&wire)).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        self.verify_wire_pdu(&response["event"]);
        for event in response["state"].as_array().unwrap() {
            self.verify_wire_pdu(event);
        }
        event
    }

    async fn peer_event(
        &self,
        room: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: Value,
    ) -> Value {
        let mut event = json!({"room_id":room,"sender":self.peer_user(),"type":event_type,"content":content,"origin_server_ts":vauxl_federation::keys::now_millis()});
        if let Some(key) = state_key {
            event["state_key"] = json!(key);
        }
        let mut tx = self.local.db.begin().await.unwrap();
        lock_room(&mut tx, room).await.unwrap();
        populate_event_auth(&mut tx, room, &mut event)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sign_event(
            &mut event,
            &self.peer.config.server.server_name,
            &self.peer.signing_key,
        )
        .unwrap();
        event
    }

    async fn send_pdu(&self, event: &Value, txn: &str) -> Value {
        let mut wire = event.clone();
        wire.as_object_mut().unwrap().remove("event_id");
        let body = json!({"origin":self.peer.config.server.server_name,"origin_server_ts":vauxl_federation::keys::now_millis(),"pdus":[wire],"edus":[]});
        let (status, response) = self
            .signed(
                "PUT",
                &format!("/_matrix/federation/v1/send/{txn}"),
                Some(&body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response
    }

    async fn event_count(&self, room: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE room_id=$1")
            .bind(room)
            .fetch_one(&self.local.db)
            .await
            .unwrap()
    }

    async fn message(&self, token: &str, room: &str, text: &str) -> Value {
        let path = format!(
            "/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            urlencoding::encode(room),
            urlencoding::encode(text)
        );
        let (status, response) = request(
            &self.app,
            "PUT",
            &path,
            Some(token),
            Some(&json!({"msgtype":"m.text","body":text})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn signed_requests_bind_exact_uri_method_destination_and_body(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let room = s.room(&owner).await;
    let path = s.make_join_path(&room);
    assert_eq!(s.signed("GET", &path, None).await.0, StatusCode::OK);
    for (signed_method, signed_path) in [
        ("POST", path.clone()),
        ("GET", path.replace("ver=11", "ver=10")),
        ("GET", path.replace("%3A", ":")),
    ] {
        let auth = s.authorization(signed_method, &signed_path, None);
        assert_eq!(
            request(&s.app, "GET", &path, Some(&auth), None).await.0,
            StatusCode::FORBIDDEN
        );
    }
    let auth = s.authorization("GET", &path, None).replace(
        &format!("destination=\"{}\"", s.local.config.server.server_name),
        "destination=\"wrong.test\"",
    );
    assert_eq!(
        request(&s.app, "GET", &path, Some(&auth), None).await.0,
        StatusCode::FORBIDDEN
    );
    let auth = format!(
        "X-Matrix origin=\"{}\",destination=\"{}\",key=\"ed25519:a\",sig=\"{}\"",
        s.peer.config.server.server_name,
        s.local.config.server.server_name,
        BASE64.encode([0; 64])
    );
    assert_eq!(
        request(&s.app, "GET", &path, Some(&auth), None).await.0,
        StatusCode::FORBIDDEN
    );

    let send = "/_matrix/federation/v1/send/body-binding";
    let original = json!({"origin":s.peer.config.server.server_name,"pdus":[]});
    let mut altered = original.clone();
    altered["pdus"] = json!([{"type":"m.room.member"}]);
    let auth = s.authorization("PUT", send, Some(&original));
    let before = s.event_count(&room).await;
    assert_eq!(
        request(&s.app, "PUT", send, Some(&auth), Some(&altered))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(s.event_count(&room).await, before);
}

#[sqlx::test(migrations = "../../migrations")]
async fn federation_routes_require_authentication_and_room_participation(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let room = s.room(&owner).await;
    let event_id: String =
        sqlx::query_scalar("SELECT event_id FROM events WHERE room_id=$1 LIMIT 1")
            .bind(&room)
            .fetch_one(&s.local.db)
            .await
            .unwrap();
    let reads = [
        format!(
            "/_matrix/federation/v1/backfill/{}?limit=10&v={}",
            urlencoding::encode(&room),
            urlencoding::encode(&event_id)
        ),
        format!(
            "/_matrix/federation/v1/state/{}",
            urlencoding::encode(&room)
        ),
        format!(
            "/_matrix/federation/v1/state_ids/{}",
            urlencoding::encode(&room)
        ),
        format!(
            "/_matrix/federation/v1/event/{}",
            urlencoding::encode(&event_id)
        ),
    ];
    for path in &reads {
        assert_eq!(
            request(&s.app, "GET", path, None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(s.signed("GET", path, None).await.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        request(&s.app, "GET", &s.make_join_path(&room), None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    for path in [
        "/_matrix/federation/v1/send/no-auth".to_owned(),
        format!(
            "/_matrix/federation/v2/send_join/{}/%24fake",
            urlencoding::encode(&room)
        ),
    ] {
        assert_eq!(
            request(&s.app, "PUT", &path, None, Some(&json!({})))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    s.join_peer(&room).await;
    for path in &reads {
        let (status, response) = s.signed("GET", path, None).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        if let Some(events) = response["pdus"].as_array() {
            for event in events {
                s.verify_wire_pdu(event);
            }
        }
    }
    let ban = format!(
        "/_matrix/client/v3/rooms/{}/ban",
        urlencoding::encode(&room)
    );
    assert_eq!(
        request(
            &s.app,
            "POST",
            &ban,
            Some(&owner),
            Some(&json!({"user_id":s.peer_user()}))
        )
        .await
        .0,
        StatusCode::OK
    );
    for path in &reads {
        assert_eq!(s.signed("GET", path, None).await.0, StatusCode::FORBIDDEN);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn signed_pdus_check_content_permissions_and_current_history(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let room = s.room(&owner).await;
    s.join_peer(&room).await;
    let valid = s
        .peer_event(
            &room,
            "m.room.message",
            None,
            json!({"msgtype":"m.text","body":"valid"}),
        )
        .await;
    let before = s.event_count(&room).await;
    let response = s.send_pdu(&valid, "valid").await;
    assert_eq!(
        response["pdus"][valid["event_id"].as_str().unwrap()],
        json!({}),
        "{response}"
    );
    assert_eq!(s.event_count(&room).await, before + 1);
    assert_eq!(
        s.send_pdu(&valid, "retry").await["pdus"][valid["event_id"].as_str().unwrap()],
        json!({})
    );
    assert_eq!(s.event_count(&room).await, before + 1);

    let mut tampered = s
        .peer_event(&room, "m.room.message", None, json!({"body":"original"}))
        .await;
    tampered["content"]["body"] = json!("tampered after PDU signing");
    let unauthorized = s
        .peer_event(
            &room,
            "m.room.power_levels",
            Some(""),
            json!({"users":{s.peer_user():100}}),
        )
        .await;
    for (index, event) in [tampered, unauthorized].iter().enumerate() {
        let response = s.send_pdu(event, &format!("invalid-{index}")).await;
        assert!(
            response["pdus"]
                .as_object()
                .unwrap()
                .values()
                .all(|v| v["error"].is_string()),
            "{response}"
        );
        assert_eq!(s.event_count(&room).await, before + 1);
    }
    let stale = s
        .peer_event(
            &room,
            "m.room.message",
            None,
            json!({"body":"stale branch"}),
        )
        .await;
    let topic = format!(
        "/_matrix/client/v3/rooms/{}/state/m.room.topic",
        urlencoding::encode(&room)
    );
    assert_eq!(
        request(
            &s.app,
            "PUT",
            &topic,
            Some(&owner),
            Some(&json!({"topic":"advance history"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = s.send_pdu(&stale, "stale").await;
    assert!(
        response["pdus"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v["error"].is_string()),
        "{response}"
    );
    assert_eq!(s.event_count(&room).await, before + 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn client_routes_enforce_roles_and_prevent_generic_membership_bypass(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let member = s.register("member").await;
    let room = s.room(&owner).await;
    let base = format!("/_matrix/client/v3/rooms/{}", urlencoding::encode(&room));
    assert_eq!(
        request(
            &s.app,
            "POST",
            &format!("{base}/join"),
            Some(&member),
            Some(&json!({}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let levels = json!({"users":{s.user("owner"):100,s.user("member"):0},"events_default":50,"state_default":50,"invite":50,"kick":50,"ban":50});
    assert_eq!(
        request(
            &s.app,
            "PUT",
            &format!("{base}/state/m.room.power_levels"),
            Some(&owner),
            Some(&levels)
        )
        .await
        .0,
        StatusCode::OK
    );
    let before = s.event_count(&room).await;
    let denied = [
        (
            "PUT",
            format!("{base}/state/m.room.topic"),
            json!({"topic":"unauthorized"}),
        ),
        (
            "PUT",
            format!("{base}/state/m.room.power_levels"),
            json!({"users":{s.user("member"):100}}),
        ),
        (
            "PUT",
            format!(
                "{base}/state/m.room.member/{}",
                urlencoding::encode(&s.user("owner"))
            ),
            json!({"membership":"leave"}),
        ),
        (
            "PUT",
            format!("{base}/send/m.room.message/retry-after-denial"),
            json!({"msgtype":"m.text","body":"no access"}),
        ),
        (
            "POST",
            format!("{base}/kick"),
            json!({"user_id":s.user("owner")}),
        ),
        (
            "POST",
            format!("{base}/ban"),
            json!({"user_id":s.user("owner")}),
        ),
        (
            "POST",
            format!("{base}/invite"),
            json!({"user_id":s.user("newmember")}),
        ),
    ];
    for (method, path, body) in denied {
        let (status, response) = request(&s.app, method, &path, Some(&member), Some(&body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {response}");
        assert_eq!(s.event_count(&room).await, before);
    }
    let mut levels = levels;
    levels["events_default"] = json!(0);
    assert_eq!(
        request(
            &s.app,
            "PUT",
            &format!("{base}/state/m.room.power_levels"),
            Some(&owner),
            Some(&levels)
        )
        .await
        .0,
        StatusCode::OK
    );
    let send = format!("{base}/send/m.room.message/retry-after-denial");
    let body = json!({"msgtype":"m.text","body":"permitted retry"});
    let (status, first) = request(&s.app, "PUT", &send, Some(&member), Some(&body)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (_, again) = request(&s.app, "PUT", &send, Some(&member), Some(&body)).await;
    assert_eq!(first, again);
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE event_id=$1)")
        .bind(first["event_id"].as_str().unwrap())
        .fetch_one(&s.local.db)
        .await
        .unwrap();
    assert!(exists, "retry must return an actual persisted event ID");
    assert_eq!(
        request(
            &s.app,
            "POST",
            &format!("{base}/ban"),
            Some(&owner),
            Some(&json!({"user_id":s.user("member")}))
        )
        .await
        .0,
        StatusCode::OK
    );
    for (method, path, body) in [
        ("POST", format!("{base}/join"), json!({})),
        (
            "PUT",
            format!(
                "{base}/state/m.room.member/{}",
                urlencoding::encode(&s.user("member"))
            ),
            json!({"membership":"join"}),
        ),
    ] {
        assert_eq!(
            request(&s.app, method, &path, Some(&member), Some(&body))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn unsupported_remote_join_does_not_import_room_history(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let room = format!("!unverified:{}", s.peer.config.server.server_name);
    let path = format!("/_matrix/client/v3/join/{}", urlencoding::encode(&room));
    let (status, response) = request(&s.app, "POST", &path, Some(&owner), Some(&json!({}))).await;
    assert!(status.is_client_error(), "{response}");
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rooms WHERE room_id=$1)")
        .bind(room)
        .fetch_one(&s.local.db)
        .await
        .unwrap();
    assert!(!exists);
}

fn message_bodies(events: &Value) -> std::collections::BTreeSet<String> {
    events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "m.room.message")
        .filter_map(|e| e["content"]["body"].as_str().map(str::to_owned))
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn private_history_is_filtered_for_clients_and_remote_servers(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let member = s.register("member").await;
    for visibility in ["invited", "joined"] {
        let body = json!({"preset":"private_chat","initial_state":[{"type":"m.room.history_visibility","content":{"history_visibility":visibility}}]});
        let (status, response) = request(
            &s.app,
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&owner),
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let room = response["room_id"].as_str().unwrap();
        let base = format!("/_matrix/client/v3/rooms/{}", urlencoding::encode(room));
        let before = s.message(&owner, room, "before invitation").await;
        for user in [s.user("member"), s.peer_user()] {
            assert_eq!(
                request(
                    &s.app,
                    "POST",
                    &format!("{base}/invite"),
                    Some(&owner),
                    Some(&json!({"user_id":user}))
                )
                .await
                .0,
                StatusCode::OK
            );
        }
        let invited = s.message(&owner, room, "during invitation").await;
        assert_eq!(
            request(
                &s.app,
                "POST",
                &format!("{base}/join"),
                Some(&member),
                Some(&json!({}))
            )
            .await
            .0,
            StatusCode::OK
        );
        s.join_peer(room).await;
        let joined = s.message(&owner, room, "after join").await;
        for (event, allowed) in [
            (&before, false),
            (&invited, visibility == "invited"),
            (&joined, true),
        ] {
            let path = format!(
                "/_matrix/federation/v1/event/{}",
                urlencoding::encode(event["event_id"].as_str().unwrap())
            );
            assert_eq!(
                s.signed("GET", &path, None).await.0,
                if allowed {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                },
                "{visibility}: {event}"
            );
        }
        assert_eq!(
            request(
                &s.app,
                "POST",
                &format!("{base}/leave"),
                Some(&member),
                Some(&json!({}))
            )
            .await
            .0,
            StatusCode::OK
        );
        let leave = s
            .peer_event(
                room,
                "m.room.member",
                Some(&s.peer_user()),
                json!({"membership":"leave"}),
            )
            .await;
        let result = s.send_pdu(&leave, "leave").await;
        assert_eq!(
            result["pdus"][leave["event_id"].as_str().unwrap()],
            json!({}),
            "{result}"
        );
        let gap = s.message(&owner, room, "while absent").await;
        for user in [s.user("member"), s.peer_user()] {
            assert_eq!(
                request(
                    &s.app,
                    "POST",
                    &format!("{base}/invite"),
                    Some(&owner),
                    Some(&json!({"user_id":user}))
                )
                .await
                .0,
                StatusCode::OK
            );
        }
        assert_eq!(
            request(
                &s.app,
                "POST",
                &format!("{base}/join"),
                Some(&member),
                Some(&json!({}))
            )
            .await
            .0,
            StatusCode::OK
        );
        s.join_peer(room).await;
        s.message(&owner, room, "after rejoin").await;

        // Changing visibility now must not expose earlier restricted messages.
        assert_eq!(
            request(
                &s.app,
                "PUT",
                &format!("{base}/state/m.room.history_visibility"),
                Some(&owner),
                Some(&json!({"history_visibility":"shared"}))
            )
            .await
            .0,
            StatusCode::OK
        );
        s.message(&owner, room, "after policy change").await;
        let mut expected = std::collections::BTreeSet::from([
            "after join".into(),
            "after rejoin".into(),
            "after policy change".into(),
        ]);
        if visibility == "invited" {
            expected.insert("during invitation".into());
        }
        let (status, messages) = request(
            &s.app,
            "GET",
            &format!("{base}/messages?dir=b&limit=100"),
            Some(&member),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{messages}");
        assert_eq!(
            message_bodies(&messages["chunk"]),
            expected,
            "local messages, {visibility}"
        );
        let (status, sync) = request(
            &s.app,
            "GET",
            "/_matrix/client/v3/sync",
            Some(&member),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{sync}");
        assert_eq!(
            message_bodies(&sync["rooms"]["join"][room]["timeline"]["events"]),
            expected,
            "initial sync, {visibility}"
        );
        let backfill = format!(
            "/_matrix/federation/v1/backfill/{}?limit=100",
            urlencoding::encode(room)
        );
        let (status, history) = s.signed("GET", &backfill, None).await;
        assert_eq!(status, StatusCode::OK, "{history}");
        assert_eq!(
            message_bodies(&history["pdus"]),
            expected,
            "remote history, {visibility}"
        );
        for event in [before, gap] {
            let path = format!(
                "/_matrix/federation/v1/event/{}",
                urlencoding::encode(event["event_id"].as_str().unwrap())
            );
            assert_eq!(s.signed("GET", &path, None).await.0, StatusCode::FORBIDDEN);
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn room_server_acl_revokes_federation_access(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let room = s.room(&owner).await;
    s.join_peer(&room).await;
    let path = format!(
        "/_matrix/client/v3/rooms/{}/state/m.room.server_acl",
        urlencoding::encode(&room)
    );
    let acl = json!({"allow":["*"],"deny":[s.peer.config.server.server_name.to_uppercase()],"allow_ip_literals":false});
    let (status, response) = request(&s.app, "PUT", &path, Some(&owner), Some(&acl)).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let state_path = format!(
        "/_matrix/federation/v1/state/{}",
        urlencoding::encode(&room)
    );
    assert_eq!(
        s.signed("GET", &state_path, None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        s.signed("GET", &s.make_join_path(&room), None).await.0,
        StatusCode::FORBIDDEN
    );
    let event = s
        .peer_event(
            &room,
            "m.room.message",
            None,
            json!({"body":"blocked by ACL"}),
        )
        .await;
    let before = s.event_count(&room).await;
    let response = s.send_pdu(&event, "denied-acl").await;
    assert!(
        response["pdus"]
            .as_object()
            .unwrap()
            .values()
            .all(|r| r["error"].is_string()),
        "{response}"
    );
    assert_eq!(s.event_count(&room).await, before);
}

#[sqlx::test(migrations = "../../migrations")]
async fn expired_cached_keys_cannot_authenticate_requests(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let room = s.room(&owner).await;
    let path = s.make_join_path(&room);
    assert_eq!(s.signed("GET", &path, None).await.0, StatusCode::OK);
    let mut expired = vauxl_matrix::well_known::signing_key_document(&s.peer).unwrap();
    expired["valid_until_ts"] = json!(1);
    let mut expired: ruma::CanonicalJsonObject = serde_json::from_value(expired).unwrap();
    ruma::signatures::sign_json(
        &s.peer.config.server.server_name,
        &s.peer.signing_key,
        &mut expired,
    )
    .unwrap();
    let mut redis = s
        .local
        .redis
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis
        .set_ex(
            format!(
                "federation:verified-key-document:{}",
                s.peer.config.server.server_name
            ),
            serde_json::to_string(&expired).unwrap(),
            1200,
        )
        .await
        .unwrap();
    assert_eq!(s.signed("GET", &path, None).await.0, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn legacy_history_does_not_block_other_rooms_or_device_delivery(pool: PgPool) {
    let s = Servers::new(pool).await;
    let owner = s.register("owner").await;
    let legacy = s.room(&owner).await;
    s.message(&owner, &legacy, "legacy hidden message").await;
    // Model the baseline's persisted events, which had no depth/prev metadata.
    sqlx::query("UPDATE events SET raw_event=raw_event-'depth'-'prev_events' WHERE room_id=$1")
        .bind(&legacy)
        .execute(&s.local.db)
        .await
        .unwrap();
    let current = s.room(&owner).await;
    s.message(&owner, &current, "current visible message").await;
    let queued = json!({"messages":{s.user("owner"):{"*":{"marker":"device-delivery-survives"}}}});
    let (status, response) = request(
        &s.app,
        "PUT",
        "/_matrix/client/v3/sendToDevice/m.test/legacy-queue",
        Some(&owner),
        Some(&queued),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let (status, sync) =
        request(&s.app, "GET", "/_matrix/client/v3/sync", Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert_eq!(
        sync["rooms"]["join"][&legacy]["timeline"]["events"],
        json!([])
    );
    assert_eq!(
        sync["rooms"]["join"][&legacy]["timeline"]["limited"],
        json!(true)
    );
    assert!(!sync["rooms"]["join"][&legacy]["state"]["events"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        message_bodies(&sync["rooms"]["join"][&current]["timeline"]["events"]),
        std::collections::BTreeSet::from(["current visible message".into()])
    );
    assert!(sync["to_device"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["content"]["marker"] == "device-delivery-survives"));
    let path = format!(
        "/_matrix/client/v3/rooms/{}/messages?dir=b",
        urlencoding::encode(&legacy)
    );
    assert_eq!(
        request(&s.app, "GET", &path, Some(&owner), None).await.0,
        StatusCode::FORBIDDEN
    );

    // An unrelated database failure must not consume the next device message.
    assert_eq!(
        request(
            &s.app,
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.test/failing-sync",
            Some(&owner),
            Some(&queued)
        )
        .await
        .0,
        StatusCode::OK
    );
    sqlx::query("ALTER TABLE room_state RENAME TO unavailable_room_state")
        .execute(&s.local.db)
        .await
        .unwrap();
    let failed = request(&s.app, "GET", "/_matrix/client/v3/sync", Some(&owner), None).await;
    sqlx::query("ALTER TABLE unavailable_room_state RENAME TO room_state")
        .execute(&s.local.db)
        .await
        .unwrap();
    assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, retry) =
        request(&s.app, "GET", "/_matrix/client/v3/sync", Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert!(retry["to_device"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["content"]["marker"] == "device-delivery-survives"));
}
