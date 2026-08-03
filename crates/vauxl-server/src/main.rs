use anyhow::Result;
use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vauxl_matrix::{
    config::AppConfig,
    middleware::inject_db,
    routes::{
        client_info::{
            capabilities, create_filter, delete_push_rule, get_account_data, get_filter,
            get_profile, get_push_rule, get_push_rules, get_room_account_data, logout, logout_all,
            put_account_data, put_push_rule, put_room_account_data, room_keys_version,
            set_avatar_url, set_displayname, third_party_protocols, turn_server, whoami,
        },
        directory::{
            delete_room_alias, get_room_alias, public_rooms_full, public_rooms_post, put_room_alias,
        },
        ephemeral::{send_receipt, send_typing},
        keys::{claim_keys, query_keys, upload_keys},
        login::{get_login_flows, login},
        media::{download_media, download_media_with_name, thumbnail_media, upload_media},
        membership::{
            ban_from_room, invite_to_room, join_room, join_room_by_id_or_alias, kick_from_room,
            leave_room,
        },
        presence::{get_presence, set_presence},
        register::register,
        rooms::{
            create_room, get_room_members, get_room_messages_handler, get_room_state,
            send_message_event, send_state_event, send_state_event_no_key,
        },
        sync::sync,
        to_device::send_to_device,
        versions::client_versions,
    },
    signing_key::HomeserverSigningKey,
    state::AppState,
    well_known::{federation_version, key_v2_server, well_known_client, well_known_server},
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vauxl_server=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg: AppConfig = config::Config::builder()
        .add_source(config::File::with_name("config/default"))
        .add_source(config::File::with_name("config/dev").required(false))
        .add_source(
            config::Environment::with_prefix("VAUXL")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?
        .try_deserialize()?;

    tracing::info!(
        server_name = %cfg.server.server_name,
        port        = cfg.server.port,
        "Starting Vauxl homeserver"
    );

    // ── Database ──────────────────────────────────────────────────────────
    let db = PgPoolOptions::new()
        .max_connections(20)
        .connect(&cfg.database.url)
        .await?;

    sqlx::migrate!("../../migrations").run(&db).await?;
    tracing::info!("Migrations applied");

    // ── Redis ─────────────────────────────────────────────────────────────
    let redis_client = redis::Client::open(cfg.redis.url.as_str())?;
    let redis = redis_client;
    tracing::info!("Redis connected");

    // ── Signing key ───────────────────────────────────────────────────────
    let signing_key = HomeserverSigningKey::load_or_generate(&cfg.signing_key.path)?;

    // ── Shared state ──────────────────────────────────────────────────────
    let (wake_tx, _) = tokio::sync::broadcast::channel::<()>(1024);

    let state = Arc::new(AppState {
        config: cfg.clone(),
        db: db.clone(),
        redis,
        signing_key,
        wake_tx,
    });

    // ── Cors ────────────────────────────────────────────────────────────
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // ── Router ────────────────────────────────────────────────────────────
    let app = Router::new()
        // Discovery
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/_matrix/key/v2/server", get(key_v2_server))
        .route("/_matrix/federation/v1/version", get(federation_version))
        .route("/_matrix/client/versions", get(client_versions))
        // Auth
        .route("/_matrix/client/v3/register", post(register))
        .route("/_matrix/client/v3/login", get(get_login_flows).post(login))
        // Sync
        .route("/_matrix/client/v3/sync", get(sync))
        // Keys
        .route("/_matrix/client/v3/keys/upload", post(upload_keys))
        .route("/_matrix/client/v3/keys/query", post(query_keys))
        .route("/_matrix/client/v3/keys/claim", post(claim_keys))
        // Rooms
        .route("/_matrix/client/v3/createRoom", post(create_room))
        .route(
            "/_matrix/client/v3/rooms/:roomId/state",
            get(get_room_state),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/members",
            get(get_room_members),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/messages",
            get(get_room_messages_handler),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/state/:eventType",
            put(send_state_event_no_key),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
            put(send_state_event),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId",
            put(send_message_event),
        )
        // Room Keys
        .route(
            "/_matrix/client/v3/room_keys/version",
            get(room_keys_version),
        )
        // Ephemeral (real implementations)
        .route(
            "/_matrix/client/v3/rooms/:roomId/typing/:userId",
            put(send_typing),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId",
            post(send_receipt),
        )
        // Presence
        .route(
            "/_matrix/client/v3/presence/:userId/status",
            get(get_presence).put(set_presence),
        )
        // Media (v3 paths)
        .route("/_matrix/media/v3/upload", post(upload_media))
        .route(
            "/_matrix/media/v3/download/:serverName/:mediaId",
            get(download_media),
        )
        .route(
            "/_matrix/media/v3/download/:serverName/:mediaId/:fileName",
            get(download_media_with_name),
        )
        .route(
            "/_matrix/media/v3/thumbnail/:serverName/:mediaId",
            get(thumbnail_media),
        )
        // Legacy r0 media paths (Element still uses these)
        .route("/_matrix/media/r0/upload", post(upload_media))
        .route(
            "/_matrix/media/r0/download/:serverName/:mediaId",
            get(download_media),
        )
        .route(
            "/_matrix/media/r0/download/:serverName/:mediaId/:fileName",
            get(download_media_with_name),
        )
        .route(
            "/_matrix/media/r0/thumbnail/:serverName/:mediaId",
            get(thumbnail_media),
        )
        // Room directory
        .route(
            "/_matrix/client/v3/publicRooms",
            get(public_rooms_full).post(public_rooms_post),
        )
        .route(
            "/_matrix/client/v3/directory/room/:roomAlias",
            get(get_room_alias)
                .put(put_room_alias)
                .delete(delete_room_alias),
        )
        // Membership
        .route(
            "/_matrix/client/v3/join/:roomIdOrAlias",
            post(join_room_by_id_or_alias),
        )
        .route("/_matrix/client/v3/rooms/:roomId/join", post(join_room))
        .route("/_matrix/client/v3/rooms/:roomId/leave", post(leave_room))
        .route(
            "/_matrix/client/v3/rooms/:roomId/invite",
            post(invite_to_room),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/kick",
            post(kick_from_room),
        )
        .route("/_matrix/client/v3/rooms/:roomId/ban", post(ban_from_room))
        // To-device
        .route(
            "/_matrix/client/v3/sendToDevice/:eventType/:txnId",
            put(send_to_device),
        )
        // Client info — required for Element stability
        .route("/_matrix/client/v3/capabilities", get(capabilities))
        .route("/_matrix/client/v3/pushrules/", get(get_push_rules))
        .route(
            "/_matrix/client/v3/pushrules/:scope/:kind/:ruleId",
            get(get_push_rule)
                .put(put_push_rule)
                .delete(delete_push_rule),
        )
        // Filters
        .route(
            "/_matrix/client/v3/user/:userId/filter",
            post(create_filter).get(get_push_rules),
        )
        .route(
            "/_matrix/client/v3/user/:userId/filter/:filterId",
            get(get_filter),
        )
        // Account data
        .route(
            "/_matrix/client/v3/user/:userId/account_data/:eventType",
            get(get_account_data).put(put_account_data),
        )
        .route(
            "/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:eventType",
            get(get_room_account_data).put(put_room_account_data),
        )
        // Profile
        .route("/_matrix/client/v3/profile/:userId", get(get_profile))
        .route(
            "/_matrix/client/v3/profile/:userId/displayname",
            put(set_displayname),
        )
        .route(
            "/_matrix/client/v3/profile/:userId/avatar_url",
            put(set_avatar_url),
        )
        // Logout
        .route("/_matrix/client/v3/logout", post(logout))
        .route("/_matrix/client/v3/logout/all", post(logout_all))
        // Optional but reduces log noise
        .route("/_matrix/client/v3/voip/turnServer", get(turn_server))
        .route(
            "/_matrix/client/v3/thirdparty/protocols",
            get(third_party_protocols),
        )
        // Whoami
        .route("/_matrix/client/v3/account/whoami", get(whoami))
        // Health
        .route("/_vauxl/health", get(health))
        .with_state(state)
        .layer(middleware::from_fn_with_state(db, inject_db))
        .layer(cors);

    let addr = format!("{}:{}", cfg.server.listen_address, cfg.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(address = %addr, "Listening");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
