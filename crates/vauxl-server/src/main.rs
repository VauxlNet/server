use anyhow::Result;
use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vauxl_matrix::{
    config::AppConfig,
    middleware::inject_db,
    routes::{
        keys::{claim_keys, query_keys, upload_keys},
        login::{get_login_flows, login},
        membership::{
            ban_from_room, invite_to_room, join_room, join_room_by_id_or_alias, kick_from_room,
            leave_room,
        },
        register::register,
        rooms::{
            create_room, get_room_members, get_room_state, send_message_event, send_state_event,
            send_state_event_no_key,
        },
        sync::sync,
        to_device::send_to_device,
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
        .add_source(config::Environment::with_prefix("VAUXL").separator("__"))
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
    let state = Arc::new(AppState {
        config: cfg.clone(),
        db: db.clone(),
        redis,
        signing_key,
    });

    // ── Router ────────────────────────────────────────────────────────────
    let app = Router::new()
        // Discovery
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/_matrix/key/v2/server", get(key_v2_server))
        .route("/_matrix/federation/v1/version", get(federation_version))
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
        // Health
        .route("/_vauxl/health", get(health))
        .with_state(state)
        .layer(middleware::from_fn_with_state(db, inject_db));

    let addr = format!("{}:{}", cfg.server.listen_address, cfg.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(address = %addr, "Listening");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
