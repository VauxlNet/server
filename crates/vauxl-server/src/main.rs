use anyhow::Result;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use vauxl_matrix::{
    config::AppConfig,
    middleware::inject_db,
    routes::{
        login::{get_login_flows, login},
        register::register,
        sync::sync,
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
