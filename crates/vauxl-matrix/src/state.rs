use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::{config::AppConfig, signing_key::HomeserverSigningKey};

pub struct AppState {
    pub config: AppConfig,
    pub db: PgPool,
    pub redis: redis::Client,
    pub signing_key: HomeserverSigningKey,
    /// Broadcast channel — send here when an event is stored,
    /// /sync receivers wake immediately
    pub wake_tx: broadcast::Sender<()>,
}

pub type SharedState = Arc<AppState>;
