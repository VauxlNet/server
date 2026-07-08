use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::{config::AppConfig, signing_key::HomeserverSigningKey};

/// Sent on the wake channel whenever a new event is stored.
/// /sync subscribers wake immediately instead of waiting for timeout.
#[derive(Debug, Clone)]
pub struct WakeEvent {
    pub room_id: String,
}

pub struct AppState {
    pub config: AppConfig,
    pub db: PgPool,
    pub redis: redis::Client,
    pub signing_key: HomeserverSigningKey,
    /// Broadcast channel — send here when an event is stored,
    /// /sync receivers wake immediately
    pub wake_tx: broadcast::Sender<WakeEvent>,
}

pub type SharedState = Arc<AppState>;
