//! Shared application state — passed to every axum handler.

use sqlx::PgPool;
use std::sync::Arc;

use crate::{config::AppConfig, signing_key::HomeserverSigningKey};

pub struct AppState {
    pub config: AppConfig,
    pub db: PgPool,
    pub signing_key: HomeserverSigningKey,
}

pub type SharedState = Arc<AppState>;
