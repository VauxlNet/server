//! Axum middleware layers.

use axum::{extract::Request, middleware::Next, response::Response};
use sqlx::PgPool;

/// Inserts the DB pool into request extensions so auth middleware can use it.
pub async fn inject_db(
    axum::extract::State(pool): axum::extract::State<PgPool>,
    mut req: Request,
    next: Next,
) -> Response {
    req.extensions_mut().insert(pool);
    next.run(req).await
}
