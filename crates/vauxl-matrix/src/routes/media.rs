//! Media repository (P1-013).
//!
//! Files are stored on the local filesystem under data/media/.
//! Encrypted media: client encrypts before upload — server stores opaque bytes.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{auth::AuthenticatedUser, error::MatrixError, state::SharedState};

const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB

/// POST /_matrix/media/v3/upload
/// Also handles: POST /_matrix/media/r0/upload
pub async fn upload_media(
    State(state): State<SharedState>,
    auth: AuthenticatedUser,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Value>, MatrixError> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();

    let filename = headers
        .get("x-filename")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    // Read body with size limit
    let bytes = axum::body::to_bytes(body, MAX_FILE_SIZE as usize)
        .await
        .map_err(|_| MatrixError::BadJson("Request body too large or unreadable".into()))?;

    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(MatrixError::BadJson(format!(
            "File too large. Max size: {} MB",
            MAX_FILE_SIZE / 1024 / 1024
        )));
    }

    let media_id = generate_media_id();
    let server_name = &state.config.server.server_name;
    let storage_dir = PathBuf::from("data/media");
    let storage_path = storage_dir.join(&media_id);
    let storage_path_str = storage_path.to_string_lossy().to_string();

    // Ensure storage directory exists
    tokio::fs::create_dir_all(&storage_dir)
        .await
        .map_err(|e| MatrixError::Internal(format!("Storage dir error: {e}")))?;

    // Write file
    let mut file = tokio::fs::File::create(&storage_path)
        .await
        .map_err(|e| MatrixError::Internal(format!("File create error: {e}")))?;

    file.write_all(&bytes)
        .await
        .map_err(|e| MatrixError::Internal(format!("File write error: {e}")))?;

    // Store metadata in DB
    sqlx::query!(
        r#"
        INSERT INTO media
            (media_id, server_name, uploader_id, content_type, file_size, filename, storage_path)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        media_id,
        server_name,
        auth.user_id,
        content_type,
        bytes.len() as i64,
        filename,
        &storage_path_str,
    )
    .execute(&state.db)
    .await
    .map_err(MatrixError::from)?;

    tracing::debug!(
        media_id    = %media_id,
        size        = bytes.len(),
        content_type = %content_type,
        "Media uploaded"
    );

    Ok(Json(json!({
        "content_uri": format!("mxc://{}/{}", server_name, media_id)
    })))
}

/// GET /_matrix/media/v3/download/{serverName}/{mediaId}
/// GET /_matrix/media/v3/download/{serverName}/{mediaId}/{fileName}
pub async fn download_media(
    State(state): State<SharedState>,
    Path((server_name, media_id)): Path<(String, String)>,
) -> Result<Response, MatrixError> {
    serve_media(&state, &server_name, &media_id, false).await
}

pub async fn download_media_with_name(
    State(state): State<SharedState>,
    Path((server_name, media_id, _filename)): Path<(String, String, String)>,
) -> Result<Response, MatrixError> {
    serve_media(&state, &server_name, &media_id, false).await
}

#[derive(Debug, Deserialize)]
pub struct ThumbnailQuery {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub method: Option<String>, // crop | scale
}

/// GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}
pub async fn thumbnail_media(
    State(state): State<SharedState>,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(_query): Query<ThumbnailQuery>,
) -> Result<Response, MatrixError> {
    // For MVP: serve the original file as the thumbnail
    // Real thumbnail generation with the `image` crate can be added later
    serve_media(&state, &server_name, &media_id, true).await
}

async fn serve_media(
    state: &SharedState,
    server_name: &str,
    media_id: &str,
    _thumbnail: bool,
) -> Result<Response, MatrixError> {
    // Only serve media from our own server in MVP
    if server_name != state.config.server.server_name {
        return Err(MatrixError::NotFound);
    }

    let row = sqlx::query!(
        "SELECT content_type, storage_path, filename FROM media WHERE media_id = $1",
        media_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(MatrixError::from)?
    .ok_or(MatrixError::NotFound)?;

    let bytes = tokio::fs::read(&row.storage_path)
        .await
        .map_err(|_| MatrixError::NotFound)?;

    let content_type = row.content_type.clone();

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("content-length", bytes.len().to_string())
        .header("cache-control", "public, max-age=86400")
        .header("access-control-allow-origin", "*");

    if let Some(filename) = &row.filename {
        response = response.header(
            "content-disposition",
            format!("inline; filename=\"{}\"", filename),
        );
    }

    response
        .body(Body::from(bytes))
        .map_err(|e| MatrixError::Internal(e.to_string()))
}

fn generate_media_id() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let bytes = Uuid::new_v4().as_bytes().to_vec();
    URL_SAFE_NO_PAD.encode(bytes)
}
