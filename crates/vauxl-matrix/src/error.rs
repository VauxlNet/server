//! Matrix-compatible error responses.
//!
//! Every error the CS API returns must follow the Matrix error format:
//! {"errcode": "M_UNKNOWN", "error": "Human readable message"}

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MatrixError {
    #[error("Missing or invalid token")]
    MissingToken,

    #[error("Unknown token")]
    UnknownToken,

    #[error("Forbidden")]
    Forbidden,

    #[error("User ID already taken")]
    UserInUse,

    #[error("Invalid username")]
    InvalidUsername,

    #[error("Invalid password")]
    WeakPassword,

    #[error("Rate limited")]
    LimitExceeded,

    #[error("Not found")]
    NotFound,

    #[error("Bad JSON: {0}")]
    BadJson(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl MatrixError {
    fn errcode(&self) -> &'static str {
        match self {
            Self::MissingToken => "M_MISSING_TOKEN",
            Self::UnknownToken => "M_UNKNOWN_TOKEN",
            Self::Forbidden => "M_FORBIDDEN",
            Self::UserInUse => "M_USER_IN_USE",
            Self::InvalidUsername => "M_INVALID_USERNAME",
            Self::WeakPassword => "M_WEAK_PASSWORD",
            Self::LimitExceeded => "M_LIMIT_EXCEEDED",
            Self::NotFound => "M_NOT_FOUND",
            Self::BadJson(_) => "M_BAD_JSON",
            Self::Internal(_) => "M_UNKNOWN",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::MissingToken | Self::UnknownToken => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::LimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::UserInUse | Self::InvalidUsername | Self::WeakPassword | Self::BadJson(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for MatrixError {
    fn into_response(self) -> Response {
        let body = json!({
            "errcode": self.errcode(),
            "error":   self.to_string(),
        });
        (self.status(), Json(body)).into_response()
    }
}

impl From<sqlx::Error> for MatrixError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "Database error");
        Self::Internal(e.to_string())
    }
}

impl From<anyhow::Error> for MatrixError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "Internal error");
        Self::Internal(e.to_string())
    }
}
