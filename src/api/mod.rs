//! HTTP API. Two clearly separated surfaces so contributors can work on
//! either independently: issuer-side tree management ([`issuer`]) and
//! holder-side proof generation ([`holder`]).

pub mod holder;
pub mod issuer;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tower_http::trace::TraceLayer;

use crate::crypto::{CryptoError, Keys};
use crate::store::{Store, StoreError};

/// Shared application state: the connection pool and the proving/verifying
/// keys. `Keys` is large, so it is shared behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub keys: Arc<Keys>,
}

/// Build the router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/issuers", get(issuer::list_issuers))
        // `:name` is axum 0.7's path-parameter syntax. The `{name}` form is
        // axum 0.8's; on 0.7 it is not a parameter at all, so every route
        // below silently 404s. See tests/routes.rs.
        .route("/issuers/:name", get(issuer::issuer_info))
        .route("/issuers/:name/leaves", post(issuer::add_leaf))
        .route("/issuers/:name/publish", post(issuer::publish))
        .route("/issuers/:name/root", get(issuer::get_root))
        .route("/issuers/:name/prove", post(holder::prove))
        // Requests here are small (a hex commitment or secret, no root); cap
        // the body so a client can't stream an unbounded payload.
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /version` — build identification, handy for checking what is deployed.
async fn version() -> Json<serde_json::Value> {
    Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn health(State(state): State<AppState>) -> Response {
    match state.store.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error", "detail": e.to_string() })),
        )
            .into_response(),
    }
}

/// A field element supplied by a client as 64 lowercase hex characters
/// (32 big-endian bytes).
pub fn parse_fr_hex(s: &str) -> Result<ark_bn254::Fr, ApiError> {
    let bytes = hex::decode(s).map_err(|_| ApiError::BadRequest("expected hex".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest("expected 32 bytes (64 hex chars)".into()))?;
    Ok(crate::crypto::encoding::fr_from_be(&arr))
}

/// API error envelope. Each variant maps to a status code and a JSON body of
/// the shape `{ "error": "..." }`.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Full => ApiError::Conflict("the tree is full".into()),
            // Don't leak database internals to clients; log-worthy detail stays
            // in the message for the server's own tracing.
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl From<CryptoError> for ApiError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::NotAMember => {
                ApiError::NotFound("the secret's commitment is not in this tree".into())
            }
            CryptoError::ProvingFailed => ApiError::Internal("proof generation failed".into()),
        }
    }
}
