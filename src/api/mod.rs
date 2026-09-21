//! HTTP API. Two clearly separated surfaces so contributors can work on
//! either independently: issuer-side tree management ([`issuer`]) and
//! holder-side proof generation ([`holder`]).

pub mod holder;
pub mod issuer;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::Semaphore;
use tower_http::cors::{Any, CorsLayer};
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

/// How many proofs may be generated at once, from
/// `VEILPROOF_MAX_CONCURRENT_PROOFS`.
pub const ENV_MAX_CONCURRENT_PROOFS: &str = "VEILPROOF_MAX_CONCURRENT_PROOFS";

/// Default concurrent-proof budget. Deliberately small: proving is seconds of
/// CPU each, and the deployment targets hosts with a fraction of a core.
pub const DEFAULT_MAX_CONCURRENT_PROOFS: usize = 2;

/// Build the router, taking the proof budget from the environment.
pub fn router(state: AppState) -> Router {
    let capacity = std::env::var(ENV_MAX_CONCURRENT_PROOFS)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_PROOFS);
    router_with_prove_capacity(state, capacity)
}

/// Build the router with an explicit proof budget. Tests use this rather than
/// setting a process-wide environment variable.
pub fn router_with_prove_capacity(state: AppState, capacity: usize) -> Router {
    // Only `/prove` is metered. Everything else is cheap, and starving reads
    // because proving is busy would be its own outage.
    let proving = Router::new()
        .route("/issuers/:name/prove", post(holder::prove))
        .route_layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(capacity)),
            limit_concurrent_proofs,
        ))
        .with_state(state.clone());

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
        // Requests here are small (a hex commitment or secret, no root); cap
        // the body so a client can't stream an unbounded payload.
        .with_state(state)
        .merge(proving)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(cors())
        .layer(TraceLayer::new_for_http())
}

/// Refuse a proof outright when the budget is spent, rather than queueing it.
///
/// Proving is unauthenticated and costs the caller nothing while costing the
/// server seconds of CPU, so an unbounded queue is a denial-of-service waiting
/// to happen. Queued work is also usually work nobody is waiting for any more:
/// the client has given up, but the server pays for it regardless. A fast 503
/// tells the caller something true and lets it retry.
async fn limit_concurrent_proofs(
    State(permits): State<Arc<Semaphore>>,
    req: Request,
    next: Next,
) -> Response {
    match Arc::clone(&permits).try_acquire_owned() {
        // The permit lives until the response is produced, which is what bounds
        // the number of proofs actually running.
        Ok(_permit) => next.run(req).await,
        Err(_) => {
            tracing::warn!(
                capacity = permits.available_permits(),
                "refused a proof: the concurrent-proof budget is spent"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(axum::http::header::RETRY_AFTER, "5")],
                Json(json!({
                    "error": "the server is already generating as many proofs as it can handle; retry shortly"
                })),
            )
                .into_response()
        }
    }
}

/// Cross-origin policy.
///
/// The dashboard is a static site on its own domain, so every call it makes is
/// cross-origin; without this the browser blocks them all and the deployed API
/// is unusable from anything but curl.
///
/// Any origin is allowed deliberately. This API has no cookies, no sessions and
/// no ambient authority — a request is exactly as privileged as its contents,
/// so an attacker's page gains nothing by calling it that it could not do
/// directly from a server. Restricting origins would suggest a protection that
/// does not exist. Authority on the write path lives on-chain: publishing a
/// root and submitting a proof are wallet-signed contract calls, which this
/// server cannot make.
fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
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
