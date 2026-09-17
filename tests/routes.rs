//! HTTP-level tests that the router actually matches its parameterized paths.
//!
//! These exist because of a bug that reached a deployed server: the routes
//! were written with axum 0.8's `{name}` placeholder while the crate depends
//! on axum 0.7, where `{name}` is not a parameter. Every endpoint below
//! `/issuers/:name` returned 404 in production. Nothing caught it, because the
//! rest of the suite calls the store and the crypto core directly and never
//! sends a request through the router.
//!
//! The load-bearing distinction here is **how** a 404 is produced. An unmatched
//! route yields axum's own empty-bodied 404; a matched route that finds no such
//! issuer yields our `{"error": ...}` envelope. Asserting on the body is what
//! makes these tests detect a routing regression rather than pass through it.
//!
//! They need a database and are skipped when `DATABASE_URL` is unset, matching
//! tests/store_integration.rs; CI provides Postgres.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use veilproof_server::api::{router, AppState};
use veilproof_server::crypto::{self, encoding::fr_be};
use veilproof_server::store::Store;

/// A per-run unique issuer name so repeated CI runs don't collide.
fn unique_issuer(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

async fn state_or_skip() -> Option<AppState> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let store = Store::connect(&url).await.expect("connect + migrate");
    Some(AppState {
        store,
        keys: Arc::new(crypto::dev_keys()),
    })
}

/// Send one request through the router and return its status and body text.
async fn send(
    state: &AppState,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_owned())))
        .unwrap();
    let res = router(state.clone()).oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn parameterized_routes_are_matched() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    let issuer = unique_issuer("routes");
    let secret = ark_bn254::Fr::from(909_090u64);
    let commitment = hex::encode(fr_be(&crypto::leaf_commitment(secret)));

    // Before any leaf exists the tree is unknown — but the route must match,
    // so the 404 has to carry our error envelope rather than an empty body.
    let (status, body) = send(&state, "GET", &format!("/issuers/{issuer}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("error"),
        "GET /issuers/:name did not reach a handler (empty 404 = unmatched route): {body:?}",
    );

    // POST .../leaves creates the issuer and returns a position.
    let (status, body) = send(
        &state,
        "POST",
        &format!("/issuers/{issuer}/leaves"),
        Some(&format!(r#"{{"commitment":"{commitment}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add_leaf failed: {body}");
    assert!(body.contains("\"position\":0"), "unexpected body: {body}");

    // Now the issuer exists and GET .../:name reports it.
    let (status, body) = send(&state, "GET", &format!("/issuers/{issuer}"), None).await;
    assert_eq!(status, StatusCode::OK, "issuer_info failed: {body}");
    assert!(body.contains("\"leaf_count\":1"), "unexpected body: {body}");

    // Publishing returns a root, and .../root then serves it.
    let (status, body) = send(&state, "POST", &format!("/issuers/{issuer}/publish"), None).await;
    assert_eq!(status, StatusCode::OK, "publish failed: {body}");
    assert!(body.contains("\"root\""), "unexpected body: {body}");

    let (status, root_body) = send(&state, "GET", &format!("/issuers/{issuer}/root"), None).await;
    assert_eq!(status, StatusCode::OK, "get_root failed: {root_body}");
    assert_eq!(root_body, body, "published root and /root disagree");
}

#[tokio::test]
async fn prove_route_is_matched() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    // A syntactically valid request against an issuer with no tree. The point
    // is only that it reaches the handler: an unmatched route would 404 with
    // an empty body instead of the handler's JSON error.
    let issuer = unique_issuer("prove-route");
    let body = format!(
        r#"{{"secret":"{}","holder_address":"GBUT33CNKAKSH5EXJTYXSWDELEODFWJPAHW36YUGLRSIAN72P77MQ3WX"}}"#,
        "11".repeat(32)
    );
    let (status, body) = send(
        &state,
        "POST",
        &format!("/issuers/{issuer}/prove"),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("error"),
        "POST /issuers/:name/prove did not reach a handler: {body:?}",
    );
}

#[tokio::test]
async fn a_genuinely_unknown_path_404s_with_an_empty_body() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    // This is the control for the assertions above: it shows that an unmatched
    // route really does produce an empty body, so "body contains error" is a
    // meaningful signal that a route was matched.
    let (status, body) = send(&state, "GET", "/no/such/path", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.is_empty(), "expected an empty 404 body, got {body:?}");

    // The literal brace form must NOT be a route. If someone reintroduces
    // axum 0.8 syntax on axum 0.7, this is what the server would be serving.
    let (status, body) = send(&state, "GET", "/issuers/%7Bname%7D/root", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("error"),
        "a braced segment should be treated as an ordinary issuer name: {body:?}",
    );
}

/// Send a request with explicit headers, returning status and response headers.
async fn send_with_headers(
    state: &AppState,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap) {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (res.status(), res.headers().clone())
}

#[tokio::test]
async fn cors_preflight_is_answered() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    // The dashboard is on its own domain, so a POST with a JSON content-type is
    // preceded by this preflight. If it is not answered the browser never sends
    // the real request and the deployed API is unusable from the web app —
    // while curl, which does no preflight, keeps working.
    let (status, headers) = send_with_headers(
        &state,
        "OPTIONS",
        "/issuers/anything/prove",
        &[
            ("origin", "https://veilproof-web.vercel.app"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
        ],
    )
    .await;

    assert!(
        status.is_success(),
        "preflight should succeed, got {status}"
    );
    assert!(
        headers.contains_key("access-control-allow-origin"),
        "preflight response carries no allow-origin header: {headers:?}",
    );
    let allowed = headers["access-control-allow-methods"].to_str().unwrap();
    assert!(
        allowed.contains("POST") || allowed.contains('*'),
        "POST is not an allowed method: {allowed}",
    );
}

#[tokio::test]
async fn ordinary_responses_carry_the_allow_origin_header() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    // Answering the preflight is not enough: the browser also checks the header
    // on the actual response before handing the body to JavaScript.
    let (status, headers) = send_with_headers(
        &state,
        "GET",
        "/issuers",
        &[("origin", "https://veilproof-web.vercel.app")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.contains_key("access-control-allow-origin"),
        "GET /issuers response carries no allow-origin header",
    );
}
