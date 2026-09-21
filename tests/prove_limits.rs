//! The concurrent-proof budget.
//!
//! `POST /prove` is unauthenticated and costs the caller nothing, while costing
//! the server seconds of CPU. Without a bound, a handful of callers can occupy
//! every core indefinitely. These tests pin that the budget refuses work
//! rather than queueing it, that it only applies to proving, and that the rest
//! of the API keeps serving while proving is saturated.
//!
//! They need a database and are skipped when `DATABASE_URL` is unset.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use veilproof_server::api::{router_with_prove_capacity, AppState};
use veilproof_server::crypto::{self, encoding::fr_be};
use veilproof_server::store::Store;

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

/// Send one request through a router built with the given proof budget.
async fn send(
    state: &AppState,
    capacity: usize,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, String, Option<String>) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_owned())))
        .unwrap();
    let res = router_with_prove_capacity(state.clone(), capacity)
        .oneshot(req)
        .await
        .unwrap();
    let status = res.status();
    let retry_after = res
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        retry_after,
    )
}

/// A published single-member tree, returning the issuer name and the request
/// body that proves membership of it.
async fn fixture(state: &AppState, prefix: &str) -> (String, String) {
    let issuer = unique_issuer(prefix);
    let secret = ark_bn254::Fr::from(76_543u64);
    let commitment = hex::encode(fr_be(&crypto::leaf_commitment(secret)));
    let (status, body, _) = send(
        state,
        1,
        "POST",
        &format!("/issuers/{issuer}/leaves"),
        Some(&format!(r#"{{"commitment":"{commitment}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add_leaf failed: {body}");
    let (status, body, _) = send(
        state,
        1,
        "POST",
        &format!("/issuers/{issuer}/publish"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish failed: {body}");

    let prove_body = format!(
        r#"{{"secret":"{}","holder_address":"GABSD5ONPJO6TKFWQC6K2OAV4ZW5C4TEE6YZF7XBYH6HLPZ66TFV7ZDF"}}"#,
        hex::encode(fr_be(&secret))
    );
    (issuer, prove_body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_saturated_budget_refuses_rather_than_queues() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let (issuer, prove_body) = fixture(&state, "limit").await;
    let path = format!("/issuers/{issuer}/prove");

    // One router, budget of one, shared between both requests — a fresh router
    // per request would get a fresh semaphore and defeat the point.
    let app = router_with_prove_capacity(state.clone(), 1);

    let first = {
        let app = app.clone();
        let path = path.clone();
        let body = prove_body.clone();
        tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri(&path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            app.oneshot(req).await.unwrap().status()
        })
    };

    // Let the first request take the permit. Proving runs for a couple of
    // hundred milliseconds, so this leaves a wide window.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let req = Request::builder()
        .method("POST")
        .uri(&path)
        .header("content-type", "application/json")
        .body(Body::from(prove_body.clone()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let retry_after = res
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body =
        String::from_utf8_lossy(&res.into_body().collect().await.unwrap().to_bytes()).into_owned();

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "second proof should have been refused, got {status}: {body}",
    );
    assert_eq!(
        retry_after.as_deref(),
        Some("5"),
        "a 503 without Retry-After leaves the caller guessing",
    );
    assert!(body.contains("error"), "unexpected body: {body}");

    assert_eq!(
        first.await.expect("the first proof panicked"),
        StatusCode::OK,
        "the first proof should have been served normally",
    );

    // Once the permit is released the budget recovers — a limiter that stays
    // stuck closed would also pass the assertions above.
    let (status, body, _) = send(&state, 1, "POST", &path, Some(&prove_body)).await;
    assert_eq!(status, StatusCode::OK, "budget did not recover: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_budget_does_not_apply_to_the_rest_of_the_api() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let (issuer, prove_body) = fixture(&state, "limit-scope").await;
    let app = router_with_prove_capacity(state.clone(), 1);

    let proving = {
        let app = app.clone();
        let path = format!("/issuers/{issuer}/prove");
        tokio::spawn(async move {
            let req = Request::builder()
                .method("POST")
                .uri(&path)
                .header("content-type", "application/json")
                .body(Body::from(prove_body))
                .unwrap();
            app.oneshot(req).await.unwrap().status()
        })
    };

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Reads must keep working while the proof budget is spent. Starving these
    // because proving is busy would be an outage of its own.
    for path in ["/health", "/issuers", "/issuers/nonexistent-issuer"] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let status = app.clone().oneshot(req).await.unwrap().status();
        assert_ne!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path} was refused while proving was saturated",
        );
    }

    assert_eq!(
        proving.await.expect("the proof panicked"),
        StatusCode::OK,
        "the in-flight proof should still have succeeded",
    );
}
