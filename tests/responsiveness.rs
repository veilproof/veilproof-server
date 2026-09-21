//! The server must keep answering while a proof is being generated.
//!
//! Groth16 proving takes seconds of solid CPU. Run directly on an async worker
//! thread it blocks the runtime, and on a host with a single worker nothing
//! else gets a turn — including `/health`. A platform that health-checks the
//! service then concludes it is dead and restarts it mid-proof, which is how
//! this first showed up: `POST /prove` returned 502 on a free-tier host, and
//! the whole service was still 502ing afterwards.
//!
//! So this test pins the property that actually matters, on a runtime with
//! exactly one worker thread, which is the worst case and the one free tiers
//! resemble. It needs a database and is skipped when `DATABASE_URL` is unset.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use veilproof_server::api::{router, AppState};
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

/// One worker thread: the setup where blocking the runtime is unmistakable.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_runtime_keeps_making_progress_during_a_proof() {
    let Some(state) = state_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    // A tree containing one holder, with its root published.
    let issuer = unique_issuer("responsive");
    let secret = ark_bn254::Fr::from(4_242_424u64);
    let commitment = hex::encode(fr_be(&crypto::leaf_commitment(secret)));
    let (status, body) = send(
        &state,
        "POST",
        &format!("/issuers/{issuer}/leaves"),
        Some(&format!(r#"{{"commitment":"{commitment}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add_leaf failed: {body}");
    let (status, body) = send(&state, "POST", &format!("/issuers/{issuer}/publish"), None).await;
    assert_eq!(status, StatusCode::OK, "publish failed: {body}");

    let secret_hex = hex::encode(fr_be(&secret));
    let prove_body = format!(
        r#"{{"secret":"{secret_hex}","holder_address":"GABSD5ONPJO6TKFWQC6K2OAV4ZW5C4TEE6YZF7XBYH6HLPZ66TFV7ZDF"}}"#
    );
    let prove_path = format!("/issuers/{issuer}/prove");

    // A ticker that simply wakes every 10ms and counts. It stands in for every
    // other task the runtime owes attention to — the health endpoint, other
    // requests, timeouts.
    //
    // Timing a single competing request would not discriminate: proving with
    // development keys takes a couple of hundred milliseconds, and one probe
    // can slip into a gap while a proof waits on the database. Counting ticks
    // across the whole proof measures the runtime's progress rather than one
    // lucky moment.
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker = {
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // Run the proof as a runtime task, the way a real request is served. The
    // test body runs on the calling thread via block_on, so proving from here
    // would not occupy a worker at all.
    let started = Instant::now();
    let (status, body) = {
        let state = state.clone();
        let path = prove_path.clone();
        let body = prove_body.clone();
        tokio::spawn(async move { send(&state, "POST", &path, Some(&body)).await })
            .await
            .expect("the proving task panicked")
    };
    let elapsed = started.elapsed();
    ticker.abort();

    assert_eq!(status, StatusCode::OK, "prove failed: {body}");
    assert!(body.contains("\"proof\""), "unexpected prove body: {body}");

    // How many wake-ups the runtime should have managed, if proving left it
    // free. Half of the theoretical maximum is a wide margin: the failure mode
    // being caught is near-total starvation.
    let observed = ticks.load(Ordering::Relaxed);
    let expected = elapsed.as_millis() as usize / 10;
    assert!(
        observed * 2 >= expected,
        "the runtime managed {observed} wake-ups during a {elapsed:?} proof, \
         against roughly {expected} expected — proving is running on the async \
         runtime and starving everything else on it, including /health. A \
         platform health check would time out and restart the instance mid-proof.",
    );
}
