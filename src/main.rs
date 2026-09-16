//! Entry point: wire the trusted-setup keys, the database, and the HTTP API
//! together, then serve.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use veilproof_server::api::{router, AppState};
use veilproof_server::crypto;
use veilproof_server::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set (see .env.example)")?;
    let bind: SocketAddr = std::env::var("VEILPROOF_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;

    // Trusted setup. If VEILPROOF_KEYS_DIR points at keys produced by
    // `veilproof-keygen` (or a ceremony), load them. Otherwise fall back to
    // the deterministic development setup, which is INSECURE (a known seed
    // means known toxic waste — anyone can forge proofs). See the README.
    let keys = match std::env::var("VEILPROOF_KEYS_DIR") {
        Ok(dir) => {
            let keys = crypto::Keys::load(std::path::Path::new(&dir))?;
            tracing::info!(dir, "loaded trusted-setup keys from disk");
            Arc::new(keys)
        }
        Err(_) => {
            tracing::warn!(
                "VEILPROOF_KEYS_DIR not set — using the DEVELOPMENT trusted setup \
                 (deterministic, insecure). Do not use for anything of value; \
                 run veilproof-keygen and set VEILPROOF_KEYS_DIR. See the README."
            );
            Arc::new(crypto::dev_keys())
        }
    };

    let store = Store::connect(&database_url).await?;
    tracing::info!("database connected and migrated");

    let state = AppState { store, keys };
    let app = router(state);

    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, "veilproof-server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve on Ctrl-C or SIGTERM so the container stops cleanly.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
