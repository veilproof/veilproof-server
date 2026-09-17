//! Entry point: wire the trusted-setup keys, the database, and the HTTP API
//! together, then serve.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use veilproof_server::api::{router, AppState};
use veilproof_server::keysource;
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

    // Trusted setup, from a URL, a directory, or the insecure development
    // fallback — see keysource for the precedence and the integrity pin.
    let keys = Arc::new(keysource::load_from_env().await?);

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
