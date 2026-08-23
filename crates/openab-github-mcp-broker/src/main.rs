use anyhow::{Context, Result};
use openab_github_mcp_broker::Config;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let listen = config.listen.clone();
    let upstream = config.upstream_url.clone();
    let app = openab_github_mcp_broker::router(config)?;
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind GitHub MCP broker to {listen}"))?;
    info!(%listen, %upstream, "OpenAB delegated GitHub MCP broker listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve delegated GitHub MCP broker")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
