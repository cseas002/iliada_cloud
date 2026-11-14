//! `iliada-account`: the Iliada account server.
//!
//! Settings come from the environment:
//!   ILIADA_ACCOUNT_ORIGIN   where people reach it (default http://localhost:8480)
//!   ILIADA_ACCOUNT_LISTEN   address to listen on (default 127.0.0.1:8480)
//!   ILIADA_ACCOUNT_DATA     where accounts and data are kept (default ./data)
//!   ILIADA_ACCOUNT_QUOTA_MB what each account may keep (default 1024)
//!   ILIADA_ACCOUNT_LOG_CODES=1  development: write email codes to the log

use anyhow::{Context, Result};
use iliada_account::{AppState, Config, router, store::Store};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
    let origin = var("ILIADA_ACCOUNT_ORIGIN", "http://localhost:8480");
    let listen = var("ILIADA_ACCOUNT_LISTEN", "127.0.0.1:8480");
    let data_dir = std::path::PathBuf::from(var("ILIADA_ACCOUNT_DATA", "data"));
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating {}", data_dir.display()))?;
    let config = Config {
        origin: origin
            .parse()
            .context("ILIADA_ACCOUNT_ORIGIN is not an address")?,
        log_email_codes: var("ILIADA_ACCOUNT_LOG_CODES", "") == "1",
        quota: var("ILIADA_ACCOUNT_QUOTA_MB", "1024")
            .parse::<u64>()
            .context("ILIADA_ACCOUNT_QUOTA_MB")?
            << 20,
        data_dir: data_dir.clone(),
    };
    let state = AppState::new(config, Store::open(&data_dir.join("accounts.sqlite"))?)?;
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("listening on {listen}"))?;
    tracing::info!("Iliada account server on {listen}, reached at {origin}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
