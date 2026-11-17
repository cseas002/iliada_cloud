//! `iliada-account`: the Iliada account server.
//!
//! Settings come from the environment:
//!   ILIADA_ACCOUNT_ORIGIN   where people reach it (default http://localhost:8480)
//!   ILIADA_ACCOUNT_LISTEN   address to listen on (default 127.0.0.1:8480)
//!   ILIADA_ACCOUNT_DATA     where accounts and data are kept (default ./data)
//!   ILIADA_ACCOUNT_QUOTA_MB what each account may keep (default 1024)
//!   ILIADA_ACCOUNT_SMTP_URL_FILE  a file holding the SMTP address with its
//!                           password, e.g. smtps://user:password@smtp.example.com
//!                           (or ILIADA_ACCOUNT_SMTP_URL itself)
//!   ILIADA_ACCOUNT_MAIL_FROM  who sign-in emails are from, e.g.
//!                           "Iliada <account@example.org>"
//!   ILIADA_ACCOUNT_MAILS_PER_HOUR  sign-in emails to everyone in an hour (500)
//!   ILIADA_ACCOUNT_LOG_CODES=1  development: write email codes to the log

use anyhow::{Context, Result, bail};
use iliada_account::mail::Mail;
use iliada_account::store::{SendLimits, Store};
use iliada_account::{AppState, Config, router};

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
        mail: mail(&var)?,
        send_limits: SendLimits {
            per_hour: var("ILIADA_ACCOUNT_MAILS_PER_HOUR", "500")
                .parse()
                .context("ILIADA_ACCOUNT_MAILS_PER_HOUR")?,
            ..SendLimits::default()
        },
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

/// How sign-in codes are sent: SMTP when it is set up, the log while
/// developing. A server with neither refuses to start, rather than taking
/// sign-ups it can't finish.
fn mail(var: &dyn Fn(&str, &str) -> String) -> Result<Mail> {
    let file = var("ILIADA_ACCOUNT_SMTP_URL_FILE", "");
    let url = if file.is_empty() {
        var("ILIADA_ACCOUNT_SMTP_URL", "")
    } else {
        std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?
    };
    if !url.trim().is_empty() {
        let from = var("ILIADA_ACCOUNT_MAIL_FROM", "");
        if from.is_empty() {
            bail!("ILIADA_ACCOUNT_MAIL_FROM: who sign-in emails are from");
        }
        return Mail::smtp(&url, &from);
    }
    if var("ILIADA_ACCOUNT_LOG_CODES", "") == "1" {
        return Ok(Mail::Log);
    }
    bail!(
        "no way to send sign-in codes: set ILIADA_ACCOUNT_SMTP_URL_FILE and \
         ILIADA_ACCOUNT_MAIL_FROM, or ILIADA_ACCOUNT_LOG_CODES=1 while developing"
    )
}
