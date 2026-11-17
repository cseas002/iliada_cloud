//! Sending sign-in codes by email (any SMTP service: Postmark, Resend,
//! Amazon SES, a mail server of your own), or writing them to the log
//! while developing.

use anyhow::{Context, Result};
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub enum Mail {
    /// Development: codes go to the server's log, nothing is sent.
    Log,
    Smtp {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        from: Mailbox,
    },
}

impl Mail {
    /// An SMTP sender from a URL such as
    /// `smtps://user:password@smtp.example.com` (port 465) or
    /// `smtp://user:password@smtp.example.com:587?tls=required`.
    pub fn smtp(url: &str, from: &str) -> Result<Mail> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url.trim())
            .context("the SMTP address isn't one (smtps://user:password@host)")?
            .build();
        let from = from
            .parse()
            .with_context(|| format!("{from:?} isn't an email address"))?;
        Ok(Mail::Smtp {
            transport: Box::new(transport),
            from,
        })
    }

    pub async fn send_code(&self, to: &str, code: &str) -> Result<()> {
        match self {
            Mail::Log => {
                tracing::info!(email = %to, %code, "sign-in code (development: not emailed)");
                Ok(())
            }
            Mail::Smtp { transport, from } => {
                let message = Message::builder()
                    .from(from.clone())
                    .to(to.parse().context("the email address")?)
                    .subject(format!("{code} is your Iliada sign-in code"))
                    .body(code_text(code))?;
                transport.send(message).await.context("sending the email")?;
                tracing::info!(email = %to, "sign-in code sent");
                Ok(())
            }
        }
    }
}

fn code_text(code: &str) -> String {
    format!(
        "Your Iliada sign-in code is\n\n    {code}\n\n\
         Type it on the page where you asked for it. It works for 10 minutes.\n\n\
         If you didn't ask for it, you can ignore this email: nobody can sign in\n\
         without the code.\n"
    )
}
