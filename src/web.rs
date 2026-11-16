//! The account website: sign in or sign up, your account (passkeys, signed-in
//! computers, storage, delete), and `/device`, where a computer's code is
//! approved.
//!
//! Pages are plain HTML made here; `app.js` does only what a browser must
//! (passkeys) and the buttons. The sign-in lives in an HttpOnly cookie, so
//! no script on the page can read it, and a strict Content Security Policy
//! allows only this site's own script and style.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use crate::AppState;
use crate::store::{Account, Kind, Session};

pub const COOKIE: &str = "iliada_session";
/// How long the website stays signed in.
const COOKIE_DAYS: u32 = 30;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(home))
        .route("/device", get(device))
        .route(
            "/app.js",
            get(|| {
                asset(
                    "text/javascript; charset=utf-8",
                    include_str!("../assets/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| {
                asset(
                    "text/css; charset=utf-8",
                    include_str!("../assets/style.css"),
                )
            }),
        )
        .route(
            "/logo.svg",
            get(|| asset("image/svg+xml", include_str!("../assets/iliada.svg"))),
        )
}

fn secure(s: &AppState) -> &'static str {
    if s.config.origin.scheme() == "https" {
        "; Secure"
    } else {
        ""
    }
}

pub fn set_cookie(s: &AppState, token: &str) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        COOKIE_DAYS * 86400,
        secure(s)
    )
}

pub fn clear_cookie(s: &AppState) -> String {
    format!(
        "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        secure(s)
    )
}

/// The website's sign-in token from the request's cookies.
pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, v)| *k == COOKIE && !v.is_empty())
        .map(|(_, v)| v.to_owned())
}

/// Text made safe to put in HTML (also inside attribute values).
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const SECURITY_HEADERS: [(&str, &str); 4] = [
    (
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; \
         form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
];

fn page(title: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Iliada</title>
<link rel="icon" href="/logo.svg">
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>
</head>
<body>
<main>
<header><img src="/logo.svg" alt="" width="44" height="44"><span>Iliada</span></header>
{body}
</main>
</body>
</html>"#,
        title = esc(title)
    );
    let mut r = Html(html).into_response();
    for (k, v) in SECURITY_HEADERS {
        r.headers_mut().insert(k, HeaderValue::from_static(v));
    }
    r
}

async fn asset(kind: &'static str, body: &'static str) -> Response {
    let mut r = body.into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    r.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// The signed-in browser's session and account, if any.
fn signed_in(s: &AppState, headers: &HeaderMap) -> Option<(Session, Account)> {
    let token = session_cookie(headers)?;
    let session = s.store.session(&token).ok()??;
    if session.kind != Kind::Web {
        return None;
    }
    let account = s.store.account(&session.account).ok()??;
    Some((session, account))
}

fn sign_in_form(intro: &str) -> String {
    format!(
        r#"<section class="card" id="signin">
<h1>Sign in</h1>
<p>{intro}</p>
<label for="email">Email</label>
<input id="email" type="email" autocomplete="username webauthn" placeholder="you@example.com" required>
<div class="buttons">
<button class="primary" id="passkey-login">Sign in with a passkey</button>
<button id="email-code">Email me a code</button>
</div>
<div id="code-step" hidden>
<label for="code">The six-digit code we emailed you</label>
<input id="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6">
<div class="buttons"><button class="primary" id="code-submit">Continue</button></div>
</div>
<p class="note">New here? Enter your email and choose <b>Email me a code</b>: that makes your
account. Then add a passkey, so next time your fingerprint, face or PIN is enough.</p>
<p class="message" id="message" role="status"></p>
</section>"#,
        intro = esc(intro)
    )
}

async fn home(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((me, account)) = signed_in(&s, &headers) else {
        return page(
            "Sign in",
            &sign_in_form(
                "Your Iliada account keeps your settings, encrypted on your computer before they leave it.",
            ),
        );
    };
    let passkeys = s.store.passkeys(&account.id).map(|p| p.len()).unwrap_or(0);
    let used = crate::used(&s, &account.id).unwrap_or(0);
    let mut computers = String::new();
    let mut browsers = String::new();
    for x in s.store.sessions(&account.id).unwrap_or_default() {
        let this = x.id == me.id;
        let row = format!(
            r#"<li><div><b>{name}</b><span class="when" data-time="{last}">{this}</span></div>{button}</li>"#,
            name = esc(if x.kind == Kind::Web {
                "Web browser"
            } else {
                &x.name
            }),
            last = x.last_used,
            this = if this { "this browser" } else { "" },
            button = if this {
                String::new()
            } else {
                format!(
                    r#"<button class="small" data-end-session="{}">Sign out</button>"#,
                    esc(&x.id)
                )
            },
        );
        if x.kind == Kind::Computer {
            computers.push_str(&row)
        } else {
            browsers.push_str(&row)
        }
    }
    if computers.is_empty() {
        computers = r#"<li class="empty">No computers yet. On your Iliada computer: Settings → Account → Sign in.</li>"#.into();
    }
    let body = format!(
        r#"<section class="card">
<h1>Your account</h1>
<p class="email">{email}</p>
<div class="row"><div><b>Passkeys</b><span>{passkey_text}</span></div><button id="add-passkey">Add a passkey</button></div>
<div class="row"><div><b>Storage</b><span>{used} of {quota} used</span></div></div>
<p class="message" id="message" role="status"></p>
</section>
<section class="card">
<h2>Computers</h2>
<ul class="list">{computers}</ul>
<h2>Web browsers</h2>
<ul class="list">{browsers}</ul>
</section>
<section class="card">
<div class="buttons spread"><button id="sign-out">Sign out</button><button class="danger" id="delete-account">Delete account</button></div>
<p class="note">Deleting the account deletes everything it keeps. Your computers keep their own copy.</p>
</section>"#,
        email = esc(&account.email),
        passkey_text = match passkeys {
            0 => "None yet: add one to sign in with your fingerprint, face or PIN".to_owned(),
            1 => "1 passkey".to_owned(),
            n => format!("{n} passkeys"),
        },
        used = size(used),
        quota = size(s.config.quota),
    );
    page("Your account", &body)
}

async fn device(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if signed_in(&s, &headers).is_none() {
        return page(
            "Sign in a computer",
            &sign_in_form(
                "To sign in your computer, first sign in here. Then type the code your computer shows.",
            ),
        );
    }
    let body = r#"<section class="card" id="approve">
<h1>Sign in a computer</h1>
<p>Type the code your Iliada computer shows. Only approve a code from your own computer:
it will be able to keep and read your settings.</p>
<label for="user-code">Code</label>
<input id="user-code" class="code" autocomplete="off" autocapitalize="characters" maxlength="9" placeholder="ABCD-EFGH">
<div class="buttons"><button class="primary" id="approve-button">Approve</button></div>
<p class="message" id="message" role="status"></p>
</section>"#;
    page("Sign in a computer", body)
}

fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{} KB", b >> 10),
        b => format!("{b} bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(esc(r#"<b a="x">'&"#), "&lt;b a=&quot;x&quot;&gt;&#39;&amp;");
    }

    #[test]
    fn cookie_is_found_among_others() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; iliada_session=abc; b=2"),
        );
        assert_eq!(session_cookie(&h).as_deref(), Some("abc"));
        h.insert(header::COOKIE, HeaderValue::from_static("iliada_session="));
        assert_eq!(session_cookie(&h), None);
    }

    #[test]
    fn sizes() {
        assert_eq!(size(512), "512 bytes");
        assert_eq!(size(1 << 30), "1.0 GB");
    }
}
