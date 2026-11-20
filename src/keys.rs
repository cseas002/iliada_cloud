//! Handing the account key to a new computer from one already signed in.
//!
//! The account key never reaches the server in readable form. The new
//! computer makes a one-time key pair and leaves the public half here; a
//! computer that has the account key sees the request, seals the key to
//! that public half and leaves the sealed key here; the new computer takes
//! it and opens it. Both screens show a short code made from the public
//! half, and the person checks they match before approving, so a server
//! that swapped in its own public half would be caught.
//!
//! Requests live in memory for a few minutes: a restart only means asking
//! again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::store::Kind;
use crate::{AppState, Auth, R, err};

/// How long a request waits for an answer.
pub const REQUEST_TIME: Duration = Duration::from_secs(15 * 60);
/// Open requests one account may have at once.
const MAX_PER_ACCOUNT: usize = 5;
/// The largest sealed key accepted (a key is a few dozen bytes).
const MAX_SEALED: usize = 1024;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Default)]
pub struct Requests(Mutex<HashMap<String, Request>>);

struct Request {
    account: String,
    /// The sign-in (session) of the computer that asked.
    session: String,
    computer: String,
    public_key: [u8; 32],
    created: i64,
    until: Instant,
    answer: Answer,
}

enum Answer {
    Waiting,
    Sealed(Vec<u8>),
    Refused,
}

impl Requests {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Request>> {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        m.retain(|_, r| r.until > now);
        m
    }
}

/// Only computers take part: the website never holds the account key.
fn computer(auth: &Auth) -> R<()> {
    match auth.0.kind {
        Kind::Computer => Ok(()),
        Kind::Web => Err(err(
            StatusCode::FORBIDDEN,
            "only a computer signed in to the account can do this",
        )),
    }
}

#[derive(Deserialize)]
pub struct Ask {
    public_key: String,
}

/// The new computer asks for the key: `{"public_key": base64}` → `{"id"}`.
/// A second request from the same computer replaces its first.
pub async fn ask(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    axum::Json(body): axum::Json<Ask>,
) -> R<axum::Json<serde_json::Value>> {
    computer(&auth)?;
    let public_key: [u8; 32] = B64
        .decode(body.public_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "public_key: 32 bytes in base64"))?;
    let mut m = s.keys.lock();
    m.retain(|_, r| r.session != auth.0.id);
    if m.values().filter(|r| r.account == auth.0.account).count() >= MAX_PER_ACCOUNT {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many computers are waiting for the key; try again in a few minutes",
        ));
    }
    let id = crate::store::secret();
    m.insert(
        id.clone(),
        Request {
            account: auth.0.account.clone(),
            session: auth.0.id.clone(),
            computer: auth.0.name.clone(),
            public_key,
            created: crate::store::now(),
            until: Instant::now() + REQUEST_TIME,
            answer: Answer::Waiting,
        },
    );
    Ok(axum::Json(
        json!({ "id": id, "expires_in": REQUEST_TIME.as_secs() }),
    ))
}

/// The account's other computers waiting for the key.
pub async fn list(State(s): State<Arc<AppState>>, auth: Auth) -> R<axum::Json<serde_json::Value>> {
    computer(&auth)?;
    let m = s.keys.lock();
    let mut out: Vec<_> = m
        .iter()
        .filter(|(_, r)| {
            r.account == auth.0.account
                && r.session != auth.0.id
                && matches!(r.answer, Answer::Waiting)
        })
        .map(|(id, r)| {
            json!({
                "id": id,
                "computer": r.computer,
                "public_key": B64.encode(r.public_key),
                "created": r.created,
            })
        })
        .collect();
    out.sort_by_key(|r| r["created"].as_i64());
    Ok(axum::Json(json!({ "requests": out })))
}

/// What the new computer sees: waiting, refused, or the sealed key (handed
/// over once, then forgotten).
pub async fn status(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(id): Path<String>,
) -> R<axum::Json<serde_json::Value>> {
    computer(&auth)?;
    let mut m = s.keys.lock();
    let r = m
        .get(&id)
        .filter(|r| r.session == auth.0.id)
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "no such request (it may have expired)",
            )
        })?;
    let out = match &r.answer {
        Answer::Waiting => json!({ "state": "waiting" }),
        Answer::Refused => json!({ "state": "refused" }),
        Answer::Sealed(b) => json!({ "state": "answered", "sealed": B64.encode(b) }),
    };
    if !matches!(r.answer, Answer::Waiting) {
        m.remove(&id);
    }
    Ok(axum::Json(out))
}

#[derive(Deserialize)]
pub struct Approve {
    sealed: String,
}

/// A computer with the key answers: `{"sealed": base64}`.
pub async fn approve(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<Approve>,
) -> R<StatusCode> {
    computer(&auth)?;
    let sealed = B64
        .decode(body.sealed.trim())
        .ok()
        .filter(|b| !b.is_empty() && b.len() <= MAX_SEALED)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "sealed: the sealed key in base64"))?;
    answer(&s, &auth, &id, Answer::Sealed(sealed))
}

/// A computer with the key says no.
pub async fn refuse(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(id): Path<String>,
) -> R<StatusCode> {
    computer(&auth)?;
    answer(&s, &auth, &id, Answer::Refused)
}

fn answer(s: &AppState, auth: &Auth, id: &str, answer: Answer) -> R<StatusCode> {
    let mut m = s.keys.lock();
    let r = m
        .get_mut(id)
        .filter(|r| r.account == auth.0.account && r.session != auth.0.id)
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "no such request (it may have expired)",
            )
        })?;
    if !matches!(r.answer, Answer::Waiting) {
        return Err(err(
            StatusCode::CONFLICT,
            "this request was already answered",
        ));
    }
    r.answer = answer;
    Ok(StatusCode::NO_CONTENT)
}
