//! The Iliada account server: sign-up and sign-in (passkeys, email codes),
//! computers signing in with a code approved on the website, and each
//! account's encrypted data. See iliada_os/docs/account.md.
//!
//! The server never sees anyone's data in readable form: computers encrypt
//! it before uploading (blobs are opaque bytes here).

pub mod store;
pub mod web;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, State};
use axum::http::{StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use store::{DeviceState, Kind, Session, Store};
use webauthn_rs::prelude::*;

/// How the server is set up.
pub struct Config {
    /// Where the website is reached, e.g. `https://account.example.org`
    /// (`http://localhost:<port>` while developing).
    pub origin: Url,
    /// Where accounts and their data are kept.
    pub data_dir: PathBuf,
    /// Development only: email codes are written to the log instead of sent.
    pub log_email_codes: bool,
    /// What each account may keep, in bytes.
    pub quota: u64,
}

/// The largest single blob.
pub const MAX_BLOB: usize = 64 << 20;

pub struct AppState {
    pub store: Store,
    pub config: Config,
    webauthn: Webauthn,
    /// Passkey ceremonies in progress (a few minutes at most).
    flows: Mutex<HashMap<String, Flow>>,
}

enum Flow {
    Register {
        account: String,
        state: PasskeyRegistration,
        until: Instant,
    },
    Login {
        account: String,
        state: PasskeyAuthentication,
        until: Instant,
    },
}

const FLOW_TIME: Duration = Duration::from_secs(300);

impl AppState {
    pub fn new(config: Config, store: Store) -> anyhow::Result<Arc<AppState>> {
        let rp_id = config
            .origin
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("the origin has no host"))?
            .to_owned();
        let webauthn = WebauthnBuilder::new(&rp_id, &config.origin)?
            .rp_name("Iliada")
            .build()?;
        std::fs::create_dir_all(config.data_dir.join("blobs"))?;
        Ok(Arc::new(AppState {
            store,
            config,
            webauthn,
            flows: Mutex::new(HashMap::new()),
        }))
    }

    fn flows(&self) -> std::sync::MutexGuard<'_, HashMap<String, Flow>> {
        let mut f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        f.retain(|_, flow| match flow {
            Flow::Register { until, .. } | Flow::Login { until, .. } => *until > now,
        });
        f
    }

    fn blob_dir(&self, account: &str) -> PathBuf {
        self.config.data_dir.join("blobs").join(account)
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/email/start", post(email_start))
        .route("/v1/email/finish", post(email_finish))
        .route("/v1/passkey/register/start", post(passkey_register_start))
        .route("/v1/passkey/register/finish", post(passkey_register_finish))
        .route("/v1/passkey/login/start", post(passkey_login_start))
        .route("/v1/passkey/login/finish", post(passkey_login_finish))
        .route("/v1/device/code", post(device_code))
        .route("/v1/device/token", post(device_token))
        .route("/v1/device/approve", post(device_approve))
        .route("/v1/account", get(account).delete(delete_account))
        .route("/v1/sessions/{id}", delete(end_session))
        .route("/v1/signout", post(sign_out))
        .route("/v1/blobs", get(list_blobs))
        .route(
            "/v1/blobs/{name}",
            get(get_blob).put(put_blob).delete(delete_blob),
        )
        .merge(web::routes())
        .layer(DefaultBodyLimit::max(MAX_BLOB))
        .with_state(state)
}

// ── Errors ───────────────────────────────────────────────────────────

/// An answer that isn't a success: a status and a plain sentence.
#[derive(Debug)]
pub struct Error(StatusCode, String);

fn err(status: StatusCode, msg: impl Into<String>) -> Error {
    Error(status, msg.into())
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, axum::Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        tracing::error!("{e:#}");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "something went wrong on the server",
        )
    }
}

impl From<WebauthnError> for Error {
    fn from(e: WebauthnError) -> Error {
        tracing::info!("passkey refused: {e:?}");
        err(StatusCode::UNAUTHORIZED, "the passkey was not accepted")
    }
}

type R<T> = Result<T, Error>;

// ── Who is asking ────────────────────────────────────────────────────

/// A request from a signed-in browser or computer (`Authorization: Bearer`).
pub struct Auth(pub Session);

impl FromRequestParts<Arc<AppState>> for Auth {
    type Rejection = Error;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Computers send a token; the website's pages carry a cookie.
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned)
            .or_else(|| web::session_cookie(&parts.headers))
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))?;
        match state.store.session(token.trim())? {
            Some(s) => Ok(Auth(s)),
            None => Err(err(
                StatusCode::UNAUTHORIZED,
                "not signed in (or signed out)",
            )),
        }
    }
}

impl Auth {
    /// Only the account website (not a computer) may change the account.
    fn web(&self) -> R<&Session> {
        match self.0.kind {
            Kind::Web => Ok(&self.0),
            Kind::Computer => Err(err(
                StatusCode::FORBIDDEN,
                "only the account website can do this",
            )),
        }
    }
}

fn valid_email(e: &str) -> bool {
    let e = e.trim();
    e.len() <= 254
        && e.split_once('@').is_some_and(|(user, domain)| {
            !user.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        })
        && !e.contains(char::is_whitespace)
}

fn normal_email(e: &str) -> R<String> {
    let e = e.trim().to_lowercase();
    if valid_email(&e) {
        Ok(e)
    } else {
        Err(err(StatusCode::BAD_REQUEST, "that is not an email address"))
    }
}

// ── Email codes ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EmailStart {
    email: String,
}

async fn email_start(
    State(s): State<Arc<AppState>>,
    axum::Json(b): axum::Json<EmailStart>,
) -> R<StatusCode> {
    let email = normal_email(&b.email)?;
    let code = s.store.new_email_code(&email)?;
    if s.config.log_email_codes {
        tracing::info!(%email, %code, "sign-in code (development: not emailed)");
        Ok(StatusCode::NO_CONTENT)
    } else {
        // Sending email comes with hosting (see docs/account.md).
        Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "this server can't send email yet",
        ))
    }
}

#[derive(Deserialize)]
struct EmailFinish {
    email: String,
    code: String,
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub token: String,
}

async fn email_finish(
    State(s): State<Arc<AppState>>,
    axum::Json(b): axum::Json<EmailFinish>,
) -> R<Response> {
    let email = normal_email(&b.email)?;
    if !s.store.check_email_code(&email, &b.code)? {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "that code is wrong or too old; ask for a new one",
        ));
    }
    let a = s.store.account_for_email(&email)?;
    signed_in(&s, s.store.new_session(&a.id, Kind::Web, "website")?)
}

// ── Passkeys ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct Started<T> {
    pub flow: String,
    pub options: T,
}

async fn passkey_register_start(
    State(s): State<Arc<AppState>>,
    auth: Auth,
) -> R<axum::Json<Started<CreationChallengeResponse>>> {
    let session = auth.web()?;
    let account = s
        .store
        .account(&session.account)?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "no account"))?;
    let existing: Vec<CredentialID> = s
        .store
        .passkeys(&account.id)?
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();
    let user = Uuid::parse_str(&account.id).map_err(|e| anyhow::anyhow!(e))?;
    let (options, state) = s.webauthn.start_passkey_registration(
        user,
        &account.email,
        &account.email,
        Some(existing),
    )?;
    let flow = store::secret();
    s.flows().insert(
        flow.clone(),
        Flow::Register {
            account: account.id,
            state,
            until: Instant::now() + FLOW_TIME,
        },
    );
    Ok(axum::Json(Started { flow, options }))
}

#[derive(Deserialize)]
struct Finish<T> {
    flow: String,
    credential: T,
}

async fn passkey_register_finish(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    axum::Json(b): axum::Json<Finish<RegisterPublicKeyCredential>>,
) -> R<StatusCode> {
    let session = auth.web()?;
    let Some(Flow::Register { account, state, .. }) = s.flows().remove(&b.flow) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "that took too long; try again",
        ));
    };
    if account != session.account {
        return Err(err(StatusCode::FORBIDDEN, "not your passkey"));
    }
    let pk = s
        .webauthn
        .finish_passkey_registration(&b.credential, &state)?;
    s.store.save_passkey(&account, &pk)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn passkey_login_start(
    State(s): State<Arc<AppState>>,
    axum::Json(b): axum::Json<EmailStart>,
) -> R<axum::Json<Started<RequestChallengeResponse>>> {
    let email = normal_email(&b.email)?;
    let no_passkey = || {
        err(
            StatusCode::NOT_FOUND,
            "there is no passkey for this email; sign in with a code",
        )
    };
    let account = s.store.account_by_email(&email)?.ok_or_else(no_passkey)?;
    let keys = s.store.passkeys(&account.id)?;
    if keys.is_empty() {
        return Err(no_passkey());
    }
    let (options, state) = s.webauthn.start_passkey_authentication(&keys)?;
    let flow = store::secret();
    s.flows().insert(
        flow.clone(),
        Flow::Login {
            account: account.id,
            state,
            until: Instant::now() + FLOW_TIME,
        },
    );
    Ok(axum::Json(Started { flow, options }))
}

async fn passkey_login_finish(
    State(s): State<Arc<AppState>>,
    axum::Json(b): axum::Json<Finish<PublicKeyCredential>>,
) -> R<Response> {
    let Some(Flow::Login { account, state, .. }) = s.flows().remove(&b.flow) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "that took too long; try again",
        ));
    };
    let result = s
        .webauthn
        .finish_passkey_authentication(&b.credential, &state)?;
    // Keep the passkey's counter current (it detects copied keys).
    for mut pk in s.store.passkeys(&account)? {
        if pk.update_credential(&result) == Some(true) {
            s.store.save_passkey(&account, &pk)?;
        }
    }
    signed_in(&s, s.store.new_session(&account, Kind::Web, "website")?)
}

// ── Computers signing in ─────────────────────────────────────────────

#[derive(Deserialize)]
struct DeviceCodeReq {
    name: String,
}

async fn device_code(
    State(s): State<Arc<AppState>>,
    axum::Json(b): axum::Json<DeviceCodeReq>,
) -> R<axum::Json<serde_json::Value>> {
    let name: String = b
        .name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if name.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "the computer needs a name"));
    }
    let (device_code, user_code) = s.store.new_device_code(&name)?;
    let mut verify = s.config.origin.clone();
    verify.set_path("/device");
    Ok(axum::Json(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verify.as_str(),
        "expires_in": store::DEVICE_SECONDS,
        "interval": 5,
    })))
}

#[derive(Deserialize)]
struct DeviceTokenReq {
    device_code: String,
}

async fn device_token(
    State(s): State<Arc<AppState>>,
    axum::Json(b): axum::Json<DeviceTokenReq>,
) -> R<axum::Json<Token>> {
    match s.store.poll_device(&b.device_code)? {
        DeviceState::Approved(token) => Ok(axum::Json(Token { token })),
        DeviceState::Pending => Err(err(
            StatusCode::PRECONDITION_REQUIRED,
            "authorization_pending",
        )),
        DeviceState::Expired => Err(err(StatusCode::GONE, "expired_token")),
        DeviceState::Unknown => Err(err(StatusCode::BAD_REQUEST, "invalid_grant")),
    }
}

#[derive(Deserialize)]
struct Approve {
    user_code: String,
}

async fn device_approve(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    axum::Json(b): axum::Json<Approve>,
) -> R<axum::Json<serde_json::Value>> {
    let session = auth.web()?;
    match s.store.approve_device(&b.user_code, &session.account)? {
        Some(name) => Ok(axum::Json(json!({ "name": name }))),
        None => Err(err(
            StatusCode::NOT_FOUND,
            "that code is wrong or too old; the computer shows a new one",
        )),
    }
}

// ── The account ──────────────────────────────────────────────────────

async fn account(State(s): State<Arc<AppState>>, auth: Auth) -> R<axum::Json<serde_json::Value>> {
    let a = s
        .store
        .account(&auth.0.account)?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "no account"))?;
    let sessions = s.store.sessions(&a.id)?;
    Ok(axum::Json(json!({
        "email": a.email,
        "created": a.created,
        "passkeys": s.store.passkeys(&a.id)?.len(),
        "sessions": sessions,
        "this_session": auth.0.id,
        "used": used(&s, &a.id)?,
        "quota": s.config.quota,
    })))
}

async fn delete_account(State(s): State<Arc<AppState>>, auth: Auth) -> R<StatusCode> {
    let session = auth.web()?;
    let dir = s.blob_dir(&session.account);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(anyhow::Error::from)?;
    }
    s.store.delete_account(&session.account)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Signs out a computer or browser (from the website), or itself.
async fn end_session(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(id): Path<String>,
) -> R<StatusCode> {
    if id != auth.0.id {
        auth.web()?;
    }
    if s.store.end_session(&auth.0.account, &id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(err(StatusCode::NOT_FOUND, "no such sign-in"))
    }
}

async fn sign_out(State(s): State<Arc<AppState>>, auth: Auth) -> R<Response> {
    s.store.end_session(&auth.0.account, &auth.0.id)?;
    Ok((
        [(axum::http::header::SET_COOKIE, web::clear_cookie(&s))],
        StatusCode::NO_CONTENT,
    )
        .into_response())
}

/// A browser signed in: the token as JSON, and as the website's cookie.
fn signed_in(s: &AppState, token: String) -> R<Response> {
    let cookie = web::set_cookie(s, &token);
    Ok((
        [(axum::http::header::SET_COOKIE, cookie)],
        axum::Json(Token { token }),
    )
        .into_response())
}

// ── Encrypted data ───────────────────────────────────────────────────

/// Blob names: letters, digits, `.`, `-`, `_`; not starting with a dot.
fn valid_blob_name(n: &str) -> bool {
    (1..=128).contains(&n.len())
        && !n.starts_with('.')
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

fn blob_path(s: &AppState, account: &str, name: &str) -> R<PathBuf> {
    if valid_blob_name(name) {
        Ok(s.blob_dir(account).join(name))
    } else {
        Err(err(
            StatusCode::BAD_REQUEST,
            "names are letters, digits, '.', '-' and '_'",
        ))
    }
}

pub(crate) fn used(s: &AppState, account: &str) -> anyhow::Result<u64> {
    let dir = s.blob_dir(account);
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            total += e.metadata()?.len();
        }
    }
    Ok(total)
}

async fn list_blobs(
    State(s): State<Arc<AppState>>,
    auth: Auth,
) -> R<axum::Json<serde_json::Value>> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(s.blob_dir(&auth.0.account)) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if valid_blob_name(&name) {
                let m = e.metadata().map_err(anyhow::Error::from)?;
                let modified = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs());
                out.push(json!({ "name": name, "size": m.len(), "modified": modified }));
            }
        }
    }
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(axum::Json(json!({ "blobs": out })))
}

async fn get_blob(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(name): Path<String>,
) -> R<Vec<u8>> {
    let p = blob_path(&s, &auth.0.account, &name)?;
    tokio::fs::read(&p)
        .await
        .map_err(|_| err(StatusCode::NOT_FOUND, "nothing kept under that name"))
}

async fn put_blob(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(name): Path<String>,
    body: Bytes,
) -> R<StatusCode> {
    let p = blob_path(&s, &auth.0.account, &name)?;
    let replaced = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    if used(&s, &auth.0.account)?.saturating_sub(replaced) + body.len() as u64 > s.config.quota {
        return Err(err(
            StatusCode::INSUFFICIENT_STORAGE,
            "your account is full",
        ));
    }
    let dir = s.blob_dir(&auth.0.account);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(anyhow::Error::from)?;
    // Write then rename, so a blob is never half-written.
    let tmp = dir.join(format!(".{name}.{}", store::secret()));
    tokio::fs::write(&tmp, &body)
        .await
        .map_err(anyhow::Error::from)?;
    tokio::fs::rename(&tmp, &p)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_blob(
    State(s): State<Arc<AppState>>,
    auth: Auth,
    Path(name): Path<String>,
) -> R<StatusCode> {
    let p = blob_path(&s, &auth.0.account, &name)?;
    match tokio::fs::remove_file(&p).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(err(StatusCode::NOT_FOUND, "nothing kept under that name")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails() {
        assert!(valid_email("ana@example.com"));
        for bad in [
            "",
            "ana",
            "ana@",
            "@example.com",
            "ana@example",
            "a na@example.com",
            "ana@.com",
        ] {
            assert!(!valid_email(bad), "{bad}");
        }
        assert_eq!(
            normal_email(" Ana@Example.COM ").unwrap(),
            "ana@example.com"
        );
    }

    #[test]
    fn blob_names() {
        assert!(valid_blob_name("settings-2026-11-15.enc"));
        for bad in ["", ".hidden", "../x", "a/b", "a b", &"x".repeat(129)] {
            assert!(!valid_blob_name(bad), "{bad}");
        }
    }
}
